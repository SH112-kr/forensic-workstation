from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from core.raw_index.schema import initialize_schema


class RawIndexStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn: sqlite3.Connection | None = None

    def open(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        initialize_schema(self.conn)

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def _conn(self) -> sqlite3.Connection:
        if self.conn is None:
            raise RuntimeError("RawIndexStore is not open")
        return self.conn

    def start_parser_run(self, parser_name: str, source_ref: str, *, started_at: str) -> int:
        cur = self._conn().execute(
            """
            INSERT INTO raw_index_parser_runs(
                parser_name, source_ref, status, started_at
            ) VALUES (?, ?, ?, ?)
            """,
            (parser_name, source_ref, "running", started_at),
        )
        self._conn().commit()
        return int(cur.lastrowid)

    def finish_parser_run(
        self,
        run_id: int,
        *,
        status: str,
        coverage_status: str,
        finished_at: str,
        error: str = "",
    ) -> None:
        self._conn().execute(
            """
            UPDATE raw_index_parser_runs
            SET status = ?, coverage_status = ?, finished_at = ?, error = ?
            WHERE run_id = ?
            """,
            (status, coverage_status, finished_at, error, run_id),
        )
        self._conn().commit()

    def insert_artifact(
        self,
        *,
        artifact_type: str,
        source_ref: str,
        source_path: str,
        primary_path: str,
        description: str,
        strings: dict[str, str] | None = None,
        times: dict[str, tuple[int, str]] | None = None,
        parser_run_id: int | None = None,
    ) -> int:
        cur = self._conn().execute(
            """
            INSERT INTO raw_index_artifacts(
                artifact_type, source_ref, source_path, primary_path,
                description, parser_run_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_type,
                source_ref,
                source_path,
                primary_path,
                description,
                parser_run_id,
            ),
        )
        artifact_id = int(cur.lastrowid)
        for field_name, value in (strings or {}).items():
            self._conn().execute(
                """
                INSERT INTO raw_index_artifact_strings(
                    artifact_id, field_name, value
                ) VALUES (?, ?, ?)
                """,
                (artifact_id, field_name, str(value)),
            )
        for field_name, value in (times or {}).items():
            unix_ms, formatted = value
            self._conn().execute(
                """
                INSERT INTO raw_index_artifact_times(
                    artifact_id, field_name, unix_timestamp_ms, formatted_value
                ) VALUES (?, ?, ?, ?)
                """,
                (artifact_id, field_name, int(unix_ms), formatted),
            )
        if primary_path:
            self._conn().execute(
                """
                INSERT INTO raw_index_locations(
                    artifact_id, location_value, source_path
                ) VALUES (?, ?, ?)
                """,
                (artifact_id, primary_path, source_path),
            )
        self._refresh_search_text(artifact_id)
        self._conn().commit()
        return artifact_id

    def search(
        self,
        *,
        keyword: str = "",
        artifact_type: str = "",
        start_date: str = "",
        end_date: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        params: list[Any] = []
        where: list[str] = []
        join_sql = ""
        strategy: dict[str, Any] = {
            "index": "none",
            "revalidated": False,
            "rebuilt_search_text": False,
            "fast_candidate_gap": "",
            "date_filter": "none",
        }
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        like = ""
        if keyword:
            strategy["rebuilt_search_text"] = self._ensure_search_text_current()
            join_sql = (
                "JOIN raw_index_search_text st "
                "ON st.artifact_id = a.artifact_id"
            )
            like = f"%{keyword}%"
            candidate_ids, gap = self._fast_candidate_ids(keyword, like)
            if candidate_ids is not None:
                strategy["index"] = "fts5_trigram"
                if not candidate_ids:
                    if start_date or end_date:
                        strategy["date_filter"] = "artifact_times"
                    return {
                        "total": 0,
                        "total_estimated": 0,
                        "total_is_estimated": False,
                        "count_accuracy": "exact",
                        "returned": 0,
                        "offset": offset,
                        "limit": limit,
                        "truncated": False,
                        "coverage": self._coverage_summary(),
                        "search_strategy": strategy,
                        "hits": [],
                    }
                placeholders = ",".join("?" * len(candidate_ids))
                where.append(f"a.artifact_id IN ({placeholders})")
                params.extend(candidate_ids)
            else:
                strategy["index"] = "materialized_like"
                strategy["fast_candidate_gap"] = gap
            where.append("st.search_text LIKE ?")
            params.append(like)
            strategy["revalidated"] = True
        if start_date or end_date:
            strategy["date_filter"] = "artifact_times"
            if self._has_untimed_candidate(
                artifact_type=artifact_type,
                keyword_like=like,
            ):
                coverage = self._coverage_summary()
                coverage = dict(coverage)
                gaps = list(coverage.get("gaps", []))
                gaps.append({
                    "status": "not_evaluable",
                    "reason": "raw_search_date_filter_without_indexed_times",
                    "artifact_type": artifact_type,
                })
                coverage["status"] = "not_evaluable"
                coverage["gaps"] = gaps
                return {
                    "ok": False,
                    "status": "not_evaluable",
                    "total": 0,
                    "total_estimated": 0,
                    "total_is_estimated": False,
                    "count_accuracy": "exact",
                    "returned": 0,
                    "offset": offset,
                    "limit": limit,
                    "truncated": False,
                    "coverage": coverage,
                    "search_strategy": strategy,
                    "hits": [],
                }
            start_ms = _iso_date_to_ms(start_date, is_end=False) if start_date else 0
            end_ms = _iso_date_to_ms(end_date, is_end=True) if end_date else 9999999999999
            where.append(
                """
                a.artifact_id IN (
                    SELECT artifact_id
                    FROM raw_index_artifact_times
                    WHERE unix_timestamp_ms BETWEEN ? AND ?
                )
                """
            )
            params.extend([start_ms, end_ms])
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        total = self._conn().execute(
            f"""
            SELECT COUNT(DISTINCT a.artifact_id)
            FROM raw_index_artifacts a
            {join_sql}
            {where_sql}
            """,
            params,
        ).fetchone()[0]
        rows = self._conn().execute(
            f"""
            SELECT DISTINCT
                a.artifact_id, a.artifact_type, a.source_path,
                a.primary_path, a.description
            FROM raw_index_artifacts a
            {join_sql}
            {where_sql}
            ORDER BY a.artifact_id
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        hits = [self.get_hit_detail(int(row["artifact_id"])) for row in rows]
        return {
            "total": int(total),
            "total_estimated": int(total),
            "total_is_estimated": False,
            "count_accuracy": "exact",
            "returned": len(hits),
            "offset": offset,
            "limit": limit,
            "truncated": int(total) > offset + len(hits),
            "coverage": self._coverage_summary(),
            "search_strategy": strategy,
            "hits": hits,
        }

    def get_hit_detail(self, artifact_id: int) -> dict[str, Any]:
        row = self._conn().execute(
            """
            SELECT artifact_id, artifact_type, source_path, primary_path,
                   description
            FROM raw_index_artifacts
            WHERE artifact_id = ?
            """,
            (artifact_id,),
        ).fetchone()
        if row is None:
            return {"error": f"artifact_id {artifact_id} not found"}
        fields = {
            r["field_name"]: r["value"]
            for r in self._conn().execute(
                """
                SELECT field_name, value
                FROM raw_index_artifact_strings
                WHERE artifact_id = ?
                ORDER BY field_name
                """,
                (artifact_id,),
            ).fetchall()
        }
        timestamps = {
            r["field_name"]: r["formatted_value"]
            for r in self._conn().execute(
                """
                SELECT field_name, formatted_value
                FROM raw_index_artifact_times
                WHERE artifact_id = ?
                ORDER BY field_name
                """,
                (artifact_id,),
            ).fetchall()
        }
        return {
            "hit_id": int(row["artifact_id"]),
            "artifact_type": row["artifact_type"],
            "source_path": row["source_path"],
            "location": row["primary_path"],
            "description": row["description"],
            "fields": fields,
            "timestamps": timestamps,
        }

    def _coverage_summary(self) -> dict[str, Any]:
        rows = self._conn().execute(
            """
            SELECT parser_name, source_ref, status, coverage_status, error
            FROM raw_index_parser_runs
            ORDER BY run_id
            """
        ).fetchall()
        if not rows:
            return {
                "status": "not_evaluable",
                "gaps": [{
                    "status": "not_evaluable",
                    "reason": "no_parser_runs",
                    "error": "No parser runs are recorded in this raw index.",
                }],
                "parser_runs": 0,
            }
        gaps = []
        for row in rows:
            coverage_status = str(row["coverage_status"] or "")
            status = str(row["status"] or "")
            error = str(row["error"] or "")
            if status != "completed" or coverage_status not in {"searched"} or error:
                gaps.append({
                    "parser_name": row["parser_name"],
                    "source_ref": row["source_ref"],
                    "status": coverage_status or status,
                    "parser_status": status,
                    "error": error,
                })
        summary_status = "searched"
        if gaps:
            statuses = {str(gap.get("status") or "") for gap in gaps}
            if "not_evaluable" in statuses:
                summary_status = "not_evaluable"
            else:
                summary_status = "coverage_gap"
        return {
            "status": summary_status,
            "gaps": gaps,
            "parser_runs": len(rows),
        }

    def rebuild_search_text(self) -> None:
        self._conn().execute("DELETE FROM raw_index_search_text")
        if self._fts_available():
            try:
                self._conn().execute("DELETE FROM raw_index_search_fts")
            except sqlite3.Error:
                pass
        rows = self._conn().execute(
            "SELECT artifact_id FROM raw_index_artifacts ORDER BY artifact_id"
        ).fetchall()
        for row in rows:
            self._refresh_search_text(int(row["artifact_id"]))
        self._conn().commit()

    def _ensure_search_text_current(self) -> bool:
        artifact_count = int(
            self._conn().execute(
                "SELECT COUNT(*) FROM raw_index_artifacts"
            ).fetchone()[0]
        )
        search_count = int(
            self._conn().execute(
                "SELECT COUNT(*) FROM raw_index_search_text"
            ).fetchone()[0]
        )
        if artifact_count == search_count:
            return False
        self.rebuild_search_text()
        return True

    def _refresh_search_text(self, artifact_id: int) -> None:
        search_text = self._search_text_for_artifact(artifact_id)
        self._conn().execute(
            """
            INSERT OR REPLACE INTO raw_index_search_text(
                artifact_id, search_text
            ) VALUES (?, ?)
            """,
            (artifact_id, search_text),
        )
        if self._fts_available():
            try:
                self._conn().execute(
                    "DELETE FROM raw_index_search_fts WHERE rowid = ?",
                    (artifact_id,),
                )
                self._conn().execute(
                    """
                    INSERT INTO raw_index_search_fts(rowid, search_text)
                    VALUES (?, ?)
                    """,
                    (artifact_id, search_text),
                )
            except sqlite3.Error:
                pass

    def _search_text_for_artifact(self, artifact_id: int) -> str:
        parts: list[str] = []
        row = self._conn().execute(
            """
            SELECT artifact_type, source_ref, source_path, primary_path,
                   description
            FROM raw_index_artifacts
            WHERE artifact_id = ?
            """,
            (artifact_id,),
        ).fetchone()
        if row:
            parts.extend(str(row[key] or "") for key in row.keys())
        parts.extend(
            str(r["value"] or "")
            for r in self._conn().execute(
                """
                SELECT value
                FROM raw_index_artifact_strings
                WHERE artifact_id = ?
                ORDER BY field_name, value
                """,
                (artifact_id,),
            ).fetchall()
        )
        parts.extend(
            str(r["location_value"] or "")
            for r in self._conn().execute(
                """
                SELECT location_value
                FROM raw_index_locations
                WHERE artifact_id = ?
                ORDER BY location_value
                """,
                (artifact_id,),
            ).fetchall()
        )
        return "\n".join(part for part in parts if part)

    def _fast_candidate_ids(
        self,
        keyword: str,
        like_pattern: str,
    ) -> tuple[list[int] | None, str]:
        if len(str(keyword or "")) < 3:
            return None, "keyword_too_short_for_trigram"
        if not self._fts_available():
            return None, "fts_unavailable"
        if not self._fts_count_current():
            return None, "stale_fts"
        try:
            rows = self._conn().execute(
                """
                SELECT rowid
                FROM raw_index_search_fts
                WHERE search_text LIKE ?
                ORDER BY rowid
                """,
                (like_pattern,),
            ).fetchall()
        except sqlite3.Error:
            return None, "fts_query_failed"
        return [int(row["rowid"]) for row in rows], ""

    def _fts_count_current(self) -> bool:
        try:
            fts_count = int(
                self._conn().execute(
                    "SELECT COUNT(*) FROM raw_index_search_fts"
                ).fetchone()[0]
            )
            search_count = int(
                self._conn().execute(
                    "SELECT COUNT(*) FROM raw_index_search_text"
                ).fetchone()[0]
            )
        except sqlite3.Error:
            return False
        return fts_count == search_count

    def _fts_available(self) -> bool:
        try:
            return self._conn().execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'raw_index_search_fts'
                """
            ).fetchone() is not None
        except sqlite3.Error:
            return False

    def _has_untimed_candidate(
        self,
        *,
        artifact_type: str = "",
        keyword_like: str = "",
    ) -> bool:
        joins = []
        where = []
        params: list[Any] = []
        if keyword_like:
            self._ensure_search_text_current()
            joins.append(
                "JOIN raw_index_search_text st ON st.artifact_id = a.artifact_id"
            )
            where.append("st.search_text LIKE ?")
            params.append(keyword_like)
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        where.append(
            """
            NOT EXISTS (
                SELECT 1
                FROM raw_index_artifact_times t
                WHERE t.artifact_id = a.artifact_id
            )
            """
        )
        where_sql = "WHERE " + " AND ".join(where)
        row = self._conn().execute(
            f"""
            SELECT 1
            FROM raw_index_artifacts a
            {' '.join(joins)}
            {where_sql}
            LIMIT 1
            """,
            params,
        ).fetchone()
        return row is not None


def _iso_date_to_ms(value: str, *, is_end: bool) -> int:
    if "T" not in value:
        suffix = "T23:59:59.999+00:00" if is_end else "T00:00:00+00:00"
        value = value + suffix
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
