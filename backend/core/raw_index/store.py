from __future__ import annotations

import copy
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from core.raw_index.schema import initialize_schema


MAX_FAST_CANDIDATE_IDS = 900


class RawIndexStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn: sqlite3.Connection | None = None
        self._batch_depth = 0
        self._pending_commit = False
        self._fts_available_cache: bool | None = None
        self._search_text_current_cache_version: int | None = None
        self._coverage_summary_cache_version: int | None = None
        self._coverage_summary_cache: dict[str, Any] | None = None
        self._fts_current_cache_version: int | None = None
        self._fts_current_cache: bool | None = None
        self._artifact_type_counts_cache_version: int | None = None
        self._artifact_type_counts_cache: list[dict[str, Any]] | None = None
        self._untimed_candidate_cache_version: int | None = None
        self._untimed_candidate_cache: dict[tuple[str, tuple[str, ...]], bool] = {}

    def open(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        initialize_schema(self.conn)
        self._fts_available_cache = None
        self._search_text_current_cache_version = None
        self._invalidate_coverage_summary_cache()
        self._invalidate_fts_current_cache()
        self._invalidate_artifact_type_counts_cache()
        self._invalidate_untimed_candidate_cache()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
        self._fts_available_cache = None
        self._search_text_current_cache_version = None
        self._invalidate_coverage_summary_cache()
        self._invalidate_fts_current_cache()
        self._invalidate_artifact_type_counts_cache()
        self._invalidate_untimed_candidate_cache()

    def _conn(self) -> sqlite3.Connection:
        if self.conn is None:
            raise RuntimeError("RawIndexStore is not open")
        return self.conn

    @contextmanager
    def batch(self) -> Iterator[None]:
        self._batch_depth += 1
        try:
            yield
        except Exception:
            if self._batch_depth == 1:
                self._conn().rollback()
                self._pending_commit = False
            raise
        finally:
            self._batch_depth -= 1
            if self._batch_depth == 0 and self._pending_commit:
                self._conn().commit()
                self._pending_commit = False

    def _commit(self) -> None:
        if self._batch_depth:
            self._pending_commit = True
            return
        self._conn().commit()

    def start_parser_run(self, parser_name: str, source_ref: str, *, started_at: str) -> int:
        cur = self._conn().execute(
            """
            INSERT INTO raw_index_parser_runs(
                parser_name, source_ref, status, started_at
            ) VALUES (?, ?, ?, ?)
            """,
            (parser_name, source_ref, "running", started_at),
        )
        self._commit()
        self._invalidate_coverage_summary_cache()
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
        self._commit()
        self._invalidate_coverage_summary_cache()

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
        conn = self._conn()
        cur = conn.execute(
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
            conn.execute(
                """
                INSERT INTO raw_index_artifact_strings(
                    artifact_id, field_name, value
                ) VALUES (?, ?, ?)
                """,
                (artifact_id, field_name, str(value)),
            )
        for field_name, value in (times or {}).items():
            unix_ms, formatted = value
            conn.execute(
                """
                INSERT INTO raw_index_artifact_times(
                    artifact_id, field_name, unix_timestamp_ms, formatted_value
                ) VALUES (?, ?, ?, ?)
                """,
                (artifact_id, field_name, int(unix_ms), formatted),
            )
        if primary_path:
            conn.execute(
                """
                INSERT INTO raw_index_locations(
                    artifact_id, location_value, source_path
                ) VALUES (?, ?, ?)
                """,
                (artifact_id, primary_path, source_path),
            )
        self._write_search_text(
            artifact_id,
            _search_text_from_values(
                artifact_type=artifact_type,
                source_ref=source_ref,
                source_path=source_path,
                primary_path=primary_path,
                description=description,
                strings=strings or {},
                locations=[primary_path] if primary_path else [],
            ),
            replace_fts=False,
        )
        self._commit()
        self._invalidate_artifact_type_counts_cache()
        self._invalidate_untimed_candidate_cache()
        return artifact_id

    def search(
        self,
        *,
        keyword: str = "",
        keywords: list[str] | None = None,
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
            "keyword_mode": "none",
        }
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        keyword_terms = [str(keyword).strip()] if str(keyword or "").strip() else []
        keyword_terms.extend(str(k).strip() for k in (keywords or []) if str(k).strip())
        keyword_terms = list(dict.fromkeys(keyword_terms))
        keyword_likes: list[str] = []
        if keyword_terms:
            strategy["rebuilt_search_text"] = self._ensure_search_text_current()
            join_sql = (
                "JOIN raw_index_search_text st "
                "ON st.artifact_id = a.artifact_id"
            )
            keyword_likes = [f"%{term}%" for term in keyword_terms]
            if len(keyword_terms) == 1:
                strategy["keyword_mode"] = "single"
                like = keyword_likes[0]
                candidate_ids, gap = self._fast_candidate_ids(keyword_terms[0], like)
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
            else:
                strategy["keyword_mode"] = "or"
                candidate_ids, gap = self._fast_candidate_ids_for_keywords(
                    keyword_terms,
                    keyword_likes,
                )
                if candidate_ids is not None:
                    strategy["index"] = "fts5_trigram_or"
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
                    strategy["index"] = "materialized_like_or"
                    strategy["fast_candidate_gap"] = gap
                keyword_sql = " OR ".join("st.search_text LIKE ?" for _ in keyword_likes)
                where.append(f"({keyword_sql})")
                params.extend(keyword_likes)
            strategy["revalidated"] = True
        if start_date or end_date:
            strategy["date_filter"] = "artifact_times"
            if self._has_untimed_candidate(
                artifact_type=artifact_type,
                keyword_likes=keyword_likes,
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
        if limit <= 0:
            return {
                "total": int(total),
                "total_estimated": int(total),
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 0,
                "offset": offset,
                "limit": limit,
                "truncated": int(total) > offset,
                "coverage": self._coverage_summary(),
                "search_strategy": strategy,
                "hits": [],
            }
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
        artifact_ids = [int(row["artifact_id"]) for row in rows]
        hits = self._hydrate_hit_details(artifact_ids, rows)
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
        details = self._get_hit_details([artifact_id])
        if not details:
            return {"error": f"artifact_id {artifact_id} not found"}
        return details[0]

    def get_artifact_type_counts(self) -> list[dict[str, Any]]:
        current_data_version = self._sqlite_data_version()
        if (
            current_data_version is not None
            and self._artifact_type_counts_cache is not None
            and self._artifact_type_counts_cache_version == current_data_version
        ):
            return copy.deepcopy(self._artifact_type_counts_cache)
        rows = self._conn().execute(
            """
            SELECT artifact_type, COUNT(*) AS hit_count
            FROM raw_index_artifacts
            GROUP BY artifact_type
            ORDER BY artifact_type
            """
        ).fetchall()
        counts = [
            {
                "artifact_name": row["artifact_type"],
                "hit_count": int(row["hit_count"]),
                "count_accuracy": "exact",
            }
            for row in rows
        ]
        return self._cache_artifact_type_counts(counts)

    def _cache_artifact_type_counts(
        self,
        counts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        current_data_version = self._sqlite_data_version()
        if current_data_version is not None:
            self._artifact_type_counts_cache_version = current_data_version
            self._artifact_type_counts_cache = copy.deepcopy(counts)
        return counts

    def _invalidate_artifact_type_counts_cache(self) -> None:
        self._artifact_type_counts_cache_version = None
        self._artifact_type_counts_cache = None

    def _invalidate_untimed_candidate_cache(self) -> None:
        self._untimed_candidate_cache_version = None
        self._untimed_candidate_cache = {}

    def _get_hit_details(self, artifact_ids: list[int]) -> list[dict[str, Any]]:
        if not artifact_ids:
            return []
        rows: list[sqlite3.Row] = []
        for chunk in _id_chunks(artifact_ids):
            placeholders = ",".join("?" * len(chunk))
            rows.extend(
                self._conn().execute(
                    f"""
                    SELECT artifact_id, artifact_type, source_path, primary_path,
                           description
                    FROM raw_index_artifacts
                    WHERE artifact_id IN ({placeholders})
                    """,
                    chunk,
                ).fetchall()
            )
        return self._hydrate_hit_details(artifact_ids, rows)

    def _hydrate_hit_details(
        self,
        artifact_ids: list[int],
        artifact_rows: list[sqlite3.Row],
    ) -> list[dict[str, Any]]:
        if not artifact_ids:
            return []
        artifact_row_map = {
            int(row["artifact_id"]): row for row in artifact_rows
        }
        fields: dict[int, dict[str, str]] = {
            artifact_id: {} for artifact_id in artifact_ids
        }
        timestamps: dict[int, dict[str, str]] = {
            artifact_id: {} for artifact_id in artifact_ids
        }
        conn = self._conn()
        for chunk in _id_chunks(artifact_ids):
            placeholders = ",".join("?" * len(chunk))
            for row in conn.execute(
                f"""
                SELECT artifact_id, field_name, value
                FROM raw_index_artifact_strings
                WHERE artifact_id IN ({placeholders})
                ORDER BY artifact_id, field_name
                """,
                chunk,
            ).fetchall():
                fields.setdefault(int(row["artifact_id"]), {})[
                    row["field_name"]
                ] = row["value"]
            for row in conn.execute(
                f"""
                SELECT artifact_id, field_name, formatted_value
                FROM raw_index_artifact_times
                WHERE artifact_id IN ({placeholders})
                ORDER BY artifact_id, field_name
                """,
                chunk,
            ).fetchall():
                timestamps.setdefault(int(row["artifact_id"]), {})[
                    row["field_name"]
                ] = row["formatted_value"]
        details = []
        for artifact_id in artifact_ids:
            row = artifact_row_map.get(artifact_id)
            if row is None:
                continue
            details.append({
                "hit_id": int(row["artifact_id"]),
                "artifact_type": row["artifact_type"],
                "source_path": row["source_path"],
                "location": row["primary_path"],
                "description": row["description"],
                "fields": fields.get(artifact_id, {}),
                "timestamps": timestamps.get(artifact_id, {}),
            })
        return details

    def _coverage_summary(self) -> dict[str, Any]:
        current_data_version = self._sqlite_data_version()
        if (
            current_data_version is not None
            and self._coverage_summary_cache is not None
            and self._coverage_summary_cache_version == current_data_version
        ):
            return copy.deepcopy(self._coverage_summary_cache)
        rows = self._conn().execute(
            """
            SELECT parser_name, source_ref, status, coverage_status, error
            FROM raw_index_parser_runs
            ORDER BY run_id
            """
        ).fetchall()
        if not rows:
            return self._cache_coverage_summary({
                "status": "not_evaluable",
                "gaps": [{
                    "status": "not_evaluable",
                    "reason": "no_parser_runs",
                    "error": "No parser runs are recorded in this raw index.",
                }],
                "parser_runs": 0,
            })
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
        return self._cache_coverage_summary({
            "status": summary_status,
            "gaps": gaps,
            "parser_runs": len(rows),
        })

    def _cache_coverage_summary(self, summary: dict[str, Any]) -> dict[str, Any]:
        current_data_version = self._sqlite_data_version()
        if current_data_version is not None:
            self._coverage_summary_cache_version = current_data_version
            self._coverage_summary_cache = copy.deepcopy(summary)
        return summary

    def _invalidate_coverage_summary_cache(self) -> None:
        self._coverage_summary_cache_version = None
        self._coverage_summary_cache = None

    def rebuild_search_text(self) -> None:
        self._conn().execute("DELETE FROM raw_index_search_text")
        if self._fts_available():
            try:
                self._conn().execute("DELETE FROM raw_index_search_fts")
            except sqlite3.Error:
                pass
        self._invalidate_fts_current_cache()
        rows = self._conn().execute(
            "SELECT artifact_id FROM raw_index_artifacts ORDER BY artifact_id"
        ).fetchall()
        for row in rows:
            self._refresh_search_text(int(row["artifact_id"]))
        self._commit()
        self._mark_search_text_current()

    def _ensure_search_text_current(self) -> bool:
        current_data_version = self._sqlite_data_version()
        if (
            current_data_version is not None
            and self._search_text_current_cache_version == current_data_version
        ):
            return False
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
        if (
            artifact_count == search_count
            and not self._has_search_text_id_mismatch()
        ):
            self._mark_search_text_current()
            return False
        self.rebuild_search_text()
        return True

    def _mark_search_text_current(self) -> None:
        self._search_text_current_cache_version = self._sqlite_data_version()

    def _sqlite_data_version(self) -> int | None:
        try:
            return int(self._conn().execute("PRAGMA data_version").fetchone()[0])
        except sqlite3.Error:
            return None

    def _has_search_text_id_mismatch(self) -> bool:
        missing = self._conn().execute(
            """
            SELECT 1
            FROM raw_index_artifacts a
            LEFT JOIN raw_index_search_text st
                ON st.artifact_id = a.artifact_id
            WHERE st.artifact_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        if missing is not None:
            return True
        orphan = self._conn().execute(
            """
            SELECT 1
            FROM raw_index_search_text st
            LEFT JOIN raw_index_artifacts a
                ON a.artifact_id = st.artifact_id
            WHERE a.artifact_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        return orphan is not None

    def _refresh_search_text(self, artifact_id: int) -> None:
        self._write_search_text(
            artifact_id,
            self._search_text_for_artifact(artifact_id),
        )

    def _write_search_text(
        self,
        artifact_id: int,
        search_text: str,
        *,
        replace_fts: bool = True,
    ) -> None:
        conn = self._conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO raw_index_search_text(
                artifact_id, search_text
            ) VALUES (?, ?)
            """,
            (artifact_id, search_text),
        )
        if self._fts_available():
            try:
                if replace_fts:
                    conn.execute(
                        "DELETE FROM raw_index_search_fts WHERE rowid = ?",
                        (artifact_id,),
                    )
                conn.execute(
                    """
                    INSERT INTO raw_index_search_fts(rowid, search_text)
                    VALUES (?, ?)
                    """,
                    (artifact_id, search_text),
                )
            except sqlite3.Error:
                pass
        self._invalidate_fts_current_cache()

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
                LIMIT ?
                """,
                (like_pattern, MAX_FAST_CANDIDATE_IDS + 1),
            ).fetchall()
        except sqlite3.Error:
            return None, "fts_query_failed"
        candidate_ids = [int(row["rowid"]) for row in rows]
        if len(candidate_ids) > MAX_FAST_CANDIDATE_IDS:
            return None, "fast_candidate_too_large"
        return candidate_ids, ""

    def _fast_candidate_ids_for_keywords(
        self,
        keywords: list[str],
        like_patterns: list[str],
    ) -> tuple[list[int] | None, str]:
        if any(len(str(keyword or "")) < 3 for keyword in keywords):
            return None, "keyword_too_short_for_trigram"
        if not self._fts_available():
            return None, "fts_unavailable"
        if not self._fts_count_current():
            return None, "stale_fts"
        try:
            where_sql = " OR ".join("search_text LIKE ?" for _ in like_patterns)
            rows = self._conn().execute(
                f"""
                SELECT DISTINCT rowid
                FROM raw_index_search_fts
                WHERE {where_sql}
                ORDER BY rowid
                LIMIT ?
                """,
                [*like_patterns, MAX_FAST_CANDIDATE_IDS + 1],
            ).fetchall()
        except sqlite3.Error:
            return None, "fts_query_failed"
        candidate_ids = [int(row["rowid"]) for row in rows]
        if len(candidate_ids) > MAX_FAST_CANDIDATE_IDS:
            return None, "fast_candidate_too_large"
        return candidate_ids, ""

    def _fts_count_current(self) -> bool:
        current_data_version = self._sqlite_data_version()
        if (
            current_data_version is not None
            and self._fts_current_cache is not None
            and self._fts_current_cache_version == current_data_version
        ):
            return self._fts_current_cache
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
            return self._cache_fts_current(False)
        if fts_count != search_count:
            return self._cache_fts_current(False)
        return self._cache_fts_current(not self._has_fts_id_mismatch())

    def _cache_fts_current(self, is_current: bool) -> bool:
        current_data_version = self._sqlite_data_version()
        if current_data_version is not None:
            self._fts_current_cache_version = current_data_version
            self._fts_current_cache = is_current
        return is_current

    def _invalidate_fts_current_cache(self) -> None:
        self._fts_current_cache_version = None
        self._fts_current_cache = None

    def _has_fts_id_mismatch(self) -> bool:
        try:
            missing = self._conn().execute(
                """
                SELECT 1
                FROM raw_index_search_text st
                LEFT JOIN raw_index_search_fts fts
                    ON fts.rowid = st.artifact_id
                WHERE fts.rowid IS NULL
                LIMIT 1
                """
            ).fetchone()
            if missing is not None:
                return True
            orphan = self._conn().execute(
                """
                SELECT 1
                FROM raw_index_search_fts fts
                LEFT JOIN raw_index_search_text st
                    ON st.artifact_id = fts.rowid
                WHERE st.artifact_id IS NULL
                LIMIT 1
                """
            ).fetchone()
            return orphan is not None
        except sqlite3.Error:
            return True

    def _fts_available(self) -> bool:
        if self._fts_available_cache is not None:
            return self._fts_available_cache
        try:
            self._fts_available_cache = self._conn().execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'raw_index_search_fts'
                """
            ).fetchone() is not None
        except sqlite3.Error:
            self._fts_available_cache = False
        return self._fts_available_cache

    def _has_untimed_candidate(
        self,
        *,
        artifact_type: str = "",
        keyword_likes: list[str] | None = None,
    ) -> bool:
        joins = []
        where = []
        params: list[Any] = []
        keyword_likes = keyword_likes or []
        if keyword_likes:
            self._ensure_search_text_current()
            joins.append(
                "JOIN raw_index_search_text st ON st.artifact_id = a.artifact_id"
            )
            keyword_sql = " OR ".join("st.search_text LIKE ?" for _ in keyword_likes)
            where.append(f"({keyword_sql})")
            params.extend(keyword_likes)
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        cache_key = (artifact_type, tuple(keyword_likes))
        current_data_version = self._sqlite_data_version()
        if current_data_version is not None:
            if self._untimed_candidate_cache_version != current_data_version:
                self._untimed_candidate_cache = {}
                self._untimed_candidate_cache_version = current_data_version
            if cache_key in self._untimed_candidate_cache:
                return self._untimed_candidate_cache[cache_key]
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
        result = row is not None
        if current_data_version is not None:
            self._untimed_candidate_cache[cache_key] = result
        return result


def _id_chunks(values: list[int], size: int = 900) -> Iterator[list[int]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _search_text_from_values(
    *,
    artifact_type: str,
    source_ref: str,
    source_path: str,
    primary_path: str,
    description: str,
    strings: dict[str, str],
    locations: list[str],
) -> str:
    parts = [
        artifact_type,
        source_ref,
        source_path,
        primary_path,
        description,
    ]
    parts.extend(
        str(value or "")
        for _, value in sorted(
            strings.items(),
            key=lambda item: (str(item[0]), str(item[1])),
        )
    )
    parts.extend(str(value or "") for value in sorted(locations))
    return "\n".join(str(part) for part in parts if str(part))


def _iso_date_to_ms(value: str, *, is_end: bool) -> int:
    if "T" not in value:
        suffix = "T23:59:59.999+00:00" if is_end else "T00:00:00+00:00"
        value = value + suffix
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
