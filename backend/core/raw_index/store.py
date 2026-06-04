from __future__ import annotations

import os
import sqlite3
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
        self._conn().commit()
        return artifact_id

    def search(
        self,
        *,
        keyword: str = "",
        artifact_type: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        params: list[Any] = []
        where: list[str] = []
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        if keyword:
            where.append(
                """
                a.artifact_id IN (
                    SELECT artifact_id
                    FROM raw_index_artifact_strings
                    WHERE value LIKE ?
                    UNION
                    SELECT artifact_id
                    FROM raw_index_locations
                    WHERE location_value LIKE ?
                )
                """
            )
            like = f"%{keyword}%"
            params.extend([like, like])
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        total = self._conn().execute(
            f"""
            SELECT COUNT(DISTINCT a.artifact_id)
            FROM raw_index_artifacts a
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
