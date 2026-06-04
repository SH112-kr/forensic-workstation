from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from core.connectors.base import BaseConnector
from core.raw_index.schema import RAW_INDEX_SCHEMA_VERSION
from core.raw_index.store import RawIndexStore


class RawImageIndexConnector(BaseConnector):
    def __init__(self) -> None:
        self._store: RawIndexStore | None = None
        self._path = ""
        self._metadata: dict[str, Any] = {}

    def connect(self, path: str, **kwargs: Any) -> dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Raw index not found: {path}")
        self._path = path
        self._store = RawIndexStore(path)
        self._store.open()
        try:
            self._metadata = self._load_metadata(
                expected_fingerprint=str(kwargs.get("expected_fingerprint") or "")
            )
        except Exception:
            self.disconnect()
            raise
        return self.get_metadata()

    def disconnect(self) -> None:
        if self._store:
            self._store.close()
        self._store = None
        self._path = ""
        self._metadata = {}

    def is_connected(self) -> bool:
        return self._store is not None

    def get_metadata(self) -> dict:
        return dict(self._metadata)

    def get_capabilities(self) -> list[str]:
        return ["search", "timeline", "hit_detail", "artifact_type_counts"]

    def search(
        self,
        keyword: str = "",
        filters: dict | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        filters = filters or {}
        return self._require_store().search(
            keyword=keyword,
            artifact_type=str(filters.get("artifact_type") or ""),
            limit=limit,
            offset=offset,
        )

    def get_hit_detail(self, hit_id: int) -> dict:
        return self._require_store().get_hit_detail(hit_id)

    def get_timeline(
        self,
        start_date: str = "",
        end_date: str = "",
        artifact_types: list[str] | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> dict:
        conn = self._require_store()._conn()
        start_ms = _iso_date_to_ms(start_date, is_end=False) if start_date else 0
        end_ms = _iso_date_to_ms(end_date, is_end=True) if end_date else 9999999999999
        params: list[Any] = [start_ms, end_ms]
        type_sql = ""
        if artifact_types:
            placeholders = ",".join("?" * len(artifact_types))
            type_sql = f"AND a.artifact_type IN ({placeholders})"
            params.extend(artifact_types)
        total = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            WHERE t.unix_timestamp_ms BETWEEN ? AND ? {type_sql}
            """,
            params,
        ).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT t.artifact_id, t.unix_timestamp_ms, t.formatted_value,
                   t.field_name, a.artifact_type, a.description
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            WHERE t.unix_timestamp_ms BETWEEN ? AND ? {type_sql}
            ORDER BY t.unix_timestamp_ms, t.artifact_id, t.field_name
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        entries = [
            {
                "hit_id": int(row["artifact_id"]),
                "timestamp_ms": int(row["unix_timestamp_ms"]),
                "timestamp": row["formatted_value"],
                "time_field": row["field_name"],
                "artifact_type": row["artifact_type"],
                "description": row["description"],
            }
            for row in rows
        ]
        return {
            "total_events": int(total),
            "total_is_estimated": False,
            "count_accuracy": "exact",
            "returned": len(entries),
            "offset": offset,
            "limit": limit,
            "truncated": int(total) > offset + len(entries),
            "coverage": self._require_store()._coverage_summary(),
            "entries": entries,
        }

    def get_artifact_type_counts(self) -> list[dict]:
        rows = self._require_store()._conn().execute(
            """
            SELECT artifact_type, COUNT(*) AS hit_count
            FROM raw_index_artifacts
            GROUP BY artifact_type
            ORDER BY artifact_type
            """
        ).fetchall()
        return [
            {
                "artifact_name": row["artifact_type"],
                "hit_count": int(row["hit_count"]),
                "count_accuracy": "exact",
            }
            for row in rows
        ]

    def _load_metadata(self, *, expected_fingerprint: str = "") -> dict[str, Any]:
        rows = self._require_store()._conn().execute(
            "SELECT key, value FROM raw_index_metadata"
        ).fetchall()
        meta = {row["key"]: row["value"] for row in rows}
        version = str(meta.get("schema_version") or "")
        if version != str(RAW_INDEX_SCHEMA_VERSION):
            raise RuntimeError(
                f"stale raw index schema mismatch: expected "
                f"{RAW_INDEX_SCHEMA_VERSION}, found {version or 'missing'}"
            )
        fingerprint = str(meta.get("raw_image_fingerprint") or "")
        if expected_fingerprint and fingerprint != expected_fingerprint:
            raise RuntimeError(
                "stale raw index fingerprint mismatch: expected "
                f"{expected_fingerprint}, found {fingerprint or 'missing'}"
            )
        return {
            "source_type": "raw_image_sidecar",
            "source_path": self._path,
            "schema_version": version,
            "raw_image_fingerprint": fingerprint,
        }

    def _require_store(self) -> RawIndexStore:
        if self._store is None:
            raise RuntimeError("RawImageIndexConnector is not connected")
        return self._store


def _iso_date_to_ms(value: str, *, is_end: bool) -> int:
    if "T" not in value:
        suffix = "T23:59:59.999+00:00" if is_end else "T00:00:00+00:00"
        value = value + suffix
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
