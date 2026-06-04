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
        raw_keywords = filters.get("keywords") or []
        if isinstance(raw_keywords, str):
            raw_keywords = [k.strip() for k in raw_keywords.split(",") if k.strip()]
        return self._require_store().search(
            keyword=keyword,
            keywords=list(raw_keywords),
            artifact_type=str(filters.get("artifact_type") or "").strip(),
            start_date=str(filters.get("start_date") or ""),
            end_date=str(filters.get("end_date") or ""),
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
        keywords: list[str] | None = None,
    ) -> dict:
        store = self._require_store()
        conn = store._conn()
        start_ms = _iso_date_to_ms(start_date, is_end=False) if start_date else 0
        end_ms = _iso_date_to_ms(end_date, is_end=True) if end_date else 9999999999999
        params: list[Any] = [start_ms, end_ms]
        joins: list[str] = []
        where = ["t.unix_timestamp_ms BETWEEN ? AND ?"]
        strategy: dict[str, Any] = {
            "date_filter": "artifact_times",
            "keyword_filter": "none",
            "index": "none",
            "revalidated": False,
            "rebuilt_search_text": False,
            "fast_candidate_gap": "",
            "count_accuracy": "exact",
        }
        raw_artifact_types = (
            [artifact_types]
            if isinstance(artifact_types, str)
            else artifact_types or []
        )
        artifact_type_list = list(
            dict.fromkeys(
                str(artifact_type).strip()
                for artifact_type in raw_artifact_types
                if str(artifact_type).strip()
            )
        )
        if artifact_type_list:
            placeholders = ",".join("?" * len(artifact_type_list))
            where.append(f"a.artifact_type IN ({placeholders})")
            params.extend(artifact_type_list)
        raw_keywords = (
            [k.strip() for k in keywords.split(",") if k.strip()]
            if isinstance(keywords, str)
            else keywords or []
        )
        keyword_list = list(
            dict.fromkeys(str(k).strip() for k in raw_keywords if str(k).strip())
        )
        keyword_likes: list[str] = []
        if keyword_list:
            strategy["keyword_filter"] = "search_text"
            strategy["rebuilt_search_text"] = store._ensure_search_text_current(
                conn=conn,
            )
            joins.append(
                "JOIN raw_index_search_text st ON st.artifact_id = a.artifact_id"
            )
            keyword_likes = [f"%{keyword}%" for keyword in keyword_list]
            candidate_ids, gap = store._fast_candidate_ids_for_keywords(
                keyword_list,
                keyword_likes,
                conn=conn,
            )
            if candidate_ids is not None:
                strategy["index"] = "fts5_trigram_or"
                if not candidate_ids:
                    return {
                        "total_events": 0,
                        "total_is_estimated": False,
                        "count_accuracy": "exact",
                        "returned": 0,
                        "offset": offset,
                        "limit": limit,
                        "truncated": False,
                        "coverage": store._coverage_summary(conn=conn),
                        "timeline_strategy": strategy,
                        "entries": [],
                    }
                placeholders = ",".join("?" * len(candidate_ids))
                where.append(f"a.artifact_id IN ({placeholders})")
                params.extend(candidate_ids)
            else:
                strategy["index"] = "materialized_like_or"
                strategy["fast_candidate_gap"] = gap
            keyword_sql = " OR ".join("st.search_text LIKE ?" for _ in keyword_list)
            where.append(f"({keyword_sql})")
            params.extend(keyword_likes)
            strategy["revalidated"] = True
        if _has_untimed_timeline_candidate(
            store,
            artifact_type_list=artifact_type_list,
            keyword_likes=keyword_likes,
            conn=conn,
        ):
            coverage = dict(store._coverage_summary(conn=conn))
            gaps = list(coverage.get("gaps", []))
            gaps.append({
                "status": "not_evaluable",
                "reason": "raw_timeline_date_filter_without_indexed_times",
                "artifact_types": artifact_type_list,
                "keywords": keyword_list,
            })
            coverage["status"] = "not_evaluable"
            coverage["gaps"] = gaps
            return {
                "ok": False,
                "status": "not_evaluable",
                "total_events": 0,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 0,
                "offset": offset,
                "limit": limit,
                "truncated": False,
                "coverage": coverage,
                "timeline_strategy": strategy,
                "entries": [],
            }
        join_sql = "\n            ".join(joins)
        where_sql = " AND ".join(where)
        total = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            {join_sql}
            WHERE {where_sql}
            """,
            params,
        ).fetchone()[0]
        total = int(total)
        if limit <= 0 or offset >= total:
            return {
                "total_events": total,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 0,
                "offset": offset,
                "limit": limit,
                "truncated": total > offset,
                "coverage": store._coverage_summary(conn=conn),
                "timeline_strategy": strategy,
                "entries": [],
            }
        rows = conn.execute(
            f"""
            SELECT t.artifact_id, t.unix_timestamp_ms, t.formatted_value,
                   t.field_name, a.artifact_type, a.description
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            {join_sql}
            WHERE {where_sql}
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
            "coverage": store._coverage_summary(conn=conn),
            "timeline_strategy": strategy,
            "entries": entries,
        }

    def get_artifact_type_counts(self) -> list[dict]:
        return self._require_store().get_artifact_type_counts()

    def get_coverage(self) -> dict:
        store = self._require_store()
        return store._coverage_summary(conn=store._conn())

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


def _has_untimed_timeline_candidate(
    store: RawIndexStore,
    *,
    artifact_type_list: list[str],
    keyword_likes: list[str],
    conn: Any,
) -> bool:
    return store._has_untimed_candidate_for_artifact_types(
        artifact_types=artifact_type_list,
        keyword_likes=keyword_likes,
        conn=conn,
    )


def _iso_date_to_ms(value: str, *, is_end: bool) -> int:
    if "T" not in value:
        suffix = "T23:59:59.999+00:00" if is_end else "T00:00:00+00:00"
        value = value + suffix
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
