"""AXIOM .mfdb SQLite connector — on-demand queries, no bulk loading."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from connectors.base import BaseConnector
from sql import axiom_queries as Q


class AxiomMfdbConnector(BaseConnector):

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self._path: str = ""
        # Cached lookups (small, static tables)
        self._frag_defs: dict[str, str] = {}        # frag_def_id -> name
        self._frag_types: dict[str, str] = {}        # frag_def_id -> data_type
        self._artifact_versions: dict[str, str] = {} # av_id -> artifact_name
        self._case_info: dict = {}

    # ── Connection ──

    def connect(self, path: str, **kwargs: Any) -> dict:
        uri = f"file:{path}?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._path = path
        self._cache_lookups()
        self._case_info = self._load_case_info()

        # Initialize structured artifact queries
        from connectors.axiom_artifact_queries import ArtifactQueries
        self.artifact_queries = ArtifactQueries(self._conn)

        return self._case_info

    def disconnect(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def is_connected(self) -> bool:
        return self._conn is not None

    def get_metadata(self) -> dict:
        return self._case_info

    def get_capabilities(self) -> list[str]:
        return [
            "search", "timeline", "ioc_extraction", "suspicious_detection",
            "correlation", "hash_search", "tag_search", "source_search",
            "hit_detail",
        ]

    # ── Cache ──

    def _cache_lookups(self) -> None:
        cur = self._cursor()
        cur.execute(Q.FRAGMENT_DEFINITIONS)
        for row in cur.fetchall():
            fid = str(row["fragment_definition_id"])
            self._frag_defs[fid] = row["name"]
            self._frag_types[fid] = row["data_type"] or "String"

        cur.execute(Q.ARTIFACT_VERSIONS)
        for row in cur.fetchall():
            self._artifact_versions[str(row["artifact_version_id"])] = row["artifact_name"]

    def _load_case_info(self) -> dict:
        cur = self._cursor()

        # Case info
        cur.execute(Q.CASE_INFO)
        ci = cur.fetchone()
        case_name = (ci["case_name"] or "") if ci else ""
        case_number = (ci["case_number"] or "") if ci else ""
        created_on = (ci["created_on"] or "") if ci else ""
        # Fallback: derive case name from path if DB value is empty/corrupt
        if not case_name or case_name == "None":
            case_name = os.path.basename(os.path.dirname(self._path))

        # Total hits
        cur.execute(Q.COUNT_TOTAL_HITS)
        total_hits = cur.fetchone()[0]

        # Artifact types
        cur.execute(Q.ARTIFACT_TYPE_COUNTS)
        type_counts = {row["artifact_name"]: row["hit_count"] for row in cur.fetchall()}

        # Date range
        cur.execute(Q.DATE_RANGE)
        dr = cur.fetchone()
        min_ts = dr["min_ts"] if dr else None
        max_ts = dr["max_ts"] if dr else None

        # Evidence sources
        cur.execute(Q.SOURCE_EVIDENCE)
        sources = [row["source_evidence_number"] for row in cur.fetchall()]

        # Tags
        cur.execute(Q.TAGS)
        tags = [{"name": row["tag_name"], "color": row["tag_color"]} for row in cur.fetchall()]

        return {
            "case_name": case_name,
            "case_number": case_number,
            "created_on": created_on,
            "source_path": self._path,
            "total_hits": total_hits,
            "artifact_type_count": len(type_counts),
            "artifact_types": type_counts,
            "date_range_start": self._ms_to_iso(min_ts) if min_ts else None,
            "date_range_end": self._ms_to_iso(max_ts) if max_ts else None,
            "evidence_sources": sources,
            "tags": tags,
        }

    # ── Core Query Methods ──

    def _cursor(self) -> sqlite3.Cursor:
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._conn.cursor()

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        filters = filters or {}
        artifact_type = filters.get("artifact_type", "")
        start_date = filters.get("start_date", "")
        end_date = filters.get("end_date", "")

        start_ms = self._iso_to_ms(start_date) if start_date else None
        end_ms = self._iso_to_ms(end_date) if end_date else None

        # True total count (no LIMIT) — run before paginated query
        true_total = self._count_hits(keyword, artifact_type, start_ms, end_ms)

        hit_ids = self._search_hit_ids(keyword, artifact_type, start_ms, end_ms, limit, offset)
        hits = self._hydrate_hits(hit_ids)
        result: dict = {
            "total": true_total,
            "total_estimated": true_total,  # backward compatibility
            "returned": len(hits),
            "offset": offset,
            "limit": limit,
            "truncated": true_total > offset + len(hits),
            "hits": hits,
        }

        # Zero-result diagnostics: help distinguish "no data" from "query issue"
        if not hit_ids and (artifact_type or start_ms is not None):
            diag: dict = {}
            cur = self._cursor()
            if artifact_type:
                cur.execute(
                    "SELECT COUNT(*) FROM scan_artifact_hit sah "
                    "JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id "
                    "WHERE av.artifact_name = ?", (artifact_type,))
                type_total = cur.fetchone()[0]
                diag["artifact_type_total_hits"] = type_total
                if type_total > 0 and start_ms is not None:
                    diag["note"] = (
                        f"'{artifact_type}' has {type_total} total hits but 0 matched "
                        f"the date filter. Verify the date range or try without date filter."
                    )
            if start_ms is not None and end_ms is not None:
                cur.execute(
                    "SELECT COUNT(*) FROM hit_fragment_date "
                    "WHERE unix_timestamp_ms BETWEEN ? AND ?", (start_ms, end_ms))
                date_total = cur.fetchone()[0]
                diag["date_range_total_hits"] = date_total
            if diag:
                result["diagnostic"] = diag

        return result

    def _search_hit_ids(
        self, keyword: str, artifact_type: str,
        start_ms: int | None, end_ms: int | None,
        limit: int, offset: int,
    ) -> list[int]:
        cur = self._cursor()
        has_kw = bool(keyword)
        has_type = bool(artifact_type)
        has_date = start_ms is not None and end_ms is not None

        if has_kw and has_type and has_date:
            cur.execute(Q.SEARCH_FULL, (f"%{keyword}%", artifact_type, start_ms, end_ms, limit, offset))
        elif has_kw and has_type:
            cur.execute(Q.SEARCH_BY_KEYWORD_AND_TYPE, (f"%{keyword}%", artifact_type, limit, offset))
        elif has_kw and has_date:
            cur.execute(Q.SEARCH_BY_KEYWORD_AND_DATE, (f"%{keyword}%", start_ms, end_ms, limit, offset))
        elif has_type and has_date:
            cur.execute(Q.SEARCH_BY_ARTIFACT_TYPE_AND_DATE, (artifact_type, start_ms, end_ms, limit, offset))
        elif has_kw:
            cur.execute(Q.SEARCH_BY_KEYWORD, (f"%{keyword}%", limit, offset))
        elif has_type:
            cur.execute(Q.SEARCH_BY_ARTIFACT_TYPE, (artifact_type, limit, offset))
        elif has_date:
            cur.execute(Q.SEARCH_BY_DATE_RANGE, (start_ms, end_ms, limit, offset))
        else:
            # No filters: return first N hits
            cur.execute("SELECT hit_id FROM scan_artifact_hit LIMIT ? OFFSET ?", (limit, offset))

        return [row[0] for row in cur.fetchall()]

    def _count_hits(
        self, keyword: str, artifact_type: str,
        start_ms: int | None, end_ms: int | None,
    ) -> int:
        """Count total matching hits without LIMIT — for accurate pagination."""
        cur = self._cursor()
        has_kw = bool(keyword)
        has_type = bool(artifact_type)
        has_date = start_ms is not None and end_ms is not None

        if has_kw and has_type and has_date:
            cur.execute(Q.COUNT_FULL, (f"%{keyword}%", artifact_type, start_ms, end_ms))
        elif has_kw and has_type:
            cur.execute(Q.COUNT_BY_TYPE_AND_KEYWORD, (f"%{keyword}%", artifact_type))
        elif has_kw and has_date:
            cur.execute(Q.COUNT_BY_KEYWORD_AND_DATE, (f"%{keyword}%", start_ms, end_ms))
        elif has_type and has_date:
            cur.execute(Q.COUNT_BY_ARTIFACT_TYPE_AND_DATE, (artifact_type, start_ms, end_ms))
        elif has_kw:
            cur.execute(Q.COUNT_BY_KEYWORD, (f"%{keyword}%",))
        elif has_type:
            cur.execute(Q.COUNT_BY_ARTIFACT_TYPE, (artifact_type,))
        elif has_date:
            cur.execute(Q.COUNT_BY_DATE_RANGE, (start_ms, end_ms))
        else:
            cur.execute(Q.COUNT_TOTAL_HITS)

        return cur.fetchone()[0]

    def _hydrate_hits(self, hit_ids: list[int]) -> list[dict]:
        """Reconstruct hits from fragment tables."""
        if not hit_ids:
            return []

        placeholders = ",".join("?" * len(hit_ids))
        cur = self._cursor()

        # Initialize hit dicts
        hits: dict[int, dict] = {hid: {"hit_id": hid, "fields": {}, "timestamps": {}} for hid in hit_ids}

        # String fragments
        cur.execute(Q.HYDRATE_STRINGS.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            fname = self._frag_defs.get(str(row["fragment_definition_id"]), "unknown")
            if hid in hits:
                hits[hid]["fields"][fname] = row["value"]

        # Date fragments
        cur.execute(Q.HYDRATE_DATES.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            fname = self._frag_defs.get(str(row["fragment_definition_id"]), "unknown")
            if hid in hits:
                hits[hid]["timestamps"][fname] = row["formatted_value"]

        # Int fragments
        cur.execute(Q.HYDRATE_INTS.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            fname = self._frag_defs.get(str(row["fragment_definition_id"]), "unknown")
            if hid in hits:
                hits[hid]["fields"][fname] = row["value"]

        # Float fragments
        cur.execute(Q.HYDRATE_FLOATS.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            fname = self._frag_defs.get(str(row["fragment_definition_id"]), "unknown")
            if hid in hits:
                hits[hid]["fields"][fname] = row["value"]

        # Artifact types
        cur.execute(Q.HIT_ARTIFACT_TYPES.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            if hid in hits:
                hits[hid]["artifact_type"] = row["artifact_name"]

        # Locations (first only)
        cur.execute(Q.HIT_LOCATIONS.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            if hid in hits:
                hits[hid]["location"] = row["location_value"] or ""
                hits[hid]["source_path"] = row["source_path"] or ""

        # Hashes
        cur.execute(Q.HIT_HASHES.format(placeholders=placeholders), hit_ids)
        for row in cur.fetchall():
            hid = row["hit_id"]
            if hid in hits:
                hits[hid]["hash"] = row["hash"] or ""

        return [hits[hid] for hid in hit_ids]

    def get_hit_detail(self, hit_id: int) -> dict:
        """Full detail for a single hit."""
        results = self._hydrate_hits([hit_id])
        return results[0] if results else {"error": f"hit_id {hit_id} not found"}

    # ── SRUM Aggregation ──

    def _resolve_frag_id(self, field_name: str) -> str | None:
        """Resolve fragment_definition_id from field name."""
        for fid, name in self._frag_defs.items():
            if name == field_name:
                return fid
        return None

    def srum_network_aggregate(self, process_keyword: str,
                                start_date: str = "", end_date: str = "") -> dict:
        """Get accurate total bytes sent/received for a process from ALL records (no LIMIT)."""
        cur = self._cursor()
        sent_fid = self._resolve_frag_id("Bytes Sent")
        recv_fid = self._resolve_frag_id("Bytes Received")
        if sent_fid is None or recv_fid is None:
            return {"error": "Cannot resolve fragment IDs for Bytes Sent/Received",
                    "available_fields": list(self._frag_defs.values())}

        sql = Q.SRUM_NETWORK_AGGREGATE
        params: list = [f"%{process_keyword}%"]

        if start_date or end_date:
            start_ms = self._iso_to_ms(start_date) if start_date else 0
            end_ms = self._iso_to_ms(end_date) if end_date else 9999999999999
            # Inject date filter into the subquery (before the closing parenthesis)
            sql = sql.replace(
                "AND hfs.value LIKE ?\n) matched",
                "AND hfs.value LIKE ?\n    AND hfs.hit_id IN (\n"
                "        SELECT hfd.hit_id FROM hit_fragment_date hfd\n"
                "        WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?\n"
                "    )\n) matched"
            )
            params.extend([start_ms, end_ms])

        params.extend([sent_fid, recv_fid])

        cur.execute(sql, params)
        row = cur.fetchone()

        # Also get app resource usage count
        app_sql = Q.SRUM_APP_COUNT
        app_params: list = [f"%{process_keyword}%"]
        if start_date or end_date:
            app_sql += """
  AND hfs_app.hit_id IN (
      SELECT hfd.hit_id FROM hit_fragment_date hfd
      WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
  )"""
            app_params.extend([start_ms, end_ms])
        cur.execute(app_sql, app_params)
        app_row = cur.fetchone()

        return {
            "network_total_records": row["total_records"] if row else 0,
            "total_bytes_sent": row["total_bytes_sent"] if row else 0,
            "total_bytes_received": row["total_bytes_received"] if row else 0,
            "app_total_records": app_row["total_records"] if app_row else 0,
        }

    # ── Timeline ──

    def get_timeline(
        self, start_date: str = "", end_date: str = "",
        artifact_types: list[str] | None = None, limit: int = 200,
    ) -> dict:
        cur = self._cursor()
        no_date_filter = not start_date and not end_date

        if no_date_filter and not artifact_types:
            cur.execute(Q.TIMELINE_ALL, (limit,))
        elif artifact_types:
            start_ms = self._iso_to_ms(start_date) if start_date else 0
            end_ms = self._iso_to_ms(end_date) if end_date else 9999999999999
            placeholders = ",".join("?" * len(artifact_types))
            query = Q.TIMELINE_WITH_TYPE.format(placeholders=placeholders)
            params = [start_ms, end_ms] + artifact_types + [limit]
            cur.execute(query, params)
        else:
            start_ms = self._iso_to_ms(start_date) if start_date else 0
            end_ms = self._iso_to_ms(end_date) if end_date else 9999999999999
            cur.execute(Q.TIMELINE, (start_ms, end_ms, limit))

        rows = cur.fetchall()

        # Diagnostic fallback: if 0 results, check if timeline table has any data
        if not rows:
            cur.execute("SELECT COUNT(*) FROM hit_fragment_date")
            total_in_table = cur.fetchone()[0]
            if total_in_table == 0:
                return {
                    "total_events": 0,
                    "returned": 0,
                    "entries": [],
                    "diagnostic": "hit_fragment_date table is empty",
                }
            else:
                return {
                    "total_events": 0,
                    "returned": 0,
                    "entries": [],
                    "diagnostic": f"hit_fragment_date has {total_in_table} rows but none matched the filter",
                }

        # Collect unique hit_ids for hydration
        seen_hits: dict[int, dict] = {}
        entries = []
        for row in rows:
            hid = row["hit_id"]
            if hid not in seen_hits:
                seen_hits[hid] = {
                    "hit_id": hid,
                    "timestamp_ms": row["unix_timestamp_ms"],
                    "timestamp": row["formatted_value"],
                    "time_field": row["time_field"],
                }
            entries.append(seen_hits[hid])

        # Hydrate unique hits for descriptions
        unique_ids = list(seen_hits.keys())
        if unique_ids:
            hydrated = {h["hit_id"]: h for h in self._hydrate_hits(unique_ids)}
            for entry in seen_hits.values():
                hdata = hydrated.get(entry["hit_id"], {})
                entry["artifact_type"] = hdata.get("artifact_type", "")
                entry["description"] = self._build_description(hdata)

        # Deduplicate by hit_id, keep first occurrence
        result = list(seen_hits.values())

        # True total count for the query (without LIMIT)
        if no_date_filter and not artifact_types:
            cur.execute("SELECT COUNT(DISTINCT hit_id) FROM hit_fragment_date")
        elif artifact_types:
            placeholders2 = ",".join("?" * len(artifact_types))
            cur.execute(
                f"SELECT COUNT(DISTINCT hfd.hit_id) FROM hit_fragment_date hfd "
                f"JOIN scan_artifact_hit sah ON hfd.hit_id = sah.hit_id "
                f"JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id "
                f"WHERE hfd.unix_timestamp_ms BETWEEN ? AND ? "
                f"AND av.artifact_name IN ({placeholders2})",
                [start_ms, end_ms] + artifact_types)
        else:
            cur.execute(
                "SELECT COUNT(DISTINCT hit_id) FROM hit_fragment_date "
                "WHERE unix_timestamp_ms BETWEEN ? AND ?",
                (start_ms, end_ms))
        true_total = cur.fetchone()[0]

        return {
            "total_events": true_total,
            "returned": len(result),
            "truncated": true_total > len(result),
            "entries": result,
        }

    def _build_description(self, hit: dict) -> str:
        """Build a human-readable description from a hydrated hit."""
        fields = hit.get("fields", {})
        parts = []
        # Prefer meaningful fields
        priority_keys = [
            "URL", "Title", "Name", "Path", "File Path", "Event Description Summary",
            "Event ID", "Process Name", "Executable", "Subject", "Body",
            "Remote Address", "Username", "Source IP",
        ]
        for key in priority_keys:
            if key in fields:
                val = str(fields[key])
                if val.strip():
                    parts.append(f"{key}: {val[:200]}")
                    if len(parts) >= 3:
                        break
        if not parts:
            for key, val in list(fields.items())[:3]:
                val_str = str(val)
                if val_str.strip() and len(val_str) > 1:
                    parts.append(f"{key}: {val_str[:200]}")
        return " | ".join(parts) if parts else "(no details)"

    # ── Hash Search ──

    def search_by_hash(self, hash_value: str, limit: int = 50, offset: int = 0) -> dict:
        cur = self._cursor()
        cur.execute(Q.COUNT_BY_HASH, (hash_value,))
        true_total = cur.fetchone()[0]
        cur.execute(Q.SEARCH_BY_HASH, (hash_value, limit, offset))
        hit_ids = [row[0] for row in cur.fetchall()]
        hits = self._hydrate_hits(hit_ids)
        return {
            "hash": hash_value,
            "total": true_total,
            "returned": len(hits),
            "truncated": true_total > offset + len(hits),
            "hits": hits,
        }

    def get_all_hashes(self, limit: int = 500) -> list[dict]:
        cur = self._cursor()
        cur.execute(Q.ALL_HASHES, (limit,))
        return [{"hash": row["hash"], "artifact_type": row["artifact_name"]} for row in cur.fetchall()]

    # ── Tags ──

    def get_tagged_hits(self, tag_name: str = "", limit: int = 100) -> dict:
        cur = self._cursor()
        if tag_name:
            cur.execute(Q.TAGGED_HITS_BY_NAME, (f"%{tag_name}%",))
        else:
            cur.execute(Q.TAGGED_HITS)
        tag_data = {}
        for row in cur.fetchall():
            hid = row["hit_id"]
            if hid not in tag_data:
                tag_data[hid] = []
            tag_data[hid].append(row["tag_name"])

        hit_ids = list(tag_data.keys())
        total_tagged = len(hit_ids)
        hits = self._hydrate_hits(hit_ids[:limit])
        for h in hits:
            h["tags"] = tag_data.get(h["hit_id"], [])
        return {
            "total_tagged": total_tagged,
            "returned": len(hits),
            "truncated": total_tagged > len(hits),
            "hits": hits,
        }

    # ── Source Path ──

    def search_by_source(self, path_pattern: str, limit: int = 50, offset: int = 0) -> dict:
        cur = self._cursor()
        cur.execute(Q.COUNT_BY_SOURCE_PATH, (f"%{path_pattern}%",))
        true_total = cur.fetchone()[0]
        cur.execute(Q.SEARCH_BY_SOURCE_PATH, (f"%{path_pattern}%", limit, offset))
        hit_ids = [row[0] for row in cur.fetchall()]
        hits = self._hydrate_hits(hit_ids)
        return {
            "pattern": path_pattern,
            "total": true_total,
            "returned": len(hits),
            "truncated": true_total > offset + len(hits),
            "hits": hits,
        }

    # ── Suspicious Pattern Search ──

    def search_patterns(self, patterns: list[str], limit: int = 200) -> list[int]:
        """Search string fragments for multiple LIKE patterns (OR). Returns hit_ids."""
        if not patterns:
            return []
        cur = self._cursor()
        conditions = " OR ".join(["hfs.value LIKE ?"] * len(patterns))
        query = Q.SEARCH_STRING_PATTERNS_MULTI.format(conditions=conditions)
        params = [f"%{p}%" for p in patterns] + [limit]
        cur.execute(query, params)
        return [row[0] for row in cur.fetchall()]

    # ── Artifact Type Counts ──

    def get_artifact_type_counts(self) -> list[dict]:
        cur = self._cursor()
        cur.execute(Q.ARTIFACT_TYPE_COUNTS)
        return [{"artifact_type": row["artifact_name"], "count": row["hit_count"]}
                for row in cur.fetchall()]

    # ── IOC: String Pattern Search ──

    def search_string_values(self, pattern: str, limit: int = 1000) -> list[dict]:
        """Search hit_fragment_string for values matching a LIKE pattern.
        Returns [{hit_id, value}].
        """
        cur = self._cursor()
        cur.execute(Q.STRINGS_WITH_PATTERN, (pattern, limit))
        return [{"hit_id": row["hit_id"], "value": row["value"]} for row in cur.fetchall()]

    # ── Utilities ──

    @staticmethod
    def _ms_to_iso(ms: int) -> str:
        try:
            dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            return dt.isoformat()
        except (OSError, ValueError, OverflowError):
            return ""

    @staticmethod
    def _iso_to_ms(iso_str: str) -> int:
        try:
            iso_str = iso_str.replace(" ", "T", 1)
            if "T" in iso_str:
                dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(iso_str + "T00:00:00+00:00")
            return int(dt.timestamp() * 1000)
        except (ValueError, AttributeError):
            return 0
