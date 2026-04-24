"""Base connector + ArtifactQueries for regression fixtures.

A fixture subclass provides:
  - ``metadata``  (dict matching BaseConnector.get_metadata)
  - ``hits``      (list of dicts; each hit has hit_id / artifact_type /
                   timestamp / source_path / fields / tags)
  - ``artifact_type_counts`` (list of rows for get_artifact_type_counts)
  - ``coverage_statuses``   (dict keyed by evtx / prefetch / mft_logfile_usn
                             / srum / browser — affects coverage_gate in
                             initial_triage)
  - optional ``extra_queries`` (dict mapping artifact_name → list of rows)
    for _query_artifact coverage of arbitrary artifact names.

The base handles the full search / timeline / detail / hash / source /
artifact_queries surface by filtering over ``hits`` deterministically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class FixtureHit:
    hit_id: int
    artifact_type: str
    timestamp: str  # ISO 8601 UTC
    source_path: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_row(self) -> dict[str, Any]:
        row = {
            "hit_id": self.hit_id,
            "artifact_type": self.artifact_type,
            "timestamp": self.timestamp,
            "source_path": self.source_path,
            "tags": list(self.tags),
            "fields": dict(self.fields),
            # Flattened common fields for direct access by tools
            **self.fields,
        }
        # description is a common convenience for tools that expect prose
        row.setdefault("description", self._build_description())
        return row

    def _build_description(self) -> str:
        parts = [self.artifact_type]
        for key in ("ImagePath", "ProcessName", "Full Path", "Path", "File Path",
                    "URL", "CommandLine", "Application Path"):
            val = self.fields.get(key)
            if val:
                parts.append(f"{key}={val}")
                break
        return " | ".join(parts)


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        text = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _in_range(ts: str, start: str, end: str) -> bool:
    if not start and not end:
        return True
    dt = _parse_ts(ts)
    if dt is None:
        return True
    if start:
        sdt = _parse_ts(start + "T00:00:00Z" if len(start) == 10 else start)
        if sdt and dt < sdt:
            return False
    if end:
        edt = _parse_ts(end + "T23:59:59Z" if len(end) == 10 else end)
        if edt and dt > edt:
            return False
    return True


class FixtureArtifactQueries:
    """Minimal ArtifactQueries replacement backed by fixture hits."""

    def __init__(self, connector: "FixtureConnector") -> None:
        self._c = connector

    def _hits_of(self, artifact_substrings: tuple[str, ...]) -> list[dict]:
        """Return hit dicts whose artifact_type contains any substring."""
        out: list[dict] = []
        for h in self._c.hits:
            lowered = h.artifact_type.lower()
            if any(s.lower() in lowered for s in artifact_substrings):
                out.append(h.to_row())
        return out

    # ── Event log queries ────────────────────────────────────────────
    def query_event_logs(self, eids: list[int] | None = None, limit: int = 100) -> list[dict]:
        rows = self._hits_of(("Windows Event Logs",))
        if eids:
            want = {str(e) for e in eids}
            rows = [
                r for r in rows
                if any(w in str(r.get("Event ID", "")) or w in r.get("artifact_type", "")
                       for w in want)
            ]
        return rows[: limit or len(rows)]

    def query_logon_events(self, limit: int = 100) -> list[dict]:
        return self.query_event_logs(eids=[4624], limit=limit)

    def query_failed_logons(self, limit: int = 100) -> list[dict]:
        return self.query_event_logs(eids=[4625], limit=limit)

    def query_process_creation_events(self, limit: int = 200) -> list[dict]:
        return self.query_event_logs(eids=[4688, 1], limit=limit)

    def query_service_installs(self, limit: int = 100) -> list[dict]:
        return self.query_event_logs(eids=[7045], limit=limit)

    def query_powershell_scriptblock(self, limit: int = 100) -> list[dict]:
        rows = self._hits_of(("PowerShell", "Script Events"))
        return rows[: limit or len(rows)]

    def query_log_cleared(self, limit: int = 50) -> list[dict]:
        return self.query_event_logs(eids=[1102, 104], limit=limit)

    def query_scheduled_task_events(self, limit: int = 100) -> list[dict]:
        return self.query_event_logs(eids=[4698, 4702], limit=limit)

    def query_process_access_events(self, limit: int = 100) -> list[dict]:
        return self.query_event_logs(eids=[10], limit=limit)

    # ── File-system / artifact queries ───────────────────────────────
    def query_prefetch(self, app_name_filter: str = "", limit: int = 100) -> list[dict]:
        rows = self._hits_of(("Prefetch",))
        if app_name_filter:
            needle = app_name_filter.lower()
            rows = [r for r in rows if needle in str(r.get("Application Name", "")).lower()
                    or needle in str(r.get("Full Path", "")).lower()]
        return rows[: limit or len(rows)]

    def query_scheduled_tasks(self, limit: int = 100) -> list[dict]:
        rows = self._hits_of(("Scheduled Tasks",))
        return rows[: limit or len(rows)]

    def query_services(self, service_filter: str = "", limit: int = 100) -> list[dict]:
        rows = self._hits_of(("System Services",))
        if service_filter:
            needle = service_filter.lower()
            rows = [r for r in rows if needle in str(r.get("Service Name", "")).lower()
                    or needle in str(r.get("Display Name", "")).lower()]
        return rows[: limit or len(rows)]

    def query_amcache(self, name_filter: str = "", limit: int = 100) -> list[dict]:
        rows = self._hits_of(("AmCache",))
        if name_filter:
            needle = name_filter.lower()
            rows = [r for r in rows if needle in str(r.get("File Name", "")).lower()]
        return rows[: limit or len(rows)]

    def query_shimcache(self, limit: int = 100) -> list[dict]:
        return self._hits_of(("Shim Cache",))[: limit or None]

    def query_lnk_files(self, path_filter: str = "", limit: int = 100) -> list[dict]:
        rows = self._hits_of(("LNK Files",))
        if path_filter:
            needle = path_filter.lower()
            rows = [r for r in rows if needle in str(r.get("Target Path", "")).lower()]
        return rows[: limit or len(rows)]

    # ── Generic artifact ─────────────────────────────────────────────
    def _query_artifact(self, artifact_name: str, limit: int = 100) -> list[dict]:
        # First consult fixture-provided overrides, then fall back to
        # substring match over hits.
        overrides = getattr(self._c, "extra_queries", {}) or {}
        if artifact_name in overrides:
            rows = list(overrides[artifact_name])
        else:
            rows = self._hits_of((artifact_name,))
        return rows[: limit or len(rows)]


class FixtureConnector:
    """Synthetic stub matching the subset of BaseConnector MCP tools exercise."""

    def __init__(
        self,
        metadata: dict[str, Any],
        hits: list[FixtureHit],
        artifact_type_counts: list[dict] | None = None,
        coverage_statuses: dict[str, str] | None = None,
        extra_queries: dict[str, list[dict]] | None = None,
    ) -> None:
        self.metadata = metadata
        self.hits = hits
        self.extra_queries = extra_queries or {}
        self._coverage_statuses = coverage_statuses or {}
        self._artifact_type_counts = artifact_type_counts or self._derive_counts()
        self.artifact_queries = FixtureArtifactQueries(self)

    # ── BaseConnector methods ────────────────────────────────────────
    def connect(self, path: str, **kwargs: Any) -> dict:
        return self.metadata

    def disconnect(self) -> None:
        return None

    def is_connected(self) -> bool:
        return True

    def get_metadata(self) -> dict:
        return dict(self.metadata)

    def get_capabilities(self) -> list[str]:
        return ["search", "timeline", "fixture"]

    # ── Search / timeline / detail ───────────────────────────────────
    def search(
        self,
        keyword: str = "",
        filters: dict | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        filters = filters or {}
        needle = (keyword or "").lower().strip()
        artifact_filter = str(filters.get("artifact_type", "")).lower()
        start = str(filters.get("start_date", ""))
        end = str(filters.get("end_date", ""))

        matching: list[dict] = []
        for h in self.hits:
            row = h.to_row()
            blob = " ".join(str(v) for v in row.values()).lower()
            if needle and needle not in blob:
                continue
            if artifact_filter and artifact_filter not in h.artifact_type.lower():
                continue
            if not _in_range(h.timestamp, start, end):
                continue
            matching.append(row)

        total = len(matching)
        window = matching[offset: offset + (limit or len(matching))]
        return {
            "total": total,
            "returned": len(window),
            "hits": window,
            "diagnostic": (
                ""
                if matching
                else f"0 hits (total type scanned: {len(self.hits)})"
            ),
        }

    def get_hit_detail(self, hit_id: int) -> dict:
        for h in self.hits:
            if h.hit_id == int(hit_id):
                return h.to_row()
        return {"error": f"hit_id {hit_id} not found"}

    def get_timeline(
        self,
        start_date: str = "",
        end_date: str = "",
        limit: int = 500,
        offset: int = 0,
        artifact_types: str = "",
    ) -> dict:
        entries: list[dict] = []
        type_filters = [t.strip().lower() for t in (artifact_types or "").split(",") if t.strip()]
        for h in self.hits:
            if not _in_range(h.timestamp, start_date, end_date):
                continue
            if type_filters and not any(t in h.artifact_type.lower() for t in type_filters):
                continue
            entries.append({
                "hit_id": h.hit_id,
                "timestamp": h.timestamp,
                "artifact_type": h.artifact_type,
                "description": h.to_row().get("description", ""),
                "time_field": "Created",
            })

        entries.sort(key=lambda e: e.get("timestamp", ""))
        total = len(entries)
        window = entries[offset: offset + (limit or len(entries))]
        return {
            "total_events": total,
            "returned": len(window),
            "entries": window,
            "diagnostic": "" if entries else "No timeline entries in range",
        }

    # ── Hash / source / pattern ──────────────────────────────────────
    def search_by_hash(self, hash_value: str, limit: int = 50, offset: int = 0) -> dict:
        h = (hash_value or "").lower()
        rows = [r.to_row() for r in self.hits
                if h in str(r.fields.get("SHA256", "")).lower()
                or h in str(r.fields.get("MD5", "")).lower()]
        return {"total": len(rows), "hits": rows[: limit or len(rows)]}

    def search_by_source(self, path_pattern: str, limit: int = 50, offset: int = 0) -> dict:
        needle = (path_pattern or "").lower()
        rows = [r.to_row() for r in self.hits if needle in r.source_path.lower()]
        return {"total": len(rows), "hits": rows[: limit or len(rows)]}

    def search_patterns(self, patterns: list[str], limit: int = 200) -> list[int]:
        needles = [p.lower() for p in (patterns or []) if p]
        matched: list[int] = []
        for h in self.hits:
            blob = " ".join(str(v) for v in h.to_row().values()).lower()
            if any(n in blob for n in needles):
                matched.append(h.hit_id)
                if limit and len(matched) >= limit:
                    break
        return matched

    def search_string_values(self, pattern: str, limit: int = 1000) -> list[dict]:
        needle = (pattern or "").lower()
        out: list[dict] = []
        for h in self.hits:
            blob = " ".join(str(v) for v in h.fields.values()).lower()
            if needle and needle in blob:
                out.append(h.to_row())
                if len(out) >= limit:
                    break
        return out

    def get_artifact_type_counts(self) -> list[dict]:
        return [dict(row) for row in self._artifact_type_counts]

    def get_tagged_hits(self, tag_name: str = "", limit: int = 100) -> dict:
        needle = (tag_name or "").lower()
        rows = [
            h.to_row() for h in self.hits
            if any(needle in t.lower() for t in h.tags)
        ]
        return {"total": len(rows), "hits": rows[: limit or len(rows)]}

    def get_all_hashes(self, limit: int = 500) -> list[dict]:
        seen: dict[str, dict] = {}
        for h in self.hits:
            sha = str(h.fields.get("SHA256") or h.fields.get("MD5") or "")
            if sha and sha not in seen:
                seen[sha] = {"hash": sha, "artifact_type": h.artifact_type,
                             "hit_id": h.hit_id}
            if limit and len(seen) >= limit:
                break
        return list(seen.values())

    def srum_network_aggregate(self, process_keyword: str, limit: int = 100) -> list[dict]:
        needle = process_keyword.lower()
        rows = []
        for h in self.hits:
            if "srum" not in h.artifact_type.lower():
                continue
            if needle and needle not in str(h.fields.get("Application Name", "")).lower():
                continue
            rows.append(h.to_row())
        return rows[: limit or len(rows)]

    # ── Helper hooks for harness (not part of BaseConnector) ─────────
    def coverage_statuses(self) -> dict[str, str]:
        """Expose coverage family statuses for initial_triage."""
        return dict(self._coverage_statuses)

    def _derive_counts(self) -> list[dict]:
        counts: dict[str, int] = {}
        for h in self.hits:
            counts[h.artifact_type] = counts.get(h.artifact_type, 0) + 1
        return [
            {"artifact_name": name, "hit_count": cnt, "count": cnt}
            for name, cnt in sorted(counts.items())
        ]
