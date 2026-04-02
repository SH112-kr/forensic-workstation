"""Artifact-type-aware structured queries for AXIOM .mfdb.

Each query targets a specific artifact type with its known fields,
returning structured results instead of raw keyword matches.
"""

from __future__ import annotations

import sqlite3
from typing import Any


class ArtifactQueries:
    """Structured queries against specific AXIOM artifact types."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        # Cache fragment_definition_id lookups: (artifact_name, field_name) -> frag_id
        self._frag_cache: dict[tuple[str, str], str] = {}
        self._av_cache: dict[str, str] = {}  # artifact_name -> artifact_version_id
        self._build_caches()

    def _build_caches(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""
            SELECT av.artifact_name, av.artifact_version_id, fd.fragment_definition_id, fd.name, fd.data_type
            FROM fragment_definition fd
            JOIN artifact_version av ON fd.artifact_version_id = av.artifact_version_id
        """)
        for row in cur.fetchall():
            art_name, av_id, frag_id, field_name, dtype = row
            self._frag_cache[(art_name, field_name)] = frag_id
            self._av_cache[art_name] = av_id

    def _frag_id(self, artifact: str, field: str) -> str | None:
        return self._frag_cache.get((artifact, field))

    def _av_id(self, artifact: str) -> str | None:
        return self._av_cache.get(artifact)

    # ── Windows Event Logs ──

    def query_event_logs(
        self, event_ids: list[int] | None = None,
        provider: str = "",
        keyword_in_data: str = "",
        limit: int = 100,
    ) -> list[dict]:
        """Query Windows Event Logs by Event ID, provider, or event data content."""
        art = "Windows Event Logs"
        av_id = self._av_id(art)
        if not av_id:
            return []

        eid_frag = self._frag_id(art, "Event ID")
        cur = self._conn.cursor()

        # Start with hit_ids from this artifact type
        if event_ids and eid_frag:
            placeholders = ",".join("?" * len(event_ids))
            cur.execute(f"""
                SELECT hfi.hit_id FROM hit_fragment_int hfi
                JOIN scan_artifact_hit sah ON hfi.hit_id = sah.hit_id
                WHERE sah.artifact_version_id = ?
                  AND hfi.fragment_definition_id = ?
                  AND hfi.value IN ({placeholders})
                LIMIT ?
            """, [av_id, eid_frag] + event_ids + [limit])
        else:
            cur.execute("""
                SELECT sah.hit_id FROM scan_artifact_hit sah
                WHERE sah.artifact_version_id = ? LIMIT ?
            """, (av_id, limit))

        hit_ids = [r[0] for r in cur.fetchall()]
        if not hit_ids:
            return []

        return self._hydrate_artifact_hits(art, hit_ids, provider, keyword_in_data)

    def query_logon_events(self, limit: int = 100) -> list[dict]:
        """Query logon events (Event ID 4624) with logon type context."""
        return self.query_event_logs(event_ids=[4624], limit=limit)

    def query_failed_logons(self, limit: int = 100) -> list[dict]:
        """Query failed logon events (Event ID 4625)."""
        return self.query_event_logs(event_ids=[4625], limit=limit)

    def query_process_creation_events(self, limit: int = 200) -> list[dict]:
        """Query process creation events (Sysmon EID 1, Security EID 4688)."""
        return self.query_event_logs(event_ids=[1, 4688], limit=limit)

    def query_service_installs(self, limit: int = 100) -> list[dict]:
        """Query service installation events (Event ID 7045)."""
        return self.query_event_logs(event_ids=[7045], limit=limit)

    def query_powershell_scriptblock(self, limit: int = 100) -> list[dict]:
        """Query PowerShell Script Block Logging (Event ID 4104)."""
        return self.query_event_logs(event_ids=[4104], limit=limit)

    def query_log_cleared(self, limit: int = 50) -> list[dict]:
        """Query audit log cleared events (Event ID 1102)."""
        return self.query_event_logs(event_ids=[1102], limit=limit)

    def query_scheduled_task_events(self, limit: int = 100) -> list[dict]:
        """Query scheduled task creation/modification (Event IDs 4698, 4702)."""
        return self.query_event_logs(event_ids=[4698, 4699, 4702], limit=limit)

    def query_process_access_events(self, limit: int = 100) -> list[dict]:
        """Query process access events (Sysmon Event ID 10) — LSASS access detection."""
        return self.query_event_logs(event_ids=[10], limit=limit)

    # ── Prefetch ──

    def query_prefetch(self, app_name_filter: str = "", limit: int = 100) -> list[dict]:
        """Query Prefetch files — program execution evidence."""
        art = "Prefetch Files - Windows 8/10/11"
        av_id = self._av_id(art)
        if not av_id:
            return []

        cur = self._conn.cursor()
        if app_name_filter:
            name_frag = self._frag_id(art, "Application Name")
            if name_frag:
                cur.execute("""
                    SELECT hfs.hit_id FROM hit_fragment_string hfs
                    JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
                    WHERE sah.artifact_version_id = ?
                      AND hfs.fragment_definition_id = ?
                      AND hfs.value LIKE ?
                    LIMIT ?
                """, (av_id, name_frag, f"%{app_name_filter}%", limit))
            else:
                return []
        else:
            cur.execute("SELECT hit_id FROM scan_artifact_hit WHERE artifact_version_id = ? LIMIT ?",
                        (av_id, limit))

        hit_ids = [r[0] for r in cur.fetchall()]
        return self._hydrate_artifact_hits(art, hit_ids) if hit_ids else []

    # ── Scheduled Tasks ──

    def query_scheduled_tasks(self, limit: int = 100) -> list[dict]:
        """Query Scheduled Tasks artifact."""
        return self._query_artifact("Scheduled Tasks", limit=limit)

    # ── System Services ──

    def query_services(self, service_filter: str = "", limit: int = 100) -> list[dict]:
        """Query System Services."""
        art = "System Services"
        av_id = self._av_id(art)
        if not av_id:
            return []

        cur = self._conn.cursor()
        if service_filter:
            name_frag = self._frag_id(art, "Service Name")
            loc_frag = self._frag_id(art, "Service Location")
            frags = [f for f in [name_frag, loc_frag] if f]
            if frags:
                conditions = " OR ".join([
                    f"(hfs.fragment_definition_id = ? AND hfs.value LIKE ?)" for _ in frags
                ])
                params = []
                for f in frags:
                    params.extend([f, f"%{service_filter}%"])
                cur.execute(f"""
                    SELECT DISTINCT hfs.hit_id FROM hit_fragment_string hfs
                    JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
                    WHERE sah.artifact_version_id = ? AND ({conditions})
                    LIMIT ?
                """, [av_id] + params + [limit])
            else:
                return []
        else:
            cur.execute("SELECT hit_id FROM scan_artifact_hit WHERE artifact_version_id = ? LIMIT ?",
                        (av_id, limit))

        hit_ids = [r[0] for r in cur.fetchall()]
        return self._hydrate_artifact_hits(art, hit_ids) if hit_ids else []

    # ── AmCache ──

    def query_amcache(self, name_filter: str = "", limit: int = 100) -> list[dict]:
        """Query AmCache File Entries — program execution + SHA1 hashes."""
        art = "AmCache File Entries"
        av_id = self._av_id(art)
        if not av_id:
            return []

        cur = self._conn.cursor()
        if name_filter:
            name_frag = self._frag_id(art, "Name")
            path_frag = self._frag_id(art, "Full Path")
            frags = [f for f in [name_frag, path_frag] if f]
            if frags:
                conditions = " OR ".join([
                    f"(hfs.fragment_definition_id = ? AND hfs.value LIKE ?)" for _ in frags
                ])
                params = []
                for f in frags:
                    params.extend([f, f"%{name_filter}%"])
                cur.execute(f"""
                    SELECT DISTINCT hfs.hit_id FROM hit_fragment_string hfs
                    JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
                    WHERE sah.artifact_version_id = ? AND ({conditions})
                    LIMIT ?
                """, [av_id] + params + [limit])
            else:
                return []
        else:
            cur.execute("SELECT hit_id FROM scan_artifact_hit WHERE artifact_version_id = ? LIMIT ?",
                        (av_id, limit))

        hit_ids = [r[0] for r in cur.fetchall()]
        return self._hydrate_artifact_hits(art, hit_ids) if hit_ids else []

    # ── Shim Cache ──

    def query_shimcache(self, limit: int = 100) -> list[dict]:
        """Query Shim Cache (AppCompatCache) — program execution evidence."""
        return self._query_artifact("Shim Cache", limit=limit)

    # ── LNK Files ──

    def query_lnk_files(self, path_filter: str = "", limit: int = 100) -> list[dict]:
        """Query LNK shortcut files."""
        art = "LNK Files"
        if path_filter:
            av_id = self._av_id(art)
            if not av_id:
                return []
            frag = self._frag_id(art, "Linked Path")
            if not frag:
                return []
            cur = self._conn.cursor()
            cur.execute("""
                SELECT hfs.hit_id FROM hit_fragment_string hfs
                JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
                WHERE sah.artifact_version_id = ? AND hfs.fragment_definition_id = ? AND hfs.value LIKE ?
                LIMIT ?
            """, (av_id, frag, f"%{path_filter}%", limit))
            hit_ids = [r[0] for r in cur.fetchall()]
            return self._hydrate_artifact_hits(art, hit_ids) if hit_ids else []
        return self._query_artifact(art, limit=limit)

    # ── Generic helpers ──

    def _query_artifact(self, artifact_name: str, limit: int = 100) -> list[dict]:
        """Generic: get all hits for an artifact type."""
        av_id = self._av_id(artifact_name)
        if not av_id:
            return []
        cur = self._conn.cursor()
        cur.execute("SELECT hit_id FROM scan_artifact_hit WHERE artifact_version_id = ? LIMIT ?",
                    (av_id, limit))
        hit_ids = [r[0] for r in cur.fetchall()]
        return self._hydrate_artifact_hits(artifact_name, hit_ids) if hit_ids else []

    def _hydrate_artifact_hits(
        self, artifact_name: str, hit_ids: list[int],
        provider_filter: str = "", data_filter: str = "",
    ) -> list[dict]:
        """Hydrate hit_ids into structured dicts with all fields for this artifact type."""
        if not hit_ids:
            return []

        placeholders = ",".join("?" * len(hit_ids))
        cur = self._conn.cursor()
        hits: dict[int, dict] = {hid: {"hit_id": hid, "artifact_type": artifact_name} for hid in hit_ids}

        # String fields
        cur.execute(f"SELECT hit_id, fragment_definition_id, value FROM hit_fragment_string WHERE hit_id IN ({placeholders})", hit_ids)
        for hid, frag_id, value in cur.fetchall():
            if hid in hits:
                fname = self._resolve_field_name(artifact_name, frag_id)
                if fname:
                    hits[hid][fname] = value

        # Int fields
        cur.execute(f"SELECT hit_id, fragment_definition_id, value FROM hit_fragment_int WHERE hit_id IN ({placeholders})", hit_ids)
        for hid, frag_id, value in cur.fetchall():
            if hid in hits:
                fname = self._resolve_field_name(artifact_name, frag_id)
                if fname:
                    hits[hid][fname] = value

        # Date fields
        cur.execute(f"SELECT hit_id, fragment_definition_id, formatted_value FROM hit_fragment_date WHERE hit_id IN ({placeholders})", hit_ids)
        for hid, frag_id, value in cur.fetchall():
            if hid in hits:
                fname = self._resolve_field_name(artifact_name, frag_id)
                if fname:
                    hits[hid][fname] = value

        result = list(hits.values())

        # Post-filter
        if provider_filter:
            result = [r for r in result if provider_filter.lower() in str(r.get("Provider Name", "")).lower()]
        if data_filter:
            result = [r for r in result if data_filter.lower() in str(r.get("Event Data", "")).lower()]

        return result

    def _resolve_field_name(self, artifact_name: str, frag_id: str) -> str | None:
        """Reverse lookup: frag_id -> field name for this artifact."""
        for (art, fname), fid in self._frag_cache.items():
            if art == artifact_name and fid == frag_id:
                return fname
        return None
