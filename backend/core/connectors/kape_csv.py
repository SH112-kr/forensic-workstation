"""KAPE CSV connector — loads EZ tool CSV output into in-memory SQLite.

Inherits from AxiomMfdbConnector so all existing search/timeline/hydration
methods work without modification. Only connect() and _load_case_info()
are overridden.

Usage:
    c = KapeCsvConnector()
    meta = c.connect("/path/to/kape/output/dir")
    # Now use c.search(), c.get_timeline(), etc. exactly like AxiomMfdbConnector
"""

from __future__ import annotations

import csv
import glob
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any

from connectors.axiom_mfdb import AxiomMfdbConnector
from connectors.kape_csv_mapping import (
    TOOL_MAPPINGS, TIMESTAMP_FORMATS, detect_tool, detect_tool_by_headers,
    SCHTASKS_KR_TO_EN,
)


class KapeCsvConnector(AxiomMfdbConnector):

    def __init__(self) -> None:
        super().__init__()
        self._source_type = "kape"
        self._ingest_stats: dict[str, int] = {}  # tool_name -> rows ingested

    # ── Connection (override) ──

    def connect(self, path: str, **kwargs: Any) -> dict:
        if not os.path.isdir(path):
            raise ValueError(f"KAPE output path must be a directory: {path}")

        self._path = path
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        self._create_schema()
        self._ingest_csvs(path)
        self._create_indexes()
        self._cache_lookups()  # inherited — reads fragment_definition, artifact_version
        self._case_info = self._load_case_info()

        # Initialize artifact queries (same class works since schema is identical)
        from connectors.axiom_artifact_queries import ArtifactQueries
        self.artifact_queries = ArtifactQueries(self._conn)

        return self._case_info

    # ── Schema Creation ──

    def _create_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
            -- Core tables (matching AXIOM .mfdb schema)
            CREATE TABLE scan_artifact_hit (
                hit_id INTEGER PRIMARY KEY,
                artifact_version_id TEXT NOT NULL
            );

            CREATE TABLE artifact_version (
                artifact_version_id TEXT PRIMARY KEY,
                artifact_id TEXT,
                artifact_name TEXT NOT NULL
            );

            CREATE TABLE fragment_definition (
                fragment_definition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_version_id TEXT,
                name TEXT NOT NULL,
                data_type TEXT DEFAULT 'String'
            );

            -- Fragment value tables
            CREATE TABLE hit_fragment_string (
                hit_id INTEGER,
                fragment_definition_id INTEGER,
                value TEXT
            );

            CREATE TABLE hit_fragment_date (
                hit_id INTEGER,
                fragment_definition_id INTEGER,
                unix_timestamp_ms INTEGER,
                formatted_value TEXT
            );

            CREATE TABLE hit_fragment_int (
                hit_id INTEGER,
                fragment_definition_id INTEGER,
                value INTEGER
            );

            CREATE TABLE hit_fragment_float (
                hit_id INTEGER,
                fragment_definition_id INTEGER,
                value REAL
            );

            -- Hash, location, source
            CREATE TABLE hit_hash (
                hit_id INTEGER,
                hash TEXT
            );

            CREATE TABLE hit_location (
                hit_id INTEGER,
                location_value TEXT,
                source_id INTEGER DEFAULT 1,
                sort_order INTEGER DEFAULT 0
            );

            CREATE TABLE source (
                source_id INTEGER PRIMARY KEY,
                source_friendly_value TEXT
            );

            CREATE TABLE source_path (
                source_id INTEGER,
                source_path TEXT
            );

            -- Case metadata
            CREATE TABLE case_info (
                case_number TEXT,
                case_name TEXT,
                created_on TEXT
            );

            -- Tags (empty for KAPE, but tables must exist for SQL compatibility)
            CREATE TABLE tag (
                tag_id INTEGER PRIMARY KEY,
                tag_name TEXT,
                tag_description TEXT,
                tag_color TEXT
            );
            CREATE TABLE case_tag (
                case_tag_id INTEGER PRIMARY KEY,
                tag_id INTEGER
            );
            CREATE TABLE hit_case_tag (
                hit_id INTEGER,
                case_tag_id INTEGER
            );

            -- Source evidence (for compatibility)
            CREATE TABLE source_evidence (
                source_evidence_number TEXT,
                evidence_location TEXT
            );
        """)
        self._conn.commit()

    # ── CSV Ingestion ──

    def _ingest_csvs(self, dir_path: str) -> None:
        # Find all CSV files recursively, sorted for deterministic hit_ids
        csv_files = sorted(glob.glob(os.path.join(dir_path, "**", "*.csv"), recursive=True))

        self._next_hit_id = 1
        self._next_frag_def_id = 1
        # Track registered artifact versions and fragment definitions
        self._av_registry: dict[str, str] = {}  # artifact_name -> av_id
        self._frag_def_registry: dict[tuple[str, str], int] = {}  # (av_id, field_name) -> frag_def_id

        cur = self._conn.cursor()

        # Insert default source
        cur.execute("INSERT INTO source VALUES (1, 'KAPE Collection')")
        cur.execute("INSERT INTO source_path VALUES (1, ?)", (dir_path,))
        cur.execute("INSERT INTO source_evidence VALUES ('KAPE', ?)", (dir_path,))

        # Group files by tool for dedup handling
        tool_files: dict[str, list[str]] = {}
        for csv_path in csv_files:
            filename = os.path.basename(csv_path)
            tool_result = detect_tool(filename)
            if not tool_result:
                # Try header-based fallback
                try:
                    with open(csv_path, "rb") as fb:
                        first_line = fb.readline().replace(b"\x00", b"").decode("utf-8-sig", errors="replace").strip()
                    if first_line:
                        headers = [h.strip().strip('"') for h in first_line.split(",")]
                        tool_result = detect_tool_by_headers(headers)
                except Exception:
                    pass
                if not tool_result:
                    continue
            tool_names_list = [tool_result] if isinstance(tool_result, str) else tool_result
            for tn in tool_names_list:
                mapping = TOOL_MAPPINGS.get(tn)
                if mapping:
                    tool_files.setdefault(tn, []).append(csv_path)

        # Dedup key sets per tool (for VSS deduplication)
        self._dedup_seen: dict[str, set] = {}

        for tool_name, paths in tool_files.items():
            mapping = TOOL_MAPPINGS[tool_name]
            dedup_cols = mapping.get("dedup_columns")

            if dedup_cols:
                # VSS dedup: process newest files first, skip already-seen keys
                self._dedup_seen[tool_name] = set()
                for csv_path in reversed(paths):  # reversed = newest first
                    self._ingest_single_csv(cur, csv_path, tool_name, mapping)
            else:
                for csv_path in paths:
                    self._ingest_single_csv(cur, csv_path, tool_name, mapping)

        # Parse raw artifacts from collected directory (SSH keys, known_hosts)
        collected_dir = self._find_collected_dir(dir_path)
        if collected_dir:
            self._ingest_ssh_artifacts(cur, collected_dir)

        self._conn.commit()
        # Cleanup temp registries
        del self._av_registry
        del self._frag_def_registry
        del self._dedup_seen

    def _ingest_single_csv(
        self, cur: sqlite3.Cursor, csv_path: str,
        tool_name: str, mapping: dict,
    ) -> None:
        artifact_name = mapping["artifact_name"]
        field_mapping = mapping["field_mapping"]
        hash_columns = mapping.get("hash_columns", [])
        location_column = mapping.get("location_column", "")
        dedup_cols = mapping.get("dedup_columns")
        dedup_set = self._dedup_seen.get(tool_name) if dedup_cols else None
        category_filter = mapping.get("category_filter")
        category_col = "Category" if category_filter else None

        # Register artifact version if not yet done
        av_id = self._ensure_artifact_version(cur, artifact_name)

        # Register fragment definitions for all mapped fields
        frag_defs: dict[str, tuple[str, int]] = {}  # csv_col -> (data_type, frag_def_id)
        for csv_col, (dtype, axiom_name) in field_mapping.items():
            frag_id = self._ensure_fragment_def(cur, av_id, axiom_name, dtype)
            frag_defs[csv_col] = (dtype, frag_id)

        # Read CSV
        rows_ingested = 0
        try:
            # Detect UTF-16 BOM first
            utf16_enc = self._detect_utf16(csv_path)
            if utf16_enc:
                encodings_to_try = [utf16_enc]
            else:
                encodings_to_try = ("utf-8-sig", "utf-8", "cp949", "latin-1")

            for encoding in encodings_to_try:
                try:
                    # Stream lines, stripping NUL bytes on the fly (VSS artifacts)
                    def _lines(path, enc):
                        if enc.startswith("utf-16"):
                            with open(path, "r", encoding=enc) as f:
                                for line in f:
                                    yield line
                        else:
                            with open(path, "rb") as fb:
                                for raw_line in fb:
                                    if b"\x00" in raw_line:
                                        raw_line = raw_line.replace(b"\x00", b"")
                                    yield raw_line.decode(enc, errors="strict")

                    reader = csv.DictReader(_lines(csv_path, encoding))
                    if reader.fieldnames is None:
                        break

                    # Korean header translation for ScheduledTasks
                    if tool_name == "ScheduledTasks" and reader.fieldnames:
                        reader.fieldnames = [SCHTASKS_KR_TO_EN.get(f.strip(), f.strip()) for f in reader.fieldnames]

                    # Batch buffers
                    hit_batch: list[tuple] = []
                    str_batch: list[tuple] = []
                    date_batch: list[tuple] = []
                    int_batch: list[tuple] = []
                    float_batch: list[tuple] = []
                    hash_batch: list[tuple] = []
                    loc_batch: list[tuple] = []

                    for row in reader:
                        # VSS dedup: skip if this (EntryNumber, SeqNumber) already seen
                        if dedup_set is not None:
                            key = tuple(row.get(c, "") for c in dedup_cols)
                            if key in dedup_set:
                                continue
                            dedup_set.add(key)

                        # Category filter (e.g., Services from RECmd Kroll)
                        if category_filter and row.get(category_col, "") != category_filter:
                            continue

                        # RECmd Kroll Services: extract structured fields from ValueData
                        if tool_name == "RECmd_Kroll_Services":
                            vd = row.get("ValueData", "")
                            vd3 = row.get("ValueData3", "")
                            import re as _re
                            # "Name: sshd Desc: OpenSSH..." → Service Name = sshd
                            m = _re.match(r"Name:\s*(.+?)(?:\s+Desc:|$)", vd)
                            if m:
                                row["ValueName"] = m.group(1).strip()
                            # "Image path: C:\...\sshd.exe ServiceDLL:" → Service Location
                            m2 = _re.search(r"Image path:\s*(.+?)(?:\s+ServiceDLL:|$)", vd3)
                            if m2:
                                row["ValueData"] = m2.group(1).strip().strip('"')

                        hit_id = self._next_hit_id
                        self._next_hit_id += 1
                        hit_batch.append((hit_id, av_id))

                        for csv_col, (dtype, frag_id) in frag_defs.items():
                            raw_val = row.get(csv_col, "")
                            if not raw_val or raw_val.strip() == "":
                                continue

                            raw_val = raw_val.strip()

                            if dtype == "Date":
                                ts_ms, formatted = self._parse_timestamp(raw_val)
                                if ts_ms:
                                    date_batch.append((hit_id, frag_id, ts_ms, formatted))
                            elif dtype == "Int":
                                int_val = self._parse_int(raw_val)
                                if int_val is not None:
                                    int_batch.append((hit_id, frag_id, int_val))
                            elif dtype == "Float":
                                float_val = self._parse_float(raw_val)
                                if float_val is not None:
                                    float_batch.append((hit_id, frag_id, float_val))
                            else:  # String
                                str_batch.append((hit_id, frag_id, raw_val))

                        # Hash columns
                        for hcol in hash_columns:
                            hval = row.get(hcol, "").strip()
                            if hval:
                                hash_batch.append((hit_id, hval))

                        # Location
                        if location_column:
                            loc_val = row.get(location_column, "").strip()
                            if loc_val:
                                loc_batch.append((hit_id, loc_val, 1, 0))

                        rows_ingested += 1

                        # Flush batches every 5000 rows
                        if rows_ingested % 5000 == 0:
                            self._flush_batches(cur, hit_batch, str_batch,
                                                date_batch, int_batch, float_batch,
                                                hash_batch, loc_batch)
                            hit_batch.clear()
                            str_batch.clear()
                            date_batch.clear()
                            int_batch.clear()
                            float_batch.clear()
                            hash_batch.clear()
                            loc_batch.clear()

                    # Flush remaining
                    self._flush_batches(cur, hit_batch, str_batch,
                                        date_batch, int_batch, float_batch,
                                        hash_batch, loc_batch)
                    break  # Successfully read with this encoding
                except (UnicodeDecodeError, UnicodeError):
                    continue
        except Exception as e:
            print(f"  Warning: Failed to read {csv_path}: {e}", file=sys.stderr)

        if rows_ingested > 0:
            self._ingest_stats[tool_name] = (
                self._ingest_stats.get(tool_name, 0) + rows_ingested
            )

    def _flush_batches(
        self, cur: sqlite3.Cursor,
        hits: list, strings: list, dates: list,
        ints: list, floats: list, hashes: list, locs: list,
    ) -> None:
        if hits:
            cur.executemany(
                "INSERT INTO scan_artifact_hit (hit_id, artifact_version_id) VALUES (?, ?)",
                hits)
        if strings:
            cur.executemany(
                "INSERT INTO hit_fragment_string (hit_id, fragment_definition_id, value) VALUES (?, ?, ?)",
                strings)
        if dates:
            cur.executemany(
                "INSERT INTO hit_fragment_date (hit_id, fragment_definition_id, unix_timestamp_ms, formatted_value) VALUES (?, ?, ?, ?)",
                dates)
        if ints:
            cur.executemany(
                "INSERT INTO hit_fragment_int (hit_id, fragment_definition_id, value) VALUES (?, ?, ?)",
                ints)
        if floats:
            cur.executemany(
                "INSERT INTO hit_fragment_float (hit_id, fragment_definition_id, value) VALUES (?, ?, ?)",
                floats)
        if hashes:
            cur.executemany(
                "INSERT INTO hit_hash (hit_id, hash) VALUES (?, ?)",
                hashes)
        if locs:
            cur.executemany(
                "INSERT INTO hit_location (hit_id, location_value, source_id, sort_order) VALUES (?, ?, ?, ?)",
                locs)

    # ── Registration Helpers ──

    def _ensure_artifact_version(self, cur: sqlite3.Cursor, artifact_name: str) -> str:
        if artifact_name in self._av_registry:
            return self._av_registry[artifact_name]
        av_id = f"kape_{artifact_name.lower().replace(' ', '_')}"
        cur.execute(
            "INSERT INTO artifact_version (artifact_version_id, artifact_id, artifact_name) VALUES (?, ?, ?)",
            (av_id, av_id, artifact_name))
        self._av_registry[artifact_name] = av_id
        return av_id

    def _ensure_fragment_def(
        self, cur: sqlite3.Cursor,
        av_id: str, field_name: str, data_type: str,
    ) -> int:
        key = (av_id, field_name)
        if key in self._frag_def_registry:
            return self._frag_def_registry[key]
        frag_id = self._next_frag_def_id
        self._next_frag_def_id += 1
        cur.execute(
            "INSERT INTO fragment_definition (fragment_definition_id, artifact_version_id, name, data_type) VALUES (?, ?, ?, ?)",
            (frag_id, av_id, field_name, data_type))
        self._frag_def_registry[key] = frag_id
        return frag_id

    # ── Timestamp Parsing ──

    @staticmethod
    def _parse_timestamp(raw: str) -> tuple[int | None, str]:
        """Parse EZ tool timestamp → (unix_ms, iso_string)."""
        if not raw:
            return None, ""

        # Remove trailing timezone offset if present (e.g., " +00:00")
        clean = raw.strip()
        # Handle .NET-style 7-digit fractional seconds by truncating to 6
        # Python %f supports max 6 digits
        for fmt in TIMESTAMP_FORMATS:
            try:
                val = clean
                # Truncate fractional seconds to 6 digits for %f
                if ".%f" in fmt and "." in val:
                    dot_pos = val.index(".")
                    frac_end = dot_pos + 1
                    while frac_end < len(val) and val[frac_end].isdigit():
                        frac_end += 1
                    frac = val[dot_pos + 1:frac_end]
                    suffix = val[frac_end:]
                    if len(frac) > 6:
                        frac = frac[:6]
                    val = val[:dot_pos + 1] + frac + suffix

                dt = datetime.strptime(val, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ms = int(dt.timestamp() * 1000)
                iso = dt.isoformat()
                return ms, iso
            except (ValueError, OverflowError):
                continue

        # Fallback: try datetime.fromisoformat
        try:
            clean = clean.replace("Z", "+00:00")
            # Hayabusa format: "2026-03-05 07:29:05.295 +00:00" — space before tz
            # fromisoformat needs "2026-03-05T07:29:05.295+00:00"
            import re as _re
            clean = _re.sub(r'(\d) ([+-]\d{2}:\d{2})$', r'\1\2', clean)
            if ' ' in clean and 'T' not in clean:
                clean = clean.replace(' ', 'T', 1)
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ms = int(dt.timestamp() * 1000)
            return ms, dt.isoformat()
        except (ValueError, OverflowError):
            return None, ""

    @staticmethod
    def _parse_int(raw: str) -> int | None:
        try:
            # Handle comma-separated numbers (e.g., "1,234")
            return int(raw.replace(",", "").split(".")[0])
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _parse_float(raw: str) -> float | None:
        try:
            return float(raw.replace(",", ""))
        except ValueError:
            return None

    # ── Index Creation ──

    def _create_indexes(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE INDEX IF NOT EXISTS idx_hfs_value ON hit_fragment_string(value);
            CREATE INDEX IF NOT EXISTS idx_hfs_hit ON hit_fragment_string(hit_id);
            CREATE INDEX IF NOT EXISTS idx_hfs_frag ON hit_fragment_string(fragment_definition_id);
            CREATE INDEX IF NOT EXISTS idx_hfd_ts ON hit_fragment_date(unix_timestamp_ms);
            CREATE INDEX IF NOT EXISTS idx_hfd_hit ON hit_fragment_date(hit_id);
            CREATE INDEX IF NOT EXISTS idx_hfi_hit ON hit_fragment_int(hit_id);
            CREATE INDEX IF NOT EXISTS idx_hfi_frag ON hit_fragment_int(fragment_definition_id);
            CREATE INDEX IF NOT EXISTS idx_sah_avid ON scan_artifact_hit(artifact_version_id);
            CREATE INDEX IF NOT EXISTS idx_hh_hash ON hit_hash(hash);
            CREATE INDEX IF NOT EXISTS idx_hl_hit ON hit_location(hit_id);
            CREATE INDEX IF NOT EXISTS idx_hl_loc ON hit_location(location_value);
        """)
        self._conn.commit()

    # ── Case Info (override) ──

    def _load_case_info(self) -> dict:
        cur = self._cursor()

        # Case name from directory
        case_name = os.path.basename(self._path.rstrip("/\\"))

        # Insert into case_info table for SQL compatibility
        cur.execute(
            "INSERT INTO case_info (case_number, case_name, created_on) VALUES (?, ?, ?)",
            ("KAPE", case_name, datetime.now(timezone.utc).isoformat()))
        self._conn.commit()

        # Total hits
        cur.execute("SELECT COUNT(*) FROM scan_artifact_hit")
        total_hits = cur.fetchone()[0]

        # Artifact types
        cur.execute("""
            SELECT av.artifact_name, COUNT(*) AS hit_count
            FROM scan_artifact_hit sah
            JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
            GROUP BY av.artifact_name ORDER BY hit_count DESC
        """)
        type_counts = {row["artifact_name"]: row["hit_count"] for row in cur.fetchall()}

        # Date range
        cur.execute("""
            SELECT MIN(unix_timestamp_ms) AS min_ts, MAX(unix_timestamp_ms) AS max_ts
            FROM hit_fragment_date WHERE unix_timestamp_ms > 946684800000
        """)
        dr = cur.fetchone()
        min_ts = dr["min_ts"] if dr else None
        max_ts = dr["max_ts"] if dr else None

        return {
            "case_name": case_name,
            "case_number": "KAPE",
            "created_on": datetime.now(timezone.utc).isoformat(),
            "source_path": self._path,
            "source_type": "kape",
            "total_hits": total_hits,
            "artifact_type_count": len(type_counts),
            "artifact_types": type_counts,
            "date_range_start": self._ms_to_iso(min_ts) if min_ts else None,
            "date_range_end": self._ms_to_iso(max_ts) if max_ts else None,
            "evidence_sources": ["KAPE"],
            "tags": [],
            "ingest_stats": dict(self._ingest_stats),
        }

    # ── UTF-16 Detection ──

    @staticmethod
    def _detect_utf16(csv_path: str) -> str | None:
        with open(csv_path, "rb") as f:
            bom = f.read(4)
        if bom[:2] == b'\xff\xfe':
            return "utf-16-le"
        if bom[:2] == b'\xfe\xff':
            return "utf-16-be"
        return None

    # ── SSH Artifact Ingestion ──

    def _find_collected_dir(self, parsed_dir: str) -> str | None:
        """Find the KAPE collected directory relative to parsed directory."""
        parent = os.path.dirname(parsed_dir.rstrip("/\\"))
        collected = os.path.join(parent, "collected")
        return collected if os.path.isdir(collected) else None

    def _ingest_ssh_artifacts(self, cur: sqlite3.Cursor, collected_dir: str) -> None:
        """Parse SSH known_hosts and key files from collected directory."""
        import glob as _glob

        # SSH Known Hosts
        known_hosts_files = _glob.glob(os.path.join(collected_dir, "**", ".ssh", "known_hosts"), recursive=True)
        # Also check OpenSSH server config location
        known_hosts_files += _glob.glob(os.path.join(collected_dir, "**", "ssh", "known_hosts"), recursive=True)
        known_hosts_files += _glob.glob(os.path.join(collected_dir, "**", "ProgramData", "ssh", "ssh_known_hosts"), recursive=True)

        if known_hosts_files:
            av_id = self._ensure_artifact_version(cur, "SSH Known Hosts")
            frag_host = self._ensure_fragment_def(cur, av_id, "Host Names", "String")
            frag_enc = self._ensure_fragment_def(cur, av_id, "Encryption", "String")
            frag_key = self._ensure_fragment_def(cur, av_id, "Public Key", "String")
            frag_src = self._ensure_fragment_def(cur, av_id, "Source File", "String")

            seen = set()
            for kh_path in known_hosts_files:
                try:
                    with open(kh_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) < 3:
                                continue
                            host_part, key_type, key_data = parts[0], parts[1], parts[2]
                            if host_part in seen:
                                continue
                            seen.add(host_part)

                            hit_id = self._next_hit_id
                            self._next_hit_id += 1
                            cur.execute("INSERT INTO scan_artifact_hit VALUES (?,?)", (hit_id, av_id))
                            cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_host, host_part))
                            cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_enc, key_type))
                            cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_key, key_data))
                            cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_src, kh_path))
                            cur.execute("INSERT INTO hit_location VALUES (?,?,1,0)", (hit_id, host_part))
                except Exception:
                    pass

            if seen:
                self._ingest_stats["SSH_KnownHosts"] = len(seen)

        # SSH Keys
        key_patterns = [
            os.path.join(collected_dir, "**", "ssh_host_*_key"),
            os.path.join(collected_dir, "**", "ssh_host_*_key.pub"),
            os.path.join(collected_dir, "**", ".ssh", "id_*"),
            os.path.join(collected_dir, "**", ".ssh", "authorized_keys"),
        ]
        key_files = []
        for pat in key_patterns:
            key_files.extend(_glob.glob(pat, recursive=True))

        if key_files:
            av_id = self._ensure_artifact_version(cur, "SSH Keys")
            frag_name = self._ensure_fragment_def(cur, av_id, "File Name", "String")
            frag_type = self._ensure_fragment_def(cur, av_id, "Type", "String")
            frag_enc = self._ensure_fragment_def(cur, av_id, "Encryption", "String")
            frag_src = self._ensure_fragment_def(cur, av_id, "Source File", "String")
            frag_created = self._ensure_fragment_def(cur, av_id, "File System Created Date/Time - UTC", "Date")

            seen_keys = set()
            for kf in key_files:
                fname = os.path.basename(kf)
                if fname in seen_keys:
                    continue
                seen_keys.add(fname)

                # Determine key type from filename
                key_type = "Unknown"
                if ".pub" in fname:
                    key_type = "Public"
                elif "authorized_keys" in fname:
                    key_type = "Authorized"
                else:
                    key_type = "Private"

                encryption = "Unknown"
                for enc in ["ed25519", "ecdsa", "rsa", "dsa"]:
                    if enc in fname.lower():
                        encryption = enc.upper()
                        break

                hit_id = self._next_hit_id
                self._next_hit_id += 1
                cur.execute("INSERT INTO scan_artifact_hit VALUES (?,?)", (hit_id, av_id))
                cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_name, fname))
                cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_type, key_type))
                cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_enc, encryption))
                cur.execute("INSERT INTO hit_fragment_string VALUES (?,?,?)", (hit_id, frag_src, kf))

                # File creation time
                try:
                    mtime = os.path.getmtime(kf)
                    ms = int(mtime * 1000)
                    from datetime import datetime, timezone
                    iso = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                    cur.execute("INSERT INTO hit_fragment_date VALUES (?,?,?,?)", (hit_id, frag_created, ms, iso))
                except Exception:
                    pass

                cur.execute("INSERT INTO hit_location VALUES (?,?,1,0)", (hit_id, fname))

            if seen_keys:
                self._ingest_stats["SSH_Keys"] = len(seen_keys)

    def get_capabilities(self) -> list[str]:
        return [
            "search", "timeline", "ioc_extraction", "suspicious_detection",
            "correlation", "hash_search", "source_search",
        ]
