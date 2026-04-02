"""Parse and search external log files (Apache, IIS, syslog).

Supports loading from plain text files or zip archives.
Provides structured search, statistics, and timeline integration.
"""

from __future__ import annotations

import os
import re
import tempfile
import zipfile
from datetime import datetime
from typing import Any

# Maximum lines per file to prevent memory issues with very large logs
MAX_LINES_PER_FILE = 500_000

# ── Log format regexes ──

APACHE_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

IIS_W3C_FIELD_LINE = re.compile(r'^#Fields:\s+(.+)$')
IIS_COMMENT = re.compile(r'^#')

SYSLOG_BSD = re.compile(
    r'(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)


class LogConnector:
    """Parse and search external log files (Apache, IIS, syslog)."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._path: str = ""
        self._log_type: str = ""
        self._truncated: bool = False
        self._files_loaded: list[str] = []

    def load(self, path: str, log_type: str = "auto") -> dict:
        """Load and parse a log file. Supports zip archives.

        Args:
            path: Path to a log file or zip archive containing log files.
            log_type: One of "apache", "iis", "syslog", or "auto" for detection.

        Returns:
            Summary dict with load status, entry count, and detected format.
        """
        if not os.path.exists(path):
            return {"error": f"File not found: {path}"}

        self._entries = []
        self._path = path
        self._truncated = False
        self._files_loaded = []

        try:
            if zipfile.is_zipfile(path):
                self._load_zip(path, log_type)
            else:
                self._load_single_file(path, log_type)
        except Exception as e:
            return {"error": f"Failed to load log file: {e}"}

        self._log_type = log_type

        return {
            "status": "loaded",
            "path": path,
            "log_type": self._log_type,
            "total_entries": len(self._entries),
            "files_loaded": self._files_loaded,
            "truncated": self._truncated,
            "truncation_warning": (
                f"Log file(s) exceeded {MAX_LINES_PER_FILE} lines per file; entries were truncated."
                if self._truncated else None
            ),
        }

    def search(
        self,
        keyword: str = "",
        source_ip: str = "",
        start_date: str = "",
        end_date: str = "",
        status_code: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Search parsed log entries with multiple filter criteria.

        Args:
            keyword: Free-text search across all fields.
            source_ip: Filter by source IP address.
            start_date: ISO date string (yyyy-mm-dd) lower bound.
            end_date: ISO date string (yyyy-mm-dd) upper bound.
            status_code: HTTP status code or prefix (e.g. "404", "5").
            limit: Maximum results to return.
            offset: Number of results to skip (for pagination).

        Returns:
            Dict with matching entries, total matches, and pagination info.
        """
        if not self._entries:
            return {"error": "No log entries loaded. Use import_logs first."}

        results = self._entries

        # Apply filters
        if source_ip:
            results = [e for e in results if source_ip in e.get("ip", "")]

        if status_code:
            results = [e for e in results if str(e.get("status", "")).startswith(status_code)]

        if start_date:
            results = [e for e in results if e.get("timestamp_iso", "") >= start_date]

        if end_date:
            # Include the full end date (up to end of day)
            end_bound = end_date if len(end_date) > 10 else end_date + "T23:59:59"
            results = [e for e in results if e.get("timestamp_iso", "") <= end_bound]

        if keyword:
            kw_lower = keyword.lower()
            results = [e for e in results if kw_lower in e.get("_raw", "").lower()]

        total = len(results)
        paginated = results[offset:offset + limit]

        return {
            "total_matches": total,
            "offset": offset,
            "limit": limit,
            "returned": len(paginated),
            "entries": paginated,
        }

    def get_stats(self) -> dict:
        """Return summary statistics for loaded log entries.

        Returns:
            Dict with total entries, date range, unique IPs, top paths,
            and status code distribution.
        """
        if not self._entries:
            return {"error": "No log entries loaded. Use import_logs first."}

        timestamps = sorted(
            [e["timestamp_iso"] for e in self._entries if e.get("timestamp_iso")]
        )

        # Unique IPs
        ips: dict[str, int] = {}
        for e in self._entries:
            ip = e.get("ip", "")
            if ip:
                ips[ip] = ips.get(ip, 0) + 1

        # Top paths
        paths: dict[str, int] = {}
        for e in self._entries:
            p = e.get("path", "")
            if p:
                paths[p] = paths.get(p, 0) + 1
        top_paths = sorted(paths.items(), key=lambda x: x[1], reverse=True)[:20]

        # Status code distribution
        statuses: dict[str, int] = {}
        for e in self._entries:
            s = str(e.get("status", ""))
            if s:
                statuses[s] = statuses.get(s, 0) + 1

        return {
            "total_entries": len(self._entries),
            "log_type": self._log_type,
            "files_loaded": self._files_loaded,
            "date_range": {
                "earliest": timestamps[0] if timestamps else None,
                "latest": timestamps[-1] if timestamps else None,
            },
            "unique_ips": len(ips),
            "top_ips": sorted(ips.items(), key=lambda x: x[1], reverse=True)[:20],
            "top_paths": top_paths,
            "status_distribution": statuses,
        }

    def get_timeline(self, start_date: str = "", end_date: str = "", limit: int = 200) -> list:
        """Get chronological entries for timeline integration.

        Args:
            start_date: ISO date string lower bound.
            end_date: ISO date string upper bound.
            limit: Maximum entries to return.

        Returns:
            List of log entries sorted by timestamp.
        """
        if not self._entries:
            return []

        entries = self._entries

        if start_date:
            entries = [e for e in entries if e.get("timestamp_iso", "") >= start_date]

        if end_date:
            end_bound = end_date if len(end_date) > 10 else end_date + "T23:59:59"
            entries = [e for e in entries if e.get("timestamp_iso", "") <= end_bound]

        # Sort by timestamp
        entries = sorted(entries, key=lambda e: e.get("timestamp_iso", ""))

        return entries[:limit]

    # ── Internal loading methods ──

    def _load_zip(self, zip_path: str, log_type: str) -> None:
        """Extract and parse log files from a zip archive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Only extract files that look like logs
                log_members = [
                    m for m in zf.namelist()
                    if m.lower().endswith((".log", ".txt", ".csv"))
                    and not m.startswith("__MACOSX")
                ]
                if not log_members:
                    # Try all non-directory members
                    log_members = [
                        m for m in zf.namelist()
                        if not m.endswith("/") and not m.startswith("__MACOSX")
                    ]

                for member in log_members:
                    extracted = zf.extract(member, tmpdir)
                    self._load_single_file(extracted, log_type, source_name=member)

    def _load_single_file(self, file_path: str, log_type: str, source_name: str = "") -> None:
        """Parse a single log file and append entries to self._entries."""
        display_name = source_name or os.path.basename(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= MAX_LINES_PER_FILE:
                        self._truncated = True
                        break
                    lines.append(line.rstrip("\n\r"))
        except Exception as e:
            return  # Skip unreadable files silently

        if not lines:
            return

        # Auto-detect log type if needed
        detected_type = log_type
        if log_type == "auto":
            detected_type = self._detect_log_type(lines)
            if self._log_type == "" or self._log_type == "auto":
                self._log_type = detected_type

        if detected_type == "apache":
            self._parse_apache(lines, display_name)
        elif detected_type == "iis":
            self._parse_iis(lines, display_name)
        elif detected_type == "syslog":
            self._parse_syslog(lines, display_name)
        else:
            # Best-effort: store raw lines
            self._parse_raw(lines, display_name)

        self._files_loaded.append(display_name)

    def _detect_log_type(self, lines: list[str]) -> str:
        """Auto-detect log format from first non-empty lines."""
        sample = [l for l in lines[:50] if l.strip()]
        if not sample:
            return "raw"

        # Check for IIS W3C header
        for line in sample:
            if line.startswith("#Fields:"):
                return "iis"
            if line.startswith("#Software: Microsoft"):
                return "iis"

        # Check for Apache Combined format
        for line in sample[:10]:
            if APACHE_COMBINED.match(line):
                return "apache"

        # Check for syslog format
        for line in sample[:10]:
            if SYSLOG_BSD.match(line):
                return "syslog"

        return "raw"

    def _parse_apache(self, lines: list[str], source: str) -> None:
        """Parse Apache Combined Log Format entries."""
        for line in lines:
            if not line.strip():
                continue
            m = APACHE_COMBINED.match(line)
            if not m:
                continue
            entry = {
                "source_file": source,
                "log_type": "apache",
                "ip": m.group("ip"),
                "timestamp_raw": m.group("time"),
                "timestamp_iso": _parse_apache_time(m.group("time")),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": m.group("status"),
                "size": m.group("size"),
                "referer": m.group("referer") or "",
                "user_agent": m.group("ua") or "",
                "_raw": line,
            }
            self._entries.append(entry)

    def _parse_iis(self, lines: list[str], source: str) -> None:
        """Parse IIS W3C Extended Log Format entries."""
        fields: list[str] = []
        for line in lines:
            if not line.strip():
                continue
            # Parse field definition line
            fm = IIS_W3C_FIELD_LINE.match(line)
            if fm:
                fields = fm.group(1).strip().split()
                continue
            # Skip other comment lines
            if IIS_COMMENT.match(line):
                continue

            if not fields:
                continue

            parts = line.split()
            if len(parts) < len(fields):
                continue

            row = dict(zip(fields, parts))
            # Build ISO timestamp from date + time fields
            date_str = row.get("date", "")
            time_str = row.get("time", "")
            iso_ts = f"{date_str}T{time_str}" if date_str and time_str else ""

            entry = {
                "source_file": source,
                "log_type": "iis",
                "ip": row.get("c-ip", row.get("s-ip", "")),
                "timestamp_iso": iso_ts,
                "timestamp_raw": f"{date_str} {time_str}",
                "method": row.get("cs-method", ""),
                "path": row.get("cs-uri-stem", ""),
                "query": row.get("cs-uri-query", ""),
                "status": row.get("sc-status", ""),
                "size": row.get("sc-bytes", ""),
                "user_agent": row.get("cs(User-Agent)", ""),
                "referer": row.get("cs(Referer)", ""),
                "_raw": line,
                "_iis_fields": row,
            }
            self._entries.append(entry)

    def _parse_syslog(self, lines: list[str], source: str) -> None:
        """Parse BSD-style syslog entries."""
        current_year = datetime.now().year
        for line in lines:
            if not line.strip():
                continue
            m = SYSLOG_BSD.match(line)
            if not m:
                continue
            entry = {
                "source_file": source,
                "log_type": "syslog",
                "ip": "",
                "host": m.group("host"),
                "process": m.group("process"),
                "pid": m.group("pid") or "",
                "message": m.group("message"),
                "timestamp_raw": m.group("time"),
                "timestamp_iso": _parse_syslog_time(m.group("time"), current_year),
                "_raw": line,
            }
            self._entries.append(entry)

    def _parse_raw(self, lines: list[str], source: str) -> None:
        """Store unrecognized log lines as raw entries."""
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            self._entries.append({
                "source_file": source,
                "log_type": "raw",
                "line_number": i + 1,
                "timestamp_iso": "",
                "_raw": line,
            })


# ── Time parsing helpers ──

def _parse_apache_time(time_str: str) -> str:
    """Convert Apache time '10/Oct/2000:13:55:36 -0700' to ISO format."""
    try:
        # Remove timezone offset for simpler parsing
        dt = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, IndexError):
        return ""


def _parse_syslog_time(time_str: str, year: int) -> str:
    """Convert syslog time 'Jan  1 00:00:00' to ISO format with assumed year."""
    try:
        dt = datetime.strptime(time_str, "%b %d %H:%M:%S")
        dt = dt.replace(year=year)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, IndexError):
        return ""
