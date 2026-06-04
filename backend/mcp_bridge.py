"""MCP Bridge Server — exposes workstation tools to Claude Code.

Claude Code connects to this MCP server via stdio.
Tool calls are forwarded to the web UI via WebSocket for real-time display.

Run: python backend/mcp_bridge.py
Configure in ~/.claude/settings.json:
{
  "mcpServers": {
    "forensic-workstation": {
      "command": "python",
      "args": ["<project-root>/backend/mcp_bridge.py"]
    }
  }
}
"""

from __future__ import annotations

import sys
import os
import json
import re
import asyncio
import hashlib
import subprocess
from datetime import datetime, timezone
import inspect
from typing import Any, Callable

# Setup paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

from mcp.server.fastmcp import FastMCP
from core.connectors.axiom_mfdb import AxiomMfdbConnector
from core.connectors.kape_csv import KapeCsvConnector
from core.connectors.e01_image import E01ImageConnector
from core.connectors.ghidra import GhidraConnector
from core.connectors.volatility_connector import VolatilityConnector
from core.connectors.log_connector import LogConnector
from core.analysis.masker import DataMasker
from core.config import config
from core.dependencies import dependency_report, diagnose_exception
from state import (
    IMAGE_EXTENSIONS,
    app_state,
    build_not_allowed_message,
    is_path_allowed,
    load_active_case,
    load_allowed_evidence,
    resolve_active_case_evidence,
    resolve_allowed_evidence,
    resolve_image_evidence,
)

mcp = FastMCP(
    name="forensic-workstation",
    instructions=(
        "Forensic Workstation exposes offline DFIR tools for the user-selected "
        "evidence set. Before analysis, inspect the selected evidence context. "
        "If no parsed AXIOM/KAPE case is loaded but a selected disk image is "
        "available, use mount_image(evidence_ref='active_image') and raw-image "
        "tools. Never search the workspace for replacement evidence; open_case "
        "and mount_image are constrained to user-selected allowlisted evidence."
    ),
)

# Shared state — aliased to app_state._connectors so MCP tools and every
# analysis module (case_health, coverage_explainer, pivot_across_cases,
# investigation_gap_report, ...) read from the SAME dict object. Without the
# alias, open_case populated mcp_bridge._connectors while case_health read
# app_state._connectors (empty) and silently reported case_count=0.
_connectors: dict[str, Any] = app_state._connectors
_masker = DataMasker()
_event_log: list[dict] = []  # Recent events for web UI polling

# Timezone display settings
_tz_config: dict[str, Any] = {
    "local_tz_name": "KST",
    "local_tz_offset_hours": 9,
    "enabled": True,
}

_EVENT_LOG_MAX_BYTES = int(os.environ.get("FW_EVENT_LOG_MAX_BYTES", str(20 * 1024 * 1024)))  # 20 MB
_SERVER_STARTED_AT = datetime.now(timezone.utc)
_SERVER_PID = os.getpid()
_WATCHED_CODE_FILES = [
    os.path.abspath(__file__),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.py"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "connectors", "axiom_mfdb.py"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "connectors", "e01_image.py"),
]
_SERVER_CODE_MTIME_AT_START = {
    path: os.path.getmtime(path)
    for path in _WATCHED_CODE_FILES
    if os.path.exists(path)
}
_STALE_SENSITIVE_TOOLS = {
    "initial_triage_pack",
    "service_persistence_gate",
    "find_suspicious",
    "baseline_diff",
    "detect_anti_forensics",
    "hunt_evtx_rules",
    "query_evtx_file",
    "list_vss_snapshots",
    "vss_list_files",
    "vss_get_file_timestamps",
    "vss_extract_file",
    "vss_query_evtx_file",
    "vss_query_registry_hive",
    "vss_list_registry_hives",
    "vss_query_user_hives",
    "vss_service_persistence_gate",
    "query_registry_hive",
    "query_prefetch_files",
    "inspect_pe_file",
    "analyze_binary",
    "auto_triage",
}


def _log_event(event_type: str, tool: str, data: Any = None, params: Any = None, result: Any = None, duration: float = 0):
    """Record a tool event for the web UI to stream via /ws/mcp-monitor.

    Applies the same masker that tools use for their return values to the
    params payload as well — otherwise sensitive keywords (IPs, usernames,
    hostnames) that the analyst typed into a search would flow unmasked into
    the live event stream even with masking globally enabled.

    Also rotates ``.mcp_events.jsonl`` once it exceeds FW_EVENT_LOG_MAX_BYTES
    (default 20 MB) so long investigations don't leave multi-gigabyte state
    files behind. Rotation is a simple overwrite — the UI's in-memory buffer
    handles continuity for anyone watching live.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "tool": tool,
    }
    if params is not None:
        entry["params"] = _truncate(_mask(params) if _masker.enabled else params)
    if data is not None:
        entry["data"] = _truncate(_mask(data) if _masker.enabled else data)
    if result is not None:
        # ``result`` is already masked by the tool's fn(); truncating only.
        entry["result"] = _truncate(result)
    if duration:
        entry["duration_ms"] = round(duration * 1000)
    _event_log.append(entry)
    if len(_event_log) > 200:
        _event_log.pop(0)
    try:
        event_file = os.path.join(os.path.dirname(__file__), ".mcp_events.jsonl")
        # Rotate before writing so we never exceed the cap.
        try:
            if os.path.exists(event_file) and os.path.getsize(event_file) > _EVENT_LOG_MAX_BYTES:
                with open(event_file, "w", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "rotation", "tool": "_system",
                        "data": {"note": "event log rotated", "max_bytes": _EVENT_LOG_MAX_BYTES},
                    }, ensure_ascii=False) + "\n")
        except Exception:
            pass
        with open(event_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass


def _truncate(data: Any, max_len: int = 500) -> Any:
    """Truncate large data for event logging."""
    if isinstance(data, str):
        return data[:max_len] + ("..." if len(data) > max_len else "")
    if isinstance(data, dict):
        result = {}
        for k, v in list(data.items())[:15]:
            if isinstance(v, list) and len(v) > 5:
                result[k] = f"[{len(v)} items]"
            elif isinstance(v, str) and len(v) > 200:
                result[k] = v[:200] + "..."
            else:
                result[k] = v
        return result
    if isinstance(data, list):
        return f"[{len(data)} items]"
    return data


def _mask(data: Any) -> Any:
    return _masker.mask(data) if _masker.enabled else data


def _runtime_status() -> dict[str, Any]:
    stale_files = []
    latest_seen_mtime = None
    for path in _WATCHED_CODE_FILES:
        if not os.path.exists(path):
            continue
        current_mtime = os.path.getmtime(path)
        latest_seen_mtime = current_mtime if latest_seen_mtime is None else max(latest_seen_mtime, current_mtime)
        started_mtime = _SERVER_CODE_MTIME_AT_START.get(path)
        if started_mtime is not None and current_mtime > started_mtime:
            stale_files.append(path)

    return {
        "pid": _SERVER_PID,
        "started_at": _SERVER_STARTED_AT.isoformat(),
        "stale_code_detected": bool(stale_files),
        "stale_files": stale_files,
        "watched_files": list(_WATCHED_CODE_FILES),
        "latest_code_mtime": (
            datetime.fromtimestamp(latest_seen_mtime, tz=timezone.utc).isoformat()
            if latest_seen_mtime is not None else ""
        ),
    }


def _attach_dependency_status(result: Any, tool_name: str = "") -> Any:
    if not isinstance(result, dict):
        return result

    diagnostic = diagnose_exception(result.get("error", ""))
    if not diagnostic:
        try:
            diagnostic = diagnose_exception(json.dumps(result, ensure_ascii=False, default=str))
        except Exception:
            diagnostic = None
    if not diagnostic:
        return result

    out = dict(result)
    out["dependency_diagnostic"] = diagnostic
    warnings = list(out.get("runtime_warnings", []))
    warning = diagnostic["user_message"]
    if warning not in warnings:
        warnings.append(warning)
    out["runtime_warnings"] = warnings
    blockers = list(out.get("analysis_blockers", []))
    blocker = (
        f"{tool_name} could not complete because {diagnostic['dependency']['display_name']} "
        f"is not available. Recovery: {diagnostic['recovery']}"
    )
    if blocker not in blockers:
        blockers.append(blocker)
    out["analysis_blockers"] = blockers
    return out


def _attach_runtime_warning(result: Any, tool_name: str = "") -> Any:
    if not isinstance(result, dict):
        return result
    status = _runtime_status()
    if not status["stale_code_detected"]:
        return result
    out = dict(result)
    warning = (
        "Connected MCP server process is stale: backend code changed after this "
        "process started. Restart the forensic-workstation MCP server to apply "
        "the latest logic."
    )
    warnings = list(out.get("runtime_warnings", []))
    if warning not in warnings:
        warnings.append(warning)
    out["runtime_warnings"] = warnings
    out["server_runtime"] = {
        "pid": status["pid"],
        "started_at": status["started_at"],
        "stale_code_detected": True,
    }
    severity = "critical" if tool_name in _STALE_SENSITIVE_TOOLS else "warning"
    out["runtime_status"] = {
        "state": "stale_code",
        "severity": severity,
        "tool_name": tool_name,
        "stale_files": status.get("stale_files", []),
        "latest_code_mtime": status.get("latest_code_mtime", ""),
        "restart_required_before_relying_on_result": tool_name in _STALE_SENSITIVE_TOOLS,
    }
    if tool_name in _STALE_SENSITIVE_TOOLS:
        blockers = list(out.get("analysis_blockers", []))
        blocker = (
            f"{tool_name} ran on a stale MCP server process. Restart the "
            "forensic-workstation MCP server before relying on this result."
        )
        if blocker not in blockers:
            blockers.append(blocker)
        out["analysis_blockers"] = blockers
    return out


_WIN_PATH_RE = re.compile(r"([A-Za-z]:\\[^\r\n\t\"<>|]+)")


def _candidate_disk_paths_from_hits(entity_value: str, hits: list[dict[str, Any]]) -> list[str]:
    """Extract exact Windows paths from hit fields that likely refer to the entity.

    Safety rule: this helper only proposes explicit paths already present in
    forensic artifacts. It never broadens into directory scans or guessed names.
    """
    entity_lc = str(entity_value or "").strip().lower()
    candidates: list[str] = []
    for hit in hits:
        for value in (hit.get("fields", {}) or {}).values():
            text = str(value or "")
            for match in _WIN_PATH_RE.findall(text):
                path_lc = match.lower()
                basename_lc = os.path.basename(match).lower()
                if entity_lc and entity_lc not in path_lc and entity_lc not in basename_lc:
                    continue
                if match not in candidates:
                    candidates.append(match)
    return candidates


# ── Timestamp Localization ──

# Regex: matches common forensic timestamp formats (UTC)
_TS_PATTERN = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\b"
)


def _add_local_tz(utc_str: str) -> str:
    """Convert a single UTC timestamp string to 'UTC_time (LOCAL_time local_tz)' format.

    Example: '2026-03-03 01:14:44.306' → '2026-03-03 01:14:44.306 UTC (10:14:44 KST)'
    """
    if not _tz_config["enabled"]:
        return utc_str
    try:
        # Parse the timestamp — handle both 'T' and space separator
        ts_clean = utc_str.replace("T", " ")
        if "." in ts_clean:
            dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S.%f")
        else:
            dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)

        from datetime import timedelta
        offset = timedelta(hours=_tz_config["local_tz_offset_hours"])
        local_dt = dt + offset
        tz_name = _tz_config["local_tz_name"]

        return f"{utc_str} UTC ({local_dt.strftime('%Y-%m-%d %H:%M:%S')} {tz_name})"
    except Exception:
        return utc_str


def _localize_timestamps(data: Any, _depth: int = 0) -> Any:
    """Recursively walk a dict/list and annotate UTC timestamp strings with local time.

    Applied as a post-processor on tool outputs, similar to _mask().
    Only processes values that look like forensic timestamps (yyyy-mm-dd HH:MM:SS).
    """
    if not _tz_config["enabled"] or _depth > 8:
        return data

    if isinstance(data, str):
        # Only convert strings that ARE a timestamp (not containing one in the middle of text)
        stripped = data.strip()
        if _TS_PATTERN.fullmatch(stripped):
            return _add_local_tz(stripped)
        return data

    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            # Only process keys that look like timestamp fields
            k_lower = str(k).lower()
            is_ts_key = any(w in k_lower for w in (
                "time", "date", "timestamp", "created", "modified", "accessed",
                "start", "end", "last run", "recorded",
            ))
            if is_ts_key and isinstance(v, str):
                result[k] = _localize_timestamps(v, _depth + 1)
            elif isinstance(v, (dict, list)):
                result[k] = _localize_timestamps(v, _depth + 1)
            else:
                result[k] = v
        return result

    if isinstance(data, list):
        return [_localize_timestamps(item, _depth + 1) for item in data]

    return data


def _load_case_from_path(path: str, case_id: str = "") -> Any:
    """Load a single case source by path and register it under the
    ``axiom:{case_id}`` prefix so iter_axiom_cases / case_health / coverage
    can see it."""
    if not is_path_allowed(path):
        raise RuntimeError(build_not_allowed_message(path))
    if os.path.isdir(path):
        c = KapeCsvConnector()
    else:
        c = AxiomMfdbConnector()
    meta = c.connect(path)
    resolved = case_id or meta.get("case_number") or meta.get("case_name") or (
        os.path.basename(os.path.dirname(path) if not os.path.isdir(path) else path)
    )
    if resolved:
        _connectors[f"axiom:{resolved}"] = c
    return c


def _ensure_cases_hydrated() -> None:
    """Populate ``_connectors`` from ``.active_case.json`` when it is empty.

    The FastAPI server (main.py, port 8001) and the MCP server (this file)
    run as two separate Python processes. Each process owns its own
    ``app_state`` instance even though both import from ``state``, so when
    the web UI opens a case only its own process's ``_connectors`` is
    populated. Cross-process sync lives entirely in ``.active_case.json``:
    the web UI writes it via ``_write_active_case``, and MCP reads it here.

    ``_get_axiom`` already triggered rehydration when analysts went through
    a single-active-case path, but cross-case tools (case_health,
    coverage_explainer, investigation_gap_report, pivot_across_cases,
    compare_cases, save_case_snapshot, ...) read ``_connectors`` directly
    and therefore would silently see an empty dict. Calling this helper at
    the top of those tools closes the gap.

    Idempotent: early-exits when at least one connected ``axiom:*`` case
    already sits in ``_connectors``.
    """
    has_loaded = any(
        name.startswith("axiom:") and getattr(c, "is_connected", lambda: False)()
        for name, c in _connectors.items()
    )
    if has_loaded:
        return
    state_file = os.path.join(os.path.dirname(__file__), ".active_case.json")
    if not os.path.exists(state_file):
        return
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            info = json.load(f)
    except Exception:
        return
    all_cases = info.get("all_cases", [])
    targets = [
        (case.get("path", ""), case.get("case_id", ""))
        for case in all_cases
        if case.get("path") and os.path.exists(case.get("path", ""))
    ]
    if targets:
        # Parse each case in parallel — KAPE directories can each take tens
        # of seconds, so a sequential load blocks the first MCP tool call
        # for N × (per-case time) on multi-case projects.
        from concurrent.futures import ThreadPoolExecutor
        primary_path = info.get("path", "")
        last_c = None
        primary_c = None
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
            futures = {
                ex.submit(_load_case_from_path, p, cid): (p, cid)
                for p, cid in targets
            }
            for fut in futures:
                p, _cid = futures[fut]
                try:
                    loaded = fut.result()
                except Exception:
                    continue
                last_c = loaded
                if p == primary_path:
                    primary_c = loaded
        chosen = primary_c or last_c
        if chosen and "axiom" not in _connectors:
            _connectors["axiom"] = chosen
        return
    # Fallback: single-path info (older layouts).
    path = info.get("path", "")
    if path and os.path.exists(path):
        try:
            c = _load_case_from_path(path)
            _connectors["axiom"] = c
        except Exception:
            pass


def _get_axiom() -> AxiomMfdbConnector:
    c = _connectors.get("axiom")
    if c and c.is_connected():
        return c
    _ensure_cases_hydrated()
    c = _connectors.get("axiom")
    if c and c.is_connected():
        return c
    raise RuntimeError("케이스가 열려있지 않습니다. open_case를 먼저 실행하세요.")


# ── Masking Tools ──

def _get_raw_index():
    c = _connectors.get("raw_index")
    if c and c.is_connected():
        return c
    return None


def _parsed_case_loaded() -> bool:
    return any(
        (name == "axiom" or name.startswith("axiom:"))
        and getattr(connector, "is_connected", lambda: False)()
        for name, connector in _connectors.items()
    )


@mcp.tool()
async def enable_masking(hostnames: str = "", usernames: str = "", custom_values: str = "") -> dict:
    """Enable data masking for sensitive values."""
    _masker.enable()
    for h in (h.strip() for h in hostnames.split(",") if h.strip()):
        _masker.add_sensitive_value(h, "HOST")
    for u in (u.strip() for u in usernames.split(",") if u.strip()):
        _masker.add_sensitive_value(u, "USER")
    for v in (v.strip() for v in custom_values.split(",") if v.strip()):
        _masker.add_sensitive_value(v, "CUSTOM")
    return {"status": "masking enabled", **_masker.get_stats()}


@mcp.tool()
async def disable_masking() -> dict:
    """Disable data masking."""
    _masker.disable()
    return {"status": "masking disabled"}


@mcp.tool()
async def set_timezone(tz_name: str = "KST", utc_offset_hours: int = 9) -> dict:
    """Set local timezone for timestamp display.

    All tool outputs will show timestamps as 'UTC_time (local_time TZ)'.
    Default: KST (UTC+9). Set utc_offset_hours=0 to disable.

    Examples:
        set_timezone("KST", 9)   → '2026-03-03 01:14:44 UTC (10:14:44 KST)'
        set_timezone("JST", 9)   → '2026-03-03 01:14:44 UTC (10:14:44 JST)'
        set_timezone("EST", -5)  → '2026-03-03 01:14:44 UTC (2026-03-02 20:14:44 EST)'
        set_timezone("UTC", 0)   → disables local time annotation
    """
    _tz_config["local_tz_name"] = tz_name
    _tz_config["local_tz_offset_hours"] = utc_offset_hours
    _tz_config["enabled"] = utc_offset_hours != 0
    return {
        "status": "timezone set" if _tz_config["enabled"] else "local timezone disabled",
        "display_timezone": tz_name,
        "utc_offset": f"UTC{utc_offset_hours:+d}" if utc_offset_hours else "UTC",
        "example": _add_local_tz("2026-03-03 01:14:44.306") if _tz_config["enabled"] else "2026-03-03 01:14:44.306",
    }


# ── Case Tools ──

# Timeout profiles (seconds). Tune per-deployment via environment variables:
#   FW_TIMEOUT_LIGHT   — metadata lookups, cached Ghidra queries
#   FW_TIMEOUT_MEDIUM  — Volatility plugins, search, IOC extraction, reports
#   FW_TIMEOUT_HEAVY   — timeline, correlate, find_suspicious, auto_triage
TIMEOUT_LIGHT = int(os.environ.get("FW_TIMEOUT_LIGHT", "120"))
TIMEOUT_MEDIUM = int(os.environ.get("FW_TIMEOUT_MEDIUM", "600"))
TIMEOUT_HEAVY = int(os.environ.get("FW_TIMEOUT_HEAVY", "1200"))


async def _traced(tool_name: str, params: dict, fn, timeout_seconds: int = TIMEOUT_MEDIUM):
    """Run a tool function with full request/response event logging.

    Post-processing pipeline: fn() → _mask() → _localize_timestamps()
    The localization step annotates UTC timestamps with local timezone.
    Heavy operations run in a thread pool to avoid blocking the async event
    loop, with a per-tool timeout drawn from the LIGHT/MEDIUM/HEAVY profiles.
    """
    import time as _time
    import asyncio
    _log_event("request", tool_name, params=params)
    t0 = _time.time()
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, fn),
            timeout=timeout_seconds
        )
        result = _localize_timestamps(result)
        result = _attach_dependency_status(result, tool_name=tool_name)
        result = _attach_runtime_warning(result, tool_name=tool_name)
        elapsed = _time.time() - t0
        _log_event("response", tool_name, result=result, duration=elapsed)
        return result
    except asyncio.TimeoutError:
        elapsed = _time.time() - t0
        _log_event("error", tool_name,
                   data={"error": f"Operation timed out after {timeout_seconds}s"},
                   duration=elapsed)
        return {"error": f"{tool_name} timed out after {timeout_seconds}s. "
                f"Override via FW_TIMEOUT_LIGHT/MEDIUM/HEAVY env vars if the "
                f"dataset legitimately needs more time."}
    except Exception as e:
        elapsed = _time.time() - t0
        error_payload: dict[str, Any] = {"error": str(e)}
        diagnostic = diagnose_exception(e)
        if diagnostic:
            error_payload["dependency_diagnostic"] = diagnostic
            error_payload["analysis_blockers"] = [
                f"{tool_name} could not complete because {diagnostic['dependency']['display_name']} "
                f"is not available. Recovery: {diagnostic['recovery']}"
            ]
        try:
            guidance = _selected_evidence_guidance()
            if guidance.get("evidence_mode") != "no_selected_evidence":
                error_payload["selected_evidence_guidance"] = guidance
        except Exception:
            pass
        _log_event("error", tool_name, data=error_payload, duration=elapsed)
        return error_payload


@mcp.tool()
async def open_case(path: str, case_name: str = "") -> dict:
    """Open an AXIOM case (.mfdb) file or KAPE output directory."""
    def fn():
        if not is_path_allowed(path):
            return {
                "ok": False,
                "error": build_not_allowed_message(path),
                "guardrail": {
                    "reason": "path_not_in_user_selected_allowlist",
                    "blocked_path": path,
                    "selected_evidence_guidance": _selected_evidence_guidance(),
                },
            }
        _connectors.pop("axiom", None)
        if os.path.isdir(path):
            c = KapeCsvConnector()
        elif path.lower().endswith(".mfdb"):
            c = AxiomMfdbConnector()
        else:
            return {"error": f"Unsupported format. Provide .mfdb file or KAPE output directory: {path}"}
        meta = c.connect(path)
        if case_name:
            meta["case_name"] = case_name
        # Register under BOTH keys:
        #   - "axiom"              : active-case alias (_get_axiom resolves this)
        #   - "axiom:{case_id}"    : iteration prefix used by iter_axiom_cases,
        #                             case_health, coverage_explainer, pivots,
        #                             investigation_gap_report, etc.
        # Prior bug: only "axiom" was set, so every multi-case aggregator and
        # every check driven by iter_axiom_cases silently saw zero cases.
        resolved_case_id = (
            case_name
            or meta.get("case_number")
            or meta.get("case_name")
            or os.path.basename(os.path.dirname(path) if not os.path.isdir(path) else path)
        )
        _connectors["axiom"] = c
        _connectors[f"axiom:{resolved_case_id}"] = c
        return _mask({"status": "success", **meta})
    return await _traced("open_case", {"path": path, "case_name": case_name}, fn)


@mcp.tool()
async def open_raw_index(path: str) -> dict:
    """Open a raw image sidecar index as the active raw-index connector.

    Reading guide for AI consumers:
    - This opens an existing sidecar index, not the raw image itself.
    - Stale or mismatched sidecars must be treated as not_evaluable until rebuilt.
    - AXIOM/KAPE parity references should remain available during migration.
    """
    def fn():
        from core.connectors.raw_image_index import RawImageIndexConnector

        c = RawImageIndexConnector()
        meta = c.connect(path)
        app_state.set("raw_index", c)
        return meta

    return await _traced(
        "open_raw_index",
        {"path": path},
        fn,
        timeout_seconds=TIMEOUT_LIGHT,
    )


def _disconnect_raw_index_for_path(db_path: str) -> None:
    raw = _connectors.get("raw_index")
    if not raw:
        return
    try:
        source_path = str(raw.get_metadata().get("source_path") or "")
    except Exception:
        source_path = ""
    if os.path.normcase(os.path.abspath(source_path)) != os.path.normcase(
        os.path.abspath(db_path)
    ):
        return
    try:
        raw.disconnect()
    except Exception:
        pass
    if _connectors.get("raw_index") is raw:
        _connectors.pop("raw_index", None)


@mcp.tool()
async def build_raw_file_index(
    roots: str = "/c:",
    cache_root: str = "",
    force_rebuild: bool = False,
    started_at: str = "",
) -> dict:
    """Build/open a raw-image sidecar index from the mounted image file listing.

    Reading guide for AI consumers:
    - This indexes mounted-image file listings into a case-local sidecar SQLite DB.
    - Existing fingerprint-matched sidecars are reused for repeated search speed.
    - Stale/corrupt sidecars are rebuilt from the mounted image, not treated as zero.
    - AXIOM/KAPE references should remain available until parity is proven.
    """
    params = {
        "roots": roots,
        "cache_root": cache_root,
        "force_rebuild": force_rebuild,
    }

    def fn():
        from core.connectors.raw_image_index import RawImageIndexConnector
        from core.raw_index.file_indexer import index_file_listing
        from core.raw_index.store import RawIndexStore

        image = _connectors.get("e01")
        if not image or not image.is_connected():
            return {
                "ok": False,
                "status": "not_evaluable",
                "error": "No mounted image. Run mount_image first.",
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "missing_mounted_image",
                },
            }
        image_meta = image.get_metadata()
        fingerprint = _raw_image_index_fingerprint(image_meta)
        root_values = _parse_raw_index_roots(roots)
        missing_roots, available_roots = _raw_index_missing_volume_roots(
            root_values,
            image_meta,
        )
        if missing_roots:
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "fingerprint": fingerprint,
                "error": (
                    "Requested raw index roots are not present in mounted "
                    f"image volumes: {', '.join(missing_roots)}"
                ),
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_index_root_not_in_mounted_volumes",
                    "requested_roots": root_values,
                    "available_roots": available_roots,
                    "missing_roots": missing_roots,
                },
                "performance": {
                    "sidecar_reused": False,
                    "reindexed": False,
                },
            }
        db_path = _raw_index_db_path(fingerprint, root_values, cache_root)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        if os.path.exists(db_path) and force_rebuild:
            _disconnect_raw_index_for_path(db_path)
            try:
                os.remove(db_path)
            except OSError as exc:
                return {
                    "ok": False,
                    "status": "coverage_gap",
                    "error": f"Existing raw index could not be removed for force rebuild: {exc}",
                    "coverage_gap": {
                        "status": "coverage_gap",
                        "reason": "force_rebuild_sidecar_unremovable",
                    },
                }

        if os.path.exists(db_path) and not force_rebuild:
            try:
                connector = RawImageIndexConnector()
                meta = connector.connect(db_path, expected_fingerprint=fingerprint)
                coverage = connector.get_coverage()
                if (
                    coverage.get("status") == "not_evaluable"
                    or int(coverage.get("parser_runs", 0) or 0) == 0
                ):
                    connector.disconnect()
                    raise RuntimeError(
                        "Existing raw index has no evaluable parser run."
                    )
                app_state.set("raw_index", connector)
                return {
                    "ok": True,
                    "status": "opened_existing",
                    "source_type": meta["source_type"],
                    "db_path": db_path,
                    "fingerprint": fingerprint,
                    "artifact_type_counts": connector.get_artifact_type_counts(),
                    "coverage": coverage,
                    "performance": {
                        "sidecar_reused": True,
                        "reindexed": False,
                    },
                }
            except Exception as exc:
                try:
                    os.remove(db_path)
                except OSError:
                    return {
                        "ok": False,
                        "status": "coverage_gap",
                        "error": f"Existing raw index is stale/corrupt and could not be removed: {exc}",
                        "coverage_gap": {
                            "status": "coverage_gap",
                            "reason": "stale_sidecar_unremovable",
                        },
                    }

        store = RawIndexStore(db_path)
        store.open()
        try:
            with store.batch():
                store_conn = store._conn()
                store_conn.execute(
                    "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
                    ("raw_image_fingerprint", fingerprint),
                )
                store_conn.execute(
                    "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
                    ("index_roots", ",".join(root_values)),
                )
                store._commit(store_conn)
                result = index_file_listing(
                    image,
                    store,
                    roots=root_values,
                    started_at=started_at or datetime.now(timezone.utc).isoformat(),
                )
        finally:
            store.close()

        if not result.get("ok", True):
            coverage_gaps = result.get("coverage_gaps", [])
            first_gap = (
                coverage_gaps[0]
                if coverage_gaps and isinstance(coverage_gaps[0], dict)
                else {}
            )
            return {
                "ok": False,
                "status": str(result.get("status") or "not_evaluable"),
                "source_type": "raw_image_sidecar",
                "db_path": db_path,
                "fingerprint": fingerprint,
                "indexed_files": int(result.get("indexed_files", 0) or 0),
                "coverage_gaps": coverage_gaps,
                "error": str(
                    result.get("error")
                    or first_gap.get("error")
                    or "raw index was not evaluable"
                ),
                "performance": {
                    "sidecar_reused": False,
                    "reindexed": True,
                },
            }

        connector = RawImageIndexConnector()
        meta = connector.connect(db_path, expected_fingerprint=fingerprint)
        app_state.set("raw_index", connector)
        indexer_status = str(result.get("status") or "")
        return {
            "ok": True,
            "status": "indexed" if indexer_status == "completed" else indexer_status,
            "source_type": meta["source_type"],
            "db_path": db_path,
            "fingerprint": fingerprint,
            "indexed_files": int(result.get("indexed_files", 0)),
            "coverage_gaps": result.get("coverage_gaps", []),
            "coverage": connector.get_coverage(),
            "artifact_type_counts": connector.get_artifact_type_counts(),
            "performance": {
                "sidecar_reused": False,
                "reindexed": True,
            },
        }

    return await _traced(
        "build_raw_file_index",
        params,
        fn,
        timeout_seconds=TIMEOUT_HEAVY,
    )


def _parse_raw_index_roots(roots: str) -> list[str]:
    values = sorted(
        dict.fromkeys(
            _canonical_raw_index_root(item.strip())
            for item in str(roots or "").split(",")
            if item.strip()
        ),
        key=str.lower,
    )
    return values or ["/c:"]


def _raw_index_missing_volume_roots(
    root_values: list[str],
    image_meta: dict[str, Any],
) -> tuple[list[str], list[str]]:
    available_roots = sorted(
        dict.fromkeys(
            root
            for root in (
                _raw_index_drive_root(volume)
                for volume in image_meta.get("volumes", [])
            )
            if root
        ),
        key=str.lower,
    )
    if not available_roots:
        return [], []
    available = set(available_roots)
    missing = [
        root
        for root in root_values
        if (drive_root := _raw_index_drive_root(root)) and drive_root not in available
    ]
    return missing, available_roots


def _canonical_raw_index_root(root: str) -> str:
    value = root.rstrip("/\\")
    if len(value) == 2 and value[1] == ":":
        return f"/{value[0].lower()}:"
    if len(value) == 3 and value[0] == "/" and value[2] == ":":
        return f"/{value[1].lower()}:"
    return root


def _raw_index_drive_root(value: Any) -> str:
    text = str(value).strip().replace("\\", "/")
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        return f"/{text[0].lower()}:"
    if len(text) >= 3 and text[0] == "/" and text[2] == ":" and text[1].isalpha():
        return f"/{text[1].lower()}:"
    return ""


def _raw_image_index_fingerprint(image_meta: dict[str, Any]) -> str:
    material = json.dumps({
        "image_path": image_meta.get("image_path", ""),
        "hostname": image_meta.get("hostname", ""),
        "os_type": image_meta.get("os_type", ""),
        "volumes": image_meta.get("volumes", []),
        "fallback_filesystems": image_meta.get("fallback_filesystems", []),
    }, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _raw_index_db_path(
    fingerprint: str,
    roots: list[str] | None = None,
    cache_root: str = "",
) -> str:
    root = cache_root or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "export",
        "cache",
        "raw_index",
    )
    roots_material = ",".join(roots or ["/c:"])
    roots_hash = hashlib.sha256(roots_material.encode("utf-8")).hexdigest()[:16]
    return os.path.join(root, fingerprint, f"files-{roots_hash}.sqlite")


@mcp.tool()
async def server_runtime_info() -> dict:
    """Show MCP server runtime/version state for stale-session diagnostics."""
    return await _traced("server_runtime_info", {}, lambda: _runtime_status(), timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def dependency_health() -> dict:
    """Report installed/missing analysis dependencies and blocked capabilities."""
    return await _traced("dependency_health", {}, dependency_report, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def get_evidence_context() -> dict:
    """Show selected evidence, mounted image state, and the required next source action."""
    return await _traced(
        "get_evidence_context",
        {},
        lambda: _mask(_selected_evidence_guidance()),
        timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def get_summary() -> dict:
    """Get case overview."""
    def fn():
        if not _parsed_case_loaded():
            guidance = _selected_evidence_guidance()
            if guidance.get("evidence_mode") != "no_selected_evidence":
                return _mask({
                    "ok": True,
                    "mode": guidance.get("evidence_mode"),
                    "summary_scope": "selected_evidence_context",
                    "parsed_case_loaded": False,
                    "message": (
                        "No parsed AXIOM/KAPE case is loaded, but user-selected "
                        "evidence exists. Follow next_required_action instead of "
                        "searching the workspace for another case."
                    ),
                    "selected_evidence_guidance": guidance,
                })
        return _mask(_get_axiom().get_metadata())
    return await _traced("get_summary", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def get_artifact_types() -> dict:
    """List artifact types with counts."""
    def fn():
        raw = _get_raw_index()
        if raw:
            types = raw.get_artifact_type_counts()
            return _mask({
                "source_type": "raw_image_sidecar",
                "artifact_types": types,
                "total_types": len(types),
            })
        types = _get_axiom().get_artifact_type_counts()
        return _mask({"artifact_types": types, "total_types": len(types)})
    return await _traced("get_artifact_types", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def pivot_across_cases(
    entity_type: str,
    entity_value: str,
    window_minutes: int = 60,
    limit_per_case: int = 100,
    match_key: str = "raw",
) -> dict:
    """Pivot on an entity across every loaded case.

    Args:
        entity_type: One of ``hash``, ``ip``, ``username``, ``filename``,
            ``path``, ``keyword``. Hash goes through search_by_hash; the rest
            fall back to keyword search.
        entity_value: The value to pivot on.
        window_minutes: Reserved for future temporal clustering; v1 returns
            raw merged hits.
        limit_per_case: Max hits to pull from each case before merging.
        match_key: Normalization mode for result comparison.
            - ``raw`` (default): no normalization; pure string match from
              the connector side. Safest.
            - ``strict``: Tier-1 cosmetic normalization only (case +
              whitespace); does NOT collapse DOMAIN / realm / FQDN labels.
            - ``loose``: Tier-2 aggressive canonicalization (user_bare,
              host_first_label, path_basename). CAN collapse distinct
              identities (e.g. svc@a.local and svc@b.local become the
              same); each affected hit carries an explicit warning string.

    Returns per-case counts, merged hits with full provenance, and
    first/last-seen markers so you can see which case carried the entity
    first and how it propagated. Fully offline.
    """
    def fn():
        from state import app_state
        from core.analysis.case_aggregator import pivot_across_cases as _pivot
        _ensure_cases_hydrated()
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(_pivot(
            axiom_conns, entity_type, entity_value,
            window_minutes=window_minutes, limit_per_case=limit_per_case,
            match_key=match_key,
        ))
    return await _traced(
        "pivot_across_cases",
        {"entity_type": entity_type, "entity_value": entity_value[:100],
         "limit_per_case": limit_per_case, "match_key": match_key},
        fn,
        timeout_seconds=TIMEOUT_MEDIUM,
    )


@mcp.tool()
async def compare_cases() -> dict:
    """Compare every loaded case side by side — metadata plus artifact-count matrix.

    Produces a family × case table showing how many records each loaded case
    contributes per artifact family. Partial failures are reported per case;
    one disconnected case never fails the whole call. Fully offline — reads
    only from already-loaded connectors.
    """
    def fn():
        from state import app_state
        from core.analysis.case_aggregator import compare_cases as _compare
        _ensure_cases_hydrated()
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(_compare(axiom_conns))
    return await _traced("compare_cases", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def explain_zero_results(
    tool_name: str,
    params_json: str = "{}",
) -> dict:
    """Diagnose why a query returned zero rows and suggest follow-up queries.

    Use this immediately whenever search_artifacts / build_timeline /
    find_suspicious / pivot_across_cases returns an empty result set — the
    response enumerates observable reasons (structural gap, date range outside
    case window, stacked filters, no cases loaded) and proposes concrete
    retries. Never concludes "no activity"; that's always the analyst's call
    after seeing the raw evidence.

    Args:
        tool_name: The tool that just returned zero rows (e.g. "search_artifacts").
        params_json: JSON string of the params that produced the empty response.
                     Example: '{"keyword": "admin", "artifact_type": "Prefetch"}'.
    """
    def fn():
        import json as _json
        try:
            params = _json.loads(params_json) if params_json else {}
        except Exception:
            return {"error": f"params_json must be valid JSON, got: {params_json[:120]}"}
        from state import app_state
        from core.analysis.zero_results import explain_zero_results as _explain
        _ensure_cases_hydrated()
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(_explain(axiom_conns, tool_name=tool_name, params=params))
    return await _traced(
        "explain_zero_results",
        {"tool_name": tool_name, "params_json": params_json[:200]},
        fn,
        timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def coverage_explainer(artifact_types: str = "") -> dict:
    """Report which artifact families are searchable vs structurally unavailable.

    Use this before concluding "0 results = no activity". Distinguishes:
      - searched                : loaded cases hold records for this family.
      - available_not_loaded    : family is supported by the current case
                                  format but has zero records (could be genuine
                                  absence or a parser miss — verify raw evidence).
      - structurally_unavailable: the current case format cannot expose this
                                  family at all (e.g. AXIOM-only carving on a
                                  KAPE-only case). Absence here is NOT evidence
                                  of absence in reality.

    Args:
        artifact_types: Optional comma-separated names to narrow the report
                        (e.g. "Prefetch Files - Windows 8/10/11,SRUM Network Usage").
                        Omit to list every loaded family plus the AXIOM-only
                        families that would be invisible under KAPE.
    """
    def fn():
        from state import app_state
        from core.analysis.coverage import build_coverage_report
        _ensure_cases_hydrated()
        requested = [a.strip() for a in artifact_types.split(",") if a.strip()] if artifact_types else None
        # Pass only the axiom:* connectors — coverage never touches E01/Vol/Ghidra.
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        report = build_coverage_report(axiom_conns, artifact_types=requested)
        return _mask(_attach_selected_evidence_guidance(report))
    return await _traced("coverage_explainer", {"artifact_types": artifact_types}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def search_artifacts(
    keyword: str = "",
    keywords: str = "",
    artifact_type: str = "",
    start_date: str = "",
    end_date: str = "",
    fields: str = "",
    limit: int = 50,
    offset: int = 0,
    all_cases: bool = False,
) -> dict:
    """Search artifacts by keyword, type, date range.

    Args:
        keyword: Single keyword to search.
        keywords: Comma-separated keywords for OR search (e.g. "SearchHost,task.vbs,sshd").
                  Results matching ANY keyword are returned.
        artifact_type: Filter by artifact type name.
        start_date: Start date filter (ISO format).
        end_date: End date filter (ISO format).
        fields: Comma-separated field names to include in output (reduces size).
                e.g. "Name,Full Path,Application Name". Empty = all fields.
        limit: Max results (default 50, max 200).
        offset: Pagination offset.
        all_cases: When True, fan out the search across every loaded case and
                   return merged hits with per-case provenance
                   (case_id / source_type / source_path on every hit). When
                   False (default), only the active case is searched.
    """
    params = {"keyword": keyword, "keywords": keywords, "artifact_type": artifact_type,
              "start_date": start_date, "end_date": end_date, "fields": fields, "limit": limit, "offset": offset,
              "all_cases": all_cases}
    def fn():
        if all_cases:
            from state import app_state
            from core.analysis.case_aggregator import search_across_cases
            _ensure_cases_hydrated()
            axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
            cap = min(limit, config.search_max_limit)
            return _mask(search_across_cases(
                axiom_conns,
                keyword=keyword or (keywords.split(",")[0].strip() if keywords else ""),
                artifact_type=artifact_type, start_date=start_date, end_date=end_date,
                limit_per_case=cap, global_limit=cap, global_offset=offset,
            ))
        cap = min(limit, config.search_max_limit)
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords.strip() else []
        raw = _get_raw_index()
        if raw:
            field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields.strip() else []
            if kw_list:
                result = raw.search(
                    keyword="",
                    filters={
                        "artifact_type": artifact_type,
                        "start_date": start_date,
                        "end_date": end_date,
                        "keywords": kw_list,
                    },
                    limit=cap,
                    offset=offset,
                )
                page = result.get("hits", [])
                if field_list:
                    for hit in page:
                        if "fields" in hit:
                            hit["fields"] = {k: v for k, v in hit["fields"].items() if k in field_list}
                result = dict(result)
                result["source_type"] = "raw_image_sidecar"
                result["union_returned"] = result.get("total", result.get("returned", 0))
                return _mask(result)

            result = raw.search(
                keyword=keyword,
                filters={
                    "artifact_type": artifact_type,
                    "start_date": start_date,
                    "end_date": end_date,
                },
                limit=cap,
                offset=offset,
            )
            page = result.get("hits", [])
            if field_list:
                for hit in page:
                    if "fields" in hit:
                        hit["fields"] = {k: v for k, v in hit["fields"].items() if k in field_list}
            result = dict(result)
            result["source_type"] = "raw_image_sidecar"
            return _mask(result)

        axiom = _get_axiom()

        if kw_list:
            # Multi-keyword OR search: union results from each keyword
            all_hits = {}
            per_keyword_totals = {}
            for kw in kw_list:
                result = axiom.search(
                    keyword=kw,
                    filters={"artifact_type": artifact_type, "start_date": start_date, "end_date": end_date},
                    limit=cap,
                    offset=0,
                )
                per_keyword_totals[kw] = result.get("total", result.get("total_estimated", 0))
                for h in result.get("hits", []):
                    hid = h.get("hit_id")
                    if hid not in all_hits:
                        all_hits[hid] = h
                        all_hits[hid]["_matched_keyword"] = kw
            merged = sorted(all_hits.values(), key=lambda h: h.get("hit_id", 0))
            page = merged[offset:offset + cap]
            # Total is sum of per-keyword true totals (may overcount due to overlap)
            total = sum(per_keyword_totals.values())
            union_returned = len(all_hits)
        else:
            result = axiom.search(
                keyword=keyword,
                filters={"artifact_type": artifact_type, "start_date": start_date, "end_date": end_date},
                limit=cap, offset=offset,
            )
            page = result.get("hits", [])
            total = result.get("total", result.get("total_estimated", len(page)))
            per_keyword_totals = {}
            union_returned = None

        # Field projection
        field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields.strip() else []
        if field_list:
            for hit in page:
                if "fields" in hit:
                    hit["fields"] = {k: v for k, v in hit["fields"].items() if k in field_list}

        resp: dict = {
            "total_estimated": total,
            "returned": len(page),
            "truncated": total > offset + len(page),
            "hits": page,
        }
        if per_keyword_totals:
            resp["per_keyword_totals"] = per_keyword_totals
            resp["union_returned"] = union_returned
        return _mask(resp)
    return await _traced("search_artifacts", params, fn)


@mcp.tool()
async def get_hit_detail(hit_id: int) -> dict:
    """Get full detail for a specific artifact hit."""
    def fn():
        raw = _get_raw_index()
        if raw:
            detail = raw.get_hit_detail(hit_id)
            if isinstance(detail, dict):
                detail = dict(detail)
                detail["source_type"] = "raw_image_sidecar"
            return _mask(detail)
        return _mask(_get_axiom().get_hit_detail(hit_id))
    return await _traced("get_hit_detail", {"hit_id": hit_id}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def build_timeline(
    start_date: str = "",
    end_date: str = "",
    artifact_types: str = "",
    keywords: str = "",
    limit: int = 200,
    offset: int = 0,
    all_cases: bool = False,
) -> dict:
    """Build chronological timeline.

    Args:
        start_date: Start date (ISO format).
        end_date: End date (ISO format).
        artifact_types: Comma-separated artifact types to include.
        keywords: Comma-separated keywords to filter timeline events.
                  Only events whose associated hits contain ANY of these keywords are included.
                  e.g. "SearchHost,sshd,task.vbs" to build a timeline around specific IOCs.
        limit: Max events (default 200, max 500).
        offset: Skip first N events (for pagination).
    """
    params = {"start_date": start_date, "end_date": end_date,
              "artifact_types": artifact_types, "keywords": keywords, "limit": limit, "offset": offset,
              "all_cases": all_cases}
    def fn():
        cap = min(limit, config.timeline_max_limit)
        type_list = [t.strip() for t in artifact_types.split(",") if t.strip()] if artifact_types else None
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords.strip() else []

        if all_cases:
            # Merged timeline across every loaded case. Keyword filtering in
            # this mode falls back to the per-case get_timeline engine (no
            # cross-case keyword join yet) — fine for the common "what
            # happened between date X and Y?" workflow.
            from state import app_state
            from core.analysis.case_aggregator import timeline_across_cases
            _ensure_cases_hydrated()
            axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
            return _mask(timeline_across_cases(
                axiom_conns,
                start_date=start_date, end_date=end_date,
                artifact_types=type_list,
                limit_per_case=cap, global_limit=cap, global_offset=offset,
            ))

        raw = _get_raw_index()
        if raw:
            result = raw.get_timeline(
                start_date,
                end_date,
                type_list,
                cap,
                offset,
                keywords=kw_list,
            )
            result = dict(result)
            result["source_type"] = "raw_image_sidecar"
            return _mask(result)

        axiom = _get_axiom()
        if kw_list:
            return _mask(_timeline_with_keywords(axiom, start_date, end_date, kw_list, cap, offset))
        else:
            return _mask(axiom.get_timeline(start_date, end_date, type_list, cap, offset))
    return await _traced("build_timeline", params, fn, timeout_seconds=TIMEOUT_HEAVY)


@mcp.tool()
async def date_anchor_triage(
    start_date: str = "",
    end_date: str = "",
    limit_per_query: int = 10,
) -> dict:
    """Surface high-value raw anchors for a narrow date window.

    This helper is intentionally deterministic and evidence-first. It does not
    assign intent or promote a narrative; it only groups raw anchors that are
    usually decisive in the first 5-10 minutes of triage:
    services/autoruns, suspicious file drops, execution traces, and
    browser/download artifacts.
    """
    params = {
        "start_date": start_date,
        "end_date": end_date,
        "limit_per_query": limit_per_query,
    }

    def fn():
        from core.analysis.date_anchor_triage import date_anchor_triage as _date_anchor_triage

        return _mask(_date_anchor_triage(
            _get_axiom(),
            start_date=start_date,
            end_date=end_date,
            limit_per_query=max(1, min(limit_per_query, 50)),
        ))

    return await _traced("date_anchor_triage", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def temporal_anchor_correlation(
    anchor_ts: str,
    anchor_label: str = "",
    anchor_entities: str = "",
    window_before_minutes: int = 30,
    window_after_minutes: int = 30,
    source_filter: str = "",
    limit_per_source: int = 50,
    anchor_timezone_offset_hours: int = 0,
) -> dict:
    """Correlate PF/WER/browser/timeline evidence around one analyst anchor.

    This is a hypothesis-building helper, not a verdict engine. It takes a
    timestamped anchor such as a browser-cache IOC and surfaces nearby Prefetch
    last-run slots, WER reports/temp files, browser cache/code-cache files,
    Crashpad files, and loaded-case timeline rows. Temporal proximity is always
    labelled as non-causal unless direct evidence is present.

    Args:
        anchor_ts: Anchor timestamp. Prefer ISO-8601 with timezone
                   (e.g. 2025-09-26T14:11:32+09:00). If no timezone is present,
                   anchor_timezone_offset_hours is applied.
        anchor_label: Human-readable anchor description.
        anchor_entities: Comma-separated tokens to match against nearby evidence
                         (e.g. winsystem.kr,module.js,whale).
        window_before_minutes: Minutes before anchor to inspect.
        window_after_minutes: Minutes after anchor to inspect.
        source_filter: Optional comma-separated subset:
                       prefetch,wer,browser_cache,crashpad,axiom_timeline.
        limit_per_source: Max events kept per source.
        anchor_timezone_offset_hours: Offset for naive anchor_ts values.
    """
    params = {
        "anchor_ts": anchor_ts,
        "anchor_label": anchor_label,
        "anchor_entities": anchor_entities,
        "window_before_minutes": window_before_minutes,
        "window_after_minutes": window_after_minutes,
        "source_filter": source_filter,
        "limit_per_source": limit_per_source,
        "anchor_timezone_offset_hours": anchor_timezone_offset_hours,
    }

    def fn():
        from core.analysis.temporal_anchor_correlation import temporal_anchor_correlation as _anchor_corr

        e01 = _connectors.get("e01")
        if e01 is not None and not e01.is_connected():
            e01 = None

        axiom = None
        try:
            axiom = _get_axiom()
        except Exception:
            axiom = None

        return _mask(_anchor_corr(
            anchor_ts=anchor_ts,
            anchor_label=anchor_label,
            anchor_entities=anchor_entities,
            e01_connector=e01,
            axiom_connector=axiom,
            window_before_minutes=window_before_minutes,
            window_after_minutes=window_after_minutes,
            source_filter=source_filter,
            limit_per_source=limit_per_source,
            anchor_timezone_offset_hours=anchor_timezone_offset_hours,
        ))

    return await _traced("temporal_anchor_correlation", params, fn, timeout_seconds=TIMEOUT_HEAVY)


@mcp.tool()
async def hypothesis_refutation_pack(
    scenario: str = "",
    hypotheses_json: str = "",
    anchor_correlation_json: str = "",
    findings_json: str = "",
    coverage_json: str = "",
) -> dict:
    """Build a refutation-first worklist from hypotheses/correlations.

    This tool forces verification questions and benign/unrelated alternatives;
    it never authorizes a strong incident conclusion. Use it after tools such
    as temporal_anchor_correlation, competing_hypotheses, find_suspicious, or
    coverage_explainer when an artifact combination is tempting to interpret as
    a causal chain.

    Args:
        scenario: Optional analyst-facing scenario label.
        hypotheses_json: JSON output from a competing-hypotheses payload.
        anchor_correlation_json: JSON output from temporal_anchor_correlation.
        findings_json: JSON output from find_suspicious or a compatible payload.
        coverage_json: JSON output from coverage_explainer or a compatible payload.

    Reading guide for AI consumers:
    - This is not a detector and not a verdict engine.
    - Treat hypotheses[].refutation_tasks as the next worklist.
    - strong_conclusion_allowed is intentionally false on every hypothesis.
    - Missing sources are gaps, not evidence that activity did not occur.
    - Proximity-only evidence must stay separate from token-linked evidence.
    """
    params = {
        "scenario": scenario,
        "hypotheses_json": hypotheses_json[:200],
        "anchor_correlation_json": anchor_correlation_json[:200],
        "findings_json": findings_json[:200],
        "coverage_json": coverage_json[:200],
    }

    def fn():
        from core.analysis.hypothesis_refutation import hypothesis_refutation_pack as _pack

        return _mask(_pack(
            scenario=scenario,
            hypotheses_payload=hypotheses_json,
            anchor_correlation_payload=anchor_correlation_json,
            findings_payload=findings_json,
            coverage_payload=coverage_json,
        ))

    return await _traced("hypothesis_refutation_pack", params, fn, timeout_seconds=TIMEOUT_LIGHT)


def _raw_image_triage_gate(system_hive_path: str = "/c:/Windows/System32/config/SYSTEM") -> dict[str, Any]:
    """Evidence-coverage gate for raw-image-only endpoint triage."""
    e01 = _get_e01()
    context = _evidence_context(system_hive_path, "mounted_image", internal_path=system_hive_path)
    evtx_paths = [
        "/c:/Windows/System32/winevt/Logs/System.evtx",
        "/c:/Windows/System32/winevt/Logs/Security.evtx",
        "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
        "/c:/Windows/System32/winevt/Logs/Windows PowerShell.evtx",
    ]
    evtx_sources = []
    for path in evtx_paths:
        info = e01.get_file_info(path)
        evtx_sources.append({
            "path": path,
            "status": "available" if "error" not in info else "missing_or_unreadable",
            "check_type": "file_presence_only",
            "parse_status": "not_checked",
            "size": info.get("size"),
            "error": info.get("error", ""),
        })

    try:
        prefetch_listing = e01.list_directory("/c:/Windows/Prefetch")
        prefetch_files = [
            item for item in prefetch_listing
            if not item.get("is_dir") and str(item.get("name", item.get("path", ""))).lower().endswith(".pf")
        ]
        prefetch_status = {
            "status": "available" if prefetch_files else "empty_or_unavailable",
            "pf_count_sampled": len(prefetch_files),
            "listing_errors": [item.get("error") for item in prefetch_listing if item.get("error")],
        }
    except Exception as e:
        prefetch_status = {"status": "error", "error": str(e)}

    service_gate = {"ok": False, "gate_status": "unavailable"}
    service_source = {"source": "mounted_image_system_hive", "status": "unavailable"}
    try:
        from core.analysis.service_persistence import (
            build_service_persistence_gate as _build_service_gate,
            services_from_system_hive as _services_from_system_hive,
        )
        hive_out = _evidence_bound_export_path("raw_image_triage_gate", system_hive_path, "SYSTEM.hive")
        extraction = e01.extract_file(system_hive_path, hive_out)
        hive_services, hive_meta = _services_from_system_hive(hive_out)
        service_gate = _build_service_gate(
            hive_services,
            limit=20,
            file_info_lookup=e01.get_file_info,
        )
        service_source = {
            "source": "mounted_image_system_hive",
            "status": "checked",
            "system_hive_path": system_hive_path,
            "extracted_to": extraction.get("output_path", hive_out),
            "sha256": extraction.get("sha256", ""),
            "metadata": hive_meta,
        }
    except Exception as e:
        service_source = {
            "source": "mounted_image_system_hive",
            "status": "error",
            "system_hive_path": system_hive_path,
            "error": str(e),
        }

    gaps = []
    if not any(item["status"] == "available" for item in evtx_sources):
        gaps.append("event_logs_unavailable")
    if prefetch_status.get("status") != "available":
        gaps.append("prefetch_unavailable_or_empty")
    if service_source.get("status") != "checked":
        gaps.append("system_hive_services_unchecked")

    coverage_status = "complete_for_gate" if not gaps else "degraded"
    return {
        "ok": True,
        "schema": "fw.raw_image_triage_gate.v1",
        "mode": "raw_image_gate",
        "coverage_status": coverage_status,
        "strong_conclusion_allowed": False,
        "verdict_authorized": False,
        "evidence_context": context,
        "coverage": {
            "parsed_case_required_for_full_auto_triage": True,
            "parsed_case_available": context["source_separation"]["parsed_case_available"],
            "evtx_sources": evtx_sources,
            "prefetch": prefetch_status,
            "service_registry_source": service_source,
            "gaps": gaps,
        },
        "service_persistence_gate": {
            "summary": service_gate.get("summary", {}),
            "gates": service_gate.get("gates", []),
            "candidates": service_gate.get("candidates", []),
            "source_conflicts": service_gate.get("source_conflicts", []),
            "zero_result_interpretation": service_gate.get("zero_result_interpretation", ""),
        },
        "analysis_limits": [
            "This raw-image gate checks source availability and selected high-value artifacts only.",
            "EVTX entries are not parsed in this gate; run query_evtx_file for parser status and event-level matches.",
            "A clean gate does not prove the host is clean.",
        ],
        "required_followups": [
            {
                "tool_name": "service_persistence_gate",
                "reason": "Registry state must be checked even when service-install EVTX is absent.",
                "params": {"include_mounted_image": True, "system_hive_path": system_hive_path},
            },
            {
                "tool_name": "query_evtx_file",
                "reason": "EVTX availability and parser failures must be separated from activity absence.",
                "params": {"evtx_path": "/c:/Windows/System32/winevt/Logs/System.evtx", "event_ids": "7045,104"},
            },
            {
                "tool_name": "query_prefetch_files",
                "reason": "Execution traces should be checked independently of EVTX.",
                "params": {"directory": "/c:/Windows/Prefetch"},
            },
            {
                "tool_name": "query_registry_hive",
                "reason": "Direct registry state can survive when event logs are missing or incomplete.",
                "params": {"hive_path": system_hive_path, "key_path": "\\ControlSet001\\Services"},
            },
        ],
        "reading_guide": [
            "This gate is coverage-first. It does not classify compromise.",
            "A missing EVTX source is a coverage gap, not evidence that a service was never installed.",
            "Service registry candidates are leads; verify payload files, timestamps, execution traces, and source consistency.",
        ],
    }


@mcp.tool()
async def initial_triage_pack(
    scope_mode: str = "recent_14d",
    start_date: str = "",
    end_date: str = "",
    suspected_date: str = "",
    top_window_count: int = 3,
    timeline_scan_limit: int = 1200,
    include_baseline_diff: bool = True,
    reference_case_id: str = "",
) -> dict:
    """Run a window-first initial triage pass before static delta review.

    This composition tool intentionally starts from scope, coverage, and
    incident-window discovery before it surfaces baseline-diff context. It is
    tuned for Windows endpoint IR and keeps incident typing conservative:
    unknown is preferred over a forced verdict.

    Args:
        scope_mode: One of recent_14d, suspected_date_pm_3d, full_range, custom.
        start_date / end_date: Explicit ISO dates for custom scope selection.
        suspected_date: Anchor date for suspected_date_pm_3d.
        top_window_count: Number of candidate windows to keep (max 5).
        timeline_scan_limit: Max timeline entries to sample during window discovery.
        include_baseline_diff: When True, delay baseline_diff into precursor_context.
        reference_case_id: Optional golden-image/reference case id for baseline diff.

    Reading guide for AI consumers:
        - applicability.primary_domain is "windows_endpoint_ir". If the case
          is cloud / supply-chain / network-device / physical, the output
          is a degraded hint. Weight accordingly.
        - precursor_context.status == "bridged_precursor" means shared token
          overlap, not causation. Do NOT assume the static-delta item
          actually participated in the incident without direct execution
          evidence.
        - anchoring_warnings is a live list of bias risks in this pass.
          Read it before concluding.
        - lane_evidence_summary shows artifact families seen per lane (facts only).
          Significance judgment is yours.
    """
    params = {
        "scope_mode": scope_mode,
        "start_date": start_date,
        "end_date": end_date,
        "suspected_date": suspected_date,
        "top_window_count": top_window_count,
        "timeline_scan_limit": timeline_scan_limit,
        "include_baseline_diff": include_baseline_diff,
        "reference_case_id": reference_case_id,
    }

    def fn():
        from state import app_state
        from core.analysis.initial_triage import initial_triage as _initial_triage

        ref_aq = None
        if reference_case_id.strip():
            key = f"axiom:{reference_case_id.strip()}"
            ref = app_state._connectors.get(key)
            if ref is None or not ref.is_connected():
                return {
                    "ok": False,
                    "error": f"Reference case not found or not connected: {reference_case_id}",
                }
            ref_aq = ref.artifact_queries

        try:
            axiom = _get_axiom()
        except Exception as e:
            try:
                fallback = _raw_image_triage_gate()
            except Exception as raw_e:
                return _mask({
                    "ok": False,
                    "error": str(e),
                    "raw_image_fallback_error": str(raw_e),
                    "analysis_blockers": [
                        "No parsed case is loaded, and raw image triage could not run.",
                    ],
                })
            fallback["mode"] = "raw_image_fallback_for_initial_triage"
            fallback["parsed_case_error"] = str(e)
            fallback["analysis_blockers"] = [
                "Full initial_triage_pack requires a parsed AXIOM/KAPE case.",
                "Raw-image fallback ran coverage gates only; do not treat this as full automated triage.",
            ]
            return _mask(fallback)
        result = _initial_triage(
            axiom,
            scope_mode=scope_mode,
            start_date=start_date,
            end_date=end_date,
            suspected_date=suspected_date,
            top_window_count=max(1, min(top_window_count, 5)),
            timeline_scan_limit=max(200, min(timeline_scan_limit, 4000)),
            include_baseline_diff=include_baseline_diff,
            reference_aq=ref_aq,
        )
        try:
            from core.analysis.service_persistence import (
                build_service_persistence_gate as _build_service_gate,
                services_from_artifact_rows as _services_from_artifact_rows,
            )
            rows = axiom.artifact_queries.query_services(limit=0) or []
            gate = _build_service_gate(
                _services_from_artifact_rows(rows),
                limit=20,
            )
            result["service_persistence_gate"] = {
                "status": "summary_only",
                "summary": gate.get("summary", {}),
                "gates": gate.get("gates", []),
                "drilldown": {
                    "tool_name": "service_persistence_gate",
                    "params": {"limit": 50},
                    "reason": (
                        "Full service candidates are intentionally omitted from initial_triage "
                        "to reduce anchoring. Run the gate explicitly for service persistence review."
                    ),
                },
            }
        except Exception as e:
            result["service_persistence_gate"] = {
                "ok": False,
                "error": str(e),
                "gate_status": "unavailable",
            }
        return _mask(result)

    return await _traced("initial_triage_pack", params, fn, timeout_seconds=TIMEOUT_HEAVY)


@mcp.tool()
async def raw_image_triage_gate(
    system_hive_path: str = "/c:/Windows/System32/config/SYSTEM",
) -> dict:
    """Run coverage-first triage gates when only a raw disk image is loaded.

    This tool is intentionally narrower than initial_triage_pack. It checks
    whether high-value raw sources are present and forces service-registry
    review from the SYSTEM hive so EVTX absence is not mistaken for absence of
    persistence.

    Args:
        system_hive_path: Mounted-image internal path to the SYSTEM hive.

    Reading guide for AI consumers:
        - This is not a compromise detector and not a replacement for a parsed
          AXIOM/KAPE case.
        - Use gaps[] and required_followups[] as a worklist before finalizing a
          timeline from raw-image evidence.
        - A missing EVTX source is a coverage gap, not negative evidence.
    """
    return await _traced(
        "raw_image_triage_gate",
        {"system_hive_path": system_hive_path},
        lambda: _mask(_raw_image_triage_gate(system_hive_path)),
        timeout_seconds=TIMEOUT_MEDIUM,
    )


@mcp.tool()
async def slice_timeline(
    start_date: str = "",
    end_date: str = "",
    artifact_types: str = "",
    user: str = "",
    process: str = "",
    host: str = "",
    path: str = "",
    keywords: str = "",
    limit: int = 200,
    offset: int = 0,
    all_cases: bool = False,
    snapshot_slug: str = "",
    bucket_name: str = "",
) -> dict:
    """Build a timeline and then filter it by user / process / host / path.

    Runs ``build_timeline`` under the hood (same date/type/keyword contract),
    then post-filters the resulting events with case-insensitive substring
    matches across every visible field. Use this when you need a targeted
    narrative — e.g. "what did user Administrator do between X and Y?" or
    "show events involving powershell.exe" — without loading the full
    timeline and filtering mentally.

    Args:
        start_date / end_date / artifact_types / keywords / limit / offset /
            all_cases: identical to build_timeline.
        user: substring to require in each event (e.g. "Administrator").
        process: substring for the process/executable (e.g. "powershell").
        host: substring for the computer/host name.
        path: substring matched against file paths and descriptions.
        snapshot_slug + bucket_name: Optional bucket filter. When both are
            set the call resolves the bucket's hit_ids from the named
            snapshot and keeps only timeline entries whose hit_id is in
            that set. A typo in either value hard-errors with the list of
            valid buckets — never a silent empty result.

    Returns the usual timeline payload plus a ``slice`` block describing which
    filters ran and how much each one removed.
    """
    params = {
        "start_date": start_date, "end_date": end_date,
        "artifact_types": artifact_types, "keywords": keywords,
        "limit": limit, "offset": offset, "all_cases": all_cases,
        "user": user, "process": process, "host": host, "path": path,
        "snapshot_slug": snapshot_slug, "bucket_name": bucket_name,
    }

    def fn():
        from core.analysis.timeline_slice import slice_entries

        # Bucket selector resolution first — fail fast on typos.
        bucket_hit_ids: set[int] | None = None
        bucket_info: dict | None = None
        if snapshot_slug or bucket_name:
            if not (snapshot_slug and bucket_name):
                return {"ok": False, "error": "snapshot_slug and bucket_name must be provided together"}
            from core.analysis.case_snapshot import (
                resolve_bucket_hit_ids, BucketNotFoundError, SnapshotNotFoundError,
            )
            try:
                bucket_hit_ids = resolve_bucket_hit_ids(snapshot_slug, bucket_name)
                bucket_info = {"snapshot_slug": snapshot_slug, "bucket": bucket_name,
                               "hit_count": len(bucket_hit_ids)}
            except (BucketNotFoundError, SnapshotNotFoundError) as e:
                return {"ok": False, "error": str(e)}

        cap = min(limit, config.timeline_max_limit)
        type_list = [t.strip() for t in artifact_types.split(",") if t.strip()] if artifact_types else None
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords.strip() else []

        # Pull enough events to survive slicing — we deliberately over-fetch per
        # case so the post-filter has substrate, then trim back to `cap` after.
        overfetch_cap = min(cap * 4, config.timeline_max_limit)

        if all_cases:
            from state import app_state
            from core.analysis.case_aggregator import timeline_across_cases
            _ensure_cases_hydrated()
            axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
            base = timeline_across_cases(
                axiom_conns, start_date=start_date, end_date=end_date,
                artifact_types=type_list,
                limit_per_case=overfetch_cap, global_limit=overfetch_cap, global_offset=0,
            )
            raw_entries = base.get("entries", []) or []
        else:
            axiom = _get_axiom()
            if kw_list:
                base = _timeline_with_keywords(axiom, start_date, end_date, kw_list, overfetch_cap, 0)
            else:
                base = axiom.get_timeline(start_date, end_date, type_list, overfetch_cap, 0)
            raw_entries = base.get("entries", []) or []

        # Apply bucket filter BEFORE substring slicing so we never pretend
        # an empty bucket is a user typo.
        if bucket_hit_ids is not None:
            raw_entries = [e for e in raw_entries if e.get("hit_id") in bucket_hit_ids]

        filtered, slice_meta = slice_entries(
            raw_entries, user=user, process=process, host=host, path=path,
        )
        if bucket_info is not None:
            slice_meta["bucket"] = bucket_info
        sliced = filtered[offset : offset + cap]

        return _mask({
            **({"per_case": base.get("per_case")} if isinstance(base, dict) and "per_case" in base else {}),
            "entries": sliced,
            "total_events": len(filtered),
            "returned": len(sliced),
            "truncated": len(filtered) > offset + len(sliced),
            "slice": slice_meta,
            "keywords_used": kw_list,
            "all_cases": all_cases,
            "warnings": base.get("warnings", []) if isinstance(base, dict) else [],
        })

    return await _traced("slice_timeline", params, fn, timeout_seconds=TIMEOUT_HEAVY)


def _timeline_with_keywords(axiom, start_date, end_date, kw_list, limit, offset=0):
    """Build timeline filtered by keywords — finds events associated with matching hits."""
    from core.sql import axiom_queries as Q

    cur = axiom._cursor()
    start_ms = axiom._iso_to_ms(start_date) if start_date else 0
    end_ms = axiom._iso_to_ms(end_date) if end_date else 9999999999999

    conditions = " OR ".join(["hfs.value LIKE ?"] * len(kw_list))
    query = Q.TIMELINE_WITH_KEYWORD.format(keyword_conditions=conditions)
    # Replace LIMIT with LIMIT+OFFSET for pagination
    query = query.replace("LIMIT ?", "LIMIT ? OFFSET ?")
    params = [start_ms, end_ms] + [f"%{kw}%" for kw in kw_list] + [limit, offset]
    cur.execute(query, params)
    rows = cur.fetchall()

    if not rows:
        return {"total_events": 0, "returned": 0, "entries": [],
                "keywords_used": kw_list}

    seen_hits = {}
    for row in rows:
        hid = row["hit_id"]
        if hid not in seen_hits:
            seen_hits[hid] = {
                "hit_id": hid,
                "timestamp_ms": row["unix_timestamp_ms"],
                "timestamp": row["formatted_value"],
                "time_field": row["time_field"],
            }

    unique_ids = list(seen_hits.keys())
    if unique_ids:
        hydrated = {h["hit_id"]: h for h in axiom._hydrate_hits(unique_ids)}
        for entry in seen_hits.values():
            hdata = hydrated.get(entry["hit_id"], {})
            entry["artifact_type"] = hdata.get("artifact_type", "")
            entry["description"] = axiom._build_description(hdata)

    result = sorted(seen_hits.values(), key=lambda e: e.get("timestamp_ms", 0))

    # True total count (without LIMIT)
    count_conditions = " OR ".join(["hfs.value LIKE ?"] * len(kw_list))
    count_query = (
        f"SELECT COUNT(DISTINCT hfd.hit_id) "
        f"FROM hit_fragment_date hfd "
        f"JOIN hit_fragment_string hfs ON hfd.hit_id = hfs.hit_id "
        f"WHERE hfd.unix_timestamp_ms BETWEEN ? AND ? "
        f"AND ({count_conditions})"
    )
    count_params = [start_ms, end_ms] + [f"%{kw}%" for kw in kw_list]
    cur.execute(count_query, count_params)
    true_total = cur.fetchone()[0]

    return {
        "total_events": true_total,
        "returned": len(result),
        "truncated": true_total > len(result),
        "keywords_used": kw_list,
        "entries": result,
    }


@mcp.tool()
async def extract_iocs(ioc_types: str = "", exclude_private_ips: bool = True, exclude_known_good: bool = True) -> dict:
    """Extract IOCs from case data."""
    params = {"ioc_types": ioc_types, "exclude_private_ips": exclude_private_ips}
    def fn():
        from core.analysis.ioc_extractor import extract_iocs as _extract
        return _mask(_extract(_get_axiom(), ioc_types, exclude_private_ips, exclude_known_good))
    return await _traced("extract_iocs", params, fn)


# Registry of callables a hunt pack is allowed to invoke. Kept explicit so
# the authoring surface is auditable — pack steps cannot reach beyond the
# tools named here.
_HUNT_PACK_DISPATCH: dict[str, Callable[..., Any]] = {}


def _register_hunt_tool(name: str, fn: Callable[..., Any]) -> None:
    _HUNT_PACK_DISPATCH[name] = fn


def _coerce_pack_args(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Ensure each value matches the signature of the dispatched tool.

    Hunt pack JSON always sends strings for placeholders; some tools declare
    ``int`` / ``bool`` params. This mapper shallow-coerces obvious cases so
    packs remain plain data without per-tool special-casing in the engine.
    """
    fn = _HUNT_PACK_DISPATCH.get(name)
    if not fn:
        return raw
    try:
        sig = inspect.signature(fn)
    except Exception:
        return raw
    out: dict[str, Any] = {}
    for key, value in raw.items():
        param = sig.parameters.get(key)
        if param is None:
            out[key] = value
            continue
        anno = param.annotation
        if anno is int and isinstance(value, str) and value.strip().lstrip("-").isdigit():
            out[key] = int(value)
        elif anno is bool and isinstance(value, str):
            out[key] = value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            out[key] = value
    return out


@mcp.tool()
async def case_health() -> dict:
    """Can the analyst trust the substrate of this investigation?

    Runs a deterministic health suite over every loaded case and returns one
    envelope with overall_status (blocked/degraded/healthy_with_notes/healthy)
    plus per-check records. Each check publishes its thresholds and metrics
    so an analyst can audit why a check passed or failed.

    v1 checks:
      - case_loaded                        critical
      - case_date_range                    medium
      - high_value_families_empty          high
      - kape_module_failures               high
      - evtx_row_thinness                  medium
      - duplicate_source_paths             medium
      - timezone_drift                     low
      - allowlist_integrity                info

    Fully offline. No detection logic, no incident-specific heuristics.
    """
    def fn():
        from state import app_state
        from core.analysis.case_health import case_health as _health
        _ensure_cases_hydrated()
        health = _health(app_state._connectors)
        return _mask(_attach_selected_evidence_guidance(health))
    return await _traced("case_health", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def build_entity_graph(
    entity_types: str = "",
    edge_types: str = "",
    match_key: str = "raw",
    limit_per_node_type: int = 200,
    all_cases: bool = False,
    snapshot_slug: str = "",
    bucket_name: str = "",
) -> dict:
    """Build a typed graph (users / hosts / files / hashes / services / processes)
    from existing artifacts with per-node and per-edge audit trails.

    Deterministic and pure — no LLM interpretation. Every node carries
    ``collapsed_from`` listing the raw values that merged plus the rule
    that merged them; every edge carries ``derived_from`` listing the
    artifact rows that produced it. The envelope publishes the exact
    derivation criteria for each edge type so construction logic is
    auditable without reading source.

    Args:
        entity_types: Comma-separated subset of
            user / host / file / hash / service / process.
            Empty = all.
        edge_types: Comma-separated subset of
            logon / executed / has_hash / created_svc / parent_of.
            Empty = all.
        match_key: Node identity mode.
            - ``raw`` (default): Tier-1 safe_* normalization only. Never
              collapses DOMAIN / realm / FQDN / full paths.
            - ``strict``: Alias for ``raw`` — kept for API symmetry.
            - ``loose``: Invokes Tier-2 (user_bare, host_first_label,
              path_basename). CAN collapse distinct identities; each
              affected node carries lossy_merge_warning and the envelope
              carries a top-level warning list.
        limit_per_node_type: Per-type cap (default 200). Prevents graph
            explosion on huge cases; truncation is logged in the response.
        all_cases: When True (default False) iterate every loaded axiom:*
            case and merge nodes by (type, normalized_value).
    """
    def fn():
        from state import app_state
        from core.analysis.entity_graph import build_entity_graph as _build

        # Bucket filter — resolve FIRST so a typo hard-errors before we
        # waste a full graph scan on the empty set.
        bucket_hit_ids: set[int] | None = None
        bucket_info: dict | None = None
        if snapshot_slug or bucket_name:
            if not (snapshot_slug and bucket_name):
                return {"ok": False, "error": "snapshot_slug and bucket_name must be provided together"}
            from core.analysis.case_snapshot import (
                resolve_bucket_hit_ids, BucketNotFoundError, SnapshotNotFoundError,
            )
            try:
                bucket_hit_ids = resolve_bucket_hit_ids(snapshot_slug, bucket_name)
                bucket_info = {"snapshot_slug": snapshot_slug, "bucket": bucket_name,
                               "hit_count": len(bucket_hit_ids)}
            except (BucketNotFoundError, SnapshotNotFoundError) as e:
                return {"ok": False, "error": str(e)}

        ets = [t.strip() for t in entity_types.split(",") if t.strip()] or None
        edts = [t.strip() for t in edge_types.split(",") if t.strip()] or None
        # Bucket hit_ids are applied BEFORE construction inside the builder
        # (Codex Round-9c): per-type caps count only bucket hits, so a
        # bucket graph can never be starved by off-bucket entities.
        if all_cases:
            _ensure_cases_hydrated()
            result = _build(
                app_state._connectors,
                entity_types=ets, edge_types=edts,
                match_key=match_key, limit_per_node_type=limit_per_node_type,
                hit_id_filter=bucket_hit_ids,
            )
        else:
            axiom = _get_axiom()
            result = _build(
                connectors=None,
                axiom_cases=[("active", axiom)],
                entity_types=ets, edge_types=edts,
                match_key=match_key, limit_per_node_type=limit_per_node_type,
                hit_id_filter=bucket_hit_ids,
            )

        if bucket_info is not None and result.get("ok"):
            result["bucket_filter"] = bucket_info

        return _mask(result)
    return await _traced(
        "build_entity_graph",
        {"entity_types": entity_types, "edge_types": edge_types,
         "match_key": match_key, "limit_per_node_type": limit_per_node_type,
         "all_cases": all_cases,
         "snapshot_slug": snapshot_slug, "bucket_name": bucket_name},
        fn, timeout_seconds=TIMEOUT_MEDIUM,
    )


@mcp.tool()
async def baseline_diff(
    reference_case_id: str = "",
    categories: str = "",
) -> dict:
    """Compare the active case against a known-good baseline.

    Returns net-new services / scheduled_tasks / startup_items / users — items
    present in the active case but not in the reference. Use this to cut
    triage noise ("what is NEW on this host?").

    Args:
        reference_case_id: Case id of another loaded case to diff against
            (e.g. a golden-image KAPE case). Leave empty to use the built-in
            Windows baseline JSON.
        categories: Optional comma-separated subset of
            services, scheduled_tasks, startup_items, users.

    Reading guide for AI consumers:
        - "net_new" items exist in the active case but not in the reference
          baseline. This is NOT a malice indicator. Legitimate third-party
          software, legitimate admin tools, and case-normal services will
          appear as net-new.
        - Use baseline_diff as noise reduction, not as a verdict generator.
          Triage each net-new item with get_hit_detail /
          get_file_timestamps / direct evidence before treating it as
          suspicious.
        - reference_source == "builtin_windows_baseline" means the reference
          is a tiny curated list. Expect high noise. For serious triage,
          diff against a golden-image reference case.
    """
    def fn():
        from state import app_state
        from core.analysis.baseline_diff import baseline_diff as _diff
        active = _get_axiom()
        ref_aq = None
        if reference_case_id.strip():
            key = f"axiom:{reference_case_id.strip()}"
            ref = app_state._connectors.get(key)
            if ref is None or not ref.is_connected():
                return {"ok": False,
                        "error": f"Reference case not found or not connected: {reference_case_id}"}
            ref_aq = ref.artifact_queries
        cats = [c.strip() for c in categories.split(",") if c.strip()] if categories else None
        return _mask(_diff(active.artifact_queries, reference_aq=ref_aq, categories=cats))
    return await _traced(
        "baseline_diff",
        {"reference_case_id": reference_case_id, "categories": categories},
        fn, timeout_seconds=TIMEOUT_MEDIUM,
    )


@mcp.tool()
async def service_persistence_gate(
    service_filter: str = "",
    include_parsed_case: bool = True,
    include_mounted_image: bool = True,
    verify_payload_files: bool = True,
    system_hive_path: str = "/c:/Windows/System32/config/SYSTEM",
    limit: int = 50,
) -> dict:
    """Gate service persistence analysis before finalizing an IR timeline.

    This tool is designed to prevent the specific miss where an analyst checks
    only EID 7045 and overlooks service registry state. It inspects System
    Services artifacts when a parsed case is loaded and, when an E01 is
    mounted, extracts and parses the SYSTEM hive directly. For svchost services
    it follows Parameters\\ServiceDll and can verify payload presence/timestamps
    against the mounted image.

    Args:
        service_filter: Optional substring to narrow returned candidates by
            service name, image path, ServiceDll, or registry path.
        include_parsed_case: Use the active parsed case's System Services
            artifact if available.
        include_mounted_image: Use the mounted disk image SYSTEM hive
            if available.
        verify_payload_files: Re-check candidate payload paths with the
            mounted image using get_file_info-style timestamp evidence.
        system_hive_path: Internal mounted-image path to the SYSTEM hive.
        limit: Max candidate services returned after scoring.

    Reading guide for AI consumers:
        - EID 7045 absence is not service-persistence absence. Registry state
          is the primary source for installed service configuration.
        - For svchost services, ImagePath is incomplete without
          Parameters\\ServiceDll. Treat this tool's ServiceDll chain as the
          pivot to payload timestamps, hash, signature, and static analysis.
        - Built-in service-name baseline checks are noise reduction only.
          A net-new service is a lead, not a verdict.
        - If this gate is blocked or partial, do not present a final attack
          timeline as complete for persistence.
    """
    params = {
        "service_filter": service_filter,
        "include_parsed_case": include_parsed_case,
        "include_mounted_image": include_mounted_image,
        "verify_payload_files": verify_payload_files,
        "system_hive_path": system_hive_path,
        "limit": limit,
    }

    def fn():
        from core.analysis.service_persistence import (
            build_service_persistence_gate as _build_gate,
            services_from_artifact_rows as _services_from_artifact_rows,
            services_from_system_hive as _services_from_system_hive,
        )

        services: list[dict[str, Any]] = []
        sources: list[dict[str, Any]] = []

        if include_parsed_case:
            try:
                _ensure_cases_hydrated()
            except Exception:
                pass
            c = _connectors.get("axiom")
            if c is not None and c.is_connected():
                try:
                    rows = c.artifact_queries.query_services(limit=0) or []
                    parsed_services = _services_from_artifact_rows(rows)
                    services.extend(parsed_services)
                    sources.append({
                        "source": "parsed_case",
                        "status": "checked",
                        "raw_rows": len(rows),
                        "normalized_services": len(parsed_services),
                    })
                except Exception as e:
                    sources.append({"source": "parsed_case", "status": "error", "error": str(e)})
            else:
                sources.append({
                    "source": "parsed_case",
                    "status": "unavailable",
                    "note": "No active parsed case. open_case is optional but improves coverage.",
                })

        e01 = _connectors.get("e01")
        e01_connected = e01 is not None and e01.is_connected()
        if include_mounted_image:
            if e01_connected:
                try:
                    hive_out = _evidence_bound_export_path(
                        "service_persistence_gate",
                        system_hive_path,
                        "SYSTEM.hive",
                    )
                    extraction = e01.extract_file(system_hive_path, hive_out)
                    hive_services, hive_meta = _services_from_system_hive(hive_out)
                    services.extend(hive_services)
                    sources.append({
                        "source": "mounted_image_system_hive",
                        "status": "checked",
                        "system_hive_path": system_hive_path,
                        "extracted_to": extraction.get("output_path", hive_out),
                        "sha256": extraction.get("sha256", ""),
                        "normalized_services": len(hive_services),
                        "metadata": hive_meta,
                    })
                except Exception as e:
                    sources.append({
                        "source": "mounted_image_system_hive",
                        "status": "error",
                        "system_hive_path": system_hive_path,
                        "error": str(e),
                    })
            else:
                sources.append({
                    "source": "mounted_image_system_hive",
                    "status": "unavailable",
                    "note": "No mounted image. mount_image enables direct SYSTEM hive service review.",
                })

        file_lookup = None
        if verify_payload_files and e01_connected:
            file_lookup = e01.get_file_info

        result = _build_gate(
            services,
            service_filter=service_filter,
            limit=limit,
            file_info_lookup=file_lookup,
        )
        result["sources"] = sources
        result["evidence_context"] = _evidence_context(
            system_hive_path,
            "mounted_image_system_hive" if e01_connected else "parsed_case",
            internal_path=system_hive_path,
        )
        return _mask(result)

    return await _traced("service_persistence_gate", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def list_hunt_packs() -> dict:
    """List every available hunt pack (built-in + local)."""
    def fn():
        from core.analysis.hunt_packs import list_packs
        return _mask(list_packs())
    return await _traced("list_hunt_packs", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def run_hunt_pack(name: str, params_json: str = "{}") -> dict:
    """Execute a named hunt pack. Calls existing MCP tools only — no code.

    Packs are JSON recipes that list tool calls in order. The engine
    substitutes ``{param_name}`` placeholders into each step's args before
    dispatching to the named tool. Every step's resolved args and output
    summary are returned so the hunt is fully auditable.

    Args:
        name: Pack name (see list_hunt_packs).
        params_json: JSON string of parameter values for this run.
    """
    import json as _json
    try:
        params = _json.loads(params_json) if params_json else {}
    except Exception:
        return {"ok": False, "error": "params_json must be valid JSON"}

    async def dispatch(tool_name: str, args: dict[str, Any]):
        fn = _HUNT_PACK_DISPATCH.get(tool_name)
        if fn is None:
            raise RuntimeError(
                f"Tool '{tool_name}' is not registered for hunt packs. "
                f"Allowed: {sorted(_HUNT_PACK_DISPATCH.keys())}"
            )
        coerced = _coerce_pack_args(tool_name, args)
        result = fn(**coerced)
        if inspect.isawaitable(result):
            result = await result
        return result

    from core.analysis.hunt_packs import run_pack
    try:
        result = await run_pack(name, params=params, tool_dispatch=dispatch)
        return _mask(result)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
async def list_suppressions() -> dict:
    """List all rule suppression entries (active + expired).

    Suppressions mute specific find_suspicious rules in environments where the
    rule fires legitimately. Matching is exact rule_id only — no regex, no
    conditional logic. Each entry carries reason / analyst / expires_at so
    the decision is auditable.
    """
    def fn():
        from core.analysis.suppressions import list_suppressions as _list
        return _mask(_list())
    return await _traced("list_suppressions", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def add_suppression(rule_id: str, reason: str, analyst: str = "", expires_at: str = "") -> dict:
    """Suppress a specific find_suspicious rule for this environment.

    Args:
        rule_id: Exact rule_name as emitted by find_suspicious (e.g.
            "evtx_eid_4624_type10_rdp_logons"). No globs, no regex.
        reason: Required. Why this rule is muted here (audit trail).
        analyst: Optional name of the analyst adding the suppression.
        expires_at: Optional ISO 8601 timestamp; after this, the entry is
            treated as inactive and surfaced in suppression_notes.
    """
    def fn():
        from core.analysis.suppressions import add_suppression as _add
        return _mask(_add(rule_id=rule_id, reason=reason, analyst=analyst, expires_at=expires_at))
    return await _traced(
        "add_suppression",
        {"rule_id": rule_id, "analyst": analyst, "expires_at": expires_at},
        fn, timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def remove_suppression(rule_id: str) -> dict:
    """Delete a suppression entry by rule_id."""
    def fn():
        from core.analysis.suppressions import remove_suppression as _rm
        return _mask(_rm(rule_id=rule_id))
    return await _traced("remove_suppression", {"rule_id": rule_id}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def save_case_snapshot(
    name: str,
    tagged_hit_ids: str = "",
    notes: str = "",
    filters_json: str = "{}",
) -> dict:
    """Persist analyst context (tags / notes / filters / active case) as a named snapshot.

    Snapshots let an analyst resume an investigation later without re-running
    every query by hand. Loading a snapshot restores context; it never
    silently reruns detection tools.

    Args:
        name: Human-readable snapshot name (becomes the slug).
        tagged_hit_ids: Comma-separated hit ids the analyst flagged as
                        interesting (e.g. "123,456,789").
        notes: Free-form analyst notes.
        filters_json: JSON string of the current UI filter state so the
                      session can be replayed. Opaque to the engine.
    """
    def fn():
        import json as _json
        from state import app_state
        from core.analysis.case_snapshot import save_snapshot
        _ensure_cases_hydrated()
        try:
            filters = _json.loads(filters_json) if filters_json else {}
        except Exception:
            filters = {"_parse_error": filters_json[:120]}
        hits = [int(h) for h in tagged_hit_ids.split(",") if h.strip().isdigit()]
        masker_state = _masker.get_stats() if _masker.enabled else {}
        return _mask(save_snapshot(
            app_state._connectors, name=name, tagged_hits=hits,
            notes=notes, filters=filters, masker_state=masker_state,
        ))
    return await _traced("save_case_snapshot", {"name": name}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def list_case_snapshots() -> dict:
    """List every saved investigation snapshot with its metadata."""
    def fn():
        from core.analysis.case_snapshot import list_snapshots
        return _mask(list_snapshots())
    return await _traced("list_case_snapshots", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def add_hits_to_bucket(
    snapshot_slug: str,
    bucket_name: str,
    hit_ids: str,
    hypothesis: str = "",
) -> dict:
    """Append hit IDs to a named bucket inside an existing snapshot.

    Buckets let an analyst maintain multiple parallel hypothesis sets on
    the same case (e.g. 'payload_files', 'compromised_users', 'exfil_ips')
    without inventing a separate primitive. IDs are deduped and sorted.

    Args:
        snapshot_slug: Slug returned by save_case_snapshot.
        bucket_name:   Human-readable bucket label; sanitized to a slug.
        hit_ids:       Comma-separated hit_ids (e.g. "123,456,789").
        hypothesis:    Optional free-form string stored alongside the bucket.
    """
    def fn():
        from core.analysis.case_snapshot import add_hits_to_bucket as _add
        ids = [int(x) for x in hit_ids.split(",") if x.strip().lstrip("-").isdigit()]
        return _mask(_add(snapshot_slug, bucket_name, ids, hypothesis=hypothesis))
    return await _traced(
        "add_hits_to_bucket",
        {"snapshot_slug": snapshot_slug, "bucket_name": bucket_name, "count": len(hit_ids.split(","))},
        fn, timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def remove_hits_from_bucket(
    snapshot_slug: str,
    bucket_name: str,
    hit_ids: str,
) -> dict:
    """Remove hit IDs from a named bucket. Errors if the bucket doesn't exist."""
    def fn():
        from core.analysis.case_snapshot import remove_hits_from_bucket as _rm
        ids = [int(x) for x in hit_ids.split(",") if x.strip().lstrip("-").isdigit()]
        return _mask(_rm(snapshot_slug, bucket_name, ids))
    return await _traced(
        "remove_hits_from_bucket",
        {"snapshot_slug": snapshot_slug, "bucket_name": bucket_name, "count": len(hit_ids.split(","))},
        fn, timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def get_bucket_hits(snapshot_slug: str, bucket_name: str) -> dict:
    """Read a bucket's hit_ids + hypothesis. Hard-errors on unknown bucket
    so a typo can't masquerade as 'no activity'."""
    def fn():
        from core.analysis.case_snapshot import get_bucket_hits as _get
        return _mask(_get(snapshot_slug, bucket_name))
    return await _traced(
        "get_bucket_hits",
        {"snapshot_slug": snapshot_slug, "bucket_name": bucket_name},
        fn, timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def load_case_snapshot(slug: str) -> dict:
    """Load a saved snapshot by slug. Returns analyst context; does not re-run tools.

    Args:
        slug: Snapshot slug as returned by save_case_snapshot / list_case_snapshots.
    """
    def fn():
        from core.analysis.case_snapshot import load_snapshot
        return _mask(load_snapshot(slug))
    return await _traced("load_case_snapshot", {"slug": slug}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def hunt_evtx_rules(
    rule_ids: str = "",
    severity_min: str = "low",
    limit_per_rule: int = 100,
) -> dict:
    """Run a built-in Sigma-style rule pack against the case's Event Log artifact.

    Lightweight alternative to Hayabusa — no external binary or ruleset
    dependency. Covers EIDs that find_suspicious does not already handle:
    failed logon bursts, account / group creation, Kerberos weak-enc
    requests, NTLM auth, audit-policy change, firewall rule edits, SMB
    share access, scheduled task firings, RDP session events, and special-
    privilege use. Every rule is published verbatim in the response so the
    analyst can audit or tune matches.

    Args:
        rule_ids: Comma-separated rule ids (e.g. "fw-evtx-001,fw-evtx-006").
                  Empty = run every rule.
        severity_min: "low" / "medium" / "high" / "critical". Filters before
                      execution.
        limit_per_rule: Max hits kept per rule. Raw match counts are still
                        reported so nothing silently disappears.
    """
    def fn():
        from core.analysis.evtx_rules import hunt_evtx_rules as _hunt
        ids = [r.strip() for r in rule_ids.split(",") if r.strip()] if rule_ids else None
        return _mask(_hunt(_get_axiom().artifact_queries, rule_ids=ids,
                            severity_min=severity_min, limit_per_rule=limit_per_rule))
    return await _traced(
        "hunt_evtx_rules",
        {"rule_ids": rule_ids, "severity_min": severity_min, "limit_per_rule": limit_per_rule},
        fn,
        timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def detect_anti_forensics(max_details_per_rule: int = 50) -> dict:
    """Detect publicly-documented anti-forensic activity in the active case.

    Scans for a small, transparent rule set — every match is accompanied by
    the exact text that triggered it:
      - T1070.001 Security / System log cleared (EID 1102 / 104)
      - T1490    Volume snapshot deletion (system utility / wmi / powershell)
      - T1070.002 USN journal deletion (fsutil usn deletejournal)
      - T1562.002 PowerShell ScriptBlock / Transcription logging tamper
      - T1562.001 Stop-Service against Sysmon / Defender / EventLog
      - T1070    Execution of sdelete / cipher / bcdedit cleanup utilities

    Fully offline. Timestomp detection ($SI/$FN divergence) is explicitly out
    of scope — use ``get_file_timestamps`` on suspect files instead.

    Args:
        max_details_per_rule: Hard cap on the ``details`` entries per rule.
            Rules that exceed the cap report the true ``total_count`` and
            ``truncated: True`` so the analyst sees the sample was trimmed.
            Default 50 keeps the payload within MCP's ~25k-token response
            ceiling even when several rules fire on an EVTX-heavy case.
            Set to 0 to disable the cap, or raise it explicitly when you
            need a bigger sample (investigation_gap_report will still see
            the true ``total_count``).

    Reading guide for AI consumers:
        - A fired rule means the pattern matched. It does NOT confirm
          malicious tampering. Administrators legitimately clear logs,
          delete shadow copies during maintenance, and disable scriptblock
          logging in test environments.
        - Before concluding anti-forensic activity, correlate with (a)
          timing relative to other incident signals, (b) the actor account,
          (c) whether the action aligns with a known administrative task.
        - rules_fired count is NOT a severity score. A single log-cleared-
          Security-1102 rule firing can be more significant than ten VSS-
          shadow-deletion rule firings, depending on context.
        - If event logs are missing (coverage_gate.statuses.evtx ==
          "missing"), negative results here have limited weight. Do not
          read "0 rules fired" as "no tampering".
    """
    def fn():
        from core.analysis.anti_forensics import detect_anti_forensics as _run
        return _mask(_run(
            _get_axiom().artifact_queries,
            max_details_per_rule=max_details_per_rule,
        ))
    return await _traced(
        "detect_anti_forensics",
        {"max_details_per_rule": max_details_per_rule},
        fn, timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def assess_evidence_strength(findings_json: str = "") -> dict:
    """Tag suspicious findings with CLAUDE.md strength tiers.

    Annotates each detail inside a ``find_suspicious`` payload with a
    ``strength`` tier (confirmed / strong / moderate / weak) and a
    ``strength_reason`` explaining why. Adds a ``strength_rollup`` summary.

    Rules are transparent, rule-based, and fully offline:
      - confirmed: Prefetch+SRUM, MFT, definitive EIDs (4688/7045/1102/...)
      - strong:    Prefetch Last Run, Sysmon / PS ScriptBlock
      - moderate:  AmCache, UserAssist, Scheduled Tasks
      - weak:      Shim Cache, Link Date (NOT execution proof)

    Args:
        findings_json: JSON string of a find_suspicious response (the same
                       shape ``find_suspicious`` returns). Passing an empty
                       string auto-runs find_suspicious with default rules.
    """
    def fn():
        import json as _json
        from core.analysis.evidence_strength import score_findings
        if findings_json:
            try:
                payload = _json.loads(findings_json)
            except Exception:
                return {"error": f"findings_json must be valid JSON"}
        else:
            from core.analysis.suspicious import find_suspicious as _find
            payload = _find(_get_axiom().artifact_queries, rules="")
        return _mask(score_findings(payload))
    return await _traced(
        "assess_evidence_strength",
        {"findings_json": (findings_json[:200] + "…") if len(findings_json) > 200 else findings_json},
        fn,
        timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def investigation_gap_report(
    findings_json: str = "",
    snapshot_slug: str = "",
) -> dict:
    """Compose what's missing in this investigation so far.

    Pure composition — runs ``case_health``, ``build_coverage_report`` and
    ``detect_anti_forensics`` inline, optionally consumes a ``find_suspicious``
    payload, and returns one envelope categorising gaps. Does not fire any
    new detection rules.

    Output sections:
      - substrate_gaps:         failing case_health checks.
      - detection_gaps:         unevaluable_rules from find_suspicious (if
                                findings_json supplied).
      - corroboration_gaps:     findings below ``confirmed`` strength.
      - pivots_not_attempted:   for each fired rule that maps to a canonical
                                next tool, the pivot is listed — except for
                                rules whose strength is ``weak`` (pivoting on
                                weak signals invites confirmation bias).
      - bucket_gaps:            if ``snapshot_slug`` is supplied, flags
                                bucketed hit_ids that no longer exist in any
                                loaded case.
      - recommended_next_queries: deterministic top-N list of tool calls to
                                  consider next (substrate gaps first).

    When ``findings_json`` is empty the detection / corroboration / pivot
    sections are reported as ``skipped_sections`` (not silently empty) so
    the caller cannot mistake "not checked" for "nothing to do".

    Args:
        findings_json: Optional JSON string of a find_suspicious response.
                        Empty string skips findings-dependent sections.
        snapshot_slug: Optional case_snapshot slug. When supplied, bucket
                        references are reconciled against loaded cases.

    Reading guide for AI consumers:
        - pivots_not_attempted lists suggested next queries. These are
          POINTERS for further investigation, not required follow-ups.
          Chasing every pivot produces confirmation bias and wasted effort.
        - Weak-strength signals are intentionally suppressed in
          pivots_not_attempted to reduce bias. If you want to corroborate a
          weak finding, do it manually with explicit uncertainty.
        - If findings_available is false, sections requiring findings are
          listed in skipped_sections. Do NOT read a missing section as
          "no gaps there".
        - bucket_gaps.stale_references lists bucketed hit_ids no longer in
          any loaded case. A saved snapshot referencing stale hits must not
          be read as current evidence.
    """
    def fn():
        from state import app_state
        from core.analysis.investigation_gap import (
            investigation_gap_report as _run,
        )
        _ensure_cases_hydrated()
        axiom_conns = {
            k: v for k, v in (app_state._connectors or {}).items()
            if k.startswith("axiom:")
        }
        return _mask(_run(
            axiom_conns,
            findings_payload=findings_json or None,
            snapshot_slug=snapshot_slug,
        ))
    return await _traced(
        "investigation_gap_report",
        {
            "findings_json": ("<json>" if findings_json else ""),
            "snapshot_slug": snapshot_slug,
        },
        fn, timeout_seconds=TIMEOUT_LIGHT,
    )


@mcp.tool()
async def behavioral_delta_pack(
    entity_value: str,
    baseline_start: str,
    baseline_end: str,
    incident_start: str,
    incident_end: str,
    seed_keywords: str = "",
    window_minutes: int = 60,
    limit_per_keyword: int = 500,
    match_mode: str = "substring",
) -> dict:
    """Observe behavioural change for an entity between baseline and incident.

    Composition tool — runs ``correlate_keywords`` twice (baseline + incident)
    and reports structural differences: dormant gaps, volume shifts, new
    co-occurrence combinations, net-new or went-silent entities. Every
    reported claim carries ``derived_from`` pointers so the analyst can
    jump to the raw evidence behind each statement.

    Intentionally framed as OBSERVED CHANGE, not anomaly detection — the
    output gives you evidence to interpret, not a verdict.

    Args:
        entity_value: Primary keyword, the entity under investigation
            (e.g. ``"bomgar-pec"``). Always searched as the first seed.
        baseline_start / baseline_end: ISO date range defining "normal" for
            this entity (e.g. ``"2026-01-08"`` to ``"2026-04-10"``).
        incident_start / incident_end: ISO date range being scrutinised
            (e.g. ``"2026-04-11"`` to ``"2026-04-16"``).
        seed_keywords: Comma-separated extra keywords to correlate with the
            entity — e.g. ``"4648,7045"`` to surface co-occurrence with
            explicit-credential-use or new-service activity. Empty = just
            the entity.
        window_minutes: Co-occurrence window size (default 60 minutes,
            matching the usual correlate default for incident-scale
            analysis).
        limit_per_keyword: Per-keyword search cap inside each period
            (default 500). Volume ratios use true totals from
            axiom.search, so truncation never distorts the ratio; only
            the returned sample feeds first/last timestamps and
            top_windows (flagged under ``truncation_warnings``).
        match_mode: ``substring`` (default) preserves connector keyword
            search semantics. ``exact`` applies a composition-layer
            whole-value / basename / stem filter after retrieval.

    Returns an envelope with ``claims`` each tagged ``kind`` ∈
     {no_activity_in_either_period, entity_net_new_in_incident,
     entity_went_silent_in_incident, entity_dormant_then_active,
     observed_volume_change, observed_cooccurrence_change}.

    Reading guide for AI consumers:
        - This tool reports OBSERVED CHANGE between two periods. It does NOT
          classify the change as anomalous, malicious, or benign. Change
          alone is not a verdict.
        - claims[].kind values like entity_net_new_in_incident or
          observed_volume_change describe structural difference only. The
          analyst (LLM or human) interprets the meaning.
        - derived_from pointers on each claim are the evidence pointers to
          verify the claim. Do not quote the claim without reading at least
          one derived_from entry.
        - dormant_gap_reason can be "truncated_sample" or "baseline_empty"
          etc. These reasons invalidate the gap measurement — do not use
          the gap as evidence in those cases.
    """
    def fn():
        from core.analysis.behavioral_delta import behavioral_delta as _delta
        axiom = _get_axiom()
        seeds = [s.strip() for s in seed_keywords.split(",") if s.strip()] if seed_keywords else []
        return _mask(_delta(
            axiom,
            entity_value=entity_value,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            incident_start=incident_start,
            incident_end=incident_end,
            seed_keywords=seeds,
            window_minutes=window_minutes,
            limit_per_keyword=limit_per_keyword,
            match_mode=match_mode,
        ))
    return await _traced(
        "behavioral_delta_pack",
        {
            "entity_value": entity_value,
            "baseline_start": baseline_start, "baseline_end": baseline_end,
            "incident_start": incident_start, "incident_end": incident_end,
            "seed_keywords": seed_keywords,
            "window_minutes": window_minutes,
            "limit_per_keyword": limit_per_keyword,
            "match_mode": match_mode,
        },
        fn, timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def entity_story_pack(
    entity_value: str,
    start_date: str = "",
    end_date: str = "",
    seed_keywords: str = "",
    window_minutes: int = 60,
    limit_per_keyword: int = 200,
    match_key: str = "raw",
    graph_limit_per_node_type: int = 200,
    match_mode: str = "substring",
) -> dict:
    """Compose an entity-centric timeline + context story.

    Composition tool — combines keyword search / timeline chronology,
    co-occurrence windows, nearby graph entities, and supporting
    suspicious findings into a report-ready narrative scaffold.

    Intentionally descriptive, not verdict-driven: output phases such as
    ``first_seen``, ``dormant_period``, ``reactivation``, and
    ``repeat_bursts`` are structural summaries of observed chronology.

    Args:
        entity_value: Primary entity keyword under investigation.
        start_date / end_date: Optional ISO date range for the story window.
        seed_keywords: Comma-separated extra keywords to correlate around the
            entity (for example ``"4648,7045"``).
        window_minutes: Co-occurrence window size used for burst grouping.
        limit_per_keyword: Search cap per keyword. Truncation is surfaced in
            ``truncation_warnings`` rather than hidden.
        match_key: Entity-graph normalization mode (raw / strict / loose).
        graph_limit_per_node_type: Safety cap for graph expansion.
        match_mode: ``substring`` (default) preserves connector keyword
            search semantics. ``exact`` applies a composition-layer
            whole-value / basename / stem filter after retrieval.
    """
    def fn():
        from core.analysis.entity_story import entity_story as _story
        axiom = _get_axiom()
        seeds = [s.strip() for s in seed_keywords.split(",") if s.strip()] if seed_keywords else []
        return _mask(_story(
            axiom,
            entity_value=entity_value,
            start_date=start_date,
            end_date=end_date,
            seed_keywords=seeds,
            window_minutes=window_minutes,
            limit_per_keyword=limit_per_keyword,
            match_key=match_key,
            graph_limit_per_node_type=graph_limit_per_node_type,
            match_mode=match_mode,
        ))
    return await _traced(
        "entity_story_pack",
        {
            "entity_value": entity_value,
            "start_date": start_date,
            "end_date": end_date,
            "seed_keywords": seed_keywords,
            "window_minutes": window_minutes,
            "limit_per_keyword": limit_per_keyword,
            "match_key": match_key,
            "graph_limit_per_node_type": graph_limit_per_node_type,
            "match_mode": match_mode,
        },
        fn, timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def auto_seed_entities_pack(
    start_date: str = "",
    end_date: str = "",
    window_minutes: int = 60,
    limit_per_seed: int = 200,
    max_seeds: int = 12,
    match_mode: str = "exact",
) -> dict:
    """Auto-extract deterministic seeds from existing case outputs.

    Composition tool — derives a seed catalog from structured findings and
    baseline diff, then clusters their co-occurrence. No new detection rules.

    Args:
        start_date / end_date: Optional ISO date range for clustering.
        window_minutes: Co-occurrence window size for clustering.
        limit_per_seed: Search cap per selected seed.
        max_seeds: Max seeds kept in the catalog before clustering.
        match_mode: Basename/keyword matching mode for non-event-id seeds.
    """
    def fn():
        from core.analysis.auto_seed_entities import auto_seed_entities
        axiom = _get_axiom()
        return _mask(auto_seed_entities(
            axiom,
            start_date=start_date,
            end_date=end_date,
            window_minutes=window_minutes,
            limit_per_seed=limit_per_seed,
            max_seeds=max_seeds,
            match_mode=match_mode,
        ))
    return await _traced(
        "auto_seed_entities_pack",
        {
            "start_date": start_date,
            "end_date": end_date,
            "window_minutes": window_minutes,
            "limit_per_seed": limit_per_seed,
            "max_seeds": max_seeds,
            "match_mode": match_mode,
        },
        fn, timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def find_suspicious(
    rules: str = "",
    score_strength: bool = True,
    include_provenance: bool = True,
    apply_suppressions: bool = True,
    include_rule_coverage: bool = True,
) -> dict:
    """Run structured threat detection rules.

    Args:
        rules: Optional comma-separated rule names. Empty runs every rule.
        score_strength: When True (default) annotate each detail with the
            CLAUDE.md strength tier (confirmed/strong/moderate/weak).
        include_provenance: When True (default) attach supporting_artifacts
            and absent_corroboration to every finding.
        apply_suppressions: When True (default) move findings whose rule_id
            matches an active suppression entry into a separate ``suppressed``
            list. Suppressed items keep all their fields plus the matching
            suppression entry so audit is preserved.
        include_rule_coverage: When True (default) attach per-rule coverage
            metadata + a top-level ``unevaluable_rules`` list so the analyst
            can distinguish "rule ran and found nothing" from "rule couldn't
            run because required artifacts are missing". Opt-out via False
            when a caller depends on the pre-coverage payload shape.

    Reading guide for AI consumers:
        - findings[] order is not significance-sorted. Rule execution order is
          arbitrary — judge significance from details[] and matching_count.
        - For each finding, examine details[] and absent_corroboration
          before quoting. A finding with no corroboration is a hint, not
          evidence.
        - If truncated=true on a finding, run find_suspicious with that single
          rule to retrieve all records before using it as a conclusion basis.
    """
    def fn():
        from state import app_state
        from core.analysis.suspicious import find_suspicious as _find
        payload = _find(_get_axiom().artifact_queries, rules=rules)
        if score_strength:
            from core.analysis.evidence_strength import score_findings
            score_findings(payload)
        if include_provenance:
            from core.analysis.provenance import attach_provenance
            attach_provenance(payload, app_state._connectors)
        if apply_suppressions:
            from core.analysis.suppressions import apply_suppressions as _suppress
            _suppress(payload)
        if include_rule_coverage:
            from core.analysis.rule_coverage import attach_rule_coverage
            attach_rule_coverage(payload, app_state._connectors)
        return _mask(payload)
    return await _traced(
        "find_suspicious",
        {"rules": rules, "score_strength": score_strength,
         "include_provenance": include_provenance, "apply_suppressions": apply_suppressions,
         "include_rule_coverage": include_rule_coverage},
        fn, timeout_seconds=TIMEOUT_HEAVY,
    )


@mcp.tool()
async def correlate(
    pivot_field: str = "",
    pivot_value: str = "",
    keywords: str = "",
    start_date: str = "",
    end_date: str = "",
    window_minutes: int = 5,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Cross-reference artifacts.

    Two modes of operation:

    1. Classic pivot mode (pivot_field + pivot_value):
       Pivot by timestamp, user, source, or keyword.

    2. Multi-keyword correlation mode (keywords):
       Search for multiple keywords and show where they co-occur in time.
       e.g. keywords="SearchHost,task.vbs,sshd,KslD"
       Returns: per-keyword hits sorted chronologically, plus time windows
       where multiple keywords appear together.

    Args:
        pivot_field: Classic pivot type (timestamp, user, source, keyword). Optional if using keywords mode.
        pivot_value: Value to pivot on. Required for classic mode.
        keywords: Comma-separated keywords for multi-keyword correlation.
        start_date: Date filter (ISO). Used in keywords mode.
        end_date: Date filter (ISO). Used in keywords mode.
        window_minutes: Time window for co-occurrence detection (default 5 min).
        limit: Max results per keyword (default 100).
        offset: Skip first N results per keyword (for pagination).

    Reading guide for AI consumers:
        - Correlation results show temporal or keyword co-occurrence. They
          do NOT prove causation.
        - co_occurrence_windows is a list of time buckets where multiple
          seeds fired together. A window appearing here is a prompt to
          investigate, not a proof of sequence.
        - Do not infer "A caused B" from "A and B appear in the same
          window". Verify the actual sequence via direct timestamps
          (get_file_timestamps / timeline).
        - Empty or truncated results do not mean "no correlation exists".
          Check truncation_warnings and consider wider windows.
    """
    params = {"pivot_field": pivot_field, "pivot_value": pivot_value,
              "keywords": keywords, "window_minutes": window_minutes, "limit": limit, "offset": offset}
    def fn():
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords.strip() else []

        if kw_list:
            return _mask(_correlate_keywords(_get_axiom(), kw_list, start_date, end_date, window_minutes, limit, offset))
        elif pivot_field and pivot_value:
            from core.analysis.correlator import correlate as _corr
            return _mask(_corr(_get_axiom(), pivot_field, pivot_value, window_minutes, limit, offset))
        else:
            return {"error": "Provide either keywords for multi-keyword correlation, or pivot_field + pivot_value for classic mode."}
    return await _traced("correlate", params, fn, timeout_seconds=TIMEOUT_HEAVY)


def _correlate_keywords(axiom, kw_list, start_date, end_date, window_minutes, limit, offset=0):
    """Thin wrapper around ``core.analysis.correlator.correlate_keywords``.

    Kept so the MCP ``correlate`` tool keeps its original call site + limit
    policy (``config.correlate_max_limit``). Shared algorithm lives in the
    core module so composition tools (``behavioral_delta``) see identical
    window counts — Codex pre-review blocker.
    """
    from core.analysis.correlator import correlate_keywords as _corr_kw
    return _corr_kw(
        axiom, kw_list,
        start_date=start_date, end_date=end_date,
        window_minutes=window_minutes, limit=limit, offset=offset,
        max_limit=config.correlate_max_limit,
    )


@mcp.tool()
async def map_to_mitre(custom_findings: str = "") -> dict:
    """Map findings to MITRE ATT&CK.

    Args:
        custom_findings: JSON array of LLM-discovered findings to include in mapping.
                         Each item: {"technique_id": "T1572", "rule_name": "ssh_tunnel",
                                     "severity": "critical", "description": "...", "matching_count": 1}
                         These are merged with auto-detected findings from find_suspicious.
                         If empty, only auto-detected findings are mapped.
    """
    def fn():
        from core.analysis.suspicious import find_suspicious as _find
        from core.analysis.mitre_mapper import get_attack_narrative

        # Auto-detected findings
        sus = _find(_get_axiom().artifact_queries)
        findings = sus.get("findings", [])

        # Merge LLM-provided custom findings
        if custom_findings.strip():
            try:
                custom = json.loads(custom_findings)
                if isinstance(custom, list):
                    for cf in custom:
                        # Normalize: ensure mitre_techniques field exists
                        if "technique_id" in cf and "mitre_techniques" not in cf:
                            cf["mitre_techniques"] = [cf["technique_id"]]
                        if "matching_count" not in cf:
                            cf["matching_count"] = 1
                        if "rule_name" not in cf:
                            cf["rule_name"] = "llm_analysis"
                        findings.append(cf)
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON in custom_findings: {e}"}

        return _mask(get_attack_narrative(findings))
    return await _traced("map_to_mitre", {"custom_findings": custom_findings[:200] + "..." if len(custom_findings) > 200 else custom_findings}, fn)


@mcp.tool()
async def get_tagged_hits(tag_name: str = "") -> dict:
    """Get investigator-tagged hits."""
    return await _traced("get_tagged_hits", {"tag_name": tag_name}, lambda: _mask(_get_axiom().get_tagged_hits(tag_name)), timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def search_by_hash(hash_value: str, limit: int = 50, offset: int = 0) -> dict:
    """Find artifacts by hash."""
    return await _traced("search_by_hash", {"hash": hash_value, "limit": limit, "offset": offset},
                   lambda: _mask(_get_axiom().search_by_hash(hash_value, limit, offset)))


@mcp.tool()
async def generate_report(output_path: str = "") -> dict:
    """Generate HTML investigation report."""
    def fn():
        from core.analysis.report_generator import generate_report as _gen
        target_path = output_path
        if not target_path:
            out_dir = _analysis_output_dir("reports")
            target_path = os.path.join(
                out_dir,
                f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html",
            )
        result = _gen({"axiom": _get_axiom()}, _masker, target_path)
        if isinstance(result, dict):
            result["analysis_output"] = _analysis_output_context(create=False)
        return result
    return await _traced("generate_report", {"output_path": output_path}, fn)


# ── Disk Image Tools ──

_ANALYSIS_OUTPUT_DIRNAME = "forensic-workstation-output"


def _get_e01() -> E01ImageConnector:
    c = _connectors.get("e01")
    if c and c.is_connected():
        return c
    _ensure_e01_hydrated()
    c = _connectors.get("e01")
    if c and c.is_connected():
        return c
    raise RuntimeError("E01 이미지가 열려있지 않습니다. mount_image를 먼저 실행하세요.")


def _ensure_e01_hydrated(evidence_ref: str = "") -> dict[str, Any]:
    """Attach the selected disk image to this MCP process when possible."""
    c = _connectors.get("e01")
    if c and c.is_connected():
        return {"status": "already_mounted", **c.get_metadata()}

    resolved = resolve_image_evidence(evidence_ref)
    path = resolved.get("path", "")
    if not path:
        return {"status": "unavailable", "error": "No uniquely selected disk image evidence."}
    if not (is_path_allowed(path) or resolve_active_case_evidence(path)):
        return {"status": "blocked", "error": build_not_allowed_message(evidence_ref or path)}

    c = E01ImageConnector()
    meta = c.connect(path)
    _connectors["e01"] = c
    return {"status": "mounted", "resolved_from": resolved.get("source", ""), **meta}


def _workspace_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _output_target_candidates() -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []

    def add(path: str, source: str) -> None:
        value = str(path or "").strip()
        if not value:
            return
        norm = os.path.normcase(os.path.abspath(value))
        if any(item.get("norm") == norm for item in candidates):
            return
        candidates.append({"path": value, "source": source, "norm": norm})

    e01 = _connectors.get("e01")
    if e01 is not None and e01.is_connected():
        try:
            add(str(e01.get_metadata().get("image_path", "")), "mounted_image")
        except Exception:
            pass

    try:
        selected = resolve_image_evidence("").get("path", "")
        add(selected, "selected_image")
    except Exception:
        pass

    try:
        active = load_active_case()
    except Exception:
        active = {}
    for entry in [active, *active.get("all_cases", [])] if isinstance(active, dict) else []:
        add(str(entry.get("path", "")), "active_case")
        for loc in entry.get("evidence_locations", []) or []:
            add(str(loc), "active_case_evidence")

    try:
        allowed = load_allowed_evidence().get("paths", [])
    except Exception:
        allowed = []
    for path in allowed:
        add(str(path), "allowed_evidence")

    return candidates


def _analysis_output_context(create: bool = False) -> dict[str, Any]:
    for candidate in _output_target_candidates():
        path = os.path.abspath(candidate["path"])
        if os.path.isfile(path):
            target_dir = os.path.dirname(path)
        elif os.path.isdir(path):
            target_dir = path
        else:
            continue
        root = os.path.join(target_dir, _ANALYSIS_OUTPUT_DIRNAME)
        if create:
            try:
                os.makedirs(root, exist_ok=True)
            except OSError as e:
                raise RuntimeError(
                    f"Cannot create analysis output directory beside selected evidence: {root}. "
                    "Choose a writable output_dir or grant write access to the evidence folder."
                ) from e
        return {
            "root": root,
            "target_path": path,
            "target_dir": target_dir,
            "target_source": candidate.get("source", ""),
            "fallback_to_workspace": False,
        }

    root = os.path.join(_workspace_root(), "export")
    if create:
        os.makedirs(root, exist_ok=True)
    return {
        "root": root,
        "target_path": "",
        "target_dir": "",
        "target_source": "",
        "fallback_to_workspace": True,
        "fallback_reason": "No existing selected evidence or active case folder was available.",
    }


def _analysis_output_dir(*parts: str, create: bool = True) -> str:
    root = _analysis_output_context(create=create)["root"]
    path = os.path.join(root, *[str(part) for part in parts if str(part)])
    if create:
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            raise RuntimeError(
                f"Cannot create analysis output directory: {path}. "
                "Choose a writable output_dir or grant write access to the evidence folder."
            ) from e
    return path


def _analysis_relative_path(path: str) -> str:
    if not path:
        return ""
    try:
        return os.path.relpath(path, _analysis_output_context(create=False)["root"])
    except Exception:
        try:
            return os.path.relpath(path, _workspace_root())
        except Exception:
            return path


def _evidence_context(
    input_ref: str = "",
    result_source: str = "",
    *,
    local_path: str = "",
    internal_path: str = "",
) -> dict[str, Any]:
    """Return explicit source context for raw and parsed evidence outputs."""
    mounted: dict[str, Any] = {"available": False}
    e01 = _connectors.get("e01")
    if e01 is not None and e01.is_connected():
        meta = e01.get_metadata()
        mounted = {
            "available": True,
            "image_path": meta.get("image_path", ""),
            "hostname": meta.get("hostname", ""),
            "volumes": meta.get("volumes", []),
        }

    active = load_active_case()
    parsed_connector_loaded = any(
        (name == "axiom" or name.startswith("axiom:")) and getattr(connector, "is_connected", lambda: False)()
        for name, connector in _connectors.items()
    )
    active_case = {
        "configured": bool(active),
        "connector_loaded": parsed_connector_loaded,
        "path": active.get("path", ""),
        "source_type": active.get("source_type", ""),
        "evidence_sources": active.get("evidence_sources", []),
        "evidence_locations": active.get("evidence_locations", []),
    }
    allowed_images = [
        path for path in load_allowed_evidence().get("paths", [])
        if str(path).lower().endswith(IMAGE_EXTENSIONS)
    ]
    selected_image = resolve_image_evidence(input_ref)
    warnings: list[str] = []
    if result_source == "local_file":
        warnings.append(
            "Result came from a local/workspace file. Verify it belongs to the current evidence set before correlating."
        )
    if active_case["configured"] and mounted["available"]:
        case_locations = {str(v).lower() for v in active_case["evidence_locations"]}
        mounted_path = str(mounted.get("image_path", "")).lower()
        if mounted_path and case_locations and mounted_path not in case_locations:
            warnings.append(
                "Mounted image path differs from active parsed-case evidence locations; keep these sources separate."
            )

    return {
        "input_ref": input_ref,
        "internal_path": internal_path,
        "local_path": local_path,
        "result_source": result_source,
        "selected_image": selected_image,
        "mounted_image": mounted,
        "active_parsed_case": active_case,
        "analysis_output": _analysis_output_context(create=False),
        "allowed_image_count": len(allowed_images),
        "source_separation": {
            "parsed_case_configured": active_case["configured"],
            "parsed_case_loaded": parsed_connector_loaded,
            "parsed_case_available": parsed_connector_loaded,
            "mounted_image_available": mounted["available"],
            "raw_image_only_mode": mounted["available"] and not parsed_connector_loaded,
        },
        "warnings": warnings,
    }


def _selected_evidence_guidance(input_ref: str = "active_image") -> dict[str, Any]:
    """Describe the user-selected evidence and the only valid next source action.

    This is deliberately code-side guidance, not a prompt convention: tools that
    can be called before a parsed case exists attach this block so an agent sees
    the selected image path and the required ``active_image`` alias instead of
    guessing from files in the workspace.
    """
    ctx = _evidence_context(input_ref)
    selected_image = ctx.get("selected_image") or {}
    mounted_image = ctx.get("mounted_image") or {}
    separation = ctx.get("source_separation") or {}
    allowed = load_allowed_evidence().get("paths", [])
    allowed_images = [
        path for path in allowed
        if str(path).lower().endswith(IMAGE_EXTENSIONS)
    ]
    allowed_cases = [
        path for path in allowed
        if str(path).lower().endswith(".mfdb") or os.path.isdir(str(path))
    ]
    parsed_loaded = bool(separation.get("parsed_case_loaded"))

    next_action: dict[str, Any] | None = None
    evidence_mode = "parsed_case_loaded" if parsed_loaded else "no_selected_evidence"
    if not parsed_loaded and len(allowed_cases) == 1:
        evidence_mode = "parsed_case_selected_unopened"
        next_action = {
            "tool": "open_case",
            "args": {"path": allowed_cases[0]},
            "reason": "Open the user-selected allowlisted parsed case; do not search for another case path.",
        }
    elif not parsed_loaded and selected_image:
        if mounted_image.get("available"):
            evidence_mode = "raw_image_mounted"
            next_action = {
                "tool": "raw_image_triage_gate",
                "args": {"system_hive_path": "/c:/Windows/System32/config/SYSTEM"},
                "reason": "Selected disk image is mounted and no parsed case is loaded.",
            }
        else:
            evidence_mode = "raw_image_selected_unmounted"
            next_action = {
                "tool": "mount_image",
                "args": {"evidence_ref": "active_image"},
                "reason": "Use the user-selected allowlisted disk image; do not search for another case path.",
            }
    elif not parsed_loaded and len(allowed_images) > 1:
        evidence_mode = "multiple_raw_images_selected"
        next_action = {
            "tool": "mount_image",
            "args": {"evidence_ref": "<one selected image basename>"},
            "reason": "Multiple selected disk images exist; choose one from the allowlist, not from a filesystem scan.",
        }
    elif not parsed_loaded and allowed:
        evidence_mode = "selected_non_image_evidence"

    return {
        "evidence_mode": evidence_mode,
        "selected_evidence": {
            "allowlist_count": len(allowed),
            "allowed_image_count": len(allowed_images),
            "allowed_case_count": len(allowed_cases),
            "selected_image": selected_image,
        },
        "next_required_action": next_action,
        "enforcement": {
            "allowlisted_evidence_only": True,
            "do_not_search_workspace_for_replacement_evidence": True,
            "valid_selected_image_aliases": ["active_image", "loaded_image"],
        },
        "evidence_context": ctx,
    }


def _attach_selected_evidence_guidance(payload: dict[str, Any]) -> dict[str, Any]:
    guidance = _selected_evidence_guidance()
    if guidance.get("evidence_mode") in {
        "parsed_case_selected_unopened",
        "raw_image_selected_unmounted",
        "raw_image_mounted",
        "multiple_raw_images_selected",
        "selected_non_image_evidence",
    }:
        payload = dict(payload)
        payload["selected_evidence_guidance"] = guidance
    return payload


def _is_safe_local_analysis_path(path: str) -> bool:
    if not path:
        return False
    norm = os.path.normcase(os.path.abspath(path))
    root = os.path.normcase(os.path.abspath(_workspace_root()))
    output_root = os.path.normcase(os.path.abspath(_analysis_output_context(create=False)["root"]))

    def under(candidate: str, parent: str) -> bool:
        try:
            return os.path.commonpath([candidate, parent]) == parent
        except Exception:
            return False

    return is_path_allowed(path) or under(norm, root) or under(norm, output_root)


def _safe_artifact_filename(path: str, fallback: str = "artifact") -> str:
    name = os.path.basename(str(path).replace("\\", "/").rstrip("/")) or fallback
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    digest = hashlib.sha1(str(path).encode("utf-8", errors="ignore")).hexdigest()[:10]
    base, ext = os.path.splitext(name)
    return f"{base or fallback}_{digest}{ext}"


_DOCUMENT_CONTENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotx",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".hwp",
    ".hwpx",
    ".pdf",
    ".rtf",
    ".odt",
    ".ods",
    ".odp",
    ".txt",
    ".text",
    ".md",
}


def _is_document_content_path(path: str) -> bool:
    return os.path.splitext(str(path or "").replace("\\", "/").rstrip("/"))[1].lower() in _DOCUMENT_CONTENT_EXTENSIONS


def _document_content_reason(document_access_reason: str) -> str:
    return str(document_access_reason or "").strip()


def _document_content_access_allowed(document_access_approved: bool, document_access_reason: str) -> bool:
    return bool(document_access_approved) and bool(_document_content_reason(document_access_reason))


def _document_content_access_context(
    path: str,
    operation: str,
    source: str,
    document_access_reason: str,
) -> dict[str, Any]:
    ext = os.path.splitext(str(path or ""))[1].lower()
    return {
        "policy": "document_content_permissioned_access",
        "approved": True,
        "reason": _document_content_reason(document_access_reason),
        "operation": operation,
        "path": path,
        "extension": ext,
        "source": source,
        "scope": "limited extraction or static inspection only",
        "guardrails": {
            "default_blocked": True,
            "requires_explicit_analyst_approval": True,
            "document_body_minimization_required": True,
            "do_not_quote_full_document_content": True,
            "permission_is_not_a_verdict": True,
        },
    }


def _document_content_access_block(path: str, operation: str, source: str = "mounted_image") -> dict[str, Any]:
    ext = os.path.splitext(str(path or ""))[1].lower()
    return {
        "ok": False,
        "error": (
            "Document content access is blocked by default. Re-run with "
            "document_access_approved=True and a non-empty document_access_reason "
            "only when analyst approval exists."
        ),
        "blocked_by_policy": "document_content_no_open",
        "operation": operation,
        "path": path,
        "extension": ext,
        "source": source,
        "approval_required": True,
        "approval_parameters": {
            "document_access_approved": "boolean true after explicit analyst approval",
            "document_access_reason": "non-empty reason describing the narrow investigative need",
        },
        "allowed_alternatives": [
            "list_files for path/existence",
            "get_file_timestamps or vss_get_file_timestamps for timestamps",
            "metadata-only artifact searches that do not extract or display document body content",
        ],
        "policy_note": (
            "Document-like files such as DOCX/HWP/PDF/TXT are not extracted or read by default. "
            "Permissioned access is limited to the approved investigative purpose and is not a verdict."
        ),
    }


def _evidence_bound_export_path(subdir: str, internal_path: str, fallback: str) -> str:
    """Build an export path that is bound to the mounted evidence identity."""
    e01 = _connectors.get("e01")
    image_path = ""
    if e01 is not None and e01.is_connected():
        try:
            image_path = str(e01.get_metadata().get("image_path", ""))
        except Exception:
            image_path = ""
    out_dir = _analysis_output_dir(subdir)
    os.makedirs(out_dir, exist_ok=True)
    filename = _safe_artifact_filename(f"{image_path}::{internal_path}", fallback=fallback)
    fallback_ext = os.path.splitext(fallback)[1]
    if fallback_ext and not os.path.splitext(filename)[1]:
        filename = f"{filename}{fallback_ext}"
    return os.path.join(out_dir, filename)


def _materialize_local_artifact(
    path: str,
    subdir: str,
    document_access_approved: bool = False,
    document_access_reason: str = "",
    document_access_operation: str = "materialize_local_artifact",
) -> dict[str, Any]:
    """Return a local path for either a local file or a mounted-image path."""
    is_document = _is_document_content_path(path)
    if is_document and not _document_content_access_allowed(document_access_approved, document_access_reason):
        return {
            **_document_content_access_block(path, document_access_operation),
            "evidence_context": _evidence_context(path, "blocked_document_content", internal_path=path),
        }
    if os.path.exists(path):
        if not _is_safe_local_analysis_path(path):
            return {
                "ok": False,
                "error": build_not_allowed_message(path),
                "evidence_context": _evidence_context(path, "blocked_local_file", local_path=path),
            }
        local_path = os.path.abspath(path)
        result = {
            "ok": True,
            "source": "local_file",
            "local_path": local_path,
            "evidence_context": _evidence_context(path, "local_file", local_path=local_path),
        }
        if is_document:
            result["document_access"] = _document_content_access_context(
                path,
                document_access_operation,
                "local_file",
                document_access_reason,
            )
        return result

    e01 = _get_e01()
    out_dir = _analysis_output_dir(subdir)
    os.makedirs(out_dir, exist_ok=True)
    output_path = os.path.join(out_dir, _safe_artifact_filename(path))
    try:
        extraction = e01.extract_file(path, output_path)
    except Exception as e:
        return {
            "ok": False,
            "source": "mounted_image",
            "error": str(e),
            "evidence_context": _evidence_context(path, "mounted_image", internal_path=path),
        }
    result = {
        "ok": True,
        "source": "mounted_image",
        "local_path": extraction.get("output_path", output_path),
        "extraction": extraction,
        "analysis_output": _analysis_output_context(create=False),
        "evidence_context": _evidence_context(
            path,
            "mounted_image",
            local_path=extraction.get("output_path", output_path),
            internal_path=path,
        ),
    }
    if is_document:
        result["document_access"] = _document_content_access_context(
            path,
            document_access_operation,
            "mounted_image",
            document_access_reason,
        )
    return result


def _vss_snapshot_guardrails(total: int | None = None, parser_failures: list | None = None) -> dict[str, Any]:
    guardrail = {
        "evidence_role": "historical_filesystem_layer",
        "temporal_layer_required": True,
        "strong_conclusion_allowed": False,
        "absence_is_negative_evidence": False,
        "merge_with_current_fs_allowed": False,
        "vss_is_verified_clean_baseline": False,
        "bias_risks": [
            "cross_layer_merge_without_provenance",
            "vss_as_clean_baseline_assumption",
            "absence_as_negative_evidence",
        ],
        "interpretation": (
            "VSS results are historical snapshot observations. Keep them "
            "separate from current mounted-image results unless an explicit "
            "cross-layer comparison is performed."
        ),
    }
    if total == 0:
        guardrail["zero_result_guidance"] = (
            "0 matched records in a VSS snapshot means no parsed item matched "
            "this snapshot and filter. It does not prove the file or behavior "
            "never existed in other snapshots or the live layer."
        )
    if parser_failures:
        guardrail["parser_failure_guidance"] = (
            "Parser failures are VSS coverage gaps. Do not interpret failed "
            "snapshot parsing as absence of matching activity."
        )
    return guardrail


def _vss_file_coverage_for_directory(files: list[dict[str, Any]], snapshot_id: str) -> dict[str, Any]:
    failed = bool(files and "error" in files[0])
    coverage: dict[str, Any] = {
        "paths_attempted": 1,
        "paths_succeeded": 0 if failed else 1,
        "paths_skipped": 1 if failed else 0,
        "skip_reasons": {
            "access_denied": 0,
            "io_error": 0,
            "path_too_long": 0,
            "symlink": 0,
            "other": 1 if failed else 0,
        },
        "skipped_path_samples": files[:1] if failed else [],
        "truncated": False,
    }
    if failed:
        coverage["coverage_gap"] = f"1 paths unexamined in snapshot {snapshot_id}."
    return coverage


def _vss_context(snapshot: dict[str, Any], input_ref: str, local_path: str = "") -> dict[str, Any]:
    ctx = _evidence_context(
        input_ref,
        "vss_snapshot",
        local_path=local_path,
        internal_path=input_ref,
    )
    ctx["temporal_layer"] = snapshot.get("temporal_layer", "")
    ctx["snapshot_id"] = snapshot.get("snapshot_id", "")
    ctx["snapshot_index"] = snapshot.get("snapshot_index", "")
    ctx["snapshot_creation_time"] = snapshot.get("snapshot_creation_time", "")
    ctx["source_separation_note"] = (
        "VSS snapshot evidence must remain separate from current mounted-image "
        "evidence unless compared explicitly."
    )
    return ctx


def _vss_export_path(snapshot_id: str, subdir: str, internal_path: str, fallback: str) -> str:
    safe_snapshot = re.sub(r"[^A-Za-z0-9._-]", "_", str(snapshot_id or "snapshot"))
    out_dir = _analysis_output_dir("vss", safe_snapshot, subdir)
    os.makedirs(out_dir, exist_ok=True)
    e01 = _connectors.get("e01")
    image_path = ""
    if e01 is not None and e01.is_connected():
        try:
            image_path = str(e01.get_metadata().get("image_path", ""))
        except Exception:
            image_path = ""
    filename = _safe_artifact_filename(f"{image_path}::{snapshot_id}::{internal_path}", fallback=fallback)
    fallback_ext = os.path.splitext(fallback)[1]
    if fallback_ext and not os.path.splitext(filename)[1]:
        filename = f"{filename}{fallback_ext}"
    return os.path.join(out_dir, filename)


def _vss_unique_output_path(snapshot_id: str, subdir: str, internal_path: str, fallback: str) -> str:
    output_path = _vss_export_path(snapshot_id, subdir, internal_path, fallback)
    base, ext = os.path.splitext(output_path)
    counter = 1
    while os.path.exists(output_path):
        output_path = f"{base}_{counter}{ext}"
        counter += 1
    return output_path


def _vss_snapshot_export_root(snapshot_id: str, local_path: str = "") -> str:
    safe_snapshot = re.sub(r"[^A-Za-z0-9._-]", "_", str(snapshot_id or "snapshot"))
    if local_path:
        parts = os.path.abspath(local_path).split(os.sep)
        for idx, part in enumerate(parts):
            if part == safe_snapshot and idx > 0 and parts[idx - 1].lower() == "vss":
                return os.sep.join(parts[: idx + 1])
    return _analysis_output_dir("vss", safe_snapshot)


def _write_vss_quarantine_manifest(
    extraction: dict[str, Any],
    *,
    tool_name: str,
    purpose: str,
    source_path: str,
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append provenance for a VSS-extracted artifact without changing evidence."""
    try:
        snapshot_id = str(extraction.get("snapshot_id") or "snapshot")
        output_path = str(extraction.get("output_path") or "")
        root = _vss_snapshot_export_root(snapshot_id, output_path)
        os.makedirs(root, exist_ok=True)
        manifest_path = os.path.join(root, "manifest.json")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        e01 = _connectors.get("e01")
        meta: dict[str, Any] = {}
        if e01 is not None and e01.is_connected():
            try:
                meta = e01.get_metadata()
            except Exception:
                meta = {}
        image_path = str(meta.get("image_path", "") or "")
        image_identity = {
            "image_path": image_path,
            "image_basename": os.path.basename(image_path),
            "image_path_sha256": hashlib.sha256(image_path.encode("utf-8", errors="ignore")).hexdigest()
            if image_path else "",
            "hostname": meta.get("hostname", ""),
            "volumes": meta.get("volumes", []),
        }

        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = {}
        else:
            manifest = {}
        if not manifest:
            manifest = {
                "schema": "fw.vss_quarantine_manifest.v1",
                "created_at_utc": now,
                "snapshot": {
                    "snapshot_id": snapshot_id,
                    "snapshot_index": extraction.get("snapshot_index", ""),
                    "snapshot_creation_time": extraction.get("snapshot_creation_time", ""),
                    "temporal_layer": extraction.get("temporal_layer", ""),
                    "volume": extraction.get("volume", ""),
                },
                "image": image_identity,
                "analysis_output": _analysis_output_context(create=False),
                "entries": [],
                "interpretation_guardrails": {
                    "static_analysis_only": True,
                    "execute_allowed": False,
                    "vss_is_verified_clean_baseline": False,
                    "absence_is_negative_evidence": False,
                    "manifest_is_provenance_not_verdict": True,
                },
            }
        manifest["updated_at_utc"] = now
        manifest["image"] = image_identity or manifest.get("image", {})
        manifest["analysis_output"] = _analysis_output_context(create=False)

        rel_output = ""
        if output_path:
            rel_output = _analysis_relative_path(output_path)
        entry_basis = "|".join([
            snapshot_id,
            source_path,
            output_path,
            str(extraction.get("sha256", "")),
        ])
        entry = {
            "entry_id": hashlib.sha256(entry_basis.encode("utf-8", errors="ignore")).hexdigest()[:16],
            "tool_name": tool_name,
            "purpose": purpose,
            "extracted_at_utc": now,
            "source": {
                "type": "vss_snapshot",
                "path": source_path,
                "temporal_layer": extraction.get("temporal_layer", ""),
                "snapshot_id": snapshot_id,
                "snapshot_index": extraction.get("snapshot_index", ""),
                "snapshot_creation_time": extraction.get("snapshot_creation_time", ""),
                "volume": extraction.get("volume", ""),
            },
            "output": {
                "path": output_path,
                "relative_path": rel_output,
                "size": extraction.get("size", 0),
                "sha256": extraction.get("sha256", ""),
                "execute_allowed": bool(extraction.get("execute_allowed", False)),
            },
            "query": query or {},
            "safety": {
                "static_analysis_only": True,
                "execute_allowed": False,
                "warning": extraction.get("warning", "STATIC ANALYSIS ONLY - do not execute this file"),
            },
        }

        entries = [
            existing for existing in manifest.get("entries", [])
            if existing.get("entry_id") != entry["entry_id"]
        ]
        entries.append(entry)
        manifest["entries"] = entries

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        return {
            "ok": True,
            "manifest_path": manifest_path,
            "entry_id": entry["entry_id"],
            "entry_count": len(entries),
            "schema": manifest["schema"],
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "manifest_path": "",
        }


def _vss_snapshot_metadata_by_id(e01: Any, snapshot_id: str, volume: str = "/c:") -> dict[str, Any]:
    try:
        listing = e01.list_vss_snapshots(volume)
        token = str(snapshot_id or "").strip().lower()
        for snapshot in listing.get("snapshots", []) or []:
            aliases = {
                str(snapshot.get("snapshot_id", "")).lower(),
                str(snapshot.get("snapshot_index", "")).lower(),
                f"vss{snapshot.get('snapshot_index', '')}".lower(),
            }
            if token in aliases:
                return dict(snapshot)
    except Exception:
        pass
    return {
        "temporal_layer": f"vss:{snapshot_id}",
        "snapshot_id": snapshot_id,
        "snapshot_index": "",
        "snapshot_creation_time": "",
        "volume": volume,
        "integrity_note": "VSS contents are historical layers, not verified-clean baseline state.",
    }


def _vss_registry_hive_type(path: str) -> str:
    name = os.path.basename(str(path).replace("\\", "/").rstrip("/")).lower()
    if name == "ntuser.dat":
        return "NTUSER.DAT"
    if name == "usrclass.dat":
        return "UsrClass.dat"
    if name == "amcache.hve":
        return "Amcache.hve"
    upper = name.upper()
    if upper in {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}:
        return upper
    return "Unknown"


def _vss_user_from_hive_path(path: str) -> str:
    parts = str(path or "").replace("\\", "/").split("/")
    lowered = [part.lower() for part in parts]
    if "users" in lowered:
        idx = lowered.index("users")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _vss_hive_record(
    path: str,
    hive_type: str,
    snapshot: dict[str, Any],
    *,
    status: str,
    info: dict[str, Any] | None = None,
    source: str = "exact_path",
) -> dict[str, Any]:
    info = info or {}
    record = {
        "status": status,
        "source": source,
        "hive_type": hive_type,
        "path": path,
        "user": _vss_user_from_hive_path(path),
        "size": info.get("size", 0),
        "timestamps": {
            "created": info.get("created", ""),
            "modified": info.get("modified", ""),
            "accessed": info.get("accessed", ""),
            "$SI_created": info.get("$SI_created", ""),
            "$SI_modified": info.get("$SI_modified", ""),
            "$SI_mft_modified": info.get("$SI_mft_modified", ""),
            "$SI_accessed": info.get("$SI_accessed", ""),
            "$FN_created": info.get("$FN_created", ""),
            "$FN_modified": info.get("$FN_modified", ""),
        },
        **snapshot,
    }
    if info.get("error"):
        record["error"] = info.get("error")
    return record


def _vss_discover_registry_hives(
    e01: Any,
    snapshot_id: str,
    *,
    volume: str = "/c:",
    include_core_hives: bool = True,
    include_user_hives: bool = True,
    include_amcache: bool = True,
    user_filter: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    snapshot = _vss_snapshot_metadata_by_id(e01, snapshot_id, volume)
    hives: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    coverage: dict[str, Any] = {
        "exact_paths_checked": 0,
        "exact_paths_present": 0,
        "user_hive_searches": [],
        "paths_skipped": 0,
        "parser_failures": [],
        "truncated": False,
    }

    exact_candidates: list[tuple[str, str]] = []
    if include_core_hives:
        exact_candidates.extend([
            ("/c:/Windows/System32/config/SYSTEM", "SYSTEM"),
            ("/c:/Windows/System32/config/SOFTWARE", "SOFTWARE"),
            ("/c:/Windows/System32/config/SAM", "SAM"),
            ("/c:/Windows/System32/config/SECURITY", "SECURITY"),
            ("/c:/Windows/System32/config/DEFAULT", "DEFAULT"),
        ])
    if include_amcache:
        exact_candidates.append(("/c:/Windows/AppCompat/Programs/Amcache.hve", "Amcache.hve"))

    for path, hive_type in exact_candidates:
        coverage["exact_paths_checked"] += 1
        info = e01.vss_get_file_info(snapshot_id, path, volume=volume)
        if info.get("error"):
            missing.append(_vss_hive_record(path, hive_type, snapshot, status="missing", info=info))
            continue
        coverage["exact_paths_present"] += 1
        hives.append(_vss_hive_record(path, hive_type, snapshot, status="present", info=info))

    if include_user_hives:
        max_per_search = max(1, int(limit or 1))
        for pattern, hive_type in (("NTUSER.DAT", "NTUSER.DAT"), ("UsrClass.dat", "UsrClass.dat")):
            if hasattr(e01, "vss_find_files_with_coverage"):
                search_result = e01.vss_find_files_with_coverage(
                    snapshot_id,
                    pattern,
                    path="/c:/Users",
                    volume=volume,
                    limit=max_per_search,
                )
                files = search_result.get("files", []) or []
                search_coverage = search_result.get("coverage", {}) or {}
            else:
                files = e01.vss_find_files(snapshot_id, pattern, path="/c:/Users", volume=volume, limit=max_per_search)
                search_coverage = _vss_file_coverage_for_directory(files, snapshot_id)
            coverage["user_hive_searches"].append({
                "pattern": pattern,
                "returned": len(files),
                "coverage": search_coverage,
            })
            coverage["paths_skipped"] += int(search_coverage.get("paths_skipped", 0) or 0)
            coverage["parser_failures"].extend(search_coverage.get("skipped_path_samples", []) or [])
            coverage["truncated"] = bool(coverage["truncated"] or search_coverage.get("truncated"))
            for item in files:
                if item.get("error") or item.get("is_dir"):
                    continue
                path = str(item.get("path", ""))
                if user_filter and user_filter.lower() not in _vss_user_from_hive_path(path).lower():
                    continue
                hives.append(_vss_hive_record(path, hive_type, snapshot, status="present", info=item, source="user_search"))

    seen: set[tuple[str, str]] = set()
    deduped = []
    for hive in hives:
        key = (str(hive.get("hive_type", "")), str(hive.get("path", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hive)
    return {
        "snapshot": snapshot,
        "hives": deduped[: max(0, int(limit or 0))],
        "missing_hives": missing,
        "coverage": coverage,
    }


def _normalize_registry_key_path(key_path: str, hive_path: str = "") -> str:
    key = str(key_path or "").strip().replace("/", "\\")
    if not key:
        return ""
    while "\\\\" in key:
        key = key.replace("\\\\", "\\")
    lower = key.lower()
    prefixes = [
        "hkey_local_machine\\system\\",
        "hklm\\system\\",
        "computer\\hkey_local_machine\\system\\",
        "hkey_current_user\\",
        "hkcu\\",
        "hkey_local_machine\\software\\",
        "hklm\\software\\",
    ]
    for prefix in prefixes:
        if lower.startswith(prefix):
            key = key[len(prefix):]
            break
    key = "\\" + key.lstrip("\\")
    if "\\currentcontrolset\\" in key.lower() and hive_path:
        current = _current_control_set_name(hive_path)
        if current:
            key = re.sub(
                r"\\CurrentControlSet\\",
                lambda _m: f"\\{current}\\",
                key,
                flags=re.IGNORECASE,
            )
    return key


def _current_control_set_name(hive_path: str) -> str:
    try:
        from regipy.registry import RegistryHive
        hive = RegistryHive(hive_path)
        select = hive.get_key("\\Select")
        values = []
        try:
            values = list(select.iter_values())
        except Exception:
            values = list(getattr(select, "values", []) or [])
        for value in values:
            if str(value.name).lower() == "current":
                return f"ControlSet{int(value.value):03d}"
    except Exception:
        return ""
    return ""


def _search_registry_subtree(
    hive_path: str,
    root_key_path: str,
    keyword: str,
    *,
    limit: int = 100,
    offset: int = 0,
    max_scan_keys: int = 10000,
) -> dict[str, Any]:
    """Bounded registry subtree search.

    This avoids whole-hive scans from raw MCP calls. Whole-hive keyword search
    is both slow on large SYSTEM/SOFTWARE hives and easy to misread as strong
    negative evidence when it times out or stops early.
    """
    from regipy.registry import RegistryHive
    from core.connectors.registry import _iter_registry_values

    safe_limit = max(0, int(limit or 0))
    safe_offset = max(0, int(offset or 0))
    safe_max = max(1, int(max_scan_keys or 1))
    kw_lower = str(keyword or "").lower()
    if not kw_lower:
        return {"error": "keyword is required for registry subtree search"}

    hive = RegistryHive(hive_path)
    try:
        root = hive.get_key(root_key_path)
    except Exception as e:
        return {"error": f"Search root not found or error: {e}", "root_key_path": root_key_path}

    stack: list[tuple[Any, str]] = [(root, root_key_path)]
    visited = 0
    matched_total = 0
    entries: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    while stack and visited < safe_max:
        key, path = stack.pop()
        visited += 1

        values: list[dict[str, str]] = []
        matched_fields: list[str] = []
        if kw_lower in path.lower():
            matched_fields.append("path")
        try:
            raw_values = _iter_registry_values(key)
        except Exception as e:
            raw_values = []
            failures.append({"path": path, "stage": "values", "error": str(e)})
        for value in raw_values:
            name = str(getattr(value, "name", ""))
            value_type = str(getattr(value, "value_type", ""))
            value_text = str(getattr(value, "value", ""))[:500]
            if kw_lower in name.lower():
                matched_fields.append(f"value_name:{name}")
            if kw_lower in value_text.lower():
                matched_fields.append(f"value_data:{name}")
            values.append({"name": name, "type": value_type, "value": value_text})

        if matched_fields:
            matched_total += 1
            if matched_total > safe_offset and len(entries) < safe_limit:
                timestamp = ""
                try:
                    timestamp = str(key.header.last_modified)
                except Exception:
                    pass
                entries.append({
                    "path": path,
                    "timestamp": timestamp,
                    "values_count": len(values),
                    "values": values[:10],
                    "matched_fields": matched_fields[:20],
                })

        try:
            subkeys = list(key.iter_subkeys()) if hasattr(key, "iter_subkeys") else []
        except Exception as e:
            subkeys = []
            failures.append({"path": path, "stage": "subkeys", "error": str(e)})
        for subkey in reversed(subkeys):
            name = str(getattr(subkey, "name", ""))
            parent_path = path.rstrip("\\")
            child_path = f"{parent_path}\\{name}" if path != "\\" else f"\\{name}"
            stack.append((subkey, child_path))

    scan_truncated = bool(stack)
    result = {
        "total": matched_total,
        "returned": len(entries),
        "entries": entries,
        "root_key_path": root_key_path,
        "visited_keys": visited,
        "max_scan_keys": safe_max,
        "scan_truncated": scan_truncated,
        "parse_failures": failures[:50],
        "parse_failure_count": len(failures),
    }
    if scan_truncated:
        result["coverage_warnings"] = [
            (
                "Registry subtree scan stopped at max_scan_keys before exhausting the root. "
                "Treat 0 or low matches as incomplete coverage, not absence of the key/value."
            )
        ]
    return result


def _hash_local_file(path: str) -> dict[str, str]:
    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def _powershell_pe_metadata(path: str) -> dict[str, Any]:
    if os.name != "nt":
        return {"errors": ["Authenticode/version metadata requires Windows PowerShell on this host."]}
    script = r"""
$Path = $env:FW_PE_INSPECT_PATH
$Item = Get-Item -LiteralPath $Path -ErrorAction Stop
$Sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
$VI = $Item.VersionInfo
[PSCustomObject]@{
  authenticode = [PSCustomObject]@{
    status = [string]$Sig.Status
    status_message = [string]$Sig.StatusMessage
    signer_subject = if ($Sig.SignerCertificate) { [string]$Sig.SignerCertificate.Subject } else { "" }
    signer_issuer = if ($Sig.SignerCertificate) { [string]$Sig.SignerCertificate.Issuer } else { "" }
    signer_thumbprint = if ($Sig.SignerCertificate) { [string]$Sig.SignerCertificate.Thumbprint } else { "" }
  }
  version_info = [PSCustomObject]@{
    file_description = [string]$VI.FileDescription
    original_filename = [string]$VI.OriginalFilename
    internal_name = [string]$VI.InternalName
    product_name = [string]$VI.ProductName
    company_name = [string]$VI.CompanyName
    file_version = [string]$VI.FileVersion
    product_version = [string]$VI.ProductVersion
  }
} | ConvertTo-Json -Depth 5
"""
    env = dict(os.environ)
    env["FW_PE_INSPECT_PATH"] = path
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=env,
        )
    except Exception as e:
        return {"errors": [str(e)]}
    if proc.returncode != 0:
        return {"errors": [proc.stderr.strip() or f"PowerShell exited {proc.returncode}"]}
    try:
        return json.loads(proc.stdout or "{}")
    except Exception as e:
        return {"errors": [f"Failed to parse PowerShell metadata JSON: {e}"], "raw_stdout": proc.stdout[:500]}


def _raw_artifact_guardrails(
    artifact_type: str,
    *,
    total: int | None = None,
    parser_failures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Bias guardrails for raw artifact extraction tools.

    These tools expose observations, not incident verdicts. Keep this block
    close to every raw-artifact result so consumers do not have to remember the
    caveats from a separate document.
    """
    kind = artifact_type.lower()
    templates: dict[str, dict[str, Any]] = {
        "evtx": {
            "artifact_label": "offline Windows event log",
            "corroboration_required": [
                "registry/file artifacts for persistence claims",
                "process execution artifacts for execution claims",
                "coverage and parser failure review before treating 0 hits as meaningful",
            ],
            "bias_risks": ["absence_as_negative_evidence", "event_log_availability_bias", "date_filter_tunnel_vision"],
        },
        "prefetch": {
            "artifact_label": "Windows Prefetch",
            "corroboration_required": [
                "file timestamps or MFT evidence",
                "SRUM, AmCache, EVTX process/service context, or application logs",
                "host policy check because Prefetch can be disabled or cleaned",
            ],
            "bias_risks": ["execution_overstatement", "referenced_path_overstatement", "absence_as_negative_evidence"],
        },
        "registry": {
            "artifact_label": "offline registry hive",
            "corroboration_required": [
                "hive/control-set coverage review",
                "file timestamps for payload paths",
                "EVTX/service/task context where available",
            ],
            "bias_risks": ["configuration_equals_execution", "lastwrite_equals_creation", "controlset_tunnel_vision"],
        },
        "pe": {
            "artifact_label": "static PE metadata",
            "corroboration_required": [
                "file timestamps and source path",
                "execution or load evidence",
                "signature-chain validation and static/dynamic malware analysis when needed",
            ],
            "bias_risks": ["unsigned_equals_malicious", "signed_equals_benign", "versioninfo_keyword_anchoring"],
        },
    }
    tmpl = templates.get(kind, {"artifact_label": artifact_type, "corroboration_required": [], "bias_risks": []})
    guardrail = {
        "evidence_role": "extraction_only",
        "artifact_label": tmpl["artifact_label"],
        "strong_conclusion_allowed": False,
        "absence_is_negative_evidence": False,
        "bias_risks": tmpl["bias_risks"],
        "corroboration_required": tmpl["corroboration_required"],
        "interpretation": (
            "This tool returns raw/offline artifact observations. Treat them as leads "
            "to verify, not as a standalone incident conclusion."
        ),
    }
    if total == 0:
        guardrail["zero_result_guidance"] = (
            "0 matched records means no parsed item matched this source and filter. "
            "It does not prove the behavior did not occur. Recheck source coverage, "
            "parser failures, date filters, alternate artifacts, and whether the "
            "artifact family was disabled or cleaned."
        )
    if parser_failures:
        guardrail["parser_failure_guidance"] = (
            "Parser failures are coverage gaps. Do not interpret failed parsing as "
            "absence of matching activity."
        )
    return guardrail


def _get_ghidra() -> GhidraConnector:
    c = _connectors.get("ghidra")
    if c and c.is_connected():
        return c
    raise RuntimeError("바이너리가 로드되지 않았습니다. analyze_binary를 먼저 실행하세요.")


def _get_vol() -> VolatilityConnector:
    c = _connectors.get("volatility")
    if c and c.is_connected():
        return c
    raise RuntimeError("메모리 덤프가 로드되지 않았습니다. vol_load_memory를 먼저 실행하세요.")


@mcp.tool()
async def mount_image(e01_path: str = "", evidence_ref: str = "") -> dict:
    """Mount E01/VM/raw disk image for file extraction."""
    def fn():
        ref = evidence_ref or e01_path
        resolved = resolve_image_evidence(ref)
        resolved_path = resolved.get("path") or e01_path
        if not (is_path_allowed(resolved_path) or resolve_active_case_evidence(resolved_path)):
            return {"error": build_not_allowed_message(ref or "active_case")}
        old = _connectors.pop("e01", None)
        if old:
            old.disconnect()
        c = E01ImageConnector()
        meta = c.connect(resolved_path)
        _connectors["e01"] = c
        return _mask({
            "status": "mounted",
            "resolved_from": resolved.get("source") or ref or "active_image",
            **meta,
            "evidence_context": _evidence_context(ref, "mounted_image", local_path=resolved_path),
        })
    return await _traced("mount_image", {"e01_path": e01_path, "evidence_ref": evidence_ref}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def compare_case_image_entity(
    entity_value: str,
    start_date: str = "",
    end_date: str = "",
    limit_case_hits: int = 50,
    image_path_hints: str = "",
) -> dict:
    """Compare MFDB artifact hits with mounted-image file presence for one entity.

    Deterministic composition:
    - searches the active MFDB case for ``entity_value``
    - extracts exact Windows file paths already present in hit fields
    - revalidates those exact paths against the mounted image

    No broad disk scan is performed. Optional ``image_path_hints`` may provide
    extra exact Windows paths (comma-separated) to revalidate.
    """
    params = {
        "entity_value": entity_value,
        "start_date": start_date,
        "end_date": end_date,
        "limit_case_hits": limit_case_hits,
        "image_path_hints": image_path_hints,
    }
    def fn():
        axiom = _get_axiom()
        e01 = _get_e01()
        search_result = axiom.search(
            keyword=entity_value,
            filters={"start_date": start_date, "end_date": end_date},
            limit=limit_case_hits,
            offset=0,
        )
        hits = search_result.get("hits", []) or []
        candidates = _candidate_disk_paths_from_hits(entity_value, hits)
        for hint in [x.strip() for x in image_path_hints.split(",") if x.strip()]:
            if hint not in candidates:
                candidates.append(hint)

        disk_checks = []
        for path in candidates:
            info = e01.get_file_info(path)
            disk_checks.append({
                "path": path,
                "present_on_disk": "error" not in info,
                "file_info": info,
            })

        artifact_types = sorted({h.get("artifact_type", "") for h in hits if h.get("artifact_type")})
        present = [x for x in disk_checks if x["present_on_disk"]]
        missing = [x for x in disk_checks if not x["present_on_disk"]]
        return _mask({
            "entity_value": entity_value,
            "mfdb": {
                "total_hits": search_result.get("total") or search_result.get("total_estimated", 0),
                "returned_hits": len(hits),
                "artifact_types": artifact_types,
                "candidate_paths": candidates,
            },
            "mounted_image": {
                "checked_paths": len(disk_checks),
                "present_count": len(present),
                "missing_count": len(missing),
                "disk_checks": disk_checks,
            },
            "joined_assessment": {
                "has_artifact_history": bool(hits),
                "has_current_disk_presence": bool(present),
                "executed_then_missing_suspected": bool(hits) and not bool(present) and bool(candidates),
            },
        })
    return await _traced("compare_case_image_entity", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def list_files(path: str = "/", pattern: str = "") -> dict:
    """List or search files inside mounted disk image."""
    params = {"path": path, "pattern": pattern}
    def fn():
        e01 = _get_e01()
        if pattern:
            files = e01.find_files(pattern, path, limit=100)
        else:
            files = e01.list_directory(path)
        return _mask({"path": path, "pattern": pattern, "count": len(files), "files": files})
    return await _traced("list_files", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def extract_file(
    internal_path: str,
    output_dir: str = "",
    document_access_approved: bool = False,
    document_access_reason: str = "",
) -> dict:
    """Extract a file from mounted disk image for STATIC ANALYSIS ONLY.

    Document-like files are blocked by default. To extract one, pass
    document_access_approved=True with a non-empty document_access_reason
    after explicit analyst approval. Extracted files may be malware; never
    execute them.
    """
    def fn():
        is_document = _is_document_content_path(internal_path)
        if is_document and not _document_content_access_allowed(document_access_approved, document_access_reason):
            return _mask({
                **_document_content_access_block(internal_path, "extract_file"),
                "evidence_context": _evidence_context(internal_path, "blocked_document_content", internal_path=internal_path),
                "interpretation_guardrails": _raw_artifact_guardrails("file_extract", total=0),
            })
        e01 = _get_e01()
        out_dir = output_dir or _analysis_output_dir("extract")
        # Build safe output filename from internal path
        safe_name = internal_path.replace("\\", "/").split("/")[-1]
        output_path = os.path.join(out_dir, safe_name)
        # Avoid overwriting: add suffix if exists
        base, ext = os.path.splitext(output_path)
        counter = 1
        while os.path.exists(output_path):
            output_path = f"{base}_{counter}{ext}"
            counter += 1
        result = e01.extract_file(internal_path, output_path)
        result["analysis_output"] = _analysis_output_context(create=False)
        if is_document:
            result["document_access"] = _document_content_access_context(
                internal_path,
                "extract_file",
                "mounted_image",
                document_access_reason,
            )
            result["guardrails"] = {
                **result.get("guardrails", {}),
                "static_analysis_only": True,
                "document_body_minimization_required": True,
                "permission_is_not_a_verdict": True,
            }
        return _mask(result)
    return await _traced(
        "extract_file",
        {
            "internal_path": internal_path,
            "output_dir": output_dir,
            "document_access_approved": document_access_approved,
            "document_access_reason_present": bool(_document_content_reason(document_access_reason)),
        },
        fn,
    )


@mcp.tool()
async def get_file_timestamps(internal_path: str) -> dict:
    """Get full NTFS timestamps for a file in mounted disk image.

    Returns $STANDARD_INFORMATION and $FILE_NAME timestamps separately.
    Critical for forensic verification: $SI timestamps can be tampered
    (timestomping) but $FN timestamps are harder to forge.

    Use this BEFORE drawing conclusions about when a file was created or
    placed on the system. Prefetch/ShimCache alone are not sufficient to
    establish file creation time.

    Args:
        internal_path: File path inside mounted image (e.g. /c:/ProgramData/USOShared/task.vbs)
    """
    params = {"internal_path": internal_path}
    def fn():
        e01 = _get_e01()
        info = e01.get_file_info(internal_path)
        if "error" in info:
            return info
        result = {
            "path": info.get("path", internal_path),
            "size": info.get("size", 0),
            "timestamps": {},
            "forensic_notes": [],
        }
        ts = result["timestamps"]
        notes = result["forensic_notes"]

        # Standard timestamps
        ts["created"] = info.get("created", "")
        ts["modified"] = info.get("modified", "")
        ts["accessed"] = info.get("accessed", "")

        # MFT-level timestamps if available
        if "$SI_created" in info:
            ts["$SI_created"] = info["$SI_created"]
            ts["$SI_modified"] = info.get("$SI_modified", "")
            ts["$SI_mft_modified"] = info.get("$SI_mft_modified", "")
            ts["$SI_accessed"] = info.get("$SI_accessed", "")
        if "$FN_created" in info:
            ts["$FN_created"] = info["$FN_created"]
            ts["$FN_modified"] = info.get("$FN_modified", "")

        # Forensic analysis notes
        si_c = ts.get("$SI_created", "") or ts.get("created", "")
        fn_c = ts.get("$FN_created", "")
        si_m = ts.get("$SI_modified", "") or ts.get("modified", "")

        if si_c and si_m and si_c > si_m:
            notes.append("ANOMALY: Created > Modified — possible timestomping or file copy")
        if si_c and fn_c and si_c != fn_c:
            notes.append(f"$SI and $FN creation times differ — possible timestomping ($SI={si_c}, $FN={fn_c})")
        if not notes:
            notes.append("No timestamp anomalies detected")

        return _mask(result)
    return await _traced("get_file_timestamps", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def list_vss_snapshots(volume: str = "/c:") -> dict:
    """List VSS snapshots in the mounted image.

    Reading guide for AI consumers:
        - VSS snapshots are historical layers, not a verified-clean baseline.
        - Keep VSS results separate from current mounted-image results.
        - An empty or unreadable VSS catalog is a coverage gap, not evidence
          that deleted files or historical logs never existed.
    """
    params = {"volume": volume}

    def fn():
        e01 = _get_e01()
        result = e01.list_vss_snapshots(volume)
        result["source"] = "mounted_image_vss"
        result["evidence_context"] = _evidence_context(volume, "vss_catalog", internal_path=volume)
        result["interpretation_guardrails"] = _vss_snapshot_guardrails(
            total=int(result.get("snapshot_count", 0) or 0)
        )
        return _mask(result)

    return await _traced("list_vss_snapshots", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_list_files(
    snapshot_id: str,
    path: str = "/",
    pattern: str = "",
    volume: str = "/c:",
    limit: int = 100,
) -> dict:
    """List or search files inside one VSS snapshot.

    Results describe only the selected snapshot's historical layer. A missing
    file in one snapshot does not prove it never existed. The coverage block
    reports unreadable paths as coverage gaps even when matches are returned.
    """
    params = {
        "snapshot_id": snapshot_id,
        "path": path,
        "pattern": pattern,
        "volume": volume,
        "limit": limit,
    }

    def fn():
        e01 = _get_e01()
        if pattern:
            if hasattr(e01, "vss_find_files_with_coverage"):
                search_result = e01.vss_find_files_with_coverage(
                    snapshot_id,
                    pattern,
                    path=path,
                    volume=volume,
                    limit=max(1, limit),
                )
                files = search_result.get("files", [])
                coverage = search_result.get("coverage", {})
            else:
                files = e01.vss_find_files(snapshot_id, pattern, path=path, volume=volume, limit=max(1, limit))
                coverage = _vss_file_coverage_for_directory(files, snapshot_id)
        else:
            files = e01.vss_list_directory(snapshot_id, path, volume=volume)
            files = files[:max(0, limit)]
            coverage = _vss_file_coverage_for_directory(files, snapshot_id)
        first = files[0] if files else {}
        snapshot = {k: first.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        if not snapshot.get("snapshot_id"):
            info = e01.vss_get_file_info(snapshot_id, path, volume=volume)
            snapshot = {k: info.get(k, "") for k in (
                "temporal_layer",
                "snapshot_id",
                "snapshot_index",
                "snapshot_creation_time",
                "volume",
                "integrity_note",
            )}
        return _mask({
            "ok": not any("error" in item for item in files[:1]),
            "source": "vss_snapshot",
            "path": path,
            "pattern": pattern,
            "count": len(files),
            "files": files,
            "coverage": coverage,
            **snapshot,
            "evidence_context": _vss_context(snapshot, path),
            "interpretation_guardrails": _vss_snapshot_guardrails(
                total=len(files),
                parser_failures=coverage.get("skipped_path_samples", []),
            ),
        })

    return await _traced("vss_list_files", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_get_file_timestamps(
    snapshot_id: str,
    internal_path: str,
    volume: str = "/c:",
) -> dict:
    """Get NTFS timestamps for a file inside one VSS snapshot.

    These timestamps belong to the selected snapshot layer. Compare with
    current-FS timestamps only when both layers are named.
    """
    params = {"snapshot_id": snapshot_id, "internal_path": internal_path, "volume": volume}

    def fn():
        e01 = _get_e01()
        info = e01.vss_get_file_info(snapshot_id, internal_path, volume=volume)
        snapshot = {k: info.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        if "error" in info:
            return _mask({
                **info,
                "ok": False,
                "source": "vss_snapshot",
                "evidence_context": _vss_context(snapshot, internal_path),
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })

        result = {
            "ok": True,
            "source": "vss_snapshot",
            "path": info.get("path", internal_path),
            "size": info.get("size", 0),
            "timestamps": {},
            "forensic_notes": [],
            **snapshot,
        }
        ts = result["timestamps"]
        notes = result["forensic_notes"]
        ts["created"] = info.get("created", "")
        ts["modified"] = info.get("modified", "")
        ts["accessed"] = info.get("accessed", "")
        if info.get("$SI_created"):
            ts["$SI_created"] = info["$SI_created"]
            ts["$SI_modified"] = info.get("$SI_modified", "")
            ts["$SI_mft_modified"] = info.get("$SI_mft_modified", "")
            ts["$SI_accessed"] = info.get("$SI_accessed", "")
        if info.get("$FN_created"):
            ts["$FN_created"] = info["$FN_created"]
            ts["$FN_modified"] = info.get("$FN_modified", "")
        si_c = ts.get("$SI_created", "") or ts.get("created", "")
        fn_c = ts.get("$FN_created", "")
        si_m = ts.get("$SI_modified", "") or ts.get("modified", "")
        if si_c and si_m and si_c > si_m:
            notes.append("ANOMALY: Created > Modified - possible timestomping or file copy")
        if si_c and fn_c and si_c != fn_c:
            notes.append(f"$SI and $FN creation times differ - possible timestomping ($SI={si_c}, $FN={fn_c})")
        if not notes:
            notes.append("No timestamp anomalies detected in this VSS snapshot")
        result["evidence_context"] = _vss_context(snapshot, internal_path)
        result["interpretation_guardrails"] = _vss_snapshot_guardrails()
        return _mask(result)

    return await _traced("vss_get_file_timestamps", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def vss_extract_file(
    snapshot_id: str,
    internal_path: str,
    output_dir: str = "",
    volume: str = "/c:",
    document_access_approved: bool = False,
    document_access_reason: str = "",
) -> dict:
    """Extract a file from one VSS snapshot for STATIC ANALYSIS ONLY.

    VSS extractions are placed under
    forensic-workstation-output/vss/<snapshot_id>/... beside the selected
    evidence by default, so current-FS and historical-layer files cannot
    silently overwrite each other. Document-like files are blocked by default
    and require explicit analyst approval plus a non-empty
    document_access_reason. A manifest.json is updated in the snapshot export
    root for report provenance. Extracted files may be malware; never execute
    them.
    """
    params = {
        "snapshot_id": snapshot_id,
        "internal_path": internal_path,
        "output_dir": output_dir,
        "volume": volume,
        "document_access_approved": document_access_approved,
        "document_access_reason_present": bool(_document_content_reason(document_access_reason)),
    }

    def fn():
        is_document = _is_document_content_path(internal_path)
        if is_document and not _document_content_access_allowed(document_access_approved, document_access_reason):
            snapshot = _vss_snapshot_metadata_by_id(_get_e01(), snapshot_id, volume)
            return _mask({
                **_document_content_access_block(internal_path, "vss_extract_file", source="vss_snapshot"),
                "evidence_context": _vss_context(snapshot, internal_path),
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })
        if output_dir:
            safe_snapshot = re.sub(r"[^A-Za-z0-9._-]", "_", snapshot_id)
            out_root = os.path.join(os.path.abspath(output_dir), "vss", safe_snapshot)
            if not _is_safe_local_analysis_path(out_root):
                return {"ok": False, "error": build_not_allowed_message(out_root)}
            os.makedirs(out_root, exist_ok=True)
            output_path = os.path.join(out_root, _safe_artifact_filename(internal_path))
            base, ext = os.path.splitext(output_path)
            counter = 1
            while os.path.exists(output_path):
                output_path = f"{base}_{counter}{ext}"
                counter += 1
        else:
            fallback = internal_path.replace("\\", "/").rstrip("/").split("/")[-1] or "artifact"
            output_path = _vss_unique_output_path(snapshot_id, "extract", internal_path, fallback)
        e01 = _get_e01()
        result = e01.vss_extract_file(snapshot_id, internal_path, output_path, volume=volume)
        snapshot = {k: result.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        manifest = _write_vss_quarantine_manifest(
            result,
            tool_name="vss_extract_file",
            purpose="manual_static_analysis_extract",
            source_path=internal_path,
            query={"volume": volume},
        )
        result.update({
            "ok": True,
            "evidence_context": _vss_context(snapshot, internal_path, local_path=result.get("output_path", "")),
            "analysis_output": _analysis_output_context(create=False),
            "quarantine_manifest": manifest,
            "interpretation_guardrails": _vss_snapshot_guardrails(),
        })
        if is_document:
            result["document_access"] = _document_content_access_context(
                internal_path,
                "vss_extract_file",
                "vss_snapshot",
                document_access_reason,
            )
            result["guardrails"] = {
                **result.get("guardrails", {}),
                "static_analysis_only": True,
                "document_body_minimization_required": True,
                "permission_is_not_a_verdict": True,
            }
        return _mask(result)

    return await _traced("vss_extract_file", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_query_evtx_file(
    snapshot_id: str,
    evtx_path: str,
    event_ids: str = "",
    keyword: str = "",
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
    volume: str = "/c:",
) -> dict:
    """Parse and query an EVTX file from one VSS snapshot.

    Use this to check historical event logs after live logs were cleared.
    Empty results are snapshot/filter observations, not proof of absence.
    The recovery block reports chunk-level parse gaps and bounded best-effort
    recovery attempts for partially corrupt snapshot logs.
    """
    params = {
        "snapshot_id": snapshot_id,
        "evtx_path": evtx_path,
        "event_ids": event_ids,
        "keyword": keyword,
        "start_date": start_date,
        "end_date": end_date,
        "limit": limit,
        "offset": offset,
        "volume": volume,
    }

    def fn():
        from core.analysis.evtx_semantic import (
            filter_evtx_records as _filter_evtx_records,
            parse_evtx_file as _parse_evtx_file,
        )

        ids: set[int] = set()
        for part in event_ids.split(","):
            part = part.strip()
            if part:
                try:
                    ids.add(int(part))
                except ValueError:
                    return {"ok": False, "error": f"Invalid event id: {part}"}

        fallback = evtx_path.replace("\\", "/").rstrip("/").split("/")[-1] or "eventlog.evtx"
        local_path = _vss_unique_output_path(snapshot_id, "evtx_query", evtx_path, fallback)
        e01 = _get_e01()
        extraction = e01.vss_extract_file(snapshot_id, evtx_path, local_path, volume=volume)
        snapshot = {k: extraction.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        manifest = _write_vss_quarantine_manifest(
            extraction,
            tool_name="vss_query_evtx_file",
            purpose="evtx_query_source_extract",
            source_path=evtx_path,
            query={
                "event_ids": event_ids,
                "keyword": keyword,
                "start_date": start_date,
                "end_date": end_date,
                "limit": limit,
                "offset": offset,
                "volume": volume,
            },
        )
        parsed = _parse_evtx_file(local_path, target_event_ids=ids or None, limit=0, best_effort=True)
        parser_failures = (parsed.get("parser_failures", []) or []) + (
            (parsed.get("recovery", {}) or {}).get("parser_failures", []) or []
        )
        if not parsed.get("ok"):
            return _mask({
                **parsed,
                "source": "vss_snapshot",
                "evtx_path": evtx_path,
                "local_path": local_path,
                "quarantine_manifest": manifest,
                **snapshot,
                "evidence_context": _vss_context(snapshot, evtx_path, local_path=local_path),
                "interpretation_guardrails": _vss_snapshot_guardrails(
                    total=0,
                    parser_failures=parser_failures,
                ),
            })
        filtered = _filter_evtx_records(
            parsed.get("records", []) or [],
            event_ids=ids or None,
            keyword=keyword,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )
        return _mask({
            "ok": True,
            "source": "vss_snapshot",
            "evtx_path": evtx_path,
            "local_path": local_path,
            "quarantine_manifest": manifest,
            **snapshot,
            "evidence_context": _vss_context(snapshot, evtx_path, local_path=local_path),
            "parsed_record_count": parsed.get("record_count", 0),
            "event_id_counts_in_file": parsed.get("event_id_counts", {}),
            "parser_failures": parsed.get("parser_failures", []),
            "recovery": parsed.get("recovery", {}),
            "interpretation_guardrails": _vss_snapshot_guardrails(
                total=filtered.get("total", 0),
                parser_failures=parser_failures,
            ),
            **filtered,
        })

    return await _traced("vss_query_evtx_file", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_query_registry_hive(
    snapshot_id: str,
    hive_path: str,
    key_path: str = "",
    keyword: str = "",
    search_root: str = "",
    limit: int = 100,
    offset: int = 0,
    max_scan_keys: int = 10000,
    volume: str = "/c:",
) -> dict:
    """Query a registry hive extracted from one VSS snapshot.

    Registry state belongs to the selected snapshot layer. LastWrite proves
    key state at capture/snapshot time, not original creation unless supported
    by other artifacts.
    """
    params = {
        "snapshot_id": snapshot_id,
        "hive_path": hive_path,
        "key_path": key_path,
        "keyword": keyword,
        "search_root": search_root,
        "limit": limit,
        "offset": offset,
        "max_scan_keys": max_scan_keys,
        "volume": volume,
    }

    def fn():
        from core.connectors.registry import RegistryConnector

        fallback = hive_path.replace("\\", "/").rstrip("/").split("/")[-1] or "hive"
        local_hive = _vss_unique_output_path(snapshot_id, "registry_query", hive_path, fallback)
        e01 = _get_e01()
        extraction = e01.vss_extract_file(snapshot_id, hive_path, local_hive, volume=volume)
        snapshot = {k: extraction.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        manifest = _write_vss_quarantine_manifest(
            extraction,
            tool_name="vss_query_registry_hive",
            purpose="registry_query_source_extract",
            source_path=hive_path,
            query={
                "key_path": key_path,
                "keyword": keyword,
                "search_root": search_root,
                "limit": limit,
                "offset": offset,
                "max_scan_keys": max_scan_keys,
                "volume": volume,
            },
        )
        if not key_path and keyword and not search_root:
            return _mask({
                "ok": False,
                "error": "keyword search requires search_root or key_path to avoid whole-hive scans",
                "source": "vss_snapshot",
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "quarantine_manifest": manifest,
                **snapshot,
                "evidence_context": _vss_context(snapshot, hive_path, local_path=local_hive),
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })
        if not key_path and not keyword:
            return _mask({
                "ok": False,
                "error": "Provide key_path for direct extraction or keyword plus search_root for bounded search.",
                "source": "vss_snapshot",
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "quarantine_manifest": manifest,
                **snapshot,
                "evidence_context": _vss_context(snapshot, hive_path, local_path=local_hive),
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })
        c = RegistryConnector()
        meta = c.connect(local_hive)
        try:
            resolved_key = _normalize_registry_key_path(key_path, local_hive)
            if resolved_key:
                result = c.get_key(resolved_key)
                result.update({
                    "ok": "error" not in result,
                    "source": "vss_snapshot",
                    "hive_path": hive_path,
                    "local_hive_path": local_hive,
                    "quarantine_manifest": manifest,
                    **snapshot,
                    "evidence_context": _vss_context(snapshot, hive_path, local_path=local_hive),
                    "resolved_key_path": resolved_key,
                    "hive_metadata": meta,
                    "interpretation_guardrails": _vss_snapshot_guardrails(
                        total=0 if "error" in result else None,
                    ),
                })
                return _mask(result)
            resolved_root = _normalize_registry_key_path(search_root, local_hive)
            result = _search_registry_subtree(
                local_hive,
                resolved_root,
                keyword,
                limit=limit,
                offset=offset,
                max_scan_keys=max_scan_keys,
            )
            result.update({
                "ok": "error" not in result,
                "source": "vss_snapshot",
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "quarantine_manifest": manifest,
                **snapshot,
                "evidence_context": _vss_context(snapshot, hive_path, local_path=local_hive),
                "hive_metadata": meta,
                "query_semantics": {
                    "keyword": keyword,
                    "search_root": search_root,
                    "resolved_search_root": resolved_root,
                    "limit": limit,
                    "offset": offset,
                    "max_scan_keys": max_scan_keys,
                    "whole_hive_scan_allowed": False,
                },
                "interpretation_guardrails": _vss_snapshot_guardrails(
                    total=int(result.get("total", 0) or 0),
                    parser_failures=result.get("parse_failures", []),
                ),
            })
            return _mask(result)
        finally:
            c.disconnect()

    return await _traced("vss_query_registry_hive", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_list_registry_hives(
    snapshot_id: str,
    volume: str = "/c:",
    include_core_hives: bool = True,
    include_user_hives: bool = True,
    include_amcache: bool = True,
    user_filter: str = "",
    limit: int = 200,
) -> dict:
    """List likely registry hives inside one VSS snapshot.

    This discovery helper checks SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT,
    Amcache, and user NTUSER.DAT/UsrClass.dat hives. Missing hives are
    coverage observations for this snapshot, not negative evidence.
    """
    params = {
        "snapshot_id": snapshot_id,
        "volume": volume,
        "include_core_hives": include_core_hives,
        "include_user_hives": include_user_hives,
        "include_amcache": include_amcache,
        "user_filter": user_filter,
        "limit": limit,
    }

    def fn():
        e01 = _get_e01()
        discovered = _vss_discover_registry_hives(
            e01,
            snapshot_id,
            volume=volume,
            include_core_hives=include_core_hives,
            include_user_hives=include_user_hives,
            include_amcache=include_amcache,
            user_filter=user_filter,
            limit=max(1, limit),
        )
        snapshot = discovered["snapshot"]
        hives = discovered["hives"]
        return _mask({
            "ok": True,
            "source": "vss_snapshot",
            **snapshot,
            "hive_count": len(hives),
            "hives": hives,
            "missing_hives": discovered["missing_hives"],
            "coverage": discovered["coverage"],
            "evidence_context": _vss_context(snapshot, "/registry_hives"),
            "interpretation_guardrails": _vss_snapshot_guardrails(
                total=len(hives),
                parser_failures=discovered["coverage"].get("parser_failures", []),
            ),
        })

    return await _traced("vss_list_registry_hives", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_query_user_hives(
    snapshot_id: str,
    key_path: str = "",
    keyword: str = "",
    search_root: str = "",
    user_filter: str = "",
    hive_name: str = "NTUSER.DAT",
    volume: str = "/c:",
    limit: int = 100,
    offset: int = 0,
    max_scan_keys: int = 10000,
    max_hives: int = 25,
) -> dict:
    """Query user registry hives discovered inside one VSS snapshot.

    Provide key_path for direct key extraction, or keyword plus search_root for
    bounded subtree search. Whole-hive keyword scans are intentionally blocked.
    """
    params = {
        "snapshot_id": snapshot_id,
        "key_path": key_path,
        "keyword": keyword,
        "search_root": search_root,
        "user_filter": user_filter,
        "hive_name": hive_name,
        "volume": volume,
        "limit": limit,
        "offset": offset,
        "max_scan_keys": max_scan_keys,
        "max_hives": max_hives,
    }

    def fn():
        from core.connectors.registry import RegistryConnector

        e01 = _get_e01()
        if not key_path and keyword and not search_root:
            snapshot = _vss_snapshot_metadata_by_id(e01, snapshot_id, volume)
            return _mask({
                "ok": False,
                "error": "keyword search requires search_root or key_path to avoid whole-hive scans",
                "source": "vss_snapshot",
                **snapshot,
                "query_semantics": {"whole_hive_scan_allowed": False},
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })
        if not key_path and not keyword:
            snapshot = _vss_snapshot_metadata_by_id(e01, snapshot_id, volume)
            return _mask({
                "ok": False,
                "error": "Provide key_path for direct extraction or keyword plus search_root for bounded search.",
                "source": "vss_snapshot",
                **snapshot,
                "query_semantics": {"whole_hive_scan_allowed": False},
                "interpretation_guardrails": _vss_snapshot_guardrails(total=0),
            })

        discovered = _vss_discover_registry_hives(
            e01,
            snapshot_id,
            volume=volume,
            include_core_hives=False,
            include_user_hives=True,
            include_amcache=False,
            user_filter=user_filter,
            limit=max(1, max_hives * 2),
        )
        snapshot = discovered["snapshot"]
        wanted = str(hive_name or "NTUSER.DAT").strip().lower()
        hives = [
            hive for hive in discovered["hives"]
            if wanted in {"all", "*"} or str(hive.get("hive_type", "")).lower() == wanted
        ][: max(1, max_hives)]
        results = []
        failures = []
        for hive in hives:
            hive_path = str(hive.get("path", ""))
            fallback = hive_path.replace("\\", "/").rstrip("/").split("/")[-1] or "user_hive"
            local_hive = _vss_unique_output_path(snapshot_id, "registry_query_user", hive_path, fallback)
            try:
                extraction = e01.vss_extract_file(snapshot_id, hive_path, local_hive, volume=volume)
                manifest = _write_vss_quarantine_manifest(
                    extraction,
                    tool_name="vss_query_user_hives",
                    purpose="user_registry_query_source_extract",
                    source_path=hive_path,
                    query={
                        "key_path": key_path,
                        "keyword": keyword,
                        "search_root": search_root,
                        "user_filter": user_filter,
                        "hive_name": hive_name,
                        "limit": limit,
                        "offset": offset,
                        "max_scan_keys": max_scan_keys,
                        "volume": volume,
                    },
                )
                c = RegistryConnector()
                meta = c.connect(local_hive)
                try:
                    resolved_key = _normalize_registry_key_path(key_path, local_hive)
                    if resolved_key:
                        query_result = c.get_key(resolved_key)
                        query_result["resolved_key_path"] = resolved_key
                    else:
                        resolved_root = _normalize_registry_key_path(search_root, local_hive)
                        query_result = _search_registry_subtree(
                            local_hive,
                            resolved_root,
                            keyword,
                            limit=limit,
                            offset=offset,
                            max_scan_keys=max_scan_keys,
                        )
                        query_result["resolved_search_root"] = resolved_root
                    query_result.update({
                        "ok": "error" not in query_result,
                        "source": "vss_snapshot",
                        "hive_path": hive_path,
                        "local_hive_path": local_hive,
                        "quarantine_manifest": manifest,
                        "hive_metadata": meta,
                    })
                    if "error" in query_result:
                        failures.append({"hive_path": hive_path, "error": query_result["error"]})
                    results.append({
                        "user": hive.get("user", ""),
                        "hive_type": hive.get("hive_type", ""),
                        "hive": hive,
                        "query_result": query_result,
                    })
                finally:
                    c.disconnect()
            except Exception as e:
                failures.append({"hive_path": hive_path, "error": str(e)})
                results.append({
                    "user": hive.get("user", ""),
                    "hive_type": hive.get("hive_type", ""),
                    "hive": hive,
                    "query_result": {"ok": False, "error": str(e), "source": "vss_snapshot"},
                })

        return _mask({
            "ok": True,
            "source": "vss_snapshot",
            **snapshot,
            "hives_considered": len(discovered["hives"]),
            "hives_queried": len(hives),
            "results": results,
            "failures": failures,
            "coverage": discovered["coverage"],
            "query_semantics": {
                "key_path": key_path,
                "keyword": keyword,
                "search_root": search_root,
                "user_filter": user_filter,
                "hive_name": hive_name,
                "whole_hive_scan_allowed": False,
            },
            "evidence_context": _vss_context(snapshot, "/Users/*/NTUSER.DAT"),
            "interpretation_guardrails": _vss_snapshot_guardrails(
                total=len(results),
                parser_failures=failures + discovered["coverage"].get("parser_failures", []),
            ),
        })

    return await _traced("vss_query_user_hives", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vss_service_persistence_gate(
    snapshot_id: str,
    service_filter: str = "",
    verify_payload_files: bool = True,
    system_hive_path: str = "/c:/Windows/System32/config/SYSTEM",
    volume: str = "/c:",
    limit: int = 50,
) -> dict:
    """Run service persistence gate against the SYSTEM hive in one VSS snapshot.

    The tool follows ControlSet*\\Services and svchost Parameters\\ServiceDll
    in the selected historical layer. It is a coverage gate, not a verdict.
    """
    params = {
        "snapshot_id": snapshot_id,
        "service_filter": service_filter,
        "verify_payload_files": verify_payload_files,
        "system_hive_path": system_hive_path,
        "volume": volume,
        "limit": limit,
    }

    def fn():
        from core.analysis.service_persistence import (
            build_service_persistence_gate as _build_gate,
            services_from_system_hive as _services_from_system_hive,
        )

        e01 = _get_e01()
        local_hive = _vss_unique_output_path(snapshot_id, "service_persistence_gate", system_hive_path, "SYSTEM.hive")
        extraction = e01.vss_extract_file(snapshot_id, system_hive_path, local_hive, volume=volume)
        snapshot = {k: extraction.get(k, "") for k in (
            "temporal_layer",
            "snapshot_id",
            "snapshot_index",
            "snapshot_creation_time",
            "volume",
            "integrity_note",
        )}
        manifest = _write_vss_quarantine_manifest(
            extraction,
            tool_name="vss_service_persistence_gate",
            purpose="service_persistence_system_hive_extract",
            source_path=system_hive_path,
            query={
                "service_filter": service_filter,
                "verify_payload_files": verify_payload_files,
                "limit": limit,
                "volume": volume,
            },
        )
        services, hive_meta = _services_from_system_hive(local_hive)
        file_lookup = None
        if verify_payload_files:
            file_lookup = lambda internal_path: e01.vss_get_file_info(snapshot_id, internal_path, volume=volume)
        result = _build_gate(
            services,
            service_filter=service_filter,
            limit=limit,
            file_info_lookup=file_lookup,
        )
        result.update({
            "source": "vss_snapshot",
            **snapshot,
            "system_hive_path": system_hive_path,
            "local_hive_path": local_hive,
            "quarantine_manifest": manifest,
            "sources": [{
                "source": "vss_system_hive",
                "status": "checked",
                "system_hive_path": system_hive_path,
                "extracted_to": extraction.get("output_path", local_hive),
                "sha256": extraction.get("sha256", ""),
                "normalized_services": len(services),
                "metadata": hive_meta,
            }],
            "evidence_context": _vss_context(snapshot, system_hive_path, local_path=local_hive),
            "interpretation_guardrails": _vss_snapshot_guardrails(total=len(result.get("candidates", []))),
        })
        result.setdefault("reading_guide", []).append(
            "This VSS service gate describes historical registry state in one snapshot; compare layers explicitly."
        )
        return _mask(result)

    return await _traced("vss_service_persistence_gate", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


# ── Ghidra Binary Analysis Tools ──

@mcp.tool()
async def query_evtx_file(
    evtx_path: str,
    event_ids: str = "",
    keyword: str = "",
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Parse and query an offline Windows EVTX file.

    Use this instead of hand-running Get-WinEvent -Path during raw-image
    triage. ``evtx_path`` may be either:
      - a mounted-image internal path, e.g.
        /c:/Windows/System32/winevt/Logs/System.evtx
      - a local EVTX file that is either explicitly allowlisted or already
        extracted under forensic-workstation-output.

    Args:
        evtx_path: Internal mounted-image path or local EVTX path.
        event_ids: Optional comma-separated Event IDs, e.g. "7045,1102".
        keyword: Optional case-insensitive keyword across fields/provider/path.
        start_date / end_date: Optional ISO date filters (YYYY-MM-DD).
        limit / offset: Pagination over matched records.

    Reading guide for AI consumers:
        - This parses offline EVTX XML records. It does not query the live host.
        - Empty results mean no parsed record matched these filters, not that
          the behavior did not occur. Check parser_failures and date filters.
        - Event-log absence must be cross-checked with registry/file artifacts
          for persistence claims.
    """
    params = {
        "evtx_path": evtx_path,
        "event_ids": event_ids,
        "keyword": keyword,
        "start_date": start_date,
        "end_date": end_date,
        "limit": limit,
        "offset": offset,
    }

    def fn():
        from core.analysis.evtx_semantic import (
            filter_evtx_records as _filter_evtx_records,
            parse_evtx_file as _parse_evtx_file,
        )

        ids: set[int] = set()
        for part in event_ids.split(","):
            part = part.strip()
            if part:
                try:
                    ids.add(int(part))
                except ValueError:
                    return {"ok": False, "error": f"Invalid event id: {part}"}

        local_path = evtx_path
        source = "local_file"
        if os.path.exists(local_path):
            if not _is_safe_local_analysis_path(local_path):
                return {"ok": False, "error": build_not_allowed_message(local_path)}
        else:
            e01 = _get_e01()
            out_dir = _analysis_output_dir("evtx_query")
            safe_name = evtx_path.replace("\\", "/").rstrip("/").split("/")[-1] or "eventlog.evtx"
            local_path = os.path.join(out_dir, safe_name)
            extraction = e01.extract_file(evtx_path, local_path)
            source = "mounted_image"
            if extraction.get("error"):
                return {"ok": False, "error": extraction.get("error"), "source": source}

        parsed = _parse_evtx_file(local_path, target_event_ids=ids or None, limit=0)
        parser_failures = (parsed.get("parser_failures", []) or []) + (
            (parsed.get("recovery", {}) or {}).get("parser_failures", []) or []
        )
        if not parsed.get("ok"):
            return {
                **parsed,
                "source": source,
                "local_path": local_path,
                "evidence_context": _evidence_context(
                    evtx_path,
                    source,
                    local_path=local_path,
                    internal_path="" if source == "local_file" else evtx_path,
                ),
                "analysis_output": _analysis_output_context(create=False),
                "interpretation_guardrails": _raw_artifact_guardrails(
                    "evtx",
                    total=0,
                    parser_failures=parser_failures,
                ),
            }
        filtered = _filter_evtx_records(
            parsed.get("records", []) or [],
            event_ids=ids or None,
            keyword=keyword,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )
        return _mask({
            "ok": True,
            "source": source,
            "evtx_path": evtx_path,
            "local_path": local_path,
            "evidence_context": _evidence_context(
                evtx_path,
                source,
                local_path=local_path,
                internal_path="" if source == "local_file" else evtx_path,
            ),
            "analysis_output": _analysis_output_context(create=False),
            "parsed_record_count": parsed.get("record_count", 0),
            "event_id_counts_in_file": parsed.get("event_id_counts", {}),
            "parser_failures": parsed.get("parser_failures", []),
            "recovery": parsed.get("recovery", {}),
            "interpretation_guardrails": _raw_artifact_guardrails(
                "evtx",
                total=filtered.get("total", 0),
                parser_failures=parser_failures,
            ),
            **filtered,
        })

    return await _traced("query_evtx_file", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def query_prefetch_files(
    prefetch_path: str = "",
    directory: str = "/c:/Windows/Prefetch",
    pattern: str = "*.pf",
    keyword: str = "",
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Parse and query offline Windows Prefetch files from a mounted image.

    Args:
        prefetch_path: Optional single PF file path. May be a mounted-image
            internal path or a safe local file under the workspace, allowlist,
            or forensic-workstation-output.
        directory: Mounted-image or local directory to search when
            prefetch_path is empty. Defaults to Windows Prefetch.
        pattern: Glob pattern for directory searches.
        keyword: Optional case-insensitive match across executable name,
            source path, and raw referenced paths.
        start_date / end_date: Optional ISO date filters against latest run.
        limit / offset: Pagination over parsed matching Prefetch records.

    Reading guide for AI consumers:
        - Prefetch is execution evidence on systems where Prefetch is enabled,
          but it is not a standalone incident verdict.
        - Referenced paths inside Prefetch are context, not proof that every
          referenced file executed.
        - Empty results may mean Prefetch was disabled, cleared, absent,
          compressed-parser failed, or filters were too narrow.
    """
    params = {
        "prefetch_path": prefetch_path,
        "directory": directory,
        "pattern": pattern,
        "keyword": keyword,
        "start_date": start_date,
        "end_date": end_date,
        "limit": limit,
        "offset": offset,
    }

    def fn():
        from core.analysis.prefetch_semantic import parse_prefetch_bytes as _parse_pf

        source_paths: list[str] = []
        source_mode = "mounted_image"
        if prefetch_path:
            source_paths = [prefetch_path]
            if os.path.exists(prefetch_path):
                source_mode = "local_file"
        elif os.path.isdir(directory):
            if not _is_safe_local_analysis_path(directory):
                return {"ok": False, "error": build_not_allowed_message(directory)}
            import glob
            source_mode = "local_directory"
            source_paths = sorted(glob.glob(os.path.join(directory, pattern)))
        else:
            e01 = _get_e01()
            found = e01.find_files(pattern, path=directory, limit=max(1000, limit + offset))
            source_paths = [
                str(item.get("path", ""))
                for item in found
                if item.get("path") and not item.get("is_dir") and not item.get("error")
            ]

        parsed: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for path in source_paths:
            try:
                if os.path.exists(path):
                    if not _is_safe_local_analysis_path(path):
                        failures.append({"path": path, "error": build_not_allowed_message(path)})
                        continue
                    with open(path, "rb") as f:
                        data = f.read()
                else:
                    data = _get_e01().read_file_content(path, max_size=8 * 1024 * 1024)
                item = _parse_pf(data, source_path=path)
                if item.get("ok"):
                    parsed.append(item)
                else:
                    failures.append({"path": path, "error": item.get("error", "parse_failed")})
            except Exception as e:
                failures.append({"path": path, "error": str(e)})

        keyword_lc = keyword.strip().lower()
        matches = []
        for item in parsed:
            latest = str(item.get("latest_run_time_utc", "") or "")
            day = latest[:10]
            if start_date and day and day < start_date:
                continue
            if end_date and day and day > end_date:
                continue
            if keyword_lc:
                blob = " ".join([
                    str(item.get("source_path", "")),
                    str(item.get("executable_name", "")),
                    " ".join(str(v) for v in item.get("raw_referenced_paths", []) or []),
                ]).lower()
                if keyword_lc not in blob:
                    continue
            matches.append(item)

        matches.sort(key=lambda item: str(item.get("latest_run_time_utc", "")), reverse=True)
        safe_offset = max(0, offset)
        safe_limit = max(0, limit)
        returned = matches[safe_offset:safe_offset + safe_limit] if safe_limit else matches[safe_offset:]
        return _mask({
            "ok": True,
            "source_mode": source_mode,
            "evidence_context": _evidence_context(
                prefetch_path or directory,
                source_mode,
                local_path=prefetch_path if source_mode.startswith("local") else "",
                internal_path=(prefetch_path or directory) if source_mode == "mounted_image" else "",
            ),
            "searched": {
                "prefetch_path": prefetch_path,
                "directory": directory,
                "pattern": pattern,
                "source_path_count": len(source_paths),
            },
            "total": len(matches),
            "returned": len(returned),
            "offset": safe_offset,
            "limit": safe_limit,
            "truncated": safe_offset + len(returned) < len(matches),
            "records": returned,
            "parse_failures": failures[:50],
            "parse_failure_count": len(failures),
            "interpretation_guardrails": _raw_artifact_guardrails(
                "prefetch",
                total=len(matches),
                parser_failures=failures,
            ),
            "guardrails": {
                "standalone_verdict_allowed": False,
                "absence_is_negative_evidence": False,
                "referenced_paths_are_execution_evidence": False,
            },
        })

    return await _traced("query_prefetch_files", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def query_registry_hive(
    hive_path: str = "/c:/Windows/System32/config/SYSTEM",
    key_path: str = "",
    keyword: str = "",
    search_root: str = "",
    limit: int = 100,
    offset: int = 0,
    max_scan_keys: int = 10000,
) -> dict:
    """Query an offline Windows registry hive by key path or bounded keyword search.

    Args:
        hive_path: Mounted-image internal path or safe local hive path.
            Defaults to the SYSTEM hive in a mounted image.
        key_path: Optional registry key path. Accepts forms like
            ``\\ControlSet001\\Services\\uploadmgr`` or
            ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\uploadmgr``.
        keyword: Optional keyword search across key paths and values. Keyword
            search requires search_root to avoid slow whole-hive scans.
        search_root: Registry subtree root for keyword search, for example
            ``\\ControlSet001\\Services``.
        limit / offset: Pagination for keyword search.
        max_scan_keys: Safety cap for keys visited inside search_root.

    Reading guide for AI consumers:
        - Registry state proves configuration existed in the captured hive,
          not when it was originally created unless LastWrite is present.
        - CurrentControlSet is resolved from the hive's Select\\Current value
          when possible.
        - Absence of a key in one hive/control set is not evidence that the
          behavior never existed; check source coverage and shadow copies.
    """
    params = {
        "hive_path": hive_path,
        "key_path": key_path,
        "keyword": keyword,
        "search_root": search_root,
        "limit": limit,
        "offset": offset,
        "max_scan_keys": max_scan_keys,
    }

    def fn():
        from core.connectors.registry import RegistryConnector
        materialized = _materialize_local_artifact(hive_path, "registry_query")
        if not materialized.get("ok"):
            materialized["interpretation_guardrails"] = _raw_artifact_guardrails("registry", total=0)
            return materialized
        local_hive = materialized["local_path"]
        if not key_path and keyword and not search_root:
            return _mask({
                "ok": False,
                "error": (
                    "keyword search requires search_root or key_path to avoid whole-hive "
                    "scans and false confidence from timed-out scans"
                ),
                "source": materialized.get("source"),
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "evidence_context": materialized.get("evidence_context", {}),
                "query_semantics": {
                    "keyword": keyword,
                    "search_root_required": True,
                    "recommended_examples": [
                        "\\ControlSet001\\Services",
                        "\\Microsoft\\Windows\\CurrentVersion\\Run",
                    ],
                },
                "interpretation_guardrails": _raw_artifact_guardrails("registry", total=0),
            })
        if not key_path and not keyword:
            return _mask({
                "ok": False,
                "error": "Provide key_path for direct extraction or keyword plus search_root for bounded search.",
                "source": materialized.get("source"),
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "evidence_context": materialized.get("evidence_context", {}),
                "interpretation_guardrails": _raw_artifact_guardrails("registry", total=0),
            })
        c = RegistryConnector()
        meta = c.connect(local_hive)
        try:
            resolved_key = _normalize_registry_key_path(key_path, local_hive)
            if resolved_key:
                result = c.get_key(resolved_key)
                result.update({
                    "ok": "error" not in result,
                    "source": materialized.get("source"),
                    "hive_path": hive_path,
                    "local_hive_path": local_hive,
                    "evidence_context": materialized.get("evidence_context", {}),
                    "resolved_key_path": resolved_key,
                    "hive_metadata": meta,
                    "interpretation_guardrails": _raw_artifact_guardrails(
                        "registry",
                        total=0 if "error" in result else None,
                    ),
                })
                return _mask(result)
            resolved_root = _normalize_registry_key_path(search_root, local_hive)
            result = _search_registry_subtree(
                local_hive,
                resolved_root,
                keyword,
                limit=limit,
                offset=offset,
                max_scan_keys=max_scan_keys,
            )
            result.update({
                "ok": "error" not in result,
                "source": materialized.get("source"),
                "hive_path": hive_path,
                "local_hive_path": local_hive,
                "evidence_context": materialized.get("evidence_context", {}),
                "hive_metadata": meta,
                "query_semantics": {
                    "keyword": keyword,
                    "search_root": search_root,
                    "resolved_search_root": resolved_root,
                    "limit": limit,
                    "offset": offset,
                    "max_scan_keys": max_scan_keys,
                    "whole_hive_scan_allowed": False,
                },
                "interpretation_guardrails": _raw_artifact_guardrails(
                    "registry",
                    total=int(result.get("total", 0) or 0),
                    parser_failures=result.get("parse_failures", []),
                ),
            })
            return _mask(result)
        finally:
            c.disconnect()

    return await _traced("query_registry_hive", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def inspect_pe_file(
    file_path: str,
    document_access_approved: bool = False,
    document_access_reason: str = "",
) -> dict:
    """Hash and inspect a PE file's signature/version metadata without executing it.

    Args:
        file_path: Mounted-image internal path or safe local file path.
        document_access_approved: Required for document-like extensions such as .txt.
        document_access_reason: Non-empty approval reason for document-like extensions.

    Reading guide for AI consumers:
        - This is static metadata only. Unsigned does not automatically mean
          malicious, and signed does not automatically mean benign.
        - For mounted-image paths, the file is extracted under the selected
          evidence folder's forensic-workstation-output directory when possible.
        - Pair this with file timestamps and execution artifacts before
          making a persistence or malware conclusion.
    """
    params = {
        "file_path": file_path,
        "document_access_approved": document_access_approved,
        "document_access_reason_present": bool(_document_content_reason(document_access_reason)),
    }

    def fn():
        materialized = _materialize_local_artifact(
            file_path,
            "pe_inspect",
            document_access_approved=document_access_approved,
            document_access_reason=document_access_reason,
            document_access_operation="inspect_pe_file",
        )
        if not materialized.get("ok"):
            materialized["interpretation_guardrails"] = _raw_artifact_guardrails("pe", total=0)
            return materialized
        local_path = materialized["local_path"]
        hashes = _hash_local_file(local_path)
        ps_meta = _powershell_pe_metadata(local_path)
        result = {
            "ok": True,
            "source": materialized.get("source"),
            "input_path": file_path,
            "local_path": local_path,
            "evidence_context": materialized.get("evidence_context", {}),
            "size": os.path.getsize(local_path),
            "hashes": hashes,
            "authenticode": ps_meta.get("authenticode", {}),
            "version_info": ps_meta.get("version_info", {}),
            "metadata_errors": ps_meta.get("errors", []),
            "interpretation_guardrails": _raw_artifact_guardrails(
                "pe",
                parser_failures=[{"error": e} for e in ps_meta.get("errors", [])],
            ),
            "guardrails": {
                "static_analysis_only": True,
                "unsigned_is_malice_verdict": False,
                "signed_is_benign_verdict": False,
            },
        }
        if materialized.get("document_access"):
            result["document_access"] = materialized["document_access"]
        return _mask(result)

    return await _traced("inspect_pe_file", params, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def analyze_binary(file_path: str, ghidra_install_dir: str = "") -> dict:
    """Load a binary (EXE/DLL) into Ghidra for STATIC reverse engineering (no execution). First call is slow (~1min)."""
    def fn():
        phases = []
        def phase(name: str, detail: str = "") -> None:
            item = {"stage": name, "detail": detail, "timestamp": datetime.now(timezone.utc).isoformat()}
            phases.append(item)
            _log_event("progress", "analyze_binary", data=item)

        phase("prepare", "Disconnecting any previous Ghidra program and preparing static load.")
        old = _connectors.get("ghidra")
        if old and old.is_connected():
            old.disconnect()
            phase("previous_program_closed")
        g = GhidraConnector()
        phase("ghidra_load_start", "Starting pyhidra/Ghidra import and auto-analysis.")
        meta = g.connect(file_path, ghidra_install_dir=ghidra_install_dir or config.ghidra_install_dir)
        phase("ghidra_load_complete", "Binary is loaded; imports/strings/functions can now be queried.")
        _connectors["ghidra"] = g
        meta["analysis_phases"] = phases
        meta["evidence_context"] = _evidence_context(file_path, "static_binary", local_path=file_path)
        meta["guardrails"] = {
            "static_analysis_only": True,
            "binary_was_executed": False,
        }
        return _mask(meta)
    return await _traced("analyze_binary", {"file_path": file_path}, fn)


@mcp.tool()
async def ghidra_decompile(function_name: str = "", address: str = "") -> dict:
    """Decompile a function to C pseudocode."""
    params = {"function_name": function_name, "address": address}
    def fn():
        return _mask(_get_ghidra().decompile_function(address=address, name=function_name))
    return await _traced("ghidra_decompile", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def ghidra_imports() -> dict:
    """List all imported functions from the loaded binary."""
    def fn():
        imports = _get_ghidra().list_imports()
        return _mask({"total": len(imports), "imports": imports})
    return await _traced("ghidra_imports", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def ghidra_suspicious_apis() -> dict:
    """Find suspicious Win32 API imports with MITRE ATT&CK mapping."""
    def fn():
        return _mask(_get_ghidra().find_suspicious_apis())
    return await _traced("ghidra_suspicious_apis", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def ghidra_strings(keyword: str = "", min_length: int = 4, limit: int = 200, offset: int = 0) -> dict:
    """Extract and search strings from the loaded binary."""
    params = {"keyword": keyword, "min_length": min_length, "limit": limit, "offset": offset}
    def fn():
        strings = _get_ghidra().list_strings(min_length=min_length, limit=1000)
        if keyword:
            kw = keyword.lower()
            strings = [s for s in strings if kw in s.get("value", "").lower()]
        page = strings[offset:offset + limit]
        return _mask({"total": len(strings), "returned": len(page), "offset": offset, "strings": page})
    return await _traced("ghidra_strings", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def ghidra_functions(filter_pattern: str = "", limit: int = 100, offset: int = 0) -> dict:
    """List functions in the loaded binary with optional name filter."""
    params = {"filter_pattern": filter_pattern, "limit": limit, "offset": offset}
    def fn():
        funcs = _get_ghidra().list_functions(filter_pattern=filter_pattern, limit=limit + offset)
        page = funcs[offset:offset + limit]
        return _mask({"total": len(funcs), "returned": len(page), "offset": offset, "functions": page})
    return await _traced("ghidra_functions", params, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def ghidra_exports() -> dict:
    """List exported functions/symbols from the loaded binary."""
    def fn():
        exports = _get_ghidra().list_exports()
        return _mask({"total": len(exports), "exports": exports})
    return await _traced("ghidra_exports", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


# ── Volatility Memory Analysis Tools ──

@mcp.tool()
async def vol_load_memory(memory_path: str) -> dict:
    """Load memory dump for Volatility analysis. First call is slow."""
    def fn():
        old = _connectors.get("volatility")
        if old and old.is_connected():
            old.disconnect()
        v = VolatilityConnector()
        meta = v.connect(memory_path)
        _connectors["volatility"] = v
        return _mask({"status": "loaded", **meta})
    return await _traced("vol_load_memory", {"memory_path": memory_path}, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vol_pslist() -> dict:
    """List all processes from memory dump."""
    def fn():
        results = _get_vol().pslist()
        return _mask({"total": len(results), "processes": results})
    return await _traced("vol_pslist", {}, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vol_pstree() -> dict:
    """Show process tree from memory dump."""
    def fn():
        results = _get_vol().pstree()
        return _mask({"total": len(results), "processes": results})
    return await _traced("vol_pstree", {}, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vol_netscan() -> dict:
    """Scan network connections from memory dump."""
    def fn():
        results = _get_vol().netscan()
        return _mask({"total": len(results), "connections": results})
    return await _traced("vol_netscan", {}, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vol_cmdline() -> dict:
    """Show command line arguments for all processes."""
    def fn():
        results = _get_vol().cmdline()
        return _mask({"total": len(results), "cmdlines": results})
    return await _traced("vol_cmdline", {}, fn, timeout_seconds=TIMEOUT_MEDIUM)


@mcp.tool()
async def vol_malfind() -> dict:
    """Find injected/suspicious code in process memory."""
    def fn():
        results = _get_vol().malfind()
        return _mask({"total": len(results), "findings": results})
    return await _traced("vol_malfind", {}, fn, timeout_seconds=TIMEOUT_MEDIUM)


# ── SRUM Integrated View ──

@mcp.tool()
async def srum_by_process(
    process_name: str = "",
    process_names: str = "",
    start_date: str = "",
    end_date: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Query SRUM data (CPU/IO + Network) for processes.

    Args:
        process_name: Single process name (partial match supported, e.g. "synchost" matches "SyncHost.exe").
        process_names: Comma-separated process names for multi-process query.
                       e.g. "synchost,SearchHost,sshd" to compare activity across processes.
        start_date: Date filter start (ISO format).
        end_date: Date filter end (ISO format).
        limit: Max results per process (default 50).
        offset: Skip first N results per process (for pagination).
    """
    params = {"process_name": process_name, "process_names": process_names,
              "start_date": start_date, "end_date": end_date, "limit": limit, "offset": offset}
    def fn():
        axiom = _get_axiom()
        cap = min(limit, config.srum_max_limit)
        names = [n.strip() for n in process_names.split(",") if n.strip()] if process_names.strip() else []
        if process_name.strip() and process_name.strip() not in names:
            names.insert(0, process_name.strip())
        if not names:
            return {"error": "Provide process_name or process_names"}

        def _match_hit(hit, pn_lower):
            """Partial match against hit fields AND nested fields dict."""
            # Check top-level fields
            for key in ("Application Name", "application_name", "AppName"):
                val = hit.get(key, "")
                if val and pn_lower in str(val).lower():
                    return True
            # Check nested 'fields' dict (hydrated hit format)
            fields = hit.get("fields", {})
            for key in ("Application Name", "Full Path"):
                val = fields.get(key, "")
                if val and pn_lower in str(val).lower():
                    return True
            return False

        results_by_process = {}
        for pn in names:
            pn_lower = pn.lower()

            app_results = axiom.search(
                keyword=pn,
                filters={"artifact_type": "SRUM Application Resource Usage",
                          "start_date": start_date, "end_date": end_date},
                limit=cap, offset=offset,
            )
            net_results = axiom.search(
                keyword=pn,
                filters={"artifact_type": "SRUM Network Usage",
                          "start_date": start_date, "end_date": end_date},
                limit=cap, offset=offset,
            )

            app_hits = [h for h in app_results.get("hits", []) if _match_hit(h, pn_lower)]
            net_hits = [h for h in net_results.get("hits", []) if _match_hit(h, pn_lower)]

            # Compute accurate totals from ALL records via SQL aggregation (no LIMIT)
            agg = axiom.srum_network_aggregate(pn, start_date, end_date)

            results_by_process[pn] = {
                "cpu_io_records": agg.get("app_total_records", len(app_hits)),
                "network_records": agg.get("network_total_records", len(net_hits)),
                "total_bytes_sent": agg.get("total_bytes_sent", 0),
                "total_bytes_received": agg.get("total_bytes_received", 0),
                "returned_app_records": len(app_hits[:limit]),
                "returned_net_records": len(net_hits[:limit]),
                "application_resource_usage": app_hits[:limit],
                "network_usage": net_hits[:limit],
            }

        return _mask({
            "processes": names,
            "results": results_by_process,
        })
    return await _traced("srum_by_process", params, fn)


# ── WER Report Parsing ──

@mcp.tool()
async def search_wer_reports(process_filter: str = "", process_filters: str = "") -> dict:
    """Search and parse Windows Error Reporting crash reports from mounted disk image.

    Args:
        process_filter: Single process name to filter (partial match).
        process_filters: Comma-separated process names for multi-process filter.
                         e.g. "MagicLine,CrossEX,Delfino" to find crashes of security software.
                         Empty = return all WER reports.
    """
    params = {"process_filter": process_filter, "process_filters": process_filters}
    def fn():
        e01 = _get_e01()

        # Build filter list
        filters = [f.strip().lower() for f in process_filters.split(",") if f.strip()] if process_filters.strip() else []
        if process_filter.strip() and process_filter.strip().lower() not in filters:
            filters.insert(0, process_filter.strip().lower())

        # Search for Report.wer files in common WER directories
        wer_paths = [
            "ProgramData/Microsoft/Windows/WER/ReportArchive",
            "ProgramData/Microsoft/Windows/WER/ReportQueue",
        ]
        wer_files = []
        for wer_dir in wer_paths:
            try:
                found = e01.find_files("Report.wer", f"/c:/{wer_dir}", limit=200)
                wer_files.extend(found)
            except Exception:
                pass

        # Also search user profile WER directories
        try:
            users_dir = e01.list_directory("/c:/Users")
            for user_entry in users_dir:
                if user_entry.get("is_dir") and user_entry.get("name") not in (".", "..", "Public", "Default", "Default User", "All Users"):
                    user_wer = f"/c:/Users/{user_entry['name']}/AppData/Local/Microsoft/Windows/WER/ReportArchive"
                    try:
                        found = e01.find_files("Report.wer", user_wer, limit=100)
                        wer_files.extend(found)
                    except Exception:
                        pass
        except Exception:
            pass

        # Parse each WER file
        all_parsed = []
        parse_errors = []
        for wf in wer_files:
            file_path = wf.get("path", "")
            if not file_path:
                continue
            try:
                content = e01.read_file_content(file_path, max_size=1048576)
                report = _parse_wer(content, file_path)
                if report:
                    all_parsed.append(report)
                else:
                    parse_errors.append({"path": file_path, "error": "no key=value pairs found"})
            except Exception as e:
                parse_errors.append({"path": file_path, "error": str(e)})

        # Apply process filter — match against multiple fields
        if filters:
            matched = []
            for report in all_parsed:
                # Check NsAppName, AppName, AppPath, OriginalFilename, ModName
                searchable = " ".join([
                    report.get("NsAppName", ""),
                    report.get("AppName", ""),
                    report.get("AppPath", ""),
                    report.get("OriginalFilename", ""),
                    report.get("ModName", ""),
                    report.get("P0", ""),  # Some WER versions use P0 for app name
                    report.get("P3", ""),  # P3 is often the faulting module
                    report.get("source_path", ""),  # folder name often contains process
                ]).lower()
                if any(f in searchable for f in filters):
                    matched.append(report)
            reports = matched
        else:
            reports = all_parsed

        # Build per-process summary
        process_summary: dict[str, dict] = {}
        for r in all_parsed:  # summarize ALL parsed (not just filtered)
            app = r.get("NsAppName", "") or r.get("AppName", "") or r.get("P0", "unknown")
            if app not in process_summary:
                process_summary[app] = {"count": 0, "timestamps": [], "event_types": []}
            process_summary[app]["count"] += 1
            ts = r.get("EventTime_ISO", r.get("EventTime", ""))
            if ts:
                process_summary[app]["timestamps"].append(ts)
            etype = r.get("EventType", "")
            if etype and etype not in process_summary[app]["event_types"]:
                process_summary[app]["event_types"].append(etype)

        return _mask({
            "total_wer_files": len(wer_files),
            "total_parsed": len(all_parsed),
            "filter_matched": len(reports),
            "parse_errors": len(parse_errors),
            "process_summary": process_summary,
            "reports": reports,
            "errors": parse_errors[:10],  # first 10 errors for debugging
        })
    return await _traced("search_wer_reports", params, fn)


def _parse_wer(data: bytes, source_path: str) -> dict | None:
    """Parse a Report.wer file (UTF-16LE encoded, INI-like format)."""
    # Try UTF-16LE first (standard WER encoding), then UTF-16 with BOM, then UTF-8
    text = None
    for encoding in ("utf-16-le", "utf-16", "utf-8-sig", "utf-8"):
        try:
            text = data.decode(encoding)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if text is None:
        return None

    # Remove BOM if present
    text = text.lstrip("\ufeff")

    report: dict[str, Any] = {"source_path": source_path}
    current_section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Track INI sections
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            # Store all key=value pairs (no whitelist filtering)
            report[key] = value

    # Convert EventTime from Windows FILETIME to ISO format
    event_time_raw = report.get("EventTime", "")
    if event_time_raw and event_time_raw.isdigit():
        try:
            # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
            filetime = int(event_time_raw)
            import datetime
            epoch_diff = 116444736000000000  # difference between 1601 and 1970 in 100ns
            if filetime > epoch_diff:
                timestamp = (filetime - epoch_diff) / 10_000_000
                dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
                report["EventTime_ISO"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError, OverflowError):
            pass

    return report if len(report) > 1 else None


# ── External Log Import Tools ──

_log_connector = LogConnector()


@mcp.tool()
async def import_logs(log_path: str, log_type: str = "auto") -> dict:
    """Import external log file (Apache/IIS/syslog) for analysis. Supports .zip archives."""
    def fn():
        result = _log_connector.load(log_path, log_type)
        return _mask(result)
    return await _traced("import_logs", {"log_path": log_path, "log_type": log_type}, fn)


@mcp.tool()
async def search_logs(
    keyword: str = "",
    source_ip: str = "",
    start_date: str = "",
    end_date: str = "",
    status_code: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Search imported log entries by keyword, IP, date range, or status code."""
    params = {
        "keyword": keyword, "source_ip": source_ip,
        "start_date": start_date, "end_date": end_date,
        "status_code": status_code, "limit": limit, "offset": offset,
    }
    def fn():
        result = _log_connector.search(
            keyword=keyword, source_ip=source_ip,
            start_date=start_date, end_date=end_date,
            status_code=status_code, limit=limit, offset=offset,
        )
        return _mask(result)
    return await _traced("search_logs", params, fn)


@mcp.tool()
async def log_stats() -> dict:
    """Get statistics for imported logs (unique IPs, top paths, date range)."""
    def fn():
        return _mask(_log_connector.get_stats())
    return await _traced("log_stats", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


# ── Large Result Query Tool ──

@mcp.tool()
async def query_result(
    file_path: str,
    expression: str = "",
    keys: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Query large tool results saved to files. Enables flexible filtering without losing information.

    Args:
        file_path: Path to the saved result file (from tool overflow).
        expression: Python filter expression applied to each item.
                    The variable 'x' refers to each item (dict).
                    Examples:
                      - "x.get('type') == 'ip'"
                      - "'MagicLine' in str(x)"
                      - "x.get('severity') == 'critical'"
                      - ""  (empty = return all, with pagination)
        keys: Comma-separated field names to extract (reduces output size).
              Examples: "type,value,timestamp" or "" (all fields).
        limit: Max items to return (default 50).
        offset: Skip first N matched items (for pagination).

    Returns:
        Filtered and optionally projected results with match statistics.
    """
    def fn():
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        # Unwrap MCP tool result format: [{type, text}] -> parsed JSON
        if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], dict) and "text" in raw[0]:
            try:
                data = json.loads(raw[0]["text"])
            except (json.JSONDecodeError, TypeError):
                data = raw
        else:
            data = raw

        # Find the iterable collection inside the result
        items = _find_items(data)
        if items is None:
            return {"error": "No iterable collection found in result", "top_keys": list(data.keys()) if isinstance(data, dict) else str(type(data))}

        total_items = len(items)

        # Apply filter expression
        if expression.strip():
            safe_expr = expression.strip()
            _safe_globals = {"__builtins__": {}}
            _safe_locals_base = {
                "str": str, "int": int, "float": float, "bool": bool,
                "len": len, "any": any, "all": all, "sorted": sorted,
                "isinstance": isinstance, "dict": dict, "list": list, "tuple": tuple,
                "re": re, "True": True, "False": False, "None": None,
            }
            matched = []
            errors = 0
            for x in items:
                try:
                    local = {**_safe_locals_base, "x": x}
                    if eval(safe_expr, _safe_globals, local):
                        matched.append(x)
                except Exception:
                    errors += 1
            filter_info = {"expression": safe_expr, "matched": len(matched), "errors": errors}
        else:
            matched = items
            filter_info = {"expression": "(none)", "matched": len(matched)}

        # Pagination
        page = matched[offset:offset + limit]

        # Project specific keys
        key_list = [k.strip() for k in keys.split(",") if k.strip()] if keys.strip() else []
        if key_list:
            projected = []
            for item in page:
                if isinstance(item, dict):
                    projected.append({k: item.get(k) for k in key_list if k in item})
                else:
                    projected.append(item)
            page = projected

        return _mask({
            "total_items": total_items,
            "filter": filter_info,
            "returned": len(page),
            "offset": offset,
            "has_more": (offset + limit) < len(matched),
            "items": page,
        })

    return await _traced("query_result", {"file_path": file_path, "expression": expression, "keys": keys, "limit": limit, "offset": offset}, fn)


def _find_items(data: Any) -> list | None:
    """Find the main iterable collection in a tool result."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Prefer known collection keys
        for key in ("iocs", "reports", "hits", "entries", "results", "items", "findings",
                     "events", "processes", "connections", "cmdlines"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Fall back to the largest list value
        best_key, best_len = None, 0
        for k, v in data.items():
            if isinstance(v, list) and len(v) > best_len:
                best_key, best_len = k, len(v)
        if best_key:
            return data[best_key]
    return None


# ── Auto Triage Pipeline ──

@mcp.tool()
async def auto_triage(
    source_drive: str,
    case_name: str = "",
    output_dir: str = "",
    kape_path: str = "",
    skip_kape: bool = False,
    vss: bool = True,
) -> dict:
    """Automated triage pipeline: KAPE collection + parsing + analysis in one step.

    Runs the full pipeline: KAPE collect/parse → open_case → find_suspicious →
    extract_iocs → build_timeline → generate_report.

    Args:
        source_drive: Mounted drive letter (e.g. "G:" or "G")
        case_name: Case identifier (default: auto-generated from date)
        output_dir: Output directory (default: forensic-workstation-output/YYYYMMDD_casename beside selected evidence)
        kape_path: Path to kape.exe (auto-detected if empty)
        skip_kape: Skip KAPE collection (use existing parsed data in output_dir)
        vss: Include Volume Shadow Copies (default: True, requires admin)

    Reading guide for AI consumers:
        - This tool orchestrates a full-pipeline pass. It does NOT replace
          hypothesis-driven drill-down. Use its output as a starting index,
          not a verdict.
        - findings[] order is not significance-sorted. Judge findings from
          their details[], matching_count, and truncation_gaps.
        - lane_evidence_summary shows artifact families seen per lane — facts
          only. Significance judgment is yours.
        - Before closing the investigation, run at least one refutation
          pass (e.g., verify benign explanation for the primary remote tool
          or service).
    """
    import subprocess
    import time as _t
    from datetime import datetime as _dt
    from core.config import find_kape

    params = {"source_drive": source_drive, "case_name": case_name,
              "output_dir": output_dir, "skip_kape": skip_kape, "vss": vss}

    def fn():
        steps: list[dict] = []
        t_start = _t.time()

        # ── Step 0: Resolve paths ──
        drive = source_drive.rstrip(":\\/ ") + ":\\"
        datestamp = _dt.now().strftime("%Y%m%d")
        cname = case_name or "case"
        if output_dir:
            out_dir = output_dir
        else:
            out_dir = _analysis_output_dir(f"{datestamp}_{cname}")

        collected_dir = os.path.join(out_dir, "collected")
        parsed_dir = os.path.join(out_dir, "parsed")

        # ── Step 1: KAPE Collection + Parsing ──
        if not skip_kape:
            kape = kape_path or find_kape()
            if not kape or not os.path.isfile(kape):
                return {"error": f"kape.exe not found. Set FORENSIC_KAPE_PATH or pass kape_path. Searched: {kape}"}

            cmd = [
                kape,
                "--tsource", drive,
                "--tdest", collected_dir,
                "--target", "ForensicWorkstation",
                "--mdest", parsed_dir,
                "--module", "ForensicWorkstation",
                "--msource", collected_dir,
            ]
            if vss:
                cmd += ["--vss", "--vd"]

            steps.append({"step": "kape_start", "command": " ".join(cmd)})

            t1 = _t.time()
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=7200,  # 2h max
                )
                kape_duration = round(_t.time() - t1, 1)
                steps.append({
                    "step": "kape_complete",
                    "duration_s": kape_duration,
                    "return_code": result.returncode,
                    "stdout_tail": result.stdout[-500:] if result.stdout else "",
                    "stderr_tail": result.stderr[-500:] if result.stderr else "",
                })
                if result.returncode != 0:
                    steps.append({"step": "kape_warning", "message": "KAPE returned non-zero exit code"})
            except subprocess.TimeoutExpired:
                return {"error": "KAPE timed out after 2 hours", "steps": steps}
            except FileNotFoundError:
                return {"error": f"Cannot execute kape.exe at: {kape}", "steps": steps}
        else:
            steps.append({"step": "kape_skipped", "using_existing": parsed_dir})

        # ── Step 2: Open Case ──
        if not os.path.isdir(parsed_dir):
            return {"error": f"Parsed directory not found: {parsed_dir}", "steps": steps}

        t2 = _t.time()
        _connectors.pop("axiom", None)
        from core.connectors.kape_csv import KapeCsvConnector
        c = KapeCsvConnector()
        case_meta = c.connect(parsed_dir)
        if case_name:
            case_meta["case_name"] = case_name
        _connectors["axiom"] = c
        steps.append({
            "step": "open_case",
            "duration_s": round(_t.time() - t2, 1),
            "total_hits": case_meta.get("total_hits", 0),
            "artifact_types": case_meta.get("artifact_type_count", 0),
        })

        # ── Step 3: Find Suspicious + Strength Scoring ──
        t2b = _t.time()
        initial_triage_summary = {}
        triage: dict[str, Any] | None = None
        try:
            from core.analysis.initial_triage import initial_triage as _initial_triage
            triage = _initial_triage(c, scope_mode="recent_14d")
            initial_triage_summary = {
                "top_window_count": len(triage.get("window_discovery", {}).get("top_windows", []) or []),
                "precursor_status": triage.get("precursor_context", {}).get("status", "historical_context"),
                "lane_evidence_summary": triage.get("lane_evidence_summary", {}),
            }
            steps.append({
                "step": "initial_triage_pack",
                "duration_s": round(_t.time() - t2b, 1),
                **initial_triage_summary,
            })
        except Exception as e:
            steps.append({"step": "initial_triage_pack", "error": str(e)})

        t3 = _t.time()
        strength_rollup = {}
        try:
            from core.analysis.suspicious import find_suspicious as _find
            from core.analysis.evidence_strength import score_findings as _score
            suspicious = _find(c.artifact_queries)
            _score(suspicious)
            findings = suspicious.get("findings", [])
            strength_rollup = suspicious.get("strength_rollup", {})
            steps.append({
                "step": "find_suspicious",
                "duration_s": round(_t.time() - t3, 1),
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
                "strength_rollup": strength_rollup,
            })
        except Exception as e:
            findings = []
            steps.append({"step": "find_suspicious", "error": str(e)})

        # ── Step 3b: Anti-forensics ──
        t3b = _t.time()
        anti_forensics = {"rules_fired": 0, "total_hits": 0, "rules": []}
        try:
            from core.analysis.anti_forensics import detect_anti_forensics as _anti
            anti_forensics = _anti(c.artifact_queries)
            steps.append({
                "step": "anti_forensics",
                "duration_s": round(_t.time() - t3b, 1),
                "rules_fired": anti_forensics.get("rules_fired", 0),
                "total_hits": anti_forensics.get("total_hits", 0),
            })
        except Exception as e:
            steps.append({"step": "anti_forensics", "error": str(e)})

        # ── Step 3c: Coverage ──
        t3c = _t.time()
        coverage_summary = {}
        try:
            from core.analysis.coverage import build_coverage_report as _cov
            cov = _cov({"axiom:auto": c})
            coverage_summary = {
                "case_format": cov.get("case_context", {}).get("case_format", ""),
                **cov.get("summary", {}),
            }
            steps.append({
                "step": "coverage",
                "duration_s": round(_t.time() - t3c, 1),
                **coverage_summary,
            })
        except Exception as e:
            steps.append({"step": "coverage", "error": str(e)})

        # ── Step 4: Extract IOCs ──
        t4 = _t.time()
        try:
            from core.analysis.ioc_extractor import extract_iocs as _extract
            iocs = _extract(c)
            ioc_list = iocs.get("iocs", [])
            steps.append({
                "step": "extract_iocs",
                "duration_s": round(_t.time() - t4, 1),
                "total_iocs": len(ioc_list),
                "by_type": iocs.get("by_type", {}),
            })
        except Exception as e:
            ioc_list = []
            steps.append({"step": "extract_iocs", "error": str(e)})

        # ── Step 5: Build Timeline ──
        t5 = _t.time()
        try:
            timeline = c.get_timeline(limit=500)
            steps.append({
                "step": "build_timeline",
                "duration_s": round(_t.time() - t5, 1),
                "total_events": timeline.get("total_events", 0),
            })
        except Exception as e:
            timeline = {}
            steps.append({"step": "build_timeline", "error": str(e)})

        # ── Step 6: MITRE Mapping ──
        t6 = _t.time()
        try:
            from core.analysis.mitre_mapper import get_attack_narrative
            mitre = get_attack_narrative(findings)
            steps.append({
                "step": "mitre_mapping",
                "duration_s": round(_t.time() - t6, 1),
                "techniques_found": len(mitre.get("techniques", [])),
            })
        except Exception as e:
            mitre = {}
            steps.append({"step": "mitre_mapping", "error": str(e)})

        bias_surface: dict[str, Any] = {}
        try:
            from core.analysis.bias_remediation import build_bias_remediation_surface
            bias_surface = build_bias_remediation_surface(
                c,
                {"findings": findings},
                findings=findings,
                triage_payload=triage,
            )
        except Exception as e:
            bias_surface = {
                "alert_summary": {"error": str(e)},
                "candidate_axes": {"error": str(e), "candidate_axes": []},
                "lane_state_board": {"error": str(e)},
            }
        quality_surface: dict[str, Any] = {}
        causal_surface: dict[str, Any] = {}
        autonomous_assessment: dict[str, Any] = {}
        try:
            from core.analysis.autonomous_assessment import assess_autonomous_case
            from core.analysis.evidence_quality import build_evidence_quality_surface
            from core.analysis.causal_chain import build_causal_chain_candidates

            quality_surface = build_evidence_quality_surface(c, {"findings": findings})
            causal_surface = build_causal_chain_candidates(c)
            autonomous_assessment = assess_autonomous_case(
                c,
                {"findings": findings, **bias_surface, **quality_surface, **causal_surface},
                triage_payload=triage,
                anti_forensics=anti_forensics,
                coverage={"summary": coverage_summary},
            )
        except Exception as e:
            autonomous_assessment = {"error": str(e)}

        # ── Step 7: Generate Report ──
        t7 = _t.time()
        try:
            from core.analysis.report_generator import generate_report as _gen
            report_path = os.path.join(out_dir, "reports", f"report_{datestamp}_{cname}.html")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            report_result = _gen({"axiom": c}, _masker, report_path)
            steps.append({
                "step": "generate_report",
                "duration_s": round(_t.time() - t7, 1),
                "report_path": report_result.get("path", report_result.get("output_path", "")),
            })
        except Exception as e:
            steps.append({"step": "generate_report", "error": str(e)})

        total_duration = round(_t.time() - t_start, 1)

        return _mask({
            "status": "complete",
            "case_name": case_meta.get("case_name", cname),
            "total_duration_s": total_duration,
            "output_dir": out_dir,
            "analysis_output": _analysis_output_context(create=False),
            "parsed_dir": parsed_dir,
            "total_hits": case_meta.get("total_hits", 0),
            "artifact_types": case_meta.get("artifact_types", {}),
            "summary": {
                "suspicious_findings": len(findings),
                "iocs_extracted": len(ioc_list),
                "timeline_events": timeline.get("total_events", 0),
                "mitre_techniques": len(mitre.get("techniques", [])),
                "strength_rollup": strength_rollup,
                "anti_forensics_rules_fired": anti_forensics.get("rules_fired", 0),
                "coverage_format": coverage_summary.get("case_format", ""),
            },
            "initial_triage": initial_triage_summary,
            **bias_surface,
            **quality_surface,
            **causal_surface,
            "autonomous_assessment": autonomous_assessment,
            "anti_forensics": anti_forensics,
            "coverage": coverage_summary,
            "steps": steps,
        })

    return await _traced("auto_triage", params, fn, timeout_seconds=TIMEOUT_HEAVY)


def main():
    mcp.run(transport="stdio")


# ── Hunt-pack dispatch registry ──
# Explicit allowlist of tools a pack author may call. Kept at module-bottom
# so the @mcp.tool functions above are fully bound before registration.
for _tool_name in (
    "case_health",
    "baseline_diff",
    "service_persistence_gate",
    "find_suspicious",
    "detect_anti_forensics",
    "hunt_evtx_rules",
    "coverage_explainer",
    "initial_triage_pack",
    "raw_image_triage_gate",
    "search_artifacts",
    "build_timeline",
    "date_anchor_triage",
    "query_evtx_file",
    "query_prefetch_files",
    "query_registry_hive",
    "inspect_pe_file",
    "extract_iocs",
    "correlate",
    "map_to_mitre",
    "compare_cases",
    "pivot_across_cases",
    "slice_timeline",
    "assess_evidence_strength",
    "auto_seed_entities_pack",
    "behavioral_delta_pack",
    "entity_story_pack",
    "get_summary",
    "get_artifact_types",
):
    _fn = globals().get(_tool_name)
    if _fn is not None:
        _register_hunt_tool(_tool_name, _fn)


if __name__ == "__main__":
    main()
