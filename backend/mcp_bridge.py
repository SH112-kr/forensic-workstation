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
from datetime import datetime, timezone
from typing import Any

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
from state import build_not_allowed_message, is_path_allowed

mcp = FastMCP(
    name="forensic-workstation",
    instructions=(
        "Forensic Workstation — DFIR 침해사고조사 플랫폼입니다. "
        "웹 UI(http://localhost:8001)와 연동됩니다. "
        "도구 호출 시 결과가 웹 UI에도 실시간으로 표시됩니다.\n\n"
        "먼저 open_case로 .mfdb 파일 또는 KAPE 결과 디렉토리를 열고, 분석 도구를 사용하세요."
    ),
)

# Shared state
_connectors: dict[str, Any] = {}
_masker = DataMasker()
_event_log: list[dict] = []  # Recent events for web UI polling

# Timezone display settings
_tz_config: dict[str, Any] = {
    "local_tz_name": "KST",
    "local_tz_offset_hours": 9,
    "enabled": True,
}

def _log_event(event_type: str, tool: str, data: Any = None, params: Any = None, result: Any = None, duration: float = 0):
    """Log a tool event for the web UI to stream."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "tool": tool,
    }
    if params is not None:
        entry["params"] = _truncate(params)
    if data is not None:
        entry["data"] = _truncate(data)
    if result is not None:
        entry["result"] = _truncate(result)
    if duration:
        entry["duration_ms"] = round(duration * 1000)
    _event_log.append(entry)
    if len(_event_log) > 200:
        _event_log.pop(0)
    try:
        event_file = os.path.join(os.path.dirname(__file__), ".mcp_events.jsonl")
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
    """Load a single case source by path and register it."""
    if not is_path_allowed(path):
        raise RuntimeError(build_not_allowed_message(path))
    if os.path.isdir(path):
        c = KapeCsvConnector()
    else:
        c = AxiomMfdbConnector()
    c.connect(path)
    if case_id:
        _connectors[f"axiom:{case_id}"] = c
    return c


def _get_axiom() -> AxiomMfdbConnector:
    c = _connectors.get("axiom")
    if c and c.is_connected():
        return c
    # Try auto-connect from web UI's active case
    state_file = os.path.join(os.path.dirname(__file__), ".active_case.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                info = json.load(f)
            all_cases = info.get("all_cases", [])
            if all_cases:
                # Parse each case in parallel — KAPE directories can each take
                # tens of seconds, so a sequential load blocks the first MCP
                # tool call for N × (per-case time) on multi-case projects.
                from concurrent.futures import ThreadPoolExecutor
                targets = [
                    (case.get("path", ""), case.get("case_id", ""))
                    for case in all_cases
                    if case.get("path") and os.path.exists(case.get("path", ""))
                ]
                if targets:
                    primary_path = info.get("path", "")
                    last_c = None
                    primary_c = None
                    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
                        futures = {
                            ex.submit(_load_case_from_path, p, cid): (p, cid)
                            for p, cid in targets
                        }
                        for fut in futures:
                            p, cid = futures[fut]
                            try:
                                loaded = fut.result()
                            except Exception:
                                continue
                            last_c = loaded
                            if p == primary_path:
                                primary_c = loaded
                    chosen = primary_c or last_c
                    if chosen:
                        _connectors["axiom"] = chosen
                        return chosen
            # Fallback: single path
            path = info.get("path", "")
            if path and os.path.exists(path):
                c = _load_case_from_path(path)
                _connectors["axiom"] = c
                return c
        except Exception:
            pass
    raise RuntimeError("케이스가 열려있지 않습니다. open_case를 먼저 실행하세요.")


# ── Masking Tools ──

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
        _log_event("error", tool_name, data={"error": str(e)}, duration=elapsed)
        return {"error": str(e)}


@mcp.tool()
async def open_case(path: str, case_name: str = "") -> dict:
    """Open an AXIOM case (.mfdb) file or KAPE output directory."""
    def fn():
        if not is_path_allowed(path):
            return {"error": build_not_allowed_message(path)}
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
        _connectors["axiom"] = c  # same key for backward compatibility
        return _mask({"status": "success", **meta})
    return await _traced("open_case", {"path": path, "case_name": case_name}, fn)


@mcp.tool()
async def get_summary() -> dict:
    """Get case overview."""
    return await _traced("get_summary", {}, lambda: _mask(_get_axiom().get_metadata()), timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def get_artifact_types() -> dict:
    """List artifact types with counts."""
    def fn():
        types = _get_axiom().get_artifact_type_counts()
        return _mask({"artifact_types": types, "total_types": len(types)})
    return await _traced("get_artifact_types", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


@mcp.tool()
async def pivot_across_cases(
    entity_type: str,
    entity_value: str,
    window_minutes: int = 60,
    limit_per_case: int = 100,
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

    Returns per-case counts, merged hits with full provenance, and
    first/last-seen markers so you can see which case carried the entity
    first and how it propagated. Fully offline.
    """
    def fn():
        from state import app_state
        from core.analysis.case_aggregator import pivot_across_cases as _pivot
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(_pivot(axiom_conns, entity_type, entity_value, window_minutes, limit_per_case))
    return await _traced(
        "pivot_across_cases",
        {"entity_type": entity_type, "entity_value": entity_value[:100], "limit_per_case": limit_per_case},
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
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(_compare(axiom_conns))
    return await _traced("compare_cases", {}, fn, timeout_seconds=TIMEOUT_LIGHT)


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
        requested = [a.strip() for a in artifact_types.split(",") if a.strip()] if artifact_types else None
        # Pass only the axiom:* connectors — coverage never touches E01/Vol/Ghidra.
        axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
        return _mask(build_coverage_report(axiom_conns, artifact_types=requested))
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
            axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
            cap = min(limit, config.search_max_limit)
            return _mask(search_across_cases(
                axiom_conns,
                keyword=keyword or (keywords.split(",")[0].strip() if keywords else ""),
                artifact_type=artifact_type, start_date=start_date, end_date=end_date,
                limit_per_case=cap, global_limit=cap, global_offset=offset,
            ))
        axiom = _get_axiom()
        cap = min(limit, config.search_max_limit)
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords.strip() else []

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
    return await _traced("get_hit_detail", {"hit_id": hit_id}, lambda: _mask(_get_axiom().get_hit_detail(hit_id)), timeout_seconds=TIMEOUT_LIGHT)


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
            axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
            return _mask(timeline_across_cases(
                axiom_conns,
                start_date=start_date, end_date=end_date,
                artifact_types=type_list,
                limit_per_case=cap, global_limit=cap, global_offset=offset,
            ))

        axiom = _get_axiom()
        if kw_list:
            return _mask(_timeline_with_keywords(axiom, start_date, end_date, kw_list, cap, offset))
        else:
            return _mask(axiom.get_timeline(start_date, end_date, type_list, cap, offset))
    return await _traced("build_timeline", params, fn, timeout_seconds=TIMEOUT_HEAVY)


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


@mcp.tool()
async def find_suspicious(rules: str = "") -> dict:
    """Run structured threat detection rules."""
    def fn():
        from core.analysis.suspicious import find_suspicious as _find
        return _mask(_find(_get_axiom().artifact_queries, rules=rules))
    return await _traced("find_suspicious", {"rules": rules}, fn, timeout_seconds=TIMEOUT_HEAVY)


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
    """Multi-keyword correlation: find where keywords co-occur in time."""
    per_keyword = {}
    all_events = []

    for kw in kw_list:
        cap = min(limit, config.correlate_max_limit)
        result = axiom.search(
            keyword=kw,
            filters={"start_date": start_date, "end_date": end_date},
            limit=cap, offset=offset,
        )
        hits = result.get("hits", [])
        true_total = result.get("total", len(hits))

        # Extract timestamps for each hit
        events = []
        for h in hits:
            ts_fields = h.get("timestamps", {})
            for ts_name, ts_val in ts_fields.items():
                ms = axiom._iso_to_ms(ts_val) if ts_val else None
                if ms:
                    events.append({
                        "keyword": kw,
                        "hit_id": h.get("hit_id"),
                        "timestamp": ts_val,
                        "timestamp_ms": ms,
                        "time_field": ts_name,
                        "artifact_type": h.get("artifact_type", ""),
                    })

        per_keyword[kw] = {
            "total_hits": true_total,
            "returned_hits": len(hits),
            "truncated": true_total > len(hits),
            "events_with_timestamps": len(events),
            "artifact_types": {},
        }
        for h in hits:
            at = h.get("artifact_type", "unknown")
            per_keyword[kw]["artifact_types"][at] = per_keyword[kw]["artifact_types"].get(at, 0) + 1

        all_events.extend(events)

    # Sort all events chronologically
    all_events.sort(key=lambda e: e.get("timestamp_ms", 0))

    # Find co-occurrence windows: time windows where 2+ different keywords appear
    window_ms = window_minutes * 60 * 1000
    co_occurrences = []
    for i, ev in enumerate(all_events):
        window_kws = {ev["keyword"]}
        window_events = [ev]
        for j in range(i + 1, len(all_events)):
            if all_events[j]["timestamp_ms"] - ev["timestamp_ms"] <= window_ms:
                window_kws.add(all_events[j]["keyword"])
                window_events.append(all_events[j])
            else:
                break
        if len(window_kws) >= 2:
            co_occurrences.append({
                "start": ev["timestamp"],
                "keywords_present": sorted(window_kws),
                "event_count": len(window_events),
            })

    # Deduplicate overlapping windows
    deduped = []
    seen_starts = set()
    for co in co_occurrences:
        key = (co["start"], tuple(co["keywords_present"]))
        if key not in seen_starts:
            seen_starts.add(key)
            deduped.append(co)

    total_events = len(all_events)
    return {
        "mode": "multi_keyword_correlation",
        "keywords": kw_list,
        "per_keyword": per_keyword,
        "co_occurrence_windows": deduped[:50],
        "total_co_occurrences": len(deduped),
        "window_minutes": window_minutes,
        "chronological_events": all_events[:limit],
        "total_chronological_events": total_events,
        "truncated": total_events > limit,
    }


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
        return _gen({"axiom": _get_axiom()}, _masker, output_path)
    return await _traced("generate_report", {"output_path": output_path}, fn)


# ── E01 Image Tools ──

_EXTRACT_DIR = os.path.join(os.path.dirname(__file__), "extracted")


def _get_e01() -> E01ImageConnector:
    c = _connectors.get("e01")
    if c and c.is_connected():
        return c
    raise RuntimeError("E01 이미지가 열려있지 않습니다. mount_image를 먼저 실행하세요.")


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
async def mount_image(e01_path: str) -> dict:
    """Mount E01/VMDK/raw disk image for file extraction."""
    def fn():
        if not is_path_allowed(e01_path):
            return {"error": build_not_allowed_message(e01_path)}
        old = _connectors.pop("e01", None)
        if old:
            old.disconnect()
        c = E01ImageConnector()
        meta = c.connect(e01_path)
        _connectors["e01"] = c
        return _mask({"status": "mounted", **meta})
    return await _traced("mount_image", {"e01_path": e01_path}, fn, timeout_seconds=TIMEOUT_LIGHT)


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
async def extract_file(internal_path: str, output_dir: str = "") -> dict:
    """Extract a file from mounted disk image for STATIC ANALYSIS ONLY. Extracted files may be malware — NEVER execute them."""
    def fn():
        e01 = _get_e01()
        out_dir = output_dir or _EXTRACT_DIR
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
        return _mask(result)
    return await _traced("extract_file", {"internal_path": internal_path}, fn)


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


# ── Ghidra Binary Analysis Tools ──

@mcp.tool()
async def analyze_binary(file_path: str, ghidra_install_dir: str = "") -> dict:
    """Load a binary (EXE/DLL) into Ghidra for STATIC reverse engineering (no execution). First call is slow (~1min)."""
    def fn():
        old = _connectors.get("ghidra")
        if old and old.is_connected():
            old.disconnect()
        g = GhidraConnector()
        meta = g.connect(file_path, ghidra_install_dir=ghidra_install_dir or config.ghidra_install_dir)
        _connectors["ghidra"] = g
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
        output_dir: Output directory (default: ./export/YYYYMMDD_casename/)
        kape_path: Path to kape.exe (auto-detected if empty)
        skip_kape: Skip KAPE collection (use existing parsed data in output_dir)
        vss: Include Volume Shadow Copies (default: True, requires admin)
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
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(backend_dir)

        if output_dir:
            out_dir = output_dir
        else:
            out_dir = os.path.join(project_dir, "export", f"{datestamp}_{cname}")

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

        # ── Step 3: Find Suspicious ──
        t3 = _t.time()
        try:
            from core.analysis.suspicious import find_suspicious as _find
            suspicious = _find(c.artifact_queries)
            findings = suspicious.get("findings", [])
            steps.append({
                "step": "find_suspicious",
                "duration_s": round(_t.time() - t3, 1),
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
            })
        except Exception as e:
            findings = []
            steps.append({"step": "find_suspicious", "error": str(e)})

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

        # ── Step 7: Generate Report ──
        t7 = _t.time()
        try:
            from core.analysis.report_generator import generate_report as _gen
            report_result = _gen({"axiom": c}, _masker, "")
            steps.append({
                "step": "generate_report",
                "duration_s": round(_t.time() - t7, 1),
                "report_path": report_result.get("output_path", ""),
            })
        except Exception as e:
            steps.append({"step": "generate_report", "error": str(e)})

        total_duration = round(_t.time() - t_start, 1)

        return _mask({
            "status": "complete",
            "case_name": case_meta.get("case_name", cname),
            "total_duration_s": total_duration,
            "output_dir": out_dir,
            "parsed_dir": parsed_dir,
            "total_hits": case_meta.get("total_hits", 0),
            "artifact_types": case_meta.get("artifact_types", {}),
            "summary": {
                "suspicious_findings": len(findings),
                "iocs_extracted": len(ioc_list),
                "timeline_events": timeline.get("total_events", 0),
                "mitre_techniques": len(mitre.get("techniques", [])),
            },
            "top_findings": [
                {"rule": f["rule_name"], "severity": f["severity"], "count": f["matching_count"]}
                for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4))[:10]
            ],
            "steps": steps,
        })

    return await _traced("auto_triage", params, fn, timeout_seconds=TIMEOUT_HEAVY)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
