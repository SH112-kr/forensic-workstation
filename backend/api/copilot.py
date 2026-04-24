"""AI Co-pilot WebSocket — bridges UI chat to core analysis functions.

The co-pilot calls the same functions as the REST API,
but applies masking before sending results to the LLM.
"""

from __future__ import annotations

import asyncio
import json
import os
import traceback
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

router = APIRouter(tags=["copilot"])

# Available tools the co-pilot can call
TOOL_REGISTRY: dict[str, dict] = {
    "search_artifacts": {
        "description": "Search artifacts by keyword, type, date range",
        "params": ["keyword", "artifact_type", "start_date", "end_date", "limit"],
    },
    "get_hit_detail": {
        "description": "Get full detail for a specific artifact hit",
        "params": ["hit_id"],
    },
    "build_timeline": {
        "description": "Build chronological timeline of events",
        "params": ["start_date", "end_date", "limit"],
    },
    "date_anchor_triage": {
        "description": "Surface decisive raw anchors for a narrow date window",
        "params": ["start_date", "end_date", "limit_per_query"],
    },
    "initial_triage_pack": {
        "description": "Window-first initial triage with coverage gates, candidate windows, and delayed baseline diff",
        "params": [
            "scope_mode",
            "start_date",
            "end_date",
            "suspected_date",
            "top_window_count",
            "timeline_scan_limit",
            "include_baseline_diff",
        ],
    },
    "find_suspicious": {
        "description": "Run structured threat detection rules",
        "params": ["rules"],
    },
    "extract_iocs": {
        "description": "Extract IOCs (IP, domain, hash, URL, email)",
        "params": ["ioc_types"],
    },
    "correlate": {
        "description": "Cross-reference artifacts by timestamp, user, source, keyword",
        "params": ["pivot_field", "pivot_value", "window_minutes"],
    },
    "map_to_mitre": {
        "description": "Map findings to MITRE ATT&CK techniques",
        "params": [],
    },
    "get_artifact_types": {
        "description": "List all artifact types with counts",
        "params": [],
    },
}


def execute_tool(name: str, params: dict) -> dict:
    """Execute a tool by name using the same core functions as the REST API."""
    from state import app_state

    axiom = app_state.get("axiom")
    if not axiom or not axiom.is_connected():
        return {"error": "No case is open."}

    try:
        if name == "search_artifacts":
            return axiom.search(
                keyword=params.get("keyword", ""),
                filters={
                    "artifact_type": params.get("artifact_type", ""),
                    "start_date": params.get("start_date", ""),
                    "end_date": params.get("end_date", ""),
                },
                limit=min(int(params.get("limit", 50)), 200),
            )
        elif name == "get_hit_detail":
            return axiom.get_hit_detail(int(params.get("hit_id", 0)))
        elif name == "build_timeline":
            return axiom.get_timeline(
                start_date=params.get("start_date", ""),
                end_date=params.get("end_date", ""),
                limit=min(int(params.get("limit", 200)), 500),
            )
        elif name == "date_anchor_triage":
            from core.analysis.date_anchor_triage import date_anchor_triage
            return date_anchor_triage(
                axiom,
                start_date=params.get("start_date", ""),
                end_date=params.get("end_date", ""),
                limit_per_query=min(int(params.get("limit_per_query", 10)), 50),
            )
        elif name == "initial_triage_pack":
            from core.analysis.initial_triage import initial_triage
            return initial_triage(
                axiom,
                scope_mode=params.get("scope_mode", "recent_14d"),
                start_date=params.get("start_date", ""),
                end_date=params.get("end_date", ""),
                suspected_date=params.get("suspected_date", ""),
                top_window_count=max(1, min(int(params.get("top_window_count", 3)), 5)),
                timeline_scan_limit=max(200, min(int(params.get("timeline_scan_limit", 1200)), 4000)),
                include_baseline_diff=bool(params.get("include_baseline_diff", True)),
            )
        elif name == "find_suspicious":
            from core.analysis.suspicious import find_suspicious
            return find_suspicious(axiom.artifact_queries, rules=params.get("rules", ""))
        elif name == "extract_iocs":
            from core.analysis.ioc_extractor import extract_iocs
            return extract_iocs(axiom, ioc_types=params.get("ioc_types", "hash"))
        elif name == "correlate":
            from core.analysis.correlator import correlate
            return correlate(
                axiom,
                pivot_field=params.get("pivot_field", "keyword"),
                pivot_value=params.get("pivot_value", ""),
                window_minutes=int(params.get("window_minutes", 5)),
            )
        elif name == "map_to_mitre":
            from core.analysis.suspicious import find_suspicious
            from core.analysis.mitre_mapper import get_attack_narrative
            sus = find_suspicious(axiom.artifact_queries)
            return get_attack_narrative(sus.get("findings", []))
        elif name == "get_artifact_types":
            types = axiom.get_artifact_type_counts()
            return {"artifact_types": types, "total": len(types)}
        else:
            return {"error": f"Unknown tool: {name}"}
    except Exception as e:
        return {"error": str(e)}


async def _safe_send_text(websocket: WebSocket, data: str) -> bool:
    """Best-effort send that exits cleanly once the socket is closed."""
    if (
        websocket.client_state == WebSocketState.DISCONNECTED
        or websocket.application_state == WebSocketState.DISCONNECTED
    ):
        return False

    try:
        await websocket.send_text(data)
        return True
    except (WebSocketDisconnect, RuntimeError):
        return False


async def _safe_send_json(websocket: WebSocket, data: dict[str, Any]) -> bool:
    """JSON variant for sockets that may already be closing."""
    if (
        websocket.client_state == WebSocketState.DISCONNECTED
        or websocket.application_state == WebSocketState.DISCONNECTED
    ):
        return False

    try:
        await websocket.send_json(data)
        return True
    except (WebSocketDisconnect, RuntimeError):
        return False


@router.get("/api/copilot/events")
async def get_mcp_events(since: int = 0):
    """Poll MCP bridge events for the Co-pilot panel.
    The MCP bridge writes events to .mcp_events.jsonl.
    This endpoint reads new events since a given line number.
    """
    import os
    event_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".mcp_events.jsonl")
    events = []
    if os.path.exists(event_file):
        try:
            with open(event_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for i, line in enumerate(lines[since:], start=since):
                try:
                    events.append({"line": i, **json.loads(line.strip())})
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
    return {"events": events, "total_lines": len(events) + since}


@router.websocket("/ws/mcp-monitor")
async def mcp_monitor_ws(websocket: WebSocket):
    """Real-time MCP traffic monitor — streams events as they happen.

    On connect, replays the last N events so the analyst doesn't have to
    re-run tools to see what just happened. After the backfill, tails the
    event file for new lines.
    """
    await websocket.accept()
    event_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".mcp_events.jsonl")
    backfill_count = int(os.environ.get("FW_EVENT_BACKFILL", "50"))
    last_pos = 0

    # Backfill: send the last N events, then tail from end.
    if os.path.exists(event_file):
        try:
            with open(event_file, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            tail = [ln.strip() for ln in all_lines[-backfill_count:] if ln.strip()]
            for line in tail:
                if not await _safe_send_text(websocket, line):
                    return
            last_pos = os.path.getsize(event_file)
        except Exception:
            last_pos = os.path.getsize(event_file) if os.path.exists(event_file) else 0

    tick = 0
    try:
        while True:
            await asyncio.sleep(0.5)  # Poll every 500ms
            tick += 1

            # Send heartbeat every 15s to keep the connection alive
            if tick % 30 == 0:
                if not await _safe_send_text(websocket, '{"type":"ping"}'):
                    return

            if not os.path.exists(event_file):
                continue
            size = os.path.getsize(event_file)
            if size < last_pos:
                # File was truncated/rotated — reset
                last_pos = 0
            if size <= last_pos:
                continue
            try:
                with open(event_file, "r", encoding="utf-8") as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()
                for line in new_lines:
                    line = line.strip()
                    if line:
                        if not await _safe_send_text(websocket, line):
                            return
            except Exception:
                pass
    except (WebSocketDisconnect, RuntimeError):
        pass


@router.websocket("/ws/copilot")
async def copilot_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                if not await _safe_send_json(websocket, {"type": "error", "content": "Invalid JSON"}):
                    return
                continue

            msg_type = msg.get("type", "")

            if msg_type == "chat":
                # User message — echo back (LLM integration placeholder)
                user_text = msg.get("content", "")
                if not await _safe_send_json(websocket, {
                    "type": "assistant",
                    "content": f"Co-pilot received: \"{user_text}\"\n\nAI integration pending. "
                               f"You can call tools directly using the tool panel.",
                }):
                    return

            elif msg_type == "tool_call":
                # Execute a tool
                tool_name = msg.get("tool", "")
                tool_params = msg.get("params", {})

                # Notify: tool is running
                if not await _safe_send_json(websocket, {
                    "type": "tool_status",
                    "tool": tool_name,
                    "status": "running",
                }):
                    return

                # Execute
                result = execute_tool(tool_name, tool_params)

                # Send result
                if not await _safe_send_json(websocket, {
                    "type": "tool_result",
                    "tool": tool_name,
                    "result": _truncate_result(result),
                }):
                    return

            elif msg_type == "list_tools":
                if not await _safe_send_json(websocket, {
                    "type": "tool_list",
                    "tools": TOOL_REGISTRY,
                }):
                    return

            else:
                if not await _safe_send_json(
                    websocket,
                    {"type": "error", "content": f"Unknown message type: {msg_type}"},
                ):
                    return

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await _safe_send_json(websocket, {"type": "error", "content": str(e)})
        except Exception:
            pass


def _truncate_result(result: dict, max_items: int = 20) -> dict:
    """Truncate large results to prevent WebSocket overload."""
    if not isinstance(result, dict):
        return result
    truncated = {}
    for k, v in result.items():
        if isinstance(v, list) and len(v) > max_items:
            truncated[k] = v[:max_items]
            truncated[f"_{k}_truncated"] = f"Showing {max_items}/{len(v)}"
        else:
            truncated[k] = v
    return truncated
