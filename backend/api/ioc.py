"""IOC extraction & correlation API."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.raw_support import active_raw_index_without_parsed_case, raw_index_coverage

router = APIRouter(prefix="/api/ioc", tags=["ioc"])

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_MCP_EVENT_FILE = os.path.join(_BACKEND_DIR, ".mcp_events.jsonl")
_DEFAULT_MANUAL_GRAPH_FILE = os.path.join(_BACKEND_DIR, ".ioc_graph_manual.json")


class IOCRequest(BaseModel):
    ioc_types: str = ""
    exclude_private_ips: bool = True
    exclude_known_good: bool = True


class IOCGraphRequest(IOCRequest):
    graph_source: str = "session"
    max_iocs: int = 140
    max_findings: int = 90


class ManualGraphObservationRequest(BaseModel):
    node_type: str = "ioc"
    value: str
    ioc_type: str = ""
    source_label: str = ""
    note: str = ""
    timestamp: str = ""


class CorrelateRequest(BaseModel):
    pivot_field: str
    pivot_value: str
    window_minutes: int = 5
    limit: int = 100


@router.post("/extract")
async def extract_iocs(req: IOCRequest):
    from state import app_state
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "ioc_types": [
                    value.strip()
                    for value in str(req.ioc_types or "").split(",")
                    if value.strip()
                ],
                "iocs": [],
                "total_iocs": 0,
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_ioc_extraction_unsupported",
                    "detail": (
                        "The active raw sidecar indexes file-system records only; "
                        "IOC extraction has not been implemented for raw sidecar "
                        "artifacts yet. Do not interpret this as no IOCs."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
                "notes": [
                    (
                        "AXIOM/KAPE IOC extraction remains a parity reference "
                        "until raw artifact-family IOC extractors are implemented."
                    ),
                ],
            }
        from core.analysis.ioc_extractor import extract_iocs as _extract
        return _extract(
            app_state.get_axiom(),
            ioc_types=req.ioc_types,
            exclude_private=req.exclude_private_ips,
            exclude_known_good=req.exclude_known_good,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/graph")
async def ioc_graph(req: IOCGraphRequest):
    from state import app_state
    try:
        from core.analysis.ioc_graph import build_analysis_session_graph, build_ioc_mitre_graph

        graph_source = str(req.graph_source or "session").lower()
        manual = _read_manual_graph_observations()
        if graph_source in {"session", "analysis_session", "mcp"}:
            return build_analysis_session_graph(
                _read_mcp_events(),
                exclude_private_ips=req.exclude_private_ips,
                exclude_known_good=req.exclude_known_good,
                max_iocs=req.max_iocs,
                max_findings=req.max_findings,
                manual_observations=manual,
            )
        if graph_source not in {"case", "case_scan", "full_case"}:
            raise HTTPException(status_code=400, detail="graph_source must be 'session' or 'case'")
        return build_ioc_mitre_graph(
            app_state._connectors,
            ioc_types=req.ioc_types,
            exclude_private_ips=req.exclude_private_ips,
            exclude_known_good=req.exclude_known_good,
            max_iocs=req.max_iocs,
            max_findings=req.max_findings,
            manual_observations=manual,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/graph/manual")
async def get_manual_graph_observations():
    return {"items": _read_manual_graph_observations()}


@router.post("/graph/manual")
async def post_manual_graph_observation(req: ManualGraphObservationRequest):
    try:
        item = _new_manual_graph_observation(req)
        items = _read_manual_graph_observations()
        items.append(item)
        _write_manual_graph_observations(items)
        return item
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/graph/manual/{observation_id}")
async def delete_manual_graph_observation(observation_id: str):
    items = _read_manual_graph_observations()
    kept = [item for item in items if item.get("id") != observation_id]
    if len(kept) == len(items):
        raise HTTPException(status_code=404, detail=f"Manual graph observation not found: {observation_id}")
    _write_manual_graph_observations(kept)
    return {"status": "deleted", "id": observation_id}


def _read_mcp_events(limit: int = 2000) -> list[dict]:
    path = _DEFAULT_MCP_EVENT_FILE
    if not os.path.exists(path):
        return []
    events: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        for line in lines:
            try:
                event = json.loads(line)
            except Exception:
                continue
            if isinstance(event, dict):
                events.append(event)
    except Exception:
        return []
    return events


def _manual_graph_store_path() -> str:
    return _DEFAULT_MANUAL_GRAPH_FILE


def _read_manual_graph_observations() -> list[dict]:
    path = _manual_graph_store_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return []
    items = payload.get("items", []) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _write_manual_graph_observations(items: list[dict]) -> None:
    path = _manual_graph_store_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "schema": "ioc_graph_manual_v1",
        "updated": datetime.now(timezone.utc).isoformat(),
        "items": items,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _new_manual_graph_observation(req: ManualGraphObservationRequest) -> dict:
    value = str(req.value or "").strip()
    if not value:
        raise ValueError("Manual graph observation value is required")
    return {
        "id": f"manual_{uuid4().hex[:12]}",
        "node_type": str(req.node_type or "ioc").strip().lower() or "ioc",
        "value": value,
        "ioc_type": str(req.ioc_type or "").strip().lower(),
        "source_label": str(req.source_label or "").strip(),
        "note": str(req.note or "").strip(),
        "timestamp": str(req.timestamp or "").strip(),
        "source_type": "analyst_external",
        "visibility": "analyst_only",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/correlate")
async def correlate(req: CorrelateRequest):
    from state import app_state
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "pivot_field": req.pivot_field,
                "pivot_value": req.pivot_value,
                "window_minutes": req.window_minutes,
                "limit": req.limit,
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_correlate_pivot_unsupported",
                    "detail": (
                        "Classic correlate pivot mode currently depends on "
                        "parsed-case field/source/user semantics that the raw "
                        "sidecar does not expose yet."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
            }
        from core.analysis.correlator import correlate as _correlate
        return _correlate(
            app_state.get_axiom(),
            pivot_field=req.pivot_field,
            pivot_value=req.pivot_value,
            window_minutes=req.window_minutes,
            limit=req.limit,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
