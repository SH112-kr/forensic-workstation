"""Hayabusa EVTX log analysis API."""

from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/logs", tags=["logs"])


class OpenEvtxRequest(BaseModel):
    path: str
    hayabusa_path: str = ""


class SearchRequest(BaseModel):
    event_id: int = 0
    keyword: str = ""
    start_time: str = ""
    end_time: str = ""


@router.post("/open")
async def open_evtx(req: OpenEvtxRequest):
    from state import app_state
    try:
        from core.connectors.hayabusa import HayabusaConnector
        app_state.remove("hayabusa")
        c = HayabusaConnector()
        hayabusa_path = req.hayabusa_path or os.environ.get("FORENSIC_HAYABUSA_PATH", "hayabusa")
        meta = c.connect(req.path, hayabusa_path=hayabusa_path)
        app_state.set("hayabusa", c)
        return meta
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _hay():
    from state import app_state
    c = app_state.get("hayabusa")
    if not c or not c.is_connected():
        raise HTTPException(status_code=400, detail="EVTX 경로가 설정되지 않았습니다.")
    return c


@router.post("/scan")
async def scan(min_level: str = "medium"):
    try:
        return _hay().run_scan(min_level=min_level)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/search")
async def search(req: SearchRequest):
    try:
        results = _hay().search_events(req.event_id, req.keyword, req.start_time, req.end_time)
        total = len(results)
        returned = results[:500]
        return {"total": total, "returned": len(returned), "truncated": total > len(returned), "events": returned}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
