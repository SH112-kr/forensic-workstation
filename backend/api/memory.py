"""Volatility memory analysis API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/memory", tags=["memory"])


class OpenMemoryRequest(BaseModel):
    path: str


@router.post("/open")
async def open_memory(req: OpenMemoryRequest):
    from state import app_state
    try:
        from core.connectors.volatility_connector import VolatilityConnector
        app_state.remove("volatility")
        c = VolatilityConnector()
        meta = c.connect(req.path)
        app_state.set("volatility", c)
        return meta
    except ImportError:
        raise HTTPException(status_code=400, detail="volatility3가 설치되지 않았습니다.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _vol():
    from state import app_state
    return app_state.get_volatility()


@router.get("/pslist")
async def pslist():
    try:
        r = _vol().pslist()
        return {"total": len(r), "processes": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/pstree")
async def pstree():
    try:
        r = _vol().pstree()
        return {"total": len(r), "processes": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/netscan")
async def netscan():
    try:
        r = _vol().netscan()
        return {"total": len(r), "connections": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/malfind")
async def malfind():
    try:
        r = _vol().malfind()
        return {"total": len(r), "findings": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/cmdline")
async def cmdline():
    try:
        r = _vol().cmdline()
        return {"total": len(r), "processes": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/dlllist")
async def dlllist(pid: int = 0):
    try:
        r = _vol().dlllist(pid if pid else None)
        return {"total": len(r), "dlls": r}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
