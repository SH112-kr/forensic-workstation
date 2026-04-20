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
        # Honour the evidence allowlist guardrail — a memory dump opened through
        # the web UI must be registered as user-picked evidence so downstream MCP
        # tools that consult is_path_allowed() will accept it too.
        app_state.add_allowed_evidence([req.path], source="memory:open")
        from core.connectors.volatility_connector import VolatilityConnector
        app_state.remove("volatility")
        c = VolatilityConnector()
        meta = c.connect(req.path)
        app_state.set("volatility", c)
        return meta
    except ImportError:
        raise HTTPException(status_code=400, detail="volatility3가 설치되지 않았습니다. pip install volatility3")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
async def status():
    """Quick readiness probe so the UI can decide whether to show the load form."""
    from state import app_state
    c = app_state.get("volatility")
    return {
        "loaded": bool(c and getattr(c, "is_connected", lambda: False)()),
        "metadata": c.get_metadata() if c and getattr(c, "is_connected", lambda: False)() else None,
    }


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
