"""Registry hive analysis API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/registry", tags=["registry"])


def _regipy_available() -> bool:
    try:
        import regipy  # noqa: F401
        return True
    except Exception:
        return False


class OpenRequest(BaseModel):
    path: str


@router.get("/status")
async def status():
    from state import app_state
    c = app_state.get("registry")
    loaded = bool(c and getattr(c, "is_connected", lambda: False)())
    return {
        "regipy_available": _regipy_available(),
        "loaded": loaded,
        "metadata": c.get_metadata() if loaded else None,
        "install_hint": None if _regipy_available() else "regipy is not installed. Run `pip install regipy`.",
    }


@router.post("/open")
async def open_hive(req: OpenRequest):
    from state import app_state
    if not _regipy_available():
        raise HTTPException(
            status_code=400,
            detail="regipy is not installed. Run `pip install regipy`.",
        )
    try:
        app_state.add_allowed_evidence([req.path], source="registry:open")
        from core.connectors.registry import RegistryConnector
        app_state.remove("registry")
        c = RegistryConnector()
        meta = c.connect(req.path)
        app_state.set("registry", c)
        return meta
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _reg():
    from state import app_state
    c = app_state.get("registry")
    if not c or not c.is_connected():
        raise HTTPException(status_code=400, detail="레지스트리 하이브가 로드되지 않았습니다.")
    return c


@router.get("/plugins")
async def run_plugins():
    try:
        return _reg().run_plugins()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/timeline")
async def timeline(limit: int = 200):
    try:
        return _reg().timeline(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/search")
async def search_registry(keyword: str, limit: int = 50):
    try:
        return _reg().search(keyword=keyword, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/key")
async def get_key(path: str):
    try:
        return _reg().get_key(path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
