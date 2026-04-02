"""YARA scanning API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/yara", tags=["yara"])


class LoadRulesRequest(BaseModel):
    path: str


class ScanRequest(BaseModel):
    target_path: str
    pattern: str = "*"
    limit: int = 100


@router.post("/load")
async def load_rules(req: LoadRulesRequest):
    from state import app_state
    try:
        from core.connectors.yara_connector import YaraConnector
        app_state.remove("yara")
        c = YaraConnector()
        meta = c.connect(req.path)
        app_state.set("yara", c)
        return meta
    except ImportError:
        raise HTTPException(status_code=400, detail="yara-python이 설치되지 않았습니다.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _yara():
    from state import app_state
    c = app_state.get("yara")
    if not c or not c.is_connected():
        raise HTTPException(status_code=400, detail="YARA 룰이 로드되지 않았습니다.")
    return c


@router.post("/scan-file")
async def scan_file(req: ScanRequest):
    try:
        results = _yara().scan_file(req.target_path)
        return {"file": req.target_path, "matches": len(results), "results": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/scan-directory")
async def scan_directory(req: ScanRequest):
    try:
        results = _yara().scan_directory(req.target_path, req.pattern, req.limit)
        return {"directory": req.target_path, "matches": len(results), "results": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
