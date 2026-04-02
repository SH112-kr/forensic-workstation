"""Report generation API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/report", tags=["report"])


class ReportRequest(BaseModel):
    output_path: str = ""


@router.post("/generate")
async def generate_report(req: ReportRequest):
    from state import app_state
    from core.analysis.report_generator import generate_report as _gen
    try:
        axiom = app_state.get("axiom")
        if not axiom or not axiom.is_connected():
            raise RuntimeError("케이스가 열려있지 않습니다.")
        return _gen({"axiom": axiom}, output_path=req.output_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/download")
async def download_report(path: str):
    import os
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path, filename=os.path.basename(path), media_type="text/html")
