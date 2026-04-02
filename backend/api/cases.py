"""Case management API — open/close cases, get summary."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/cases", tags=["cases"])


class OpenCaseRequest(BaseModel):
    path: str
    case_name: str = ""


@router.post("/open")
async def open_case(req: OpenCaseRequest):
    from state import app_state
    try:
        result = app_state.open_axiom(req.path, req.case_name)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/close")
async def close_case():
    from state import app_state
    app_state.remove("axiom")
    return {"status": "closed"}


@router.get("/summary")
async def get_summary():
    from state import app_state
    try:
        return app_state.get_axiom().get_metadata()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/types")
async def get_artifact_types():
    from state import app_state
    try:
        types = app_state.get_axiom().get_artifact_type_counts()
        return {"artifact_types": types, "total_types": len(types)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/list")
async def list_cases():
    from state import app_state
    return {"cases": app_state.list_cases()}


@router.post("/switch")
async def switch_case(case_id: str):
    from state import app_state
    try:
        meta = app_state.switch_case(case_id)
        return {"status": "switched", **meta}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
async def get_status():
    from state import app_state
    return {"connectors": app_state.list_connected()}
