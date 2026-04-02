"""IOC extraction & correlation API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/ioc", tags=["ioc"])


class IOCRequest(BaseModel):
    ioc_types: str = ""
    exclude_private_ips: bool = True
    exclude_known_good: bool = True


class CorrelateRequest(BaseModel):
    pivot_field: str
    pivot_value: str
    window_minutes: int = 5
    limit: int = 100


@router.post("/extract")
async def extract_iocs(req: IOCRequest):
    from state import app_state
    from core.analysis.ioc_extractor import extract_iocs as _extract
    try:
        return _extract(
            app_state.get_axiom(),
            ioc_types=req.ioc_types,
            exclude_private=req.exclude_private_ips,
            exclude_known_good=req.exclude_known_good,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/correlate")
async def correlate(req: CorrelateRequest):
    from state import app_state
    from core.analysis.correlator import correlate as _correlate
    try:
        return _correlate(
            app_state.get_axiom(),
            pivot_field=req.pivot_field,
            pivot_value=req.pivot_value,
            window_minutes=req.window_minutes,
            limit=req.limit,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
