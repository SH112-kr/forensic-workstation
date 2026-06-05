"""IOC extraction & correlation API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.raw_support import active_raw_index_without_parsed_case, raw_index_coverage

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
