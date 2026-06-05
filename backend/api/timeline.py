"""Timeline API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.raw_support import annotate_parsed_fallback, should_fallback_to_parsed_case
from core.config import config

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


class TimelineRequest(BaseModel):
    start_date: str = ""
    end_date: str = ""
    artifact_types: list[str] = []
    limit: int = 500
    all_cases: bool = False


@router.post("")
async def build_timeline(req: TimelineRequest):
    from state import app_state
    try:
        if req.all_cases:
            from core.analysis.case_aggregator import timeline_across_cases
            cap = min(req.limit, config.max_limit)
            result = timeline_across_cases(
                app_state._connectors,
                start_date=req.start_date,
                end_date=req.end_date,
                artifact_types=req.artifact_types or None,
                limit_per_case=cap,
                global_limit=cap,
                global_offset=0,
            )
            return {
                "entries": result["entries"],
                "total_events": result["merged_total"],
                "returned": result["returned"],
                "per_case": result["per_case"],
                "warnings": result["warnings"],
                "all_cases": True,
            }
        raw = app_state.get("raw_index")
        if raw and raw.is_connected():
            raw_result = raw.get_timeline(
                start_date=req.start_date,
                end_date=req.end_date,
                artifact_types=req.artifact_types or None,
                limit=min(req.limit, config.max_limit),
                offset=0,
            )
            if should_fallback_to_parsed_case(raw_result, app_state):
                parsed_result = app_state.get_axiom().get_timeline(
                    start_date=req.start_date,
                    end_date=req.end_date,
                    artifact_types=req.artifact_types or None,
                    limit=min(req.limit, config.max_limit),
                )
                return annotate_parsed_fallback(parsed_result, raw_result)
            return raw_result

        return app_state.get_axiom().get_timeline(
            start_date=req.start_date,
            end_date=req.end_date,
            artifact_types=req.artifact_types or None,
            limit=min(req.limit, config.max_limit),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
