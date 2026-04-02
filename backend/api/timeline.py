"""Timeline API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from core.config import config

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


class TimelineRequest(BaseModel):
    start_date: str = ""
    end_date: str = ""
    artifact_types: list[str] = []
    limit: int = 500


@router.post("")
async def build_timeline(req: TimelineRequest):
    from state import app_state
    try:
        return app_state.get_axiom().get_timeline(
            start_date=req.start_date,
            end_date=req.end_date,
            artifact_types=req.artifact_types or None,
            limit=min(req.limit, config.max_limit),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
