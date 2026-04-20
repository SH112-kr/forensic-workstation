"""Threat detection & MITRE ATT&CK API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/detection", tags=["detection"])


class DetectionRequest(BaseModel):
    rules: str = ""


@router.post("/run")
async def run_detection(req: DetectionRequest):
    from state import app_state
    from core.analysis.suspicious import find_suspicious
    from core.analysis.evidence_strength import score_findings
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        # Annotate each finding with CLAUDE.md strength tiers so the UI can
        # render confirmed / strong / moderate / weak badges without a second
        # round-trip.
        score_findings(payload)
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/anti-forensics")
async def get_anti_forensics():
    """Run the anti-forensics rule bundle against the active case."""
    from state import app_state
    from core.analysis.anti_forensics import detect_anti_forensics as _run
    try:
        return _run(app_state.get_axiom().artifact_queries)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/mitre")
async def get_mitre_mapping():
    from state import app_state
    from core.analysis.suspicious import find_suspicious
    from core.analysis.mitre_mapper import get_attack_narrative
    try:
        connector = app_state.get_axiom()
        sus = find_suspicious(connector.artifact_queries)
        return get_attack_narrative(sus.get("findings", []))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
