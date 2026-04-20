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
    from core.analysis.provenance import attach_provenance
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        # Strength tiers (confirmed/strong/moderate/weak) + provenance
        # (supporting_artifacts + absent_corroboration) so the UI can render
        # both defensibility and gaps without a second round-trip.
        score_findings(payload)
        attach_provenance(payload, app_state._connectors)
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


@router.get("/evtx-hunt")
async def get_evtx_hunt(rule_ids: str = "", severity_min: str = "low", limit_per_rule: int = 100):
    """Run the built-in Sigma-style EVTX rule pack against the active case."""
    from state import app_state
    from core.analysis.evtx_rules import hunt_evtx_rules as _hunt
    try:
        ids = [r.strip() for r in rule_ids.split(",") if r.strip()] if rule_ids else None
        return _hunt(
            app_state.get_axiom().artifact_queries,
            rule_ids=ids, severity_min=severity_min, limit_per_rule=limit_per_rule,
        )
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
