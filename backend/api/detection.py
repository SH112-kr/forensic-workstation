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
    from core.analysis.suppressions import apply_suppressions
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        score_findings(payload)
        attach_provenance(payload, app_state._connectors)
        apply_suppressions(payload)
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class SuppressionAddRequest(BaseModel):
    rule_id: str
    reason: str
    analyst: str = ""
    expires_at: str = ""


@router.get("/suppressions")
async def suppressions_list():
    from core.analysis.suppressions import list_suppressions
    return list_suppressions()


@router.post("/suppressions")
async def suppressions_add(req: SuppressionAddRequest):
    from core.analysis.suppressions import add_suppression
    return add_suppression(
        rule_id=req.rule_id, reason=req.reason,
        analyst=req.analyst, expires_at=req.expires_at,
    )


@router.delete("/suppressions/{rule_id}")
async def suppressions_remove(rule_id: str):
    from core.analysis.suppressions import remove_suppression
    return remove_suppression(rule_id=rule_id)


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
