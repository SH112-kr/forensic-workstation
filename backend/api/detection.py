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
    from core.analysis.rule_coverage import attach_rule_coverage
    from core.analysis.bias_remediation import build_bias_remediation_surface
    from core.analysis.autonomous_assessment import assess_autonomous_case
    from core.analysis.evidence_quality import build_evidence_quality_surface
    from core.analysis.causal_chain import build_causal_chain_candidates
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        score_findings(payload)
        attach_provenance(payload, app_state._connectors)
        apply_suppressions(payload)
        attach_rule_coverage(payload, app_state._connectors)
        payload.update(build_bias_remediation_surface(connector, payload))
        payload.update(build_evidence_quality_surface(connector, payload))
        payload.update(build_causal_chain_candidates(connector))
        payload["autonomous_assessment"] = assess_autonomous_case(connector, payload)
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


@router.get("/baseline-diff")
async def baseline_diff_get(reference_case_id: str = "", categories: str = ""):
    from state import app_state
    from core.analysis.baseline_diff import baseline_diff as _diff
    try:
        active = app_state.get_axiom()
        ref_aq = None
        if reference_case_id.strip():
            key = f"axiom:{reference_case_id.strip()}"
            ref = app_state._connectors.get(key)
            if ref is None or not ref.is_connected():
                raise HTTPException(status_code=400,
                    detail=f"Reference case not loaded: {reference_case_id}")
            ref_aq = ref.artifact_queries
        cats = [c.strip() for c in categories.split(",") if c.strip()] if categories else None
        return _diff(active.artifact_queries, reference_aq=ref_aq, categories=cats)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/hunt-packs")
async def hunt_packs_list():
    from core.analysis.hunt_packs import list_packs
    return list_packs()


class HuntPackRunRequest(BaseModel):
    name: str
    params: dict = {}


@router.post("/hunt-packs/run")
async def hunt_packs_run(req: HuntPackRunRequest):
    """Execute a hunt pack by name.

    Dispatches through mcp_bridge's registered hunt-pack tools so the same
    allowlist applies whether the caller is Claude Code (MCP) or the web UI.
    """
    import inspect as _ins
    from core.analysis.hunt_packs import run_pack
    import mcp_bridge as _bridge

    async def dispatch(tool_name: str, args: dict):
        fn = _bridge._HUNT_PACK_DISPATCH.get(tool_name)
        if fn is None:
            raise HTTPException(status_code=400, detail=f"Tool '{tool_name}' not permitted in hunt packs")
        coerced = _bridge._coerce_pack_args(tool_name, args)
        result = fn(**coerced)
        if _ins.isawaitable(result):
            result = await result
        return result

    return await run_pack(req.name, params=req.params, tool_dispatch=dispatch)


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
