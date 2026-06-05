"""Threat detection & MITRE ATT&CK API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.raw_support import active_raw_index_without_parsed_case, raw_index_coverage

router = APIRouter(prefix="/api/detection", tags=["detection"])


class DetectionRequest(BaseModel):
    rules: str = ""


@router.post("/run")
async def run_detection(req: DetectionRequest):
    from state import app_state
    from core.analysis.suspicious import RULE_CATEGORY_MAP
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return _raw_find_suspicious_not_evaluable(
                raw,
                req.rules,
                RULE_CATEGORY_MAP,
            )
        from core.analysis.suspicious import find_suspicious
        from core.analysis.evidence_strength import score_findings
        from core.analysis.provenance import attach_provenance
        from core.analysis.suppressions import apply_suppressions
        from core.analysis.rule_coverage import attach_rule_coverage
        from core.analysis.bias_remediation import build_bias_remediation_surface
        from core.analysis.autonomous_assessment import assess_autonomous_case
        from core.analysis.evidence_quality import build_evidence_quality_surface
        from core.analysis.causal_chain import build_causal_chain_candidates
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
    try:
        cats = [c.strip() for c in categories.split(",") if c.strip()] if categories else None
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "reference_case_id": reference_case_id.strip(),
                "categories": cats or [],
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_baseline_diff_unsupported",
                    "detail": (
                        "The active raw sidecar indexes file-system records only; "
                        "baseline diff requires parsed service, scheduled task, "
                        "startup item, and user artifact families. Do not treat "
                        "this as zero net-new items."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
                "notes": [
                    (
                        "AXIOM/KAPE baseline diff remains a parity reference "
                        "until raw service/task/startup/user extraction is implemented."
                    ),
                ],
            }
        from core.analysis.baseline_diff import baseline_diff as _diff
        active = app_state.get_axiom()
        ref_aq = None
        if reference_case_id.strip():
            key = f"axiom:{reference_case_id.strip()}"
            ref = app_state._connectors.get(key)
            if ref is None or not ref.is_connected():
                raise HTTPException(status_code=400,
                    detail=f"Reference case not loaded: {reference_case_id}")
            ref_aq = ref.artifact_queries
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
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "rules_fired": 0,
                "total_hits": 0,
                "detail_cap_per_rule": 50,
                "any_rule_truncated": False,
                "rules": [],
                "unevaluable_rules": [
                    {
                        "rule_name": "raw_sidecar_anti_forensics",
                        "coverage_status": "not_evaluable",
                        "reason": "raw_anti_forensics_unsupported",
                    },
                ],
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_anti_forensics_unsupported",
                    "detail": (
                        "detect_anti_forensics requires parsed EVTX, process "
                        "creation, PowerShell/scriptblock, service, registry, "
                        "and Prefetch-style artifacts. The active raw sidecar "
                        "does not yet expose those anti-forensic substrates."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
                "notes": [
                    (
                        "Do not interpret this as no anti-forensic activity. "
                        "Use raw EVTX/registry parsing or AXIOM/KAPE parity "
                        "sources before drawing absence conclusions."
                    ),
                ],
            }
        from core.analysis.anti_forensics import detect_anti_forensics as _run
        return _run(app_state.get_axiom().artifact_queries)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/evtx-hunt")
async def get_evtx_hunt(rule_ids: str = "", severity_min: str = "low", limit_per_rule: int = 100):
    """Run the built-in Sigma-style EVTX rule pack against the active case."""
    from state import app_state
    try:
        ids = [r.strip() for r in rule_ids.split(",") if r.strip()] if rule_ids else None
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            requested_ids = ids or []
            return {
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "rule_pack": "builtin",
                "rule_ids_requested": requested_ids,
                "severity_min": severity_min,
                "rules_evaluated": 0,
                "rules_fired": 0,
                "total_hits": 0,
                "results": [],
                "unevaluable_rules": [
                    {
                        "rule_id": rule_id,
                        "coverage_status": "not_evaluable",
                        "reason": "raw_evtx_hunt_unsupported",
                    }
                    for rule_id in requested_ids
                ],
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_evtx_hunt_unsupported",
                    "detail": (
                        "hunt_evtx_rules requires parsed Windows Event Log "
                        "records. The active raw sidecar does not yet index "
                        "EVTX rows, so no EVTX hunt rules were evaluated."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
                "notes": [
                    (
                        "Do not interpret this as no EVTX activity. Build raw "
                        "EVTX indexing or use AXIOM/KAPE parity sources first."
                    ),
                ],
            }
        from core.analysis.evtx_rules import hunt_evtx_rules as _hunt
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
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            result = get_attack_narrative([])
            result.update({
                "ok": False,
                "status": "not_evaluable",
                "source_type": "raw_image_sidecar",
                "auto_findings_evaluated": False,
                "custom_findings_mapped": 0,
                "coverage_gap": {
                    "status": "not_evaluable",
                    "reason": "raw_mitre_auto_detection_unsupported",
                    "detail": (
                        "Automatic ATT&CK mapping depends on find_suspicious "
                        "parsed-case substrates that raw sidecars do not expose yet."
                    ),
                },
                "raw_index_coverage": raw_index_coverage(raw),
                "notes": [
                    (
                        "Do not interpret this as a complete ATT&CK map. AXIOM/KAPE "
                        "remain parity references for auto-detected findings until "
                        "raw detection substrates are implemented."
                    ),
                ],
            })
            return result
        connector = app_state.get_axiom()
        sus = find_suspicious(connector.artifact_queries)
        return get_attack_narrative(sus.get("findings", []))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _raw_find_suspicious_not_evaluable(raw, rules: str, rule_category_map: dict[str, str]) -> dict:
    requested_rules = [
        value.strip().lower()
        for value in str(rules or "").split(",")
        if value.strip()
    ] or sorted(rule_category_map.keys())
    unevaluable = [
        {
            "rule_name": rule_name,
            "coverage_status": "not_evaluable",
            "reason": "raw_find_suspicious_unsupported",
            "category": rule_category_map.get(rule_name, "uncategorized"),
        }
        for rule_name in requested_rules
    ]
    return {
        "ok": False,
        "status": "not_evaluable",
        "source_type": "raw_image_sidecar",
        "rules_requested": requested_rules,
        "rules_executed": 0,
        "rules_with_hits": 0,
        "total_findings": 0,
        "findings": [],
        "zero_result_rules": [],
        "unevaluable_rules": unevaluable,
        "strength_rollup": {
            "confirmed": 0,
            "strong": 0,
            "moderate": 0,
            "weak": 0,
        },
        "coverage_manifest": {
            "queries_executed": [],
            "queries_with_hits": [],
            "queries_zero_hits": [],
            "queries_not_in_scope": [],
            "queries_not_implemented": {
                "raw_sidecar_detection_rules": (
                    "Raw sidecar detection rules have not been implemented "
                    "for the indexed artifact families yet."
                ),
            },
            "note": (
                "No find_suspicious rules were executed in raw-sidecar mode. "
                "This is not evidence of no suspicious activity."
            ),
        },
        "coverage_gap": {
            "status": "not_evaluable",
            "reason": "raw_find_suspicious_unsupported",
            "detail": (
                "find_suspicious currently depends on parsed-case "
                "artifact-query families such as EVTX, Prefetch, Services, "
                "AmCache, and WER. The active raw sidecar does not yet expose "
                "those detection substrates."
            ),
        },
        "raw_index_coverage": raw_index_coverage(raw),
        "notes": [
            (
                "AXIOM/KAPE find_suspicious output remains a parity reference "
                "until raw detection rules are implemented."
            ),
        ],
    }
