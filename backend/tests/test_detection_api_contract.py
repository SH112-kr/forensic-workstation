from __future__ import annotations

import asyncio


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


class _StubConnector:
    artifact_queries = object()


class _StubState:
    def __init__(self):
        self._connectors = {"axiom:test": object()}

    def get_axiom(self):
        return _StubConnector()


def test_run_detection_returns_raw_detection_payload(monkeypatch):
    import state
    from api.detection import DetectionRequest, run_detection
    import core.analysis.suspicious as suspicious
    import core.analysis.evidence_strength as evidence_strength
    import core.analysis.provenance as provenance
    import core.analysis.suppressions as suppressions
    import core.analysis.rule_coverage as rule_coverage
    import core.analysis.bias_remediation as bias_remediation
    import core.analysis.autonomous_assessment as autonomous_assessment

    monkeypatch.setattr(state, "app_state", _StubState())
    monkeypatch.setattr(suspicious, "find_suspicious", lambda *_args, **_kwargs: {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "query_description": "EID 7045 — service install events.",
                "matching_count": 3,
                "returned_count": 3,
                "truncated": False,
                "detail_cap": 20,
                "category": "persistence",
                "details": [],
            },
            {
                "rule_name": "evtx_eid_4648_explicit_credential_logons",
                "query_description": "EID 4648 — explicit credential logon events.",
                "matching_count": 2,
                "returned_count": 2,
                "truncated": False,
                "detail_cap": 20,
                "category": "credential_access",
                "details": [],
            },
        ],
        "total_findings": 2,
        "zero_result_rules": [],
        "strength_rollup": {"confirmed": 1, "strong": 1},
    })
    monkeypatch.setattr(evidence_strength, "score_findings", lambda payload: payload)
    monkeypatch.setattr(provenance, "attach_provenance", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(suppressions, "apply_suppressions", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rule_coverage, "attach_rule_coverage", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        bias_remediation,
        "build_bias_remediation_surface",
        lambda *_args, **_kwargs: {
            "alert_summary": {
                "key_findings": [{"rule_name": "evtx_eid_7045_service_installs", "priority_tier": "medium"}],
                "balance": {"warnings": []},
                "surface_policy": "balanced_per_category_rule",
            },
            "candidate_axes": {"candidate_axes": [{"axis_id": "persistence"}]},
            "lane_state_board": {
                "execution_impact": {"state": "unverified"},
                "blocked_lanes": ["execution_impact"],
                "allow_strong_conclusion": False,
            },
        },
    )
    monkeypatch.setattr(
        autonomous_assessment,
        "assess_autonomous_case",
        lambda *_args, **_kwargs: {
            "verdict": "unknown",
            "confidence": "incomplete",
            "decision": "collect_more_evidence",
        },
    )

    payload = _run(run_detection(DetectionRequest()))

    assert payload["total_findings"] == 2
    assert payload["findings"][0]["rule_name"] == "evtx_eid_7045_service_installs"
    assert payload["strength_rollup"] == {"confirmed": 1, "strong": 1}

    # Bias-remediation fields are additive; raw findings remain unmodified.
    assert payload["alert_summary"]["surface_policy"] == "balanced_per_category_rule"
    assert payload["candidate_axes"]["candidate_axes"][0]["axis_id"] == "persistence"
    assert payload["lane_state_board"]["allow_strong_conclusion"] is False
    assert payload["autonomous_assessment"]["decision"] == "collect_more_evidence"
    assert "top_findings" not in payload
    assert "severity" not in payload["findings"][0]

    # Findings use query_description, not description
    assert "query_description" in payload["findings"][0]
    assert "description" not in payload["findings"][0]
