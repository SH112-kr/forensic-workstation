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


class _StubKapeConnector:
    def __init__(self) -> None:
        self.artifact_queries = object()

    def connect(self, parsed_dir: str) -> dict:
        return {
            "case_name": "case_01",
            "total_hits": 42,
            "artifact_types": {"Windows Event Logs": 10},
            "artifact_type_count": 1,
        }

    def get_timeline(self, limit: int = 500) -> dict:
        return {"total_events": 7, "entries": []}


async def _passthrough_traced(_tool_name: str, _params: dict, fn, timeout_seconds: int = 0):
    return fn()


def test_auto_triage_returns_required_keys_and_no_verdict_fields(monkeypatch, tmp_path):
    import mcp_bridge
    import core.connectors.kape_csv as kape_csv
    import core.analysis.initial_triage as initial_triage_mod
    import core.analysis.suspicious as suspicious
    import core.analysis.evidence_strength as evidence_strength
    import core.analysis.anti_forensics as anti_forensics
    import core.analysis.coverage as coverage
    import core.analysis.ioc_extractor as ioc_extractor
    import core.analysis.mitre_mapper as mitre_mapper
    import core.analysis.report_generator as report_generator
    import core.analysis.autonomous_assessment as autonomous_assessment

    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir(parents=True)

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough_traced)
    monkeypatch.setattr(kape_csv, "KapeCsvConnector", _StubKapeConnector)
    initial_triage_calls = {"count": 0}

    def _fake_initial_triage(*_args, **_kwargs):
        initial_triage_calls["count"] += 1
        return {
            "lane_evidence_summary": {
                "ingress_access": {"artifact_families_seen": ["srum"], "event_count": 5},
                "execution_impact": {"artifact_families_seen": ["prefetch"], "event_count": 12},
                "persistence_cleanup": {"artifact_families_seen": [], "event_count": 0},
            },
            "lane_state_board": {
                "ingress_access": {"state": "suggested", "basis": []},
                "execution_impact": {"state": "confirmed", "basis": []},
                "persistence_cleanup": {"state": "not_seen", "basis": []},
                "blocked_lanes": ["persistence_cleanup"],
                "allow_strong_conclusion": False,
            },
            "window_discovery": {"top_windows": [{"status": "candidate"}]},
            "precursor_context": {"status": "candidate_only"},
        }

    monkeypatch.setattr(initial_triage_mod, "initial_triage", _fake_initial_triage)
    monkeypatch.setattr(suspicious, "find_suspicious", lambda *_args, **_kwargs: {
        "findings": [
            {
                "rule_name": "rule_01",
                "query_description": "EID 7045 — 3 service installation events.",
                "matching_count": 3,
                "returned_count": 3,
                "truncated": False,
                "detail_cap": 20,
                "details": [],
                "category": "persistence",
            },
        ],
        "strength_rollup": {"strong": 1},
    })
    monkeypatch.setattr(evidence_strength, "score_findings", lambda payload: payload)
    monkeypatch.setattr(anti_forensics, "detect_anti_forensics", lambda *_args, **_kwargs: {
        "rules_fired": 1,
        "total_hits": 2,
        "rules": [],
    })
    monkeypatch.setattr(coverage, "build_coverage_report", lambda *_args, **_kwargs: {
        "case_context": {"case_format": "kape_csv"},
        "summary": {"searched": 5},
    })
    monkeypatch.setattr(ioc_extractor, "extract_iocs", lambda *_args, **_kwargs: {
        "iocs": [{"type": "hash", "value": "deadbeef"}],
        "by_type": {"hash": 1},
    })
    monkeypatch.setattr(mitre_mapper, "get_attack_narrative", lambda *_args, **_kwargs: {
        "techniques": [{"technique_id": "T0001"}],
    })
    monkeypatch.setattr(report_generator, "generate_report", lambda *_args, **_kwargs: {
        "output_path": "report.html",
    })
    monkeypatch.setattr(autonomous_assessment, "assess_autonomous_case", lambda *_args, **_kwargs: {
        "verdict": "unknown",
        "confidence": "incomplete",
        "decision": "collect_more_evidence",
    })

    result = _run(mcp_bridge.auto_triage(
        source_drive="X",
        output_dir=str(tmp_path),
        skip_kape=True,
        vss=False,
    ))

    assert result["status"] == "complete"
    assert result["summary"]["strength_rollup"] == {"strong": 1}

    assert "classification" not in result
    assert "incident_type" not in result.get("initial_triage", {})
    assert "top_findings" not in result
    assert "top_findings_policy" not in result
    assert "anchoring_risk" not in result
    assert result["lane_state_board"]["allow_strong_conclusion"] is False
    assert result["alert_summary"]["surface_policy"] == "balanced_per_category_rule"
    assert result["candidate_axes"]["candidate_axes"]
    assert result["autonomous_assessment"]["decision"] == "collect_more_evidence"

    # initial_triage returns lane_evidence_summary (facts only)
    assert result["initial_triage"]["lane_evidence_summary"]["execution_impact"]["event_count"] == 12

    assert initial_triage_calls["count"] == 1
