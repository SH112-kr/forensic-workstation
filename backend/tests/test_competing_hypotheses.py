from __future__ import annotations


def _surfaces(fixture_name: str) -> dict:
    from regression.fixtures import load
    from core.analysis.initial_triage import initial_triage
    from core.analysis.suspicious import find_suspicious
    from core.analysis.evidence_strength import score_findings
    from core.analysis.bias_remediation import build_bias_remediation_surface
    from core.analysis.evidence_quality import build_evidence_quality_surface
    from core.analysis.causal_chain import build_causal_chain_candidates
    from core.analysis.autonomous_assessment import assess_autonomous_case

    connector = load(fixture_name)
    triage = initial_triage(connector)
    detection = find_suspicious(connector.artifact_queries)
    score_findings(detection)
    detection.update(build_bias_remediation_surface(connector, detection, triage_payload=triage))
    detection.update(build_evidence_quality_surface(connector, detection))
    detection.update(build_causal_chain_candidates(connector))
    assessment = assess_autonomous_case(connector, detection, triage_payload=triage)
    return {"connector": connector, "triage": triage, "detection": detection, "assessment": assessment}


def test_autonomous_assessment_carries_competing_hypotheses():
    result = _surfaces("case_ransomware_inc_like")["assessment"]

    assert result["hypothesis_summary"]["policy"] == "structured_competing_hypotheses_v1"
    assert len(result["competing_hypotheses"]) >= 4
    top = result["competing_hypotheses"][0]
    assert top["id"] == "external_intrusion_ransomware"
    assert top["falsifiers"]
    assert any("VSS" in q for q in top["next_queries"])


def test_benign_remote_case_keeps_benign_alternative_visible():
    result = _surfaces("case_benign_remote_work")["assessment"]

    hypotheses = {h["id"]: h for h in result["competing_hypotheses"]}
    assert "benign_remote_administration" in hypotheses
    assert hypotheses["benign_remote_administration"]["supporting_signals"] == ["remote_admin"]
    assert result["decision"] == "monitor_and_validate_authorization"


def test_negative_evidence_and_quality_surfaces_are_contract_visible():
    surfaces = _surfaces("case_partial_evidence")
    detection = surfaces["detection"]
    assessment = surfaces["assessment"]

    assert "evidence_quality" in detection
    assert detection["evidence_quality"]["source_tier"] >= 1
    assert "negative_evidence_summary" in assessment
    assert assessment["negative_evidence_summary"]["policy"] == "absence_is_not_equivalent_to_non_occurrence"
    assert isinstance(assessment["negative_evidence"], list)


def test_causal_chain_marks_edges_as_candidates_not_claims():
    detection = _surfaces("case_ransomware_inc_like")["detection"]
    chain = detection["causal_chain"]

    assert chain["policy"] == "causal_candidates_not_causal_claims_v1"
    assert chain["nodes"]
    assert all(edge["causal_strength"] == "candidate" for edge in chain["edges"])
    assert all(edge["correlation_type"] == "temporal_proximity" for edge in chain["edges"])
