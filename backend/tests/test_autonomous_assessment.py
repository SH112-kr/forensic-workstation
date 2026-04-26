from __future__ import annotations

import pytest


FIXTURES = [
    "case_ransomware_inc_like",
    "case_benign_remote_work",
    "case_partial_evidence",
    "case_insider_data_exfil",
    "case_anti_forensics_heavy",
    "case_empty_or_malformed",
]


def _run_fixture(name: str) -> dict:
    from regression.fixtures import load
    from core.analysis.initial_triage import initial_triage
    from core.analysis.suspicious import find_suspicious
    from core.analysis.evidence_strength import score_findings
    from core.analysis.bias_remediation import build_bias_remediation_surface
    from core.analysis.autonomous_assessment import assess_autonomous_case

    connector = load(name)
    triage = initial_triage(connector)
    detection = find_suspicious(connector.artifact_queries)
    score_findings(detection)
    detection.update(build_bias_remediation_surface(connector, detection, triage_payload=triage))
    return assess_autonomous_case(connector, detection, triage_payload=triage)


def _norm(value: str) -> str:
    return str(value or "").lower().replace("_", " ").replace("-", " ").strip()


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_autonomous_assessment_has_stable_contract(fixture_name):
    result = _run_fixture(fixture_name)

    assert result["policy"] == "autonomous_conservative_v1"
    assert result["verdict"]
    assert result["confidence"] in {"moderate", "low", "incomplete"}
    assert result["decision"] in {
        "contain",
        "preserve_and_scope_exfiltration",
        "preserve_and_reconstruct",
        "monitor_and_validate_authorization",
        "collect_more_evidence",
    }
    assert isinstance(result["basis"], list)
    assert isinstance(result["next_automated_steps"], list)


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_autonomous_assessment_respects_ground_truth_strong_conclusion_gate(fixture_name):
    from regression.ground_truth import load as load_ground_truth

    result = _run_fixture(fixture_name)
    gt = load_ground_truth(fixture_name)

    assert result["allow_strong_conclusion"] is gt["expected_allow_strong_conclusion"]
    if not gt["expected_allow_strong_conclusion"]:
        assert result["investigation_incomplete"] is True
        assert result["decision"] != "contain"


def test_autonomous_assessment_identifies_ransomware_like_fixture():
    result = _run_fixture("case_ransomware_inc_like")

    assert result["decision"] == "contain"
    assert _norm(result["verdict"]) in {"ransomware like impact", "ransomware"}
    assert result["confidence"] == "moderate"


def test_autonomous_assessment_does_not_overcall_benign_remote_admin():
    result = _run_fixture("case_benign_remote_work")

    assert result["decision"] == "monitor_and_validate_authorization"
    assert "benign" in _norm(result["verdict"]) or "admin" in _norm(result["verdict"])
    assert result["allow_strong_conclusion"] is False


def test_autonomous_assessment_surfaces_taxonomy_escape_for_insider_exfil():
    result = _run_fixture("case_insider_data_exfil")

    assert result["decision"] == "preserve_and_scope_exfiltration"
    assert "insider" in _norm(result["verdict"])
    assert result["signals"]["cloud_exfil"] is True
    assert result["signals"]["usb_exfil"] is True


def test_autonomous_assessment_keeps_partial_case_incomplete():
    result = _run_fixture("case_partial_evidence")

    assert result["verdict"] == "unknown"
    assert result["confidence"] == "incomplete"
    assert result["decision"] == "collect_more_evidence"


def test_autonomous_assessment_does_not_match_generic_decrypt_or_fileserver_text():
    from core.analysis.autonomous_assessment import assess_autonomous_case

    class Connector:
        def search(self, keyword="", filters=None, limit=2500):
            return {
                "hits": [
                    {
                        "artifact_type": "Windows Event Logs - Security",
                        "Event Data": "TLS decrypt operation completed for diagnostic logging",
                        "description": "normal crypto library message",
                    },
                    {
                        "artifact_type": "LNK Files",
                        "Target Path": r"\\fileserver01\Public",
                        "description": "ordinary shared folder access",
                    },
                ]
            }

    result = assess_autonomous_case(
        Connector(),
        {"findings": [], "lane_state_board": {"allow_strong_conclusion": True}},
    )

    assert result["signals"]["ransom_note"] is False
    assert result["signals"]["sensitive_access"] is False
    assert result["decision"] == "collect_more_evidence"


def test_autonomous_assessment_blocks_strong_conclusion_when_search_is_truncated():
    from core.analysis.autonomous_assessment import assess_autonomous_case

    class Connector:
        def __init__(self):
            self.calls = []
            self.rows = [
                {
                    "artifact_type": "Text Documents",
                    "File Path": r"C:\Users\admin\Desktop\INC-README.txt",
                    "Content Preview": "Your files have been encrypted. decrypt instructions.",
                },
                {
                    "artifact_type": "Encrypted Files",
                    "File Path": r"C:\Users\admin\Documents\a.docx.INC",
                    "Extension": ".INC",
                },
            ]
            self.rows.extend(
                {"artifact_type": "Noise", "description": f"benign row {idx}"}
                for idx in range(4998)
            )

        def search(self, keyword="", filters=None, limit=2500, offset=0):
            self.calls.append((limit, offset))
            return {
                "total": 6000,
                "returned": min(limit, max(0, len(self.rows) - offset)),
                "hits": self.rows[offset:offset + limit],
            }

    connector = Connector()
    result = assess_autonomous_case(
        connector,
        {"findings": [], "lane_state_board": {"allow_strong_conclusion": True}},
    )

    assert result["allow_strong_conclusion"] is False
    assert result["investigation_incomplete"] is True
    assert "pagination_incomplete" in result["blocked_lanes"]
    assert result["analysis_limits"]["truncated"] is True
    assert result["analysis_limits"]["remaining_count"] == 1000
    assert result["decision"] != "contain"
    assert any(step["tool"] == "search_artifacts" for step in result["next_automated_steps"])
