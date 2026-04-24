"""Unit tests for core.analysis.evidence_strength."""

from __future__ import annotations

from core.analysis.evidence_strength import classify_artifact, score_finding, score_findings


def test_classify_known_families():
    assert classify_artifact("Prefetch")["tier"] == "strong"
    assert classify_artifact("Shim Cache")["tier"] == "weak"
    assert classify_artifact("AmCache File Entries")["tier"] == "moderate"
    assert classify_artifact("Windows Event Logs (EID 4688)")["tier"] == "confirmed"
    assert classify_artifact("Windows Event Logs (EID 7045)")["tier"] == "confirmed"
    assert classify_artifact("Windows Event Logs (EID 1102)")["tier"] == "confirmed"
    assert classify_artifact("SRUM Network Usage")["tier"] == "confirmed"


def test_classify_unknown_defaults_moderate():
    r = classify_artifact("Mystery Artifact")
    assert r["tier"] == "moderate"
    assert "unclassified" in r["reason"].lower() or "default" in r["reason"].lower()


def test_classify_link_date_is_weak():
    assert classify_artifact("Link Date field (compile time)")["tier"] == "weak"


def test_score_finding_tags_per_detail_strength():
    finding = {
        "rule_name": "demo",
        "details": [
            {"artifact_type": "Shim Cache"},
            {"artifact_type": "Prefetch"},
        ],
    }
    score_finding(finding)
    assert "overall_strength" not in finding
    assert finding["details"][0]["strength"] == "weak"
    assert finding["details"][1]["strength"] == "strong"


def test_score_findings_rollup():
    payload = {
        "findings": [
            {"details": [{"artifact_type": "Prefetch"}]},
            {"details": [{"artifact_type": "Shim Cache"}]},
            {"details": [{"artifact_type": "Windows Event Logs (EID 4688)"}]},
        ],
    }
    score_findings(payload)
    rollup = payload["strength_rollup"]
    assert rollup["strong"] == 1
    assert rollup["weak"] == 1
    assert rollup["confirmed"] == 1
    assert rollup["moderate"] == 0
    assert len(payload["strength_notes"]) >= 1


def test_corroboration_upgrade():
    """Prefetch (strong) + Event Log (confirmed) for the same binary → confirmed."""
    finding = {
        "rule_name": "demo",
        "details": [
            {"artifact_type": "Prefetch",
             "fields": {"Application Name": "powershell.exe"}},
            {"artifact_type": "Windows Event Logs (EID 4688)",
             "fields": {"Image": "C:\\Windows\\System32\\powershell.exe"}},
        ],
    }
    score_finding(finding)
    # The Prefetch entry should be upgraded because Event Log provides confirmation for
    # the same file (powershell.exe).
    prefetch = finding["details"][0]
    assert prefetch["strength"] == "confirmed"
    assert "upgraded" in prefetch["strength_reason"].lower() or "corroborat" in prefetch["strength_reason"].lower()
