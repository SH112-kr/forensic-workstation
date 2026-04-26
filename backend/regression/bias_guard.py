"""Feature-level bias regression guard.

This guard is meant to run after feature changes. It reruns prior synthetic
cases and, when available, the allowlisted external DFIR validations so new
logic cannot silently introduce overcall or undercall bias.
"""

from __future__ import annotations

import re
from typing import Any


BENIGNISH_VERDICTS = {"benign", "benign admin activity", "unknown"}
INCOMPLETE_VERDICTS = {"unknown", "incomplete", "insufficient coverage", "insufficient data", "no data"}


def run_bias_guard(*, include_external: bool = True, download_external: bool = False) -> dict[str, Any]:
    """Run synthetic and optional public-data bias regression checks."""

    checks: list[dict[str, Any]] = []
    synthetic = run_synthetic_fixture_bias_guard()
    checks.extend(synthetic["checks"])

    external = None
    if include_external:
        external = run_external_bias_guard(download=download_external)
        checks.extend(external["checks"])

    failures = [check for check in checks if not check.get("ok")]
    residual_risks = [
        note
        for check in checks
        for note in check.get("residual_risks", [])
    ]
    return {
        "ok": not failures,
        "policy": "feature_bias_guard_v1",
        "check_count": len(checks),
        "failed_count": len(failures),
        "failures": failures,
        "synthetic": synthetic,
        "external": external,
        "residual_risks": residual_risks,
    }


def run_synthetic_fixture_bias_guard() -> dict[str, Any]:
    from regression.fixtures import available
    from regression.ground_truth import load as load_ground_truth

    checks = []
    for fixture_name in available():
        gt = load_ground_truth(fixture_name)
        result = _run_autonomous_fixture(fixture_name)
        check = _evaluate_synthetic_case(fixture_name, gt, result)
        checks.append(check)

    return {
        "ok": all(check["ok"] for check in checks),
        "case_count": len(checks),
        "checks": checks,
    }


def run_external_bias_guard(*, download: bool = False) -> dict[str, Any]:
    from regression.external_validation import run_external_validation

    result = run_external_validation(download=download)
    checks = [_evaluate_external_dataset(item) for item in result.get("results", [])]
    if not result.get("ok"):
        checks.append({
            "name": "external_validation_runner",
            "ok": False,
            "bias_type": "external_validation_failure",
            "details": {
                "passed": result.get("passed"),
                "failed": result.get("failed"),
                "result_count": result.get("result_count"),
            },
        })

    if not result.get("results"):
        checks.append({
            "name": "external_validation_runner",
            "ok": False,
            "bias_type": "coverage_gap",
            "details": {"reason": "no external validation datasets were available"},
        })

    return {
        "ok": all(check["ok"] for check in checks),
        "download": download,
        "result_count": result.get("result_count", 0),
        "checks": checks,
    }


def _run_autonomous_fixture(fixture_name: str) -> dict[str, Any]:
    from core.analysis.autonomous_assessment import assess_autonomous_case
    from core.analysis.bias_remediation import build_bias_remediation_surface
    from core.analysis.evidence_strength import score_findings
    from core.analysis.initial_triage import initial_triage
    from core.analysis.suspicious import find_suspicious
    from regression.fixtures import load

    connector = load(fixture_name)
    triage = initial_triage(connector)
    detection = find_suspicious(connector.artifact_queries)
    score_findings(detection)
    detection.update(build_bias_remediation_surface(connector, detection, triage_payload=triage))
    return assess_autonomous_case(connector, detection, triage_payload=triage)


def _evaluate_synthetic_case(
    fixture_name: str,
    ground_truth: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    expected = ground_truth.get("expected_verdict", {})
    expected_verdicts = {
        _norm(expected.get("primary")),
        *(_norm(item) for item in expected.get("acceptable_alternatives", [])),
    }
    expected_verdicts.discard("")
    actual_verdict = _norm(result.get("verdict"))
    decision = _norm(result.get("decision"))
    allow_strong = bool(result.get("allow_strong_conclusion"))
    expected_allow_strong = bool(ground_truth.get("expected_allow_strong_conclusion"))

    issues: list[str] = []
    bias_type = "none"
    if not _verdict_matches(actual_verdict, expected_verdicts):
        issues.append(f"verdict_mismatch:{actual_verdict or '<empty>'}")
        bias_type = "classification_drift"

    if expected_allow_strong != allow_strong:
        issues.append(
            f"strong_conclusion_gate_mismatch:expected={expected_allow_strong}:actual={allow_strong}"
        )
        bias_type = "overcall" if allow_strong else "undercall"

    expected_primary = _norm(expected.get("primary"))
    if expected_primary in BENIGNISH_VERDICTS and (allow_strong or decision == "contain"):
        issues.append("overcall_risk:benign_or_unknown_case_escalated")
        bias_type = "overcall"
    if expected_primary in INCOMPLETE_VERDICTS and decision == "contain":
        issues.append("overcall_risk:incomplete_case_contained")
        bias_type = "overcall"
    if expected_allow_strong and not allow_strong:
        issues.append("undercall_risk:strong_incident_not_allowed")
        bias_type = "undercall"

    return {
        "name": f"synthetic:{fixture_name}",
        "ok": not issues,
        "bias_type": bias_type,
        "expected_verdicts": sorted(expected_verdicts),
        "actual_verdict": actual_verdict,
        "expected_allow_strong_conclusion": expected_allow_strong,
        "actual_allow_strong_conclusion": allow_strong,
        "decision": decision,
        "issues": issues,
    }


def _evaluate_external_dataset(item: dict[str, Any]) -> dict[str, Any]:
    dataset = item.get("dataset", "unknown_external_dataset")
    issues = []
    residual_risks = []
    attribution_limitations = []
    bias_type = "none"

    if not item.get("ok"):
        issues.append("dataset_validation_failed")
        bias_type = "external_validation_failure"

    bias = item.get("bias_evaluation") or {}
    overcall_count = int(bias.get("overcall_count") or 0)
    undercall_count = int(bias.get("undercall_count") or 0)
    missed_stage_count = int(bias.get("missed_stage_count") or 0)
    bias_notes = list(bias.get("bias_notes") or [])

    if overcall_count:
        issues.append(f"overcall_count:{overcall_count}")
        bias_type = "overcall"
    if undercall_count:
        issues.append(f"undercall_count:{undercall_count}")
        bias_type = "undercall"
    if missed_stage_count:
        issues.append(f"missed_stage_count:{missed_stage_count}")
        bias_type = "undercall"
    if bias_notes:
        issues.extend(f"bias_note:{note}" for note in bias_notes)
        if bias_type == "none":
            bias_type = "analysis_bias"

    for result in item.get("results", []):
        if result.get("known_gap"):
            known_gap = str(result.get("known_gap", ""))
            if "requires network/session context" in known_gap.lower():
                attribution_limitations.append(f"{dataset}:{result.get('filename') or result.get('scenario', 'known_gap')}")
            else:
                residual_risks.append(f"{dataset}:{result.get('scenario', 'known_gap')}")

    return {
        "name": f"external:{dataset}",
        "ok": not issues,
        "bias_type": bias_type,
        "issues": issues,
        "residual_risks": residual_risks,
        "details": {
            "overcall_count": overcall_count,
            "undercall_count": undercall_count,
            "missed_stage_count": missed_stage_count,
            "bias_notes": bias_notes,
            "attribution_limitations": attribution_limitations,
        },
    }


def _norm(value: Any) -> str:
    text = str(value or "").lower().replace("_", " ").replace("-", " ")
    return re.sub(r"\s+", " ", text).strip()


def _verdict_matches(actual: str, expected_verdicts: set[str]) -> bool:
    if actual in expected_verdicts:
        return True
    if actual in INCOMPLETE_VERDICTS and expected_verdicts & INCOMPLETE_VERDICTS:
        return True
    if "benign" in actual and expected_verdicts & BENIGNISH_VERDICTS:
        return True
    if "admin" in actual and "benign admin activity" in expected_verdicts:
        return True
    return False
