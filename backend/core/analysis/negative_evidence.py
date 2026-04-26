"""Negative-evidence accounting for autonomous forensic assessment.

This module makes absence explicit. A zero result can mean very different
things: a family was not collected, a parser failed, the family is structurally
unavailable, or the evidence is genuinely absent. Autonomous analysis must not
collapse those cases into "nothing happened".
"""

from __future__ import annotations

from typing import Any


LANE_REQUIRED_FAMILIES: dict[str, list[str]] = {
    "ingress_access": [
        "Windows Event Logs",
        "SRUM",
        "Browser",
        "Remote Access",
    ],
    "execution_impact": [
        "Prefetch",
        "AmCache",
        "SRUM",
        "Encrypted Files",
        "File Signature Mismatch",
    ],
    "persistence_cleanup": [
        "Scheduled Tasks",
        "System Services",
        "Windows Event Logs",
        "$LogFile",
        "UsnJrnl",
    ],
}


def build_negative_evidence_surface(
    detection_payload: dict[str, Any] | None = None,
    *,
    triage_payload: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return explicit negative-evidence records and parser/coverage gaps."""
    detection_payload = detection_payload or {}
    triage_payload = triage_payload or {}
    coverage = coverage or {}

    records: list[dict[str, Any]] = []
    parser_failures: list[dict[str, Any]] = []

    for zero in detection_payload.get("zero_result_queries", []) or []:
        records.append({
            "kind": "rule_zero_result",
            "rule_name": zero.get("rule_name", ""),
            "artifact_family": zero.get("artifact_type") or zero.get("artifact_family") or "",
            "reason": "queried_no_hits",
            "interpretation": zero.get("note", "Rule was queried and returned no matching records."),
        })

    for finding in detection_payload.get("findings", []) or []:
        for absent in finding.get("absent_corroboration", []) or []:
            records.append({
                "kind": "absent_corroboration",
                "rule_name": finding.get("rule_name", ""),
                "artifact_family": absent.get("family", ""),
                "reason": absent.get("status", "unknown"),
                "interpretation": absent.get("reason", ""),
            })

    lane_board = (
        detection_payload.get("lane_state_board")
        or triage_payload.get("lane_state_board")
        or {}
    )
    lane_summary = (
        detection_payload.get("lane_evidence_summary")
        or triage_payload.get("lane_evidence_summary")
        or {}
    )
    for lane, families in LANE_REQUIRED_FAMILIES.items():
        state = (lane_board.get(lane, {}) or {}).get("state", "")
        seen = {
            str(x).lower()
            for x in (lane_summary.get(lane, {}) or {}).get("artifact_families_seen", []) or []
        }
        if state in {"not_seen", "unverified", "unknown", ""}:
            for family in families:
                if any(family.lower() in s or s in family.lower() for s in seen):
                    continue
                records.append({
                    "kind": "lane_gap",
                    "lane": lane,
                    "artifact_family": family,
                    "reason": "not_observed_in_lane",
                    "interpretation": (
                        f"{family} did not contribute evidence to {lane}. "
                        "Treat conclusions touching this lane as incomplete unless another source corroborates it."
                    ),
                })

    for item in _iter_coverage_items(coverage):
        status = str(item.get("status", "") or "").lower()
        if status in {"parser_failed", "failed", "partial", "timeout"}:
            parser_failures.append({
                "artifact_family": item.get("artifact_type") or item.get("family") or "",
                "status": status,
                "reason": item.get("reason") or item.get("detail") or "",
            })
        elif status in {"structurally_unavailable", "available_not_loaded"}:
            records.append({
                "kind": "coverage_gap",
                "artifact_family": item.get("artifact_type") or item.get("family") or "",
                "reason": status,
                "interpretation": item.get("reason") or item.get("detail") or "",
            })

    blocking = [
        r for r in records
        if r.get("reason") in {
            "structurally_unavailable",
            "available_not_loaded",
            "not_observed_in_lane",
            "parser_error",
            "parser_failed",
            "failed",
            "timeout",
        }
    ]

    return {
        "negative_evidence": records,
        "parser_failures": parser_failures,
        "negative_evidence_summary": {
            "total_records": len(records),
            "blocking_records": len(blocking) + len(parser_failures),
            "parser_failures": len(parser_failures),
            "policy": "absence_is_not_equivalent_to_non_occurrence",
        },
        "notes": [
            "Negative evidence separates not_collected/parser_failed/zero_records from genuine absence.",
            "Autonomous conclusions should downgrade confidence when blocking_records or parser_failures are present.",
        ],
    }


def _iter_coverage_items(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    if not coverage:
        return []
    for key in ("items", "artifact_families", "coverage", "results"):
        value = coverage.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    summary = coverage.get("summary")
    if isinstance(summary, dict):
        items = []
        for key, value in summary.items():
            if isinstance(value, list):
                items.extend(x for x in value if isinstance(x, dict))
        return items
    return []
