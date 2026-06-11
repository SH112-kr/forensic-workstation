"""Bias remediation helpers for balanced evidence surfaces.

The raw detection payload remains an evidence inventory. These helpers add a
separate additive surface that reduces first-screen anchoring:

- balanced key findings, capped by category and rule
- candidate axes with support, unknowns, and verification status
- lane state board from initial-triage coverage/window facts
"""

from __future__ import annotations

import os
import sys
from typing import Any


_DISABLE_ENV_VAR = "FW_BIAS_REMEDIATION_DISABLE"


def is_bias_remediation_enabled() -> bool:
    """Return True unless the remediation surface is explicitly disabled."""
    raw = str(os.environ.get(_DISABLE_ENV_VAR, "") or "").strip().lower()
    return raw not in {"1", "true", "yes", "on"}


def disabled_guardrail_surface() -> dict[str, Any]:
    """Explicit marker returned instead of a silently empty surface.

    Consumers (especially the LLM) must be able to tell "guardrails ran"
    apart from "guardrails were switched off"; an empty dict reads as the
    former.
    """
    return {
        "guardrails_active": False,
        "guardrail_warning": (
            f"{_DISABLE_ENV_VAR} is set: alert balancing, candidate axes, "
            "and lane state gates are OFF for this response. Conclusions "
            "are unguarded; re-enable before relying on this output."
        ),
    }


def build_lane_evidence_summary_surface(
    connector: Any,
    *,
    triage_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return lane evidence + lane state from initial_triage or surface an error."""
    if not is_bias_remediation_enabled():
        return disabled_guardrail_surface()

    try:
        triage_payload = triage_payload or _run_initial_triage(connector)
        return {
            "lane_evidence_summary": (triage_payload or {}).get("lane_evidence_summary", {}) or {},
            "lane_state_board": (triage_payload or {}).get("lane_state_board", {}) or {},
        }
    except Exception as e:
        return {
            "lane_evidence_summary": {"error": str(e)},
            "lane_state_board": {"error": str(e)},
        }


def build_bias_remediation_surface(
    connector: Any,
    payload: dict[str, Any],
    *,
    findings: list[dict[str, Any]] | None = None,
    triage_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return additive anti-anchoring fields for detection/triage responses."""
    if not is_bias_remediation_enabled():
        return disabled_guardrail_surface()

    try:
        rows = list(findings if findings is not None else payload.get("findings", []) or [])
        triage_payload = triage_payload or _run_initial_triage(connector)
        surface = {
            "guardrails_active": True,
            "alert_summary": {
                "key_findings": select_key_findings(rows),
                "balance": analyze_finding_balance(rows),
                "surface_policy": "balanced_per_category_rule",
            },
            "candidate_axes": build_candidate_axes(rows, triage_payload),
        }
        surface.update(build_lane_evidence_summary_surface(connector, triage_payload=triage_payload))
        return surface
    except Exception as e:
        return {
            "alert_summary": {"error": str(e)},
            "candidate_axes": {"error": str(e), "candidate_axes": []},
            "lane_evidence_summary": {"error": str(e)},
            "lane_state_board": {"error": str(e)},
        }


def select_key_findings(
    findings: list[dict[str, Any]],
    *,
    limit: int = 10,
    per_category_cap: int = 2,
    per_rule_cap: int = 1,
) -> list[dict[str, Any]]:
    """Select a balanced first-screen set without mutating raw findings."""
    selected: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for finding in sorted(findings, key=_finding_sort_key):
        category = str(finding.get("category") or "uncategorized")
        rule = str(finding.get("rule_name") or "")
        if category_counts.get(category, 0) >= per_category_cap:
            continue
        if rule_counts.get(rule, 0) >= per_rule_cap:
            continue
        selected.append(_surface_finding(finding))
        category_counts[category] = category_counts.get(category, 0) + 1
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        if len(selected) >= limit:
            break

    if len(selected) < limit:
        seen = {item.get("rule_name") for item in selected}
        for finding in sorted(findings, key=_finding_sort_key):
            if finding.get("rule_name") in seen:
                continue
            selected.append(_surface_finding(finding))
            if len(selected) >= limit:
                break

    return selected


def analyze_finding_balance(findings: list[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for finding in findings:
        category = str(finding.get("category") or "uncategorized")
        categories[category] = categories.get(category, 0) + 1

    total = sum(categories.values())
    dominant_category = {"name": "", "count": 0, "share": 0.0}
    warnings: list[str] = []
    if total:
        name, count = max(categories.items(), key=lambda item: item[1])
        share = round(count / total, 3)
        dominant_category = {"name": name, "count": count, "share": share}
        if total >= 3 and share >= 0.6:
            warnings.append(
                f"One category dominates current findings ({name} {round(share * 100)}%). Review other lanes before forming a conclusion."
            )

    return {
        "total_findings": total,
        "categories": categories,
        "dominant_category": dominant_category,
        "warnings": warnings,
    }


def build_candidate_axes(
    findings: list[dict[str, Any]],
    triage_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    categories: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        categories.setdefault(str(finding.get("category") or "uncategorized"), []).append(finding)

    lane_board = (triage_payload or {}).get("lane_state_board", {}) or {}
    axes: list[dict[str, Any]] = []
    for category, rows in sorted(categories.items(), key=lambda item: (-len(item[1]), item[0])):
        signals = [
            {
                "rule_name": row.get("rule_name", ""),
                "category": category,
                "count": int(row.get("matching_count", 0) or 0),
                "query_description": row.get("query_description", ""),
            }
            for row in rows[:3]
        ]
        lane = _category_lane(category)
        lane_state = (lane_board.get(lane, {}) or {}).get("state", "unknown") if lane else "unknown"
        axes.append({
            "axis_id": category,
            "label": _label(category),
            "supporting_signals": signals,
            "unknowns": _unknowns_for_category(category, lane_state),
            "verification": {
                "status": _verification_status(rows, lane_state),
                "lane": lane or "unmapped",
                "lane_state": lane_state,
                "why_not_higher": _why_not_higher(lane_state),
            },
        })

    if not axes:
        return {"candidate_axes": [], "notes": ["No findings surfaced candidate axes. Check coverage before concluding clean."]}

    axes.append({
        "axis_id": "outside_taxonomy",
        "label": "Outside Current Taxonomy",
        "supporting_signals": [],
        "unknowns": [
            "Could this be insider exfiltration, benign administration, supply-chain activity, cloud-only activity, or physical access?",
            "Are relevant artifact families unavailable or structurally missing?",
        ],
        "verification": {
            "status": "plausible",
            "lane": "unmapped",
            "lane_state": "unknown",
            "why_not_higher": "Included to prevent taxonomy anchoring; requires analyst verification.",
        },
    })
    return {"candidate_axes": axes}


def _run_initial_triage(connector: Any) -> dict[str, Any]:
    triage_mod = (
        sys.modules.get("analysis.initial_triage")
        or sys.modules.get("core.analysis.initial_triage")
    )
    if triage_mod is None:
        from core.analysis import initial_triage as triage_mod
    return triage_mod.initial_triage(connector, scope_mode="recent_14d")


def _surface_finding(finding: dict[str, Any]) -> dict[str, Any]:
    out = dict(finding)
    out["display_text"] = finding.get("query_description") or finding.get("description") or ""
    out["priority_tier"] = _priority_tier(finding)
    return out


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, str]:
    return (
        -_priority_score(finding),
        -int(finding.get("matching_count", 0) or 0),
        str(finding.get("rule_name") or ""),
    )


def _priority_score(finding: dict[str, Any]) -> int:
    details = finding.get("details") or []
    tier_order = {"confirmed": 4, "strong": 3, "moderate": 2, "weak": 1}
    best = max((tier_order.get(str(d.get("strength", "moderate")), 2) for d in details), default=2)
    category = str(finding.get("category") or "")
    if category in {"anti_forensics", "credential_access", "execution"}:
        best += 1
    return best


def _priority_tier(finding: dict[str, Any]) -> str:
    score = _priority_score(finding)
    if score >= 5:
        return "critical"
    if score >= 4:
        return "high"
    if score >= 3:
        return "medium"
    return "info"


def _verification_status(rows: list[dict[str, Any]], lane_state: str) -> str:
    if lane_state == "confirmed":
        return "supported"
    if lane_state == "suggested":
        return "plausible"
    if len(rows) >= 2:
        return "plausible"
    return "weak"


def _category_lane(category: str) -> str:
    if category in {"remote_access", "credential_access", "initial_access"}:
        return "ingress_access"
    if category in {"execution", "tool_execution"}:
        return "execution_impact"
    if category in {"persistence", "anti_forensics", "tool_installation"}:
        return "persistence_cleanup"
    return ""


def _unknowns_for_category(category: str, lane_state: str) -> list[str]:
    unknowns = {
        "remote_access": ["Was execution or file impact verified after access?", "Was access expected administration?"],
        "credential_access": ["Which account context was affected?", "Is there corroborating logon or process evidence?"],
        "execution": ["What downstream file, registry, or network changes followed?", "Is execution corroborated by SRUM, Prefetch, or EVTX?"],
        "persistence": ["Was the item malicious, legitimate admin tooling, or pre-existing?", "Did it execute or only exist?"],
        "anti_forensics": ["What activity immediately preceded cleanup?", "Are alternate logs or timeline sources available?"],
    }.get(category, ["What evidence would refute this angle?", "Which artifact families are missing or thin?"])
    if lane_state in {"unverified", "not_seen", "unknown"}:
        unknowns.append("Mapped lane is not fully verified.")
    return unknowns


def _why_not_higher(lane_state: str) -> str:
    if lane_state in {"confirmed", "suggested"}:
        return ""
    if lane_state == "not_seen":
        return "Mapped lane has no corroborating window evidence."
    if lane_state == "unverified":
        return "Mapped lane has available artifacts but no corroborating window evidence."
    return "Lane state is unavailable."


def _label(value: str) -> str:
    return value.replace("_", " ").title()
