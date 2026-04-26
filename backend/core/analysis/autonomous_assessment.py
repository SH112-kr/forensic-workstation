"""Autonomous case assessment built on deterministic evidence surfaces.

This module turns the evidence inventory + bias-remediation surfaces into a
conservative machine-readable decision. It is designed for unattended triage:
when evidence is incomplete, it returns a limited operational decision instead
of requiring a human analyst to manually downgrade the conclusion.
"""

from __future__ import annotations

from typing import Any

from core.analysis.competing_hypotheses import build_competing_hypotheses
from core.analysis.negative_evidence import build_negative_evidence_surface


DEFAULT_PAGE_SIZE = 2500
DEFAULT_MAX_PAGES = 20


def assess_autonomous_case(
    connector: Any,
    detection_payload: dict[str, Any],
    *,
    triage_payload: dict[str, Any] | None = None,
    anti_forensics: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative autonomous verdict and next machine actions."""
    triage_payload = triage_payload or {}
    lane_board = (
        detection_payload.get("lane_state_board")
        or triage_payload.get("lane_state_board")
        or {}
    )
    findings = detection_payload.get("findings", []) or []
    categories = {str(f.get("category") or "uncategorized") for f in findings}
    row_result = _case_rows(connector)
    rows = row_result["rows"]
    pagination_state = row_result["pagination"]

    signals = {
        "ransom_note": _has_row(
            rows,
            ("ransom", "readme", "inc-readme", "decrypt"),
            artifact_terms=("text documents", "ransom note"),
            path_terms=(".txt", "readme"),
        ),
        "extension_churn": _has_row(
            rows,
            (".inc", ".locked", "extension churn", "renamed files"),
            artifact_terms=("encrypted files",),
            path_terms=(".inc", ".locked"),
        ),
        "cloud_exfil": _has_row(
            rows,
            ("drive.google.com", "googledrivefs", "dropbox", "mega.nz", "cloud sync"),
            field_terms=("url", "application name", "target path", "full path", "description"),
        ),
        "usb_exfil": _has_row(
            rows,
            ("usb", "kingston", "removable", "datatraveler", "e:\\confidential"),
            artifact_terms=("event logs", "jump list", "shellbags", "lnk files"),
            field_terms=("device description", "target path", "full path", "event data"),
        ),
        "sensitive_access": _has_row(
            rows,
            ("confidential", "legal", "compensation", "roadmap", "client data"),
            artifact_terms=("lnk files", "shellbags", "browser", "history", "jump list"),
            field_terms=("target path", "target full path", "full path", "url", "title"),
        ),
        "remote_admin": _has_row(
            rows,
            ("bomgar", "teamviewer", "anydesk", "screenconnect", "beyondtrust"),
            field_terms=("application name", "full path", "service name", "display name", "imagepath", "image path"),
        ),
        "anti_forensics": bool((anti_forensics or {}).get("rules_fired"))
        or "anti_forensics" in categories
        or _has_row(
            rows,
            ("wevtutil", "log cleared", "vssadmin", "shadow copy", "tamper"),
            artifact_terms=("event logs", "powershell", "script events"),
            field_terms=("event data", "commandline", "command line", "description"),
        ),
    }

    allow_strong = lane_board.get("allow_strong_conclusion") is True
    if pagination_state.get("truncated"):
        allow_strong = False
    blocked_lanes = list(lane_board.get("blocked_lanes", []) or [])
    if pagination_state.get("truncated") and "pagination_incomplete" not in blocked_lanes:
        blocked_lanes.append("pagination_incomplete")
    lane_states = {
        lane: (lane_board.get(lane, {}) or {}).get("state", "unknown")
        for lane in ("ingress_access", "execution_impact", "persistence_cleanup")
    }

    verdict = "unknown"
    confidence = "incomplete" if blocked_lanes else "low"
    decision = "collect_more_evidence"
    basis: list[str] = []
    alternatives: list[str] = []

    if signals["ransom_note"] and signals["extension_churn"] and allow_strong:
        verdict = "ransomware_like_impact"
        confidence = "moderate"
        decision = "contain"
        basis.extend(["ransom-note or decrypt-instruction evidence", "extension churn or encrypted-file evidence"])
    elif signals["cloud_exfil"] and signals["usb_exfil"] and signals["sensitive_access"]:
        verdict = "insider_data_exfiltration"
        confidence = "moderate" if lane_states.get("ingress_access") in {"confirmed", "suggested"} else "low"
        decision = "preserve_and_scope_exfiltration"
        basis.extend(["cloud exfiltration pattern", "USB/removable-media activity", "sensitive data access"])
        alternatives.extend(["authorized bulk transfer", "backup or migration activity"])
    elif signals["anti_forensics"]:
        verdict = "anti_forensics_observed"
        confidence = "low" if blocked_lanes else "moderate"
        decision = "preserve_and_reconstruct"
        basis.append("anti-forensic activity observed")
        alternatives.extend(["authorized administrative maintenance", "cleanup after unrelated troubleshooting"])
    elif signals["remote_admin"] and not signals["ransom_note"] and not signals["extension_churn"]:
        verdict = "benign_or_admin_remote_activity"
        confidence = "moderate" if lane_states.get("execution_impact") in {"not_seen", "unverified"} else "low"
        decision = "monitor_and_validate_authorization"
        basis.append("remote administration evidence without impact indicators")
        alternatives.append("early-stage intrusion with impact artifacts missing from collection")

    if not allow_strong and verdict == "ransomware_like_impact":
        verdict = "impact_suspected_incomplete"
        confidence = "incomplete"
        decision = "collect_more_evidence"
        alternatives.append("ransomware-like impact cannot be strongly concluded while lanes are blocked")

    if not basis:
        basis.append("no autonomous pattern reached decision threshold")

    if blocked_lanes and verdict not in {"insider_data_exfiltration", "benign_or_admin_remote_activity"}:
        confidence = "incomplete"

    negative_surface = build_negative_evidence_surface(
        detection_payload,
        triage_payload=triage_payload,
        coverage=coverage,
    )
    if negative_surface.get("negative_evidence_summary", {}).get("blocking_records"):
        if confidence == "moderate":
            confidence = "low"
        if verdict == "unknown":
            decision = "collect_more_evidence"
    hypotheses = build_competing_hypotheses(
        signals,
        lane_states=lane_states,
        negative_evidence=negative_surface,
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "decision": decision,
        "investigation_incomplete": bool(blocked_lanes),
        "allow_strong_conclusion": allow_strong,
        "blocked_lanes": blocked_lanes,
        "lane_states": lane_states,
        "basis": basis,
        "signals": signals,
        "analysis_limits": pagination_state,
        "considered_alternatives": alternatives,
        **negative_surface,
        **hypotheses,
        "next_automated_steps": _next_steps(decision, blocked_lanes, coverage or {}),
        "policy": "autonomous_conservative_v1",
    }


def _case_rows(connector: Any) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    pagination = {
        "page_size": DEFAULT_PAGE_SIZE,
        "max_pages": DEFAULT_MAX_PAGES,
        "pages_read": 0,
        "total": 0,
        "returned": 0,
        "truncated": False,
        "remaining_count": 0,
        "source": "search",
    }
    try:
        for page in range(DEFAULT_MAX_PAGES):
            offset = page * DEFAULT_PAGE_SIZE
            search = connector.search(
                keyword="",
                filters={},
                limit=DEFAULT_PAGE_SIZE,
                offset=offset,
            ) or {}
            hits = [row for row in search.get("hits", []) or [] if isinstance(row, dict)]
            rows.extend(hits)
            total = int(search.get("total") or len(rows))
            pagination.update({
                "pages_read": page + 1,
                "total": total,
                "returned": len(rows),
                "remaining_count": max(total - len(rows), 0),
            })
            explicit_truncated = bool(search.get("truncated"))
            if len(rows) >= total and not explicit_truncated:
                break
            if not hits:
                break
        pagination["truncated"] = pagination["remaining_count"] > 0
    except Exception:
        pass
    if rows:
        return {"rows": rows, "pagination": pagination}
    try:
        timeline = connector.get_timeline(limit=2500) or {}
        for row in timeline.get("entries", []) or []:
            if isinstance(row, dict):
                rows.append(row)
        total = int(timeline.get("total_events") or len(rows))
        pagination.update({
            "source": "timeline",
            "pages_read": 1,
            "total": total,
            "returned": len(rows),
            "remaining_count": max(total - len(rows), 0),
            "truncated": total > len(rows),
        })
    except Exception:
        pass
    return {"rows": rows, "pagination": pagination}


def _has_row(
    rows: list[dict[str, Any]],
    needles: tuple[str, ...],
    *,
    artifact_terms: tuple[str, ...] = (),
    path_terms: tuple[str, ...] = (),
    field_terms: tuple[str, ...] = (),
) -> bool:
    for row in rows:
        blob = _row_blob(row)
        if not any(needle.lower() in blob for needle in needles):
            continue
        artifact = str(row.get("artifact_type", "")).lower()
        if artifact_terms and any(term in artifact for term in artifact_terms):
            return True
        if path_terms and any(term in _path_blob(row) for term in path_terms):
            return True
        if field_terms and _field_blob(row, field_terms, needles):
            return True
        if not artifact_terms and not path_terms and not field_terms:
            return True
    return False


def _row_blob(row: dict[str, Any]) -> str:
    return " ".join(str(v) for v in row.values()).lower()


def _path_blob(row: dict[str, Any]) -> str:
    keys = ("source_path", "File Path", "Full Path", "Path", "Target Path", "Target Full Path", "description")
    return " ".join(str(row.get(key, "")) for key in keys).lower()


def _field_blob(
    row: dict[str, Any],
    field_terms: tuple[str, ...],
    needles: tuple[str, ...],
) -> bool:
    fields = row.get("fields", {})
    values: list[str] = []
    if isinstance(fields, dict):
        for key, value in fields.items():
            if any(term in str(key).lower() for term in field_terms):
                values.append(str(value))
    for key, value in row.items():
        if any(term in str(key).lower() for term in field_terms):
            values.append(str(value))
    text = " ".join(values).lower()
    return bool(text and any(needle.lower() in text for needle in needles))


def _next_steps(decision: str, blocked_lanes: list[str], coverage: dict[str, Any]) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    if decision == "contain":
        steps.extend([
            {"tool": "generate_report", "why": "Create the autonomous containment handoff report."},
            {"tool": "hunt_evtx_rules", "why": "Broaden event-log verification around execution and cleanup."},
        ])
    elif decision == "preserve_and_scope_exfiltration":
        steps.extend([
            {"tool": "slice_timeline", "why": "Scope cloud, USB, and sensitive-share activity windows."},
            {"tool": "extract_iocs", "why": "Collect cloud domains, paths, accounts, and device identifiers."},
        ])
    elif decision == "preserve_and_reconstruct":
        steps.extend([
            {"tool": "detect_anti_forensics", "why": "Inventory cleanup and tamper actions."},
            {"tool": "build_timeline", "why": "Reconstruct activity around the tamper window."},
        ])
    elif decision == "monitor_and_validate_authorization":
        steps.extend([
            {"tool": "baseline_diff", "why": "Compare remote-admin artifacts against a known-good reference."},
            {"tool": "slice_timeline", "why": "Confirm there is no downstream impact window."},
        ])
    else:
        steps.append({"tool": "coverage_explainer", "why": "Identify missing artifact families blocking autonomous conclusion."})

    for lane in blocked_lanes:
        if lane == "pagination_incomplete":
            steps.append({"tool": "search_artifacts", "why": "Continue paginated evidence collection before any strong conclusion."})
        else:
            steps.append({"tool": "initial_triage_pack", "why": f"Re-run after collecting evidence for blocked lane: {lane}."})

    if coverage.get("summary", {}).get("structurally_unavailable"):
        steps.append({"tool": "coverage_explainer", "why": "Document structurally unavailable artifact families."})
    return steps
