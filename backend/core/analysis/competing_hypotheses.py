"""Deterministic competing-hypothesis surface.

The goal is not to prove a case automatically. The goal is to force the
analysis engine to carry plausible alternatives and falsification checks so an
LLM or UI cannot anchor on the first coherent story.
"""

from __future__ import annotations

from typing import Any


HYPOTHESIS_LIBRARY: list[dict[str, Any]] = [
    {
        "id": "external_intrusion_ransomware",
        "label": "External intrusion with ransomware impact",
        "support_signals": ["ransom_note", "extension_churn", "remote_admin", "anti_forensics"],
        "falsifiers": [
            "No ransom note or decrypt instruction in user-writable paths.",
            "No mass rename/encryption/file overwrite evidence in MFT/USN/LogFile.",
            "Remote-administration activity is documented business-hours maintenance.",
            "No execution artifact for the alleged encryptor.",
        ],
        "next_queries": [
            "Compare encrypted-file timestamps with Prefetch/SRUM execution windows.",
            "Search VSS for pre-impact versions and deleted Prefetch/EVTX records.",
            "Check service/task creation immediately before first impact.",
        ],
    },
    {
        "id": "insider_exfiltration",
        "label": "Insider or authorized-user data exfiltration",
        "support_signals": ["cloud_exfil", "usb_exfil", "sensitive_access"],
        "falsifiers": [
            "Cloud/USB movement matches approved migration or backup schedule.",
            "Sensitive-file access belongs to normal job role and baseline.",
            "No outbound transfer or removable-media write near sensitive access.",
        ],
        "next_queries": [
            "Correlate sensitive-file opens with USB mount and cloud-sync activity.",
            "Compare user activity to baseline business-hours and volume profile.",
            "Build account-to-device timeline around the suspected transfer window.",
        ],
    },
    {
        "id": "benign_remote_administration",
        "label": "Benign remote administration or maintenance",
        "support_signals": ["remote_admin"],
        "falsifiers": [
            "Remote tool spawned suspicious child processes or wrote payloads.",
            "Remote session coincides with impact, credential theft, or persistence.",
            "Source IP/account is not part of approved administration pattern.",
        ],
        "next_queries": [
            "Baseline remote-tool session times, users, and network volume.",
            "Check for downstream impact after each remote session.",
            "Verify service install source and vendor-signed binary path.",
        ],
    },
    {
        "id": "anti_forensics_without_confirmed_impact",
        "label": "Anti-forensics observed, impact not yet confirmed",
        "support_signals": ["anti_forensics"],
        "falsifiers": [
            "Log/VSS/USN actions are tied to documented maintenance.",
            "No missing timeline segments or deleted execution artifacts are recoverable.",
            "No related suspicious execution before the cleanup window.",
        ],
        "next_queries": [
            "Recover deleted logs or Prefetch from VSS if available.",
            "Check USN/$LogFile continuity around the cleanup window.",
            "Search for process creation events invoking cleanup utilities.",
        ],
    },
]


def build_competing_hypotheses(
    signals: dict[str, Any] | None = None,
    *,
    lane_states: dict[str, str] | None = None,
    negative_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ranked alternatives and mandatory falsification checks."""
    signals = signals or {}
    lane_states = lane_states or {}
    negative_summary = (negative_evidence or {}).get("negative_evidence_summary", {})
    blocking = int(negative_summary.get("blocking_records") or 0)

    hypotheses = []
    for template in HYPOTHESIS_LIBRARY:
        present = [s for s in template["support_signals"] if bool(signals.get(s))]
        missing = [s for s in template["support_signals"] if not bool(signals.get(s))]
        score = len(present) * 2 - len(missing)
        if blocking:
            score -= 1
        status = "plausible" if present else "low_support"
        if missing and present:
            status = "needs_falsification"
        if not present:
            status = "alternative_to_recheck"

        hypotheses.append({
            "id": template["id"],
            "label": template["label"],
            "relative_score": score,
            "status": status,
            "supporting_signals": present,
            "missing_signals": missing,
            "falsifiers": list(template["falsifiers"]),
            "next_queries": list(template["next_queries"]),
        })

    hypotheses.sort(key=lambda h: (-h["relative_score"], h["id"]))
    top = hypotheses[0] if hypotheses else {}
    runner_up = hypotheses[1] if len(hypotheses) > 1 else {}
    gap = int(top.get("relative_score", 0)) - int(runner_up.get("relative_score", 0))
    ambiguity = gap < 3 or blocking > 0 or any(v in {"unverified", "not_seen"} for v in lane_states.values())

    return {
        "competing_hypotheses": hypotheses,
        "hypothesis_summary": {
            "top_hypothesis": top.get("id", ""),
            "runner_up": runner_up.get("id", ""),
            "confidence_gap": gap,
            "ambiguous": ambiguity,
            "policy": "structured_competing_hypotheses_v1",
        },
        "bias_controls": [
            "At least four alternatives are carried even when one story appears likely.",
            "Each hypothesis includes falsifiers; supporting evidence alone is not sufficient.",
            "Blocking negative evidence and unverified lanes keep the hypothesis summary ambiguous.",
        ],
    }
