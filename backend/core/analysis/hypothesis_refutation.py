"""Refutation-first composition for DFIR hypotheses.

This module exists to make compositional reasoning auditable without turning
artifact combinations into verdict rules. It deliberately forces checks and
alternatives, not conclusions.
"""

from __future__ import annotations

from typing import Any
import json


_BROWSER_ANCHOR_TASKS = [
    {
        "task_id": "verify_crash_owner",
        "question": "Which process actually faulted near the anchor?",
        "suggested_tools": ["search_wer_reports", "temporal_anchor_correlation"],
        "required_evidence": ["Report.wer", "Crashpad report", "WER temp file"],
        "bias_control": "A nearby WERFAULT Prefetch entry is not enough to identify the faulting application.",
    },
    {
        "task_id": "verify_browser_context",
        "question": "Was the URL or browser profile active around the anchor?",
        "suggested_tools": ["temporal_anchor_correlation", "search_artifacts", "srum_by_process"],
        "required_evidence": ["Browser History", "Browser Cache", "Code Cache", "SRUM Network Usage"],
        "bias_control": "A cache timestamp can be recovered, rewritten, or detached from the user's visible browsing sequence.",
    },
    {
        "task_id": "verify_payload_lifecycle",
        "question": "Did any new script, executable, DLL, or document payload appear after the anchor?",
        "suggested_tools": ["build_timeline", "date_anchor_triage", "compare_case_image_entity"],
        "required_evidence": ["MFT/USN or file timestamps", "AmCache", "Prefetch", "EVTX process creation"],
        "bias_control": "Do not upgrade a browser/crash lead to compromise without a downstream payload or process chain.",
    },
    {
        "task_id": "verify_unrelated_base_rate",
        "question": "Is the nearby artifact common for this host outside the anchor window?",
        "suggested_tools": ["behavioral_delta_pack", "build_timeline"],
        "required_evidence": ["Baseline WERFAULT/Crashpad frequency", "Nearby non-IOC browser crashes"],
        "bias_control": "Common high-base-rate artifacts can appear close to important timestamps by chance.",
    },
]


def hypothesis_refutation_pack(
    *,
    scenario: str = "",
    hypotheses_payload: Any | None = None,
    anchor_correlation_payload: Any | None = None,
    findings_payload: Any | None = None,
    coverage_payload: Any | None = None,
) -> dict[str, Any]:
    """Build a refutation-first worklist from hypotheses and correlations."""
    hypotheses_doc = _coerce_payload(hypotheses_payload)
    anchor_doc = _coerce_payload(anchor_correlation_payload)
    findings_doc = _coerce_payload(findings_payload)
    coverage_doc = _coerce_payload(coverage_payload)

    anchor_signals = _anchor_signals(anchor_doc)
    coverage_gaps = _coverage_gaps(anchor_doc, coverage_doc)
    finding_signals = _finding_signals(findings_doc)

    hypotheses: list[dict[str, Any]] = []
    if anchor_doc:
        hypotheses.extend(_browser_anchor_hypotheses(anchor_signals, coverage_gaps, finding_signals))
    hypotheses.extend(_carry_forward_hypotheses(hypotheses_doc, coverage_gaps))
    if not hypotheses:
        hypotheses.extend(_generic_hypotheses(scenario, coverage_gaps))

    for hypothesis in hypotheses:
        _apply_common_gate(hypothesis, coverage_gaps)

    return {
        "ok": True,
        "policy": "refutation_first_composition_v1",
        "contract": {
            "forced_checks": True,
            "forced_conclusions": False,
            "result_role": "verification_worklist",
            "strong_case_conclusion_allowed": False,
            "reason": (
                "This pack never converts an artifact combination into a verdict. "
                "It only lists checks, alternatives, gaps, and gates."
            ),
        },
        "scenario": scenario,
        "summary": {
            "hypothesis_count": len(hypotheses),
            "anchor_event_count": anchor_signals["event_count"],
            "token_linked_count": anchor_signals["token_linked_count"],
            "proximity_only_count": anchor_signals["proximity_only_count"],
            "missing_source_count": len(coverage_gaps),
            "strong_conclusions_blocked": True,
        },
        "hypotheses": hypotheses,
        "coverage_gaps": coverage_gaps,
        "bias_controls": [
            "Mandatory checks are forced; causal conclusions are not.",
            "Benign and unrelated alternatives remain visible when proximity-only evidence exists.",
            "Missing source families are recorded as gaps, not as negative evidence.",
            "Token-linked evidence is separated from proximity-only evidence.",
            "A strong claim requires direct or independently corroborated downstream evidence outside this pack.",
        ],
        "reading_guide": [
            "Use hypotheses[].refutation_tasks as the next worklist.",
            "Do not sort by support alone; read contradictions and missing_evidence first.",
            "A hypothesis with support but unresolved gates is still a working hypothesis.",
        ],
    }


def _coerce_payload(value: Any | None) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return {"_parse_error": "payload was not valid JSON"}
        return parsed if isinstance(parsed, dict) else {"_parse_error": "payload JSON was not an object"}
    return {"_parse_error": f"unsupported payload type: {type(value).__name__}"}


def _anchor_signals(anchor_doc: dict[str, Any]) -> dict[str, Any]:
    token_linked = [x for x in anchor_doc.get("token_linked", []) or [] if isinstance(x, dict)]
    proximity_only = [x for x in anchor_doc.get("proximity_only", []) or [] if isinstance(x, dict)]
    all_events = token_linked + proximity_only
    anchor = anchor_doc.get("anchor", {}) if isinstance(anchor_doc.get("anchor"), dict) else {}
    label = str(anchor.get("label", "") or anchor_doc.get("anchor_label", "") or "")

    def has_text(event: dict[str, Any], needle: str) -> bool:
        blob = " ".join(str(v) for v in event.values()).lower()
        return needle.lower() in blob

    return {
        "event_count": len(all_events),
        "token_linked_count": len(token_linked),
        "proximity_only_count": len(proximity_only),
        "has_browser_anchor": _looks_browserish(label, anchor),
        "has_werfault_proximity": any(has_text(e, "werfault") for e in proximity_only),
        "has_wer_token_link": any(
            str(e.get("source_artifact", "")).lower() == "wer report"
            and e.get("shared_anchor_tokens")
            for e in token_linked
        ),
        "has_proximity_only": bool(proximity_only),
        "source_counts": anchor_doc.get("summary", {}).get("source_counts", {})
        if isinstance(anchor_doc.get("summary"), dict) else {},
        "dominance_warning": anchor_doc.get("dominance_warning", ""),
        "anchor_label": label,
    }


def _looks_browserish(label: str, anchor: dict[str, Any]) -> bool:
    text = f"{label} {' '.join(str(x) for x in anchor.get('entities', []) or [])}".lower()
    return any(token in text for token in ("browser", "cache", "url", "http", "whale", "chrome", "edge"))


def _coverage_gaps(anchor_doc: dict[str, Any], coverage_doc: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for item in anchor_doc.get("missing_sources", []) or []:
        if isinstance(item, dict):
            gaps.append({
                "source": item.get("source", ""),
                "reason": item.get("reason", ""),
                "interpretation": "Missing source is a collection/parser gap, not negative evidence.",
            })

    coverage_items = coverage_doc.get("coverage", []) if isinstance(coverage_doc.get("coverage"), list) else []
    for item in coverage_items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "")).lower()
        if status in {"available_not_loaded", "structurally_unavailable", "parser_failed", "failed", "partial"}:
            gaps.append({
                "source": item.get("artifact_type") or item.get("family") or "",
                "reason": status,
                "interpretation": item.get("reason") or "Coverage gap blocks strong conclusions.",
            })
    return gaps


def _finding_signals(findings_doc: dict[str, Any]) -> dict[str, bool]:
    findings = findings_doc.get("findings", []) if isinstance(findings_doc.get("findings"), list) else []
    blob = " ".join(json.dumps(f, default=str).lower() for f in findings if isinstance(f, dict))
    return {
        "process_creation": any(token in blob for token in ("4688", "process creation", "sysmon")),
        "payload_file": any(token in blob for token in ("payload", ".exe", ".dll", ".js", ".vbs", "amcache")),
        "network": any(token in blob for token in ("srum", "network", "dns", "http", "url")),
    }


def _browser_anchor_hypotheses(
    signals: dict[str, Any],
    coverage_gaps: list[dict[str, Any]],
    finding_signals: dict[str, bool],
) -> list[dict[str, Any]]:
    if not signals["has_browser_anchor"] and not signals["event_count"]:
        return []

    downstream = finding_signals["process_creation"] or finding_signals["payload_file"]
    network = finding_signals["network"]

    exploit_missing = []
    if not signals["has_wer_token_link"]:
        exploit_missing.append("No retained WER/Crashpad report directly names the browser/profile/URL token.")
    if not downstream:
        exploit_missing.append("No downstream payload file or process-creation evidence supplied to this pack.")
    if not network:
        exploit_missing.append("No browser-network/SRUM corroboration supplied to this pack.")
    if coverage_gaps:
        exploit_missing.append("One or more required source families are missing or unavailable.")

    hypotheses = [
        {
            "id": "browser_delivered_exploit_or_payload_chain",
            "label": "Browser-delivered exploit or payload chain",
            "role": "working_hypothesis",
            "supporting_observations": _compact([
                "Browser/cache-style anchor present" if signals["has_browser_anchor"] else "",
                "Nearby WERFAULT Prefetch/event exists" if signals["has_werfault_proximity"] else "",
                "WER report shares an anchor token" if signals["has_wer_token_link"] else "",
            ]),
            "contradicting_observations": [],
            "missing_evidence": exploit_missing,
            "refutation_tasks": list(_BROWSER_ANCHOR_TASKS),
            "status": "lead_needs_refutation",
            "claim_gate": {
                "allowed_claim": "candidate lead only",
                "blocked_claim": "exploit or compromise confirmed",
                "blocking_reason": "Direct payload/process/network corroboration is required outside temporal proximity.",
            },
        },
        {
            "id": "benign_browser_crash_or_site_error",
            "label": "Benign browser crash or site/script error",
            "role": "benign_alternative",
            "supporting_observations": _compact([
                "WER/WERFAULT activity near browser/cache anchor" if signals["has_werfault_proximity"] or signals["has_wer_token_link"] else "",
                "No downstream payload/process evidence supplied" if not downstream else "",
            ]),
            "contradicting_observations": _compact([
                "Downstream payload/process signal supplied" if downstream else "",
            ]),
            "missing_evidence": [
                "Need WER/Crashpad faulting module and browser state around the timestamp.",
                "Need baseline crash frequency for the same host/profile.",
            ],
            "refutation_tasks": [
                _BROWSER_ANCHOR_TASKS[0],
                _BROWSER_ANCHOR_TASKS[1],
                _BROWSER_ANCHOR_TASKS[3],
            ],
            "status": "plausible_alternative",
            "claim_gate": {
                "allowed_claim": "benign explanation remains plausible",
                "blocked_claim": "incident ruled out",
                "blocking_reason": "Benign plausibility is not negative evidence against compromise.",
            },
        },
        {
            "id": "unrelated_high_base_rate_artifact",
            "label": "Unrelated high-base-rate artifact near the anchor",
            "role": "unrelated_alternative",
            "supporting_observations": _compact([
                "Proximity-only events are present" if signals["has_proximity_only"] else "",
                signals["dominance_warning"],
            ]),
            "contradicting_observations": _compact([
                "A WER report shares anchor tokens" if signals["has_wer_token_link"] else "",
            ]),
            "missing_evidence": [
                "Need frequency of the same event type outside the anchor window.",
                "Need independent token or parent/child evidence to tie the artifact to the anchor.",
            ],
            "refutation_tasks": [_BROWSER_ANCHOR_TASKS[3]],
            "status": "plausible_alternative" if signals["has_proximity_only"] else "low_support_alternative",
            "claim_gate": {
                "allowed_claim": "temporal co-occurrence may be unrelated",
                "blocked_claim": "artifact is unrelated",
                "blocking_reason": "Base-rate comparison is required before treating proximity as noise.",
            },
        },
        {
            "id": "collection_or_parser_gap",
            "label": "Collection, parser, or retention gap hides decisive evidence",
            "role": "coverage_alternative",
            "supporting_observations": [
                f"{len(coverage_gaps)} source gap(s) recorded"
            ] if coverage_gaps else [],
            "contradicting_observations": [],
            "missing_evidence": [
                "Raw WER/Crashpad/browser/SRUM/EVTX evidence may need separate collection or parsing.",
            ],
            "refutation_tasks": [
                {
                    "task_id": "close_source_gaps",
                    "question": "Can the missing source family be loaded, parsed, or recovered?",
                    "suggested_tools": ["coverage_explainer", "case_health", "compare_case_image_entity"],
                    "required_evidence": [gap.get("source", "") for gap in coverage_gaps] or ["source coverage report"],
                    "bias_control": "A missing Report.wer or parser miss must not be read as 'no crash' or 'no exploit'.",
                }
            ],
            "status": "gap_blocks_conclusion" if coverage_gaps else "low_support_alternative",
            "claim_gate": {
                "allowed_claim": "evidence coverage is incomplete",
                "blocked_claim": "absence proves non-occurrence",
                "blocking_reason": "Coverage gaps must be closed or explicitly carried into the report.",
            },
        },
    ]
    return hypotheses


def _carry_forward_hypotheses(hypotheses_doc: dict[str, Any], coverage_gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = hypotheses_doc.get("competing_hypotheses", [])
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        falsifiers = [str(x) for x in row.get("falsifiers", []) or []]
        next_queries = [str(x) for x in row.get("next_queries", []) or []]
        out.append({
            "id": str(row.get("id", "hypothesis")),
            "label": str(row.get("label", row.get("id", "Hypothesis"))),
            "role": "carried_forward_hypothesis",
            "supporting_observations": list(row.get("supporting_signals", []) or []),
            "contradicting_observations": [],
            "missing_evidence": list(row.get("missing_signals", []) or []),
            "refutation_tasks": [
                {
                    "task_id": f"falsify_{idx + 1}",
                    "question": falsifier,
                    "suggested_tools": [],
                    "required_evidence": [],
                    "bias_control": "Support alone is insufficient; attempt to falsify the hypothesis.",
                }
                for idx, falsifier in enumerate(falsifiers)
            ] + [
                {
                    "task_id": f"next_query_{idx + 1}",
                    "question": query,
                    "suggested_tools": [],
                    "required_evidence": [],
                    "bias_control": "Treat this as follow-up evidence collection, not as confirmation.",
                }
                for idx, query in enumerate(next_queries)
            ],
            "status": "carried_forward_for_refutation",
            "claim_gate": {
                "allowed_claim": "working hypothesis",
                "blocked_claim": "case conclusion",
                "blocking_reason": "Refutation tasks and coverage gaps remain unresolved.",
            },
        })
    return out


def _generic_hypotheses(scenario: str, coverage_gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    label = scenario or "Unspecified incident scenario"
    return [
        {
            "id": "primary_incident_hypothesis",
            "label": label,
            "role": "working_hypothesis",
            "supporting_observations": [],
            "contradicting_observations": [],
            "missing_evidence": ["No structured hypothesis or anchor-correlation payload was supplied."],
            "refutation_tasks": [
                {
                    "task_id": "define_anchor_and_alternatives",
                    "question": "What timestamp, entity, or artifact anchors this hypothesis?",
                    "suggested_tools": ["date_anchor_triage", "temporal_anchor_correlation", "build_timeline"],
                    "required_evidence": ["timestamped anchor", "at least one benign alternative"],
                    "bias_control": "Do not analyze from a family name or verdict label alone.",
                }
            ],
            "status": "needs_structuring",
            "claim_gate": {
                "allowed_claim": "investigation question",
                "blocked_claim": "incident conclusion",
                "blocking_reason": "No structured evidence payload was supplied.",
            },
        },
        {
            "id": "benign_or_admin_alternative",
            "label": "Benign, administrative, or unrelated alternative",
            "role": "benign_alternative",
            "supporting_observations": [],
            "contradicting_observations": [],
            "missing_evidence": ["Need baseline and authorization context."],
            "refutation_tasks": [
                {
                    "task_id": "baseline_authorization_context",
                    "question": "Does the activity match normal user, admin, application, or maintenance behavior?",
                    "suggested_tools": ["behavioral_delta_pack", "baseline_diff", "entity_story_pack"],
                    "required_evidence": ["baseline period", "user/application owner context"],
                    "bias_control": "Every suspicious-looking pattern needs a normal-operation comparator.",
                }
            ],
            "status": "mandatory_alternative",
            "claim_gate": {
                "allowed_claim": "alternative to test",
                "blocked_claim": "activity benign",
                "blocking_reason": "Baseline match must be observed before calling it benign.",
            },
        },
        {
            "id": "coverage_gap_alternative",
            "label": "Insufficient coverage or parser gap",
            "role": "coverage_alternative",
            "supporting_observations": [f"{len(coverage_gaps)} source gap(s) recorded"] if coverage_gaps else [],
            "contradicting_observations": [],
            "missing_evidence": ["Need coverage report for the relevant artifact families."],
            "refutation_tasks": [
                {
                    "task_id": "explain_missing_sources",
                    "question": "Which required sources are absent, unavailable, or unparsed?",
                    "suggested_tools": ["coverage_explainer", "case_health"],
                    "required_evidence": ["coverage report", "case health report"],
                    "bias_control": "Zero results only matter after source availability is understood.",
                }
            ],
            "status": "mandatory_alternative",
            "claim_gate": {
                "allowed_claim": "coverage limits exist",
                "blocked_claim": "no activity occurred",
                "blocking_reason": "Absence cannot be interpreted without coverage.",
            },
        },
    ]


def _apply_common_gate(hypothesis: dict[str, Any], coverage_gaps: list[dict[str, Any]]) -> None:
    hypothesis["strong_conclusion_allowed"] = False
    hypothesis["composition_warning"] = (
        "This is a refutation target, not a rule verdict. Do not promote it without "
        "independent corroboration and resolved coverage gaps."
    )
    if coverage_gaps:
        hypothesis.setdefault("missing_evidence", [])
        if "Coverage gaps remain unresolved." not in hypothesis["missing_evidence"]:
            hypothesis["missing_evidence"].append("Coverage gaps remain unresolved.")


def _compact(values: list[str]) -> list[str]:
    return [value for value in values if value]
