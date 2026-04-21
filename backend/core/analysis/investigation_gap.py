"""Investigation gap report — composition tool for LLM reasoning support.

This is NOT a new analysis primitive. It runs three existing primitives —
``case_health``, ``build_coverage_report`` and ``detect_anti_forensics`` —
plus an optional caller-supplied ``find_suspicious`` payload and/or a
snapshot slug, and composes their outputs into one envelope an LLM can read
without juggling five tool calls.

Design rules (Codex Round 14 / 14b):
  - Composition only. Never invent new detection logic.
  - Never synthesise a finding; only point at things the analyst has not
    yet looked at.
  - When ``findings_payload`` is absent we MUST set ``findings_available``
    false and list the sections we cannot fill in ``skipped_sections`` so
    the caller cannot silently read "no gaps" as "all clear". Only
    ``detection_gaps`` and ``corroboration_gaps`` require findings —
    anti-forensic pivots still emit via ``pivots_not_attempted``.
  - Weak-strength signals are suppressed in ``pivots_not_attempted`` —
    corroborating a weak signal with more tools often turns into
    confirmation bias. The analyst decides whether to chase it manually.
  - ``bucket_gaps.stale_references`` lists bucketed hit_ids that are no
    longer in any loaded case so a stale snapshot cannot masquerade as
    "saved decisions".

Output shape (stable for callers):
  {
    "ok": True,
    "findings_available": bool,
    "skipped_sections": [section_name, ...],
    "substrate_gaps": [...],
    "detection_gaps": [...],
    "corroboration_gaps": [...],
    "pivots_not_attempted": [...],
    "bucket_gaps": {...} | None,
    "recommended_next_queries": [...],
    "notes": [str, ...],
  }
"""

from __future__ import annotations

import json
from typing import Any


# Hand-curated, auditable map from fired detection rule names (and selected
# anti-forensic rule names) to the canonical MCP tool + params an analyst
# would call to drive the investigation forward. Kept small on purpose —
# the goal is "point at the obvious next step", not "plan the case".
#
# Every entry carries a ``why`` string so the caller can see the reasoning
# attached to the suggestion.
_PIVOT_MAP: dict[str, list[dict[str, Any]]] = {
    # Anti-forensic rules ---------------------------------------------------
    "log_cleared_security_1102": [
        {
            "tool_name": "search_logs",
            "params": {"keyword": "1102", "limit": 50},
            "why": "Find the immediate context — who cleared the Security log and when.",
        },
        {
            "tool_name": "build_timeline",
            "params": {"artifact_types": "Windows Event Logs"},
            "why": "Look for gaps around the clear event that would indicate destroyed evidence.",
        },
    ],
    "log_cleared_system_104": [
        {
            "tool_name": "search_logs",
            "params": {"keyword": "104", "limit": 50},
            "why": "Correlate the System log clear with surrounding events.",
        },
    ],
    "vss_shadow_deletion": [
        {
            "tool_name": "build_timeline",
            "params": {"artifact_types": "Prefetch,Windows Event Logs"},
            "why": "Locate the execution of the deletion command and preceding process tree.",
        },
        {
            "tool_name": "find_suspicious",
            "params": {"rules": "ransomware_markers"},
            "why": "Snapshot deletion is a canonical ransomware step — check for corroborating markers.",
        },
    ],
    "usn_journal_deletion": [
        {
            "tool_name": "search_artifacts",
            "params": {"keyword": "fsutil", "artifact_type": "Prefetch"},
            "why": "Corroborate the journal deletion with a Prefetch execution record.",
        },
    ],
    "ps_logging_tamper": [
        {
            "tool_name": "search_artifacts",
            "params": {"keyword": "ScriptBlockLogging"},
            "why": "Read the exact registry rows that were modified.",
        },
    ],
    "security_service_stop": [
        {
            "tool_name": "search_artifacts",
            "params": {"keyword": "Sysmon,Defender,EventLog"},
            "why": "Find which service(s) were stopped and when.",
        },
    ],
    "cleanup_tool_execution": [
        {
            "tool_name": "get_file_timestamps",
            "params": {},
            "why": "Confirm the MFT timestamp of each anti-forensic utility so you can place it on the timeline.",
        },
    ],
    # Detection rules ------------------------------------------------------
    "persistence_service_install": [
        {
            "tool_name": "baseline_diff",
            "params": {"categories": "services"},
            "why": "Compare against the Windows known-good baseline to isolate the net-new service.",
        },
    ],
    "persistence_scheduled_task": [
        {
            "tool_name": "baseline_diff",
            "params": {"categories": "scheduled_tasks"},
            "why": "Compare against the Windows known-good baseline to isolate the net-new task.",
        },
    ],
    "suspicious_hash_observed": [
        {
            "tool_name": "search_by_hash",
            "params": {},
            "why": "Check whether the same hash appears in other loaded cases.",
        },
    ],
}


def _load_optional_findings(findings_payload: Any) -> dict[str, Any] | None:
    """Accept a dict or a JSON string; return None if nothing usable.

    Shape validation is deliberately strict: ``findings`` must be a list and
    every item inside it must be a dict. Codex R14b: a payload like
    ``{"findings": "x"}`` or ``{"findings": [1]}`` previously set
    ``findings_available=True`` then crashed in ``_corroboration_gaps`` when
    it called ``.get()`` on a non-dict.
    """
    def _valid(p: Any) -> bool:
        if not isinstance(p, dict):
            return False
        findings = p.get("findings")
        if not isinstance(findings, list):
            return False
        return all(isinstance(item, dict) for item in findings)

    if findings_payload is None:
        return None
    if isinstance(findings_payload, dict):
        return findings_payload if _valid(findings_payload) else None
    if isinstance(findings_payload, str) and findings_payload.strip():
        try:
            parsed = json.loads(findings_payload)
        except Exception:
            return None
        return parsed if _valid(parsed) else None
    return None


def _substrate_gaps(case_health_out: dict[str, Any]) -> list[dict[str, Any]]:
    checks = case_health_out.get("checks", []) or []
    gaps = []
    for c in checks:
        if c.get("passed"):
            continue
        gaps.append({
            "check_name": c.get("check_name"),
            "severity": c.get("severity"),
            "detail": c.get("detail"),
            "suggested_action": c.get("suggested_action"),
        })
    return gaps


def _detection_gaps(findings: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Pull the existing ``unevaluable_rules`` list verbatim. No synthesis."""
    if not findings:
        return []
    unevaluable = findings.get("unevaluable_rules") or []
    out = []
    for u in unevaluable:
        out.append({
            "rule_name": u.get("rule_name") or u.get("rule_id"),
            "missing_artifacts": u.get("missing_artifacts") or u.get("missing") or [],
            "reason": u.get("reason") or "Rule could not run — required artifacts absent.",
        })
    return out


def _corroboration_gaps(findings: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Findings whose strength is below 'confirmed' — the obvious next step is
    to corroborate them. Weak findings still appear here so the analyst sees
    them, but pivots_not_attempted will deliberately skip them."""
    if not findings:
        return []
    out = []
    for f in findings.get("findings", []) or []:
        strength = f.get("overall_strength") or "moderate"
        if strength == "confirmed":
            continue
        out.append({
            "rule_name": f.get("rule_name") or f.get("rule_id"),
            "overall_strength": strength,
            "absent_corroboration": f.get("absent_corroboration") or [],
            "hint": f"Strength={strength}. Corroborate via supporting_artifacts before concluding.",
        })
    return out


def _pivots_not_attempted(
    findings: dict[str, Any] | None,
    anti_forensics_out: dict[str, Any],
) -> list[dict[str, Any]]:
    """Match fired rules to canonical next tools via the _PIVOT_MAP.

    Codex R14b contract: anti-forensic rules are emitted independently of
    ``findings`` — they carry their own strength and do not require a
    find_suspicious payload. Only the findings branch is gated by presence.
    Weak-strength signals are suppressed everywhere (confirmation-bias guard).
    """
    out: list[dict[str, Any]] = []

    fired_names: list[tuple[str, str]] = []  # (rule_name, strength)

    # Anti-forensic rules — always included. We treat them as moderate for
    # pivot purposes because the rules themselves require exact matches.
    for r in anti_forensics_out.get("rules", []) or []:
        if r.get("ok") and r.get("count"):
            fired_names.append((r.get("rule_name") or "", "moderate"))

    # Detection findings — strength per rule is already computed.
    if findings:
        for f in findings.get("findings", []) or []:
            strength = f.get("overall_strength") or "moderate"
            name = f.get("rule_name") or f.get("rule_id") or ""
            if name:
                fired_names.append((name, strength))

    # Codex R14 fix: suppress pivots for weak-only findings.
    for name, strength in fired_names:
        if strength == "weak":
            continue
        pivots = _PIVOT_MAP.get(name)
        if not pivots:
            continue
        out.append({
            "rule_name": name,
            "strength": strength,
            "suggested_pivots": pivots,
        })
    return out


def _bucket_gaps(
    snapshot_slug: str,
    connectors: dict[str, Any],
) -> dict[str, Any] | None:
    """When a snapshot slug is supplied, flag bucketed hit_ids that no longer
    exist in any loaded case. Stale references are the most common source of
    "my saved investigation is useless now" confusion."""
    if not snapshot_slug:
        return None
    try:
        from core.analysis.case_snapshot import load_snapshot
    except Exception as e:  # pragma: no cover — defensive import
        return {"ok": False, "error": f"case_snapshot unavailable: {e}"}
    snap = load_snapshot(snapshot_slug)
    if not snap.get("ok"):
        return {"ok": False, "error": snap.get("error", "Snapshot unreadable")}

    buckets = snap.get("tagged_hits_by_bucket") or {}
    display_names = snap.get("bucket_display_names") or {}

    # Collect every hit_id that exists in any loaded case via search().
    # We cap at a per-case budget to avoid DoS on huge substrates; when the
    # cap is hit we fall back to "cannot verify" rather than false-stale.
    known_hit_ids: set[int] = set()
    cap_hit = False
    per_case_cap = 50_000
    for name, c in (connectors or {}).items():
        if not name.startswith("axiom:"):
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        try:
            # Pull from each connector via a wide-open paged search. Most
            # connectors cap themselves well below per_case_cap.
            res = c.search(keyword="", limit=per_case_cap, offset=0)
            hits = (res or {}).get("hits") or []
            if len(hits) >= per_case_cap:
                cap_hit = True
            for h in hits:
                hid = h.get("hit_id")
                if isinstance(hid, int):
                    known_hit_ids.add(hid)
        except Exception:
            continue

    loaded: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for slug, hit_ids in buckets.items():
        stale_ids = [h for h in hit_ids if h not in known_hit_ids]
        loaded.append({
            "bucket": slug,
            "display_name": display_names.get(slug, slug),
            "total": len(hit_ids),
            "stale": len(stale_ids),
        })
        if stale_ids and not cap_hit:
            stale.append({
                "bucket": slug,
                "display_name": display_names.get(slug, slug),
                "stale_hit_ids": stale_ids[:50],
                "stale_count": len(stale_ids),
            })

    return {
        "ok": True,
        "snapshot_slug": snapshot_slug,
        "verification_capped": cap_hit,
        "loaded": loaded,
        "stale_references": stale,
        "note": (
            "verification_capped=true means at least one case returned the "
            "per-case cap; stale detection was skipped to avoid false alarms."
            if cap_hit else
            "Every hit_id was reconciled against every loaded case."
        ),
    }


def _recommended_next_queries(
    substrate_gaps: list[dict[str, Any]],
    detection_gaps: list[dict[str, Any]],
    pivots: list[dict[str, Any]],
    coverage_out: dict[str, Any],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # 1) High-severity substrate gaps should always lead.
    for g in substrate_gaps:
        if g.get("severity") in {"critical", "high"} and g.get("suggested_action"):
            out.append({
                "tool_name": "case_health",
                "params": {},
                "why": f"substrate: {g['check_name']} — {g['suggested_action']}",
            })

    # 2) Coverage gaps — only structurally_unavailable are actionable.
    unavail = [
        c for c in (coverage_out.get("coverage") or [])
        if c.get("status") == "structurally_unavailable"
    ]
    if unavail:
        out.append({
            "tool_name": "coverage_explainer",
            "params": {},
            "why": (
                f"{len(unavail)} family/ies are structurally unavailable on "
                "the loaded case. Load the MFDB if one exists for this incident."
            ),
        })

    # 3) Detection gaps — surface the rule_coverage blockers.
    for d in detection_gaps[:5]:
        out.append({
            "tool_name": "find_suspicious",
            "params": {"rules": d.get("rule_name", "")},
            "why": f"Rule '{d.get('rule_name')}' could not run — {d.get('reason')}",
        })

    # 4) Pivots — limit to 5 so the list stays readable.
    for p in pivots[:5]:
        for sug in p.get("suggested_pivots", [])[:2]:
            out.append({
                "tool_name": sug["tool_name"],
                "params": sug.get("params", {}),
                "why": f"[{p['rule_name']}] {sug['why']}",
            })

    return out


def investigation_gap_report(
    connectors: dict[str, Any],
    findings_payload: Any = None,
    snapshot_slug: str = "",
) -> dict[str, Any]:
    """Compose gaps from case_health + coverage + anti_forensics (+ optional
    findings, + optional snapshot).

    No new analysis is performed. The function only reformats the output of
    existing primitives and attaches canonical next-step tool calls via a
    hand-curated table.
    """
    from core.analysis.case_health import case_health as _health
    from core.analysis.coverage import build_coverage_report
    from core.analysis.anti_forensics import detect_anti_forensics

    findings = _load_optional_findings(findings_payload)
    findings_available = findings is not None
    skipped: list[str] = []
    if not findings_available:
        # Only detection_gaps and corroboration_gaps strictly depend on a
        # find_suspicious payload. Anti-forensic pivots can still fire.
        skipped = ["detection_gaps", "corroboration_gaps"]

    health_out = _health(connectors)
    coverage_out = build_coverage_report(connectors)

    # anti_forensics wants an ArtifactQueries; pick the active case via state.
    af_out: dict[str, Any] = {"ok": False, "rules": [], "rules_fired": 0}
    try:
        aq = None
        for name, c in (connectors or {}).items():
            if name.startswith("axiom:") and getattr(c, "is_connected", lambda: False)():
                aq = getattr(c, "artifact_queries", None)
                if aq is not None:
                    break
        if aq is not None:
            af_out = detect_anti_forensics(aq)
        else:
            af_out = {"ok": True, "rules": [], "rules_fired": 0, "note": "No active case — anti-forensics skipped."}
    except Exception as e:  # noqa: BLE001
        af_out = {"ok": False, "error": f"anti_forensics unavailable: {e}", "rules": [], "rules_fired": 0}

    substrate_gaps = _substrate_gaps(health_out)
    detection_gaps = _detection_gaps(findings) if findings_available else []
    corroboration_gaps = _corroboration_gaps(findings) if findings_available else []
    # Codex R14b: anti-forensic pivots must emit even without findings; the
    # helper is pure-function safe when findings=None.
    pivots = _pivots_not_attempted(findings, af_out)

    bucket_gaps = _bucket_gaps(snapshot_slug, connectors) if snapshot_slug else None

    recommended = _recommended_next_queries(
        substrate_gaps, detection_gaps, pivots, coverage_out,
    )

    notes = [
        "Composition tool — runs case_health, coverage_explainer and "
        "detect_anti_forensics then reformats their outputs. No new rules fire here.",
        "Pivot suggestions are drawn from a hand-curated table; rules with no "
        "entry in the table will not appear in pivots_not_attempted.",
    ]
    if not findings_available:
        notes.append(
            "findings_payload was not supplied — detection_gaps / corroboration_gaps "
            "were skipped. Anti-forensic pivots are still included. Re-run with the "
            "output of find_suspicious to fill in the findings-dependent sections."
        )
    if bucket_gaps and bucket_gaps.get("verification_capped"):
        notes.append(
            "bucket_gaps.verification_capped=true: at least one case hit the "
            "per-case search cap. Stale references could not be confirmed."
        )

    return {
        "ok": True,
        "findings_available": findings_available,
        "skipped_sections": skipped,
        "substrate_gaps": substrate_gaps,
        "detection_gaps": detection_gaps,
        "corroboration_gaps": corroboration_gaps,
        "pivots_not_attempted": pivots,
        "bucket_gaps": bucket_gaps,
        "recommended_next_queries": recommended,
        "notes": notes,
    }
