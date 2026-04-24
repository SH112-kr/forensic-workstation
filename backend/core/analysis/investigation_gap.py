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
    "truncation_gaps": [...],
    "bucket_gaps": {...} | None,
    "recommended_next_queries": [],
    "notes": [str, ...],
  }
"""

from __future__ import annotations

import json
from typing import Any



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
    """All findings with their absent_corroboration lists.

    Every finding is surfaced so the LLM can decide which ones warrant
    additional cross-artifact corroboration. No code-side strength filter
    is applied — that judgment belongs to the analyst.
    """
    if not findings:
        return []
    out = []
    for f in findings.get("findings", []) or []:
        absent = f.get("absent_corroboration") or []
        out.append({
            "rule_name": f.get("rule_name") or f.get("rule_id"),
            "absent_corroboration": absent,
        })
    return out



def _truncation_pivots(findings: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Emit mandatory pagination pivots for any finding whose details list was capped.

    When suspicious.py truncated a rule's details (truncated=True), the analyst
    has not seen all evidence for that rule and must paginate before concluding.
    These pivots carry severity="mandatory" to distinguish them from optional pivots.
    """
    if not findings:
        return []
    out: list[dict[str, Any]] = []
    for f in (findings.get("findings") or []):
        if not f.get("truncated"):
            continue
        matching = int(f.get("matching_count") or 0)
        returned = int(f.get("returned_count") or 0)
        rule = str(f.get("rule_name") or "")
        remaining = matching - returned
        out.append({
            "rule_name": rule,
            "pivot_reason": "truncated_details",
            "severity": "mandatory",
            "matching_count": matching,
            "returned_count": returned,
            "remaining_unseen": remaining,
            "suggested_pivots": [
                {
                    "tool_name": "find_suspicious",
                    "params": {"rules": rule},
                    "why": (
                        f"Rule '{rule}' returned only {returned} of {matching} records. "
                        f"{remaining} records are unseen — must re-run this single rule "
                        "before using it as a conclusion basis."
                    ),
                }
            ],
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
    truncation_gaps = _truncation_pivots(findings) if findings_available else []

    bucket_gaps = _bucket_gaps(snapshot_slug, connectors) if snapshot_slug else None

    notes = [
        "Composition tool — runs case_health, coverage_explainer and "
        "detect_anti_forensics then reformats their outputs. No new rules fire here.",
    ]
    if not findings_available:
        notes.append(
            "findings_payload was not supplied — detection_gaps / corroboration_gaps "
            "were skipped. Re-run with the output of find_suspicious to fill in the "
            "findings-dependent sections."
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
        "truncation_gaps": truncation_gaps,
        "bucket_gaps": bucket_gaps,
        "recommended_next_queries": [],
        "notes": notes,
    }
