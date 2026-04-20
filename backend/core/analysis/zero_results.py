"""Explain why a forensic query returned zero rows.

A thin diagnostic layer on top of ``coverage.build_coverage_report``. The goal
is to turn an empty response into actionable next steps instead of the default
"no activity" misreading that CLAUDE.md explicitly warns about.

Everything here is offline and transparent: every cause includes the concrete
observation that triggered it (e.g. "date range is outside the case window:
2026-04-01 > 2026-03-15"), so an analyst can challenge the recommendation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.analysis.coverage import build_coverage_report


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # accept "2026-04-12", "2026-04-12T10:00:00", or "2026-04-12 10:00:00"
        s2 = s.replace(" ", "T")
        # trim sub-second/tz noise
        if "." in s2:
            s2 = s2.split(".")[0]
        if "+" in s2:
            s2 = s2.split("+")[0]
        if s2.endswith("Z"):
            s2 = s2[:-1]
        return datetime.fromisoformat(s2)
    except Exception:
        return None


def _case_date_range(connectors: dict[str, Any]) -> tuple[str, str] | None:
    """Union earliest-start and latest-end across every loaded case."""
    starts: list[str] = []
    ends: list[str] = []
    for name, c in connectors.items():
        if not name.startswith("axiom:"):
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        try:
            meta = c.get_metadata() or {}
        except Exception:
            continue
        s = meta.get("date_range_start")
        e = meta.get("date_range_end")
        if s:
            starts.append(str(s))
        if e:
            ends.append(str(e))
    if not starts and not ends:
        return None
    return (min(starts) if starts else "", max(ends) if ends else "")


def explain_zero_results(
    connectors: dict[str, Any],
    tool_name: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Diagnose a zero-result response and return causes + follow-up queries.

    ``tool_name`` and ``params`` describe what the user just ran. The function
    never claims "no activity"; it enumerates the observable reasons the
    response could be empty and suggests concrete follow-ups.
    """
    causes: list[dict[str, Any]] = []
    suggestions: list[dict[str, Any]] = []

    artifact_type = str(params.get("artifact_type") or "").strip()
    keyword = str(params.get("keyword") or "").strip()
    keywords = str(params.get("keywords") or "").strip()
    start_date = str(params.get("start_date") or "").strip()
    end_date = str(params.get("end_date") or "").strip()

    coverage = build_coverage_report(connectors, artifact_types=[artifact_type] if artifact_type else None)
    cov_items = coverage.get("coverage", [])

    # 1) Structural gap — the family cannot exist under the current case format.
    for it in cov_items:
        if it.get("artifact_type") == artifact_type and it.get("status") == "structurally_unavailable":
            causes.append({
                "cause": "structurally_unavailable",
                "confidence": "high",
                "detail": (
                    f"Artifact family '{artifact_type}' is structurally unavailable "
                    "under the current case format — it cannot produce hits here."
                ),
                "reason": it.get("reason"),
            })
            suggestions.append({
                "tool_name": "coverage_explainer",
                "params": {"artifact_types": artifact_type},
                "why": "Confirm the structural gap and see which case format exposes this family.",
            })

    # 2) No records loaded for the requested family.
    for it in cov_items:
        if it.get("artifact_type") == artifact_type and it.get("status") == "available_not_loaded":
            causes.append({
                "cause": "available_but_zero_records",
                "confidence": "medium",
                "detail": (
                    f"Artifact family '{artifact_type}' is supported by the current case "
                    "format but parsed zero records. This could be a genuine absence, a "
                    "parser miss, or incomplete collection — verify the raw evidence."
                ),
            })

    # 3) Date range outside case window.
    case_range = _case_date_range(connectors)
    if case_range:
        case_start, case_end = case_range
        qs, qe = _parse_iso(start_date), _parse_iso(end_date)
        cs, ce = _parse_iso(case_start), _parse_iso(case_end)
        if qs and ce and qs > ce:
            causes.append({
                "cause": "date_range_after_case",
                "confidence": "high",
                "detail": (
                    f"start_date {start_date} is after the case's last record "
                    f"({case_end}). No evidence can exist in that window."
                ),
            })
            suggestions.append({
                "tool_name": tool_name,
                "params": {**params, "start_date": "", "end_date": ""},
                "why": "Retry without date filters to see whether the case holds any matching records at all.",
            })
        if qe and cs and qe < cs:
            causes.append({
                "cause": "date_range_before_case",
                "confidence": "high",
                "detail": (
                    f"end_date {end_date} is before the case's first record "
                    f"({case_start})."
                ),
            })

    # 4) Over-narrow keyword.
    combined_kw = keyword or keywords
    if combined_kw and (artifact_type or start_date or end_date):
        causes.append({
            "cause": "filters_stacked",
            "confidence": "low",
            "detail": (
                "Multiple filters are stacked (keyword + artifact_type/date). "
                "Any one of them could be excluding results."
            ),
        })
        # Suggest relaxing — keyword only, then artifact_type only.
        if combined_kw:
            suggestions.append({
                "tool_name": tool_name,
                "params": {**params, "artifact_type": "", "start_date": "", "end_date": ""},
                "why": "Retry with only the keyword to see if the filter stack is over-constrained.",
            })
        if artifact_type:
            suggestions.append({
                "tool_name": tool_name,
                "params": {**params, "keyword": "", "keywords": ""},
                "why": "Retry with only the artifact_type to see if the keyword was the limiting filter.",
            })

    # 5) No cases loaded at all.
    if coverage.get("case_context", {}).get("case_format") == "none":
        causes.append({
            "cause": "no_cases_loaded",
            "confidence": "high",
            "detail": "No cases are currently loaded — any query will return 0 rows.",
        })
        suggestions.append({
            "tool_name": "open_case",
            "params": {"path": "(evidence path)"},
            "why": "Open an MFDB or KAPE directory before running analysis tools.",
        })

    # 6) Generic last-resort advice.
    if not causes:
        causes.append({
            "cause": "unexplained",
            "confidence": "low",
            "detail": (
                "No obvious structural, date, or coverage reason was detected. "
                "Re-check the keyword spelling, or broaden the query to confirm the "
                "filter is what's excluding results."
            ),
        })
        suggestions.append({
            "tool_name": "coverage_explainer",
            "params": {},
            "why": "Inspect full coverage to verify which families have records at all.",
        })

    # Always provide a follow-up into coverage_explainer.
    if not any(s.get("tool_name") == "coverage_explainer" for s in suggestions):
        suggestions.append({
            "tool_name": "coverage_explainer",
            "params": {},
            "why": "See searchable vs structurally-unavailable families for the loaded cases.",
        })

    return {
        "ok": True,
        "tool": "explain_zero_results",
        "input": {"tool_name": tool_name, "params": params},
        "case_context": coverage.get("case_context", {}),
        "likely_causes": causes,
        "suggested_queries": suggestions,
        "notes": [
            "0 results does not mean 'no activity'. Always pair this with coverage_explainer "
            "and a broader retry before concluding absence of evidence.",
        ],
    }
