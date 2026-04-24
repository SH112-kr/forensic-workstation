"""Regression harness metrics (M1-M4).

All functions are pure: same inputs → same outputs. Parsed LLM output and
ground truth dicts are the only sources of variance.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


_HEDGED_PHRASES = (
    "evidence suggests",
    "basis:",
    "may indicate",
    "consistent with",
    "suggests that",
    "appears to",
    "possibly",
)


def _norm(text: Any) -> str:
    return str(text or "").lower().strip()


def verdict_correct(final_answer: dict, ground_truth: dict) -> bool:
    """M1 — predicted verdict matches ground truth primary or an alternative."""
    predicted = _norm(final_answer.get("verdict"))
    expected = ground_truth.get("expected_verdict") or {}
    acceptable = {_norm(expected.get("primary"))}
    acceptable.update(_norm(v) for v in expected.get("acceptable_alternatives", []))
    acceptable.discard("")
    return predicted in acceptable


def is_false_positive(final_answer: dict, ground_truth: dict) -> bool:
    """M2 — benign fixture flagged as compromise (verdict != benign|unknown)."""
    expected = ground_truth.get("expected_verdict") or {}
    if _norm(expected.get("primary")) != "benign":
        return False
    predicted = _norm(final_answer.get("verdict"))
    return predicted not in {"benign", "unknown"}


def tool_diversity(tool_calls: list[dict]) -> dict:
    """M3 — diversity of tools used during the analysis."""
    names = [call.get("name") for call in tool_calls or [] if call.get("name")]
    total = len(names)
    if not names:
        return {
            "total_calls": 0,
            "unique_tools": 0,
            "diversity_ratio": 0.0,
            "top_tool_share": 0.0,
            "top_tool": None,
        }
    counter = Counter(names)
    top_tool, top_count = counter.most_common(1)[0]
    return {
        "total_calls": total,
        "unique_tools": len(counter),
        "diversity_ratio": round(len(counter) / total, 3),
        "top_tool_share": round(top_count / total, 3),
        "top_tool": top_tool,
    }


def uncertainty_cited(final_answer_text: str) -> dict:
    """M4 — LLM cited uncertainty / limitation markers in reasoning."""
    lower = _norm(final_answer_text)
    applicability_mentioned = "applicability" in lower or "primary_domain" in lower
    strong_conclusion_mentioned = (
        "allow_strong_conclusion" in lower
        or "investigation incomplete" in lower
        or "blocked_lanes" in lower
    )
    hedged_language = any(phrase in lower for phrase in _HEDGED_PHRASES)
    markers = {
        "applicability_mentioned": applicability_mentioned,
        "strong_conclusion_mentioned": strong_conclusion_mentioned,
        "hedged_language": hedged_language,
    }
    markers["total_cited"] = sum(1 for v in markers.values() if v)
    return markers


_REFUTATION_MARKERS = (
    "refuted",
    "refutes",
    "refute",
    "not a ",
    "no evidence of",
    "no evidence for",
    "absence of",
    "absent",
    "rejected",
    "rules out",
    "inconsistent with",
    "cannot confirm",
    "does not support",
    "not supported",
    "refutation",
    "refuting",
    # Structural markers from the standard prompt's JSON block
    "considered_alternatives",
    "refutation_checked",
)

# A small window of characters around each phrase is scanned for refutation
# language. 120 chars is roughly one sentence-worth of context on either side.
_REFUTATION_CONTEXT_CHARS = 120


def _phrase_in_refutation_context(text: str, phrase: str) -> bool:
    """True iff every occurrence of ``phrase`` falls inside refutation text.

    Returns False when the phrase appears in at least one context without a
    nearby refutation marker — that is the case where the LLM is making a
    positive claim and the phrase counts as a prohibited violation.
    """
    needle = _norm(phrase)
    if not needle:
        return False
    start = 0
    found_any = False
    while True:
        idx = text.find(needle, start)
        if idx < 0:
            break
        found_any = True
        window_start = max(0, idx - _REFUTATION_CONTEXT_CHARS)
        window_end = min(len(text), idx + len(needle) + _REFUTATION_CONTEXT_CHARS)
        window = text[window_start:window_end]
        if not any(m in window for m in _REFUTATION_MARKERS):
            return False  # Found an assertive occurrence
        start = idx + len(needle)
    return found_any


def _required_group_matched(text: str, group) -> bool:
    """True if any synonym in ``group`` appears in text. Strings are treated
    as single-member groups for backward compatibility.
    """
    if isinstance(group, str):
        return _norm(group) in text
    for alt in group:
        if _norm(alt) in text:
            return True
    return False


def _group_label(group) -> str:
    """Human-readable label for a required-phrase group (first member)."""
    if isinstance(group, str):
        return group
    return next(iter(group), "") if group else ""


def check_required_phrases(final_answer_text: str, ground_truth: dict) -> dict:
    """Helper — verify required / prohibited phrases.

    Supports two shapes per entry in ``required_phrases``:
      - a plain string (legacy)
      - a list of synonyms (OR within the group; outer list is AND)

    Prohibited matches are suppressed when the phrase only appears inside a
    refutation context (near "refuted", "no evidence of", ...), so a model
    that correctly dismisses a hypothesis is not punished for naming it.
    """
    lower = _norm(final_answer_text)
    required = [p for p in ground_truth.get("required_phrases", []) if p]
    prohibited = [p for p in ground_truth.get("prohibited_phrases", []) if p]

    required_hits: list = []
    required_missing: list = []
    for group in required:
        if _required_group_matched(lower, group):
            required_hits.append(group)
        else:
            required_missing.append(_group_label(group))

    prohibited_hits: list[str] = []
    for phrase in prohibited:
        norm_phrase = _norm(phrase)
        if not norm_phrase or norm_phrase not in lower:
            continue
        if _phrase_in_refutation_context(lower, norm_phrase):
            continue
        prohibited_hits.append(phrase)

    return {
        "required_total": len(required),
        "required_matched": len(required_hits),
        "required_missing": required_missing,
        "prohibited_violations": prohibited_hits,
    }
