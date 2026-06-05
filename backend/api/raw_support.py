"""Helpers for raw-sidecar-only API fallbacks."""

from __future__ import annotations

from typing import Any


def active_raw_index_without_parsed_case(app_state: Any) -> Any | None:
    """Return the active raw index only when no parsed AXIOM/KAPE case exists."""
    getter = getattr(app_state, "get", None)
    raw = getter("raw_index") if callable(getter) else None
    if not raw or not callable(getattr(raw, "is_connected", None)):
        return None
    if not raw.is_connected():
        return None

    return None if parsed_case_loaded(app_state) else raw


def parsed_case_loaded(app_state: Any) -> bool:
    connectors = getattr(app_state, "_connectors", {}) or {}
    return any(
        (name == "axiom" or str(name).startswith("axiom:"))
        and callable(getattr(connector, "is_connected", None))
        and connector.is_connected()
        for name, connector in connectors.items()
    )


def raw_index_coverage(raw: Any) -> dict:
    coverage = getattr(raw, "get_coverage", None)
    if callable(coverage):
        return coverage()
    return {"status": "searched", "gaps": []}


def should_fallback_to_parsed_case(raw_result: Any, app_state: Any) -> bool:
    if not isinstance(raw_result, dict) or not parsed_case_loaded(app_state):
        return False
    if str(raw_result.get("status") or "") == "not_evaluable":
        return True
    return bool(raw_result.get("error"))


def annotate_parsed_fallback(parsed_result: dict, raw_result: dict) -> dict:
    result = dict(parsed_result)
    coverage = raw_result.get("coverage", raw_result.get("raw_index_coverage"))
    if not isinstance(coverage, dict):
        gaps = []
        if raw_result.get("error"):
            gaps.append({"error": str(raw_result["error"])})
        coverage = {"status": "not_evaluable", "gaps": gaps}
    result["fallback_source"] = "parsed_case"
    result["raw_index_status"] = str(
        raw_result.get("status") or ("error" if raw_result.get("error") else "not_evaluable")
    )
    result["raw_index_coverage"] = coverage
    return result
