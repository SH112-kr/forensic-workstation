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

    connectors = getattr(app_state, "_connectors", {}) or {}
    parsed_loaded = any(
        (name == "axiom" or str(name).startswith("axiom:"))
        and callable(getattr(connector, "is_connected", None))
        and connector.is_connected()
        for name, connector in connectors.items()
    )
    return None if parsed_loaded else raw


def raw_index_coverage(raw: Any) -> dict:
    coverage = getattr(raw, "get_coverage", None)
    if callable(coverage):
        return coverage()
    return {"status": "searched", "gaps": []}
