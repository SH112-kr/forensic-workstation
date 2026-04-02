"""Cross-reference and correlation — SQL-based."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connectors.axiom_mfdb import AxiomMfdbConnector


def correlate(
    connector: AxiomMfdbConnector,
    pivot_field: str,
    pivot_value: str,
    window_minutes: int = 5,
    limit: int = 100,
) -> dict:
    pivot_field = pivot_field.lower().strip()

    if pivot_field == "timestamp":
        return _by_timestamp(connector, pivot_value, window_minutes, limit)
    elif pivot_field == "user":
        return _by_keyword_in_fields(connector, pivot_value, _user_fields(), "user", limit)
    elif pivot_field == "source":
        return _by_source(connector, pivot_value, limit)
    elif pivot_field == "keyword":
        return _by_keyword(connector, pivot_value, limit)
    else:
        return {"error": f"Unknown pivot_field: {pivot_field}. Use: timestamp, user, source, keyword"}


def _user_fields() -> list[str]:
    return [
        "Security Identifier", "Username", "Account", "Owner",
        "Account Name", "Source User", "Target User", "User Name",
    ]


def _by_timestamp(connector: AxiomMfdbConnector, pivot_value: str, window_minutes: int, limit: int) -> dict:
    center_ms = connector._iso_to_ms(pivot_value)
    if not center_ms:
        return {"error": f"Cannot parse timestamp: {pivot_value}"}

    window_ms = window_minutes * 60 * 1000
    start_ms = center_ms - window_ms
    end_ms = center_ms + window_ms

    result = connector.get_timeline(
        start_date=connector._ms_to_iso(start_ms),
        end_date=connector._ms_to_iso(end_ms),
        limit=limit,
    )

    # Group by artifact type
    type_counts: dict[str, int] = {}
    for entry in result.get("entries", []):
        at = entry.get("artifact_type", "unknown")
        type_counts[at] = type_counts.get(at, 0) + 1

    return {
        "pivot": "timestamp",
        "pivot_value": pivot_value,
        "window_minutes": window_minutes,
        "total_matches": result.get("total_events", 0),
        "artifact_type_breakdown": type_counts,
        "entries": result.get("entries", []),
    }


def _by_keyword_in_fields(
    connector: AxiomMfdbConnector, value: str, field_names: list[str],
    label: str, limit: int,
) -> dict:
    # Search for the value in string fragments
    hit_ids = connector.search_patterns([value], limit=limit)
    hits = connector._hydrate_hits(hit_ids)

    # Filter to hits where the value appears in one of the target fields
    matched = []
    for h in hits:
        fields = h.get("fields", {})
        for fname in field_names:
            fval = str(fields.get(fname, ""))
            if value.lower() in fval.lower():
                matched.append(h)
                break

    type_counts: dict[str, int] = {}
    for h in matched:
        at = h.get("artifact_type", "unknown")
        type_counts[at] = type_counts.get(at, 0) + 1

    return {
        "pivot": label,
        "pivot_value": value,
        "total_matches": len(matched),
        "artifact_type_breakdown": type_counts,
        "hits": matched[:limit],
    }


def _by_source(connector: AxiomMfdbConnector, value: str, limit: int) -> dict:
    result = connector.search_by_source(value, limit=limit)
    hits = result.get("hits", [])

    type_counts: dict[str, int] = {}
    for h in hits:
        at = h.get("artifact_type", "unknown")
        type_counts[at] = type_counts.get(at, 0) + 1

    return {
        "pivot": "source",
        "pivot_value": value,
        "total_matches": result.get("total", 0),
        "artifact_type_breakdown": type_counts,
        "hits": hits,
    }


def _by_keyword(connector: AxiomMfdbConnector, value: str, limit: int) -> dict:
    result = connector.search(keyword=value, limit=limit)
    hits = result.get("hits", [])

    type_counts: dict[str, int] = {}
    for h in hits:
        at = h.get("artifact_type", "unknown")
        type_counts[at] = type_counts.get(at, 0) + 1

    return {
        "pivot": "keyword",
        "pivot_value": value,
        "total_matches": result.get("total_estimated", 0),
        "artifact_type_breakdown": type_counts,
        "hits": hits,
    }
