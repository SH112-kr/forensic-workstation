"""Cross-reference and correlation — SQL-based."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_mfdb import AxiomMfdbConnector


# Hard cap for the cross-period consumers (behavioral_delta) — the MCP
# wrapper separately lets the caller override via ``config.correlate_max_limit``.
_DEFAULT_CORRELATE_MAX_LIMIT = 500


def correlate_keywords(
    axiom: "AxiomMfdbConnector",
    kw_list: list[str],
    start_date: str = "",
    end_date: str = "",
    window_minutes: int = 5,
    limit: int = 100,
    offset: int = 0,
    max_limit: int = _DEFAULT_CORRELATE_MAX_LIMIT,
) -> dict:
    """Multi-keyword co-occurrence computation.

    Extracted from ``mcp_bridge._correlate_keywords`` so both the MCP
    ``correlate`` tool and composition tools (``behavioral_delta``, future
    packs) share one implementation. Without a single source of truth,
    the two would drift on edge cases (same-hit multiple-timestamp
    fan-out, co-occurrence window dedup) and produce different window
    counts for identical input — exactly the Codex pre-review blocker.

    Input contract consumed from ``axiom.search()``:
        ``{"hits": [{"hit_id": int, "timestamps": {ts_name: iso_str},
                     "artifact_type": str}], "total": int}``

    Every timestamp field on a hit contributes one event. This matches
    the original behaviour — do not deduplicate across timestamp fields
    inside a single hit without updating every caller's expected counts.

    Returns the same envelope the MCP tool already exposes so shape is
    preserved 1:1.
    """
    per_keyword: dict[str, dict[str, Any]] = {}
    all_events: list[dict[str, Any]] = []

    for kw in kw_list:
        cap = min(limit, max_limit)
        result = axiom.search(
            keyword=kw,
            filters={"start_date": start_date, "end_date": end_date},
            limit=cap, offset=offset,
        )
        hits = result.get("hits", [])
        true_total = result.get("total", len(hits))

        events: list[dict[str, Any]] = []
        for h in hits:
            ts_fields = h.get("timestamps", {}) or {}
            for ts_name, ts_val in ts_fields.items():
                ms = axiom._iso_to_ms(ts_val) if ts_val else None
                if ms:
                    events.append({
                        "keyword": kw,
                        "hit_id": h.get("hit_id"),
                        "timestamp": ts_val,
                        "timestamp_ms": ms,
                        "time_field": ts_name,
                        "artifact_type": h.get("artifact_type", ""),
                    })

        artifact_counts: dict[str, int] = {}
        for h in hits:
            at = h.get("artifact_type", "unknown")
            artifact_counts[at] = artifact_counts.get(at, 0) + 1

        per_keyword[kw] = {
            "total_hits": true_total,
            "returned_hits": len(hits),
            "truncated": true_total > len(hits),
            "events_with_timestamps": len(events),
            "artifact_types": artifact_counts,
        }
        all_events.extend(events)

    all_events.sort(key=lambda e: e.get("timestamp_ms", 0))

    window_ms = window_minutes * 60 * 1000
    co_occurrences: list[dict[str, Any]] = []
    for i, ev in enumerate(all_events):
        window_kws = {ev["keyword"]}
        window_events = [ev]
        for j in range(i + 1, len(all_events)):
            if all_events[j]["timestamp_ms"] - ev["timestamp_ms"] <= window_ms:
                window_kws.add(all_events[j]["keyword"])
                window_events.append(all_events[j])
            else:
                break
        if len(window_kws) >= 2:
            co_occurrences.append({
                "start": ev["timestamp"],
                "keywords_present": sorted(window_kws),
                "event_count": len(window_events),
            })

    deduped: list[dict[str, Any]] = []
    seen_starts: set[tuple[str, tuple[str, ...]]] = set()
    for co in co_occurrences:
        key = (co["start"], tuple(co["keywords_present"]))
        if key not in seen_starts:
            seen_starts.add(key)
            deduped.append(co)

    total_events = len(all_events)
    return {
        "mode": "multi_keyword_correlation",
        "keywords": list(kw_list),
        "per_keyword": per_keyword,
        "co_occurrence_windows": deduped[:50],
        "total_co_occurrences": len(deduped),
        "window_minutes": window_minutes,
        "chronological_events": all_events[:limit],
        "total_chronological_events": total_events,
        "truncated": total_events > limit,
    }


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
