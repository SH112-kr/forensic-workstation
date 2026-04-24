"""Cross-reference and correlation — SQL-based."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_mfdb import AxiomMfdbConnector


# Hard cap for the cross-period consumers (behavioral_delta) — the MCP
# wrapper separately lets the caller override via ``config.correlate_max_limit``.
_DEFAULT_CORRELATE_MAX_LIMIT = 500
_EVENT_ID_SPEC_RE = re.compile(r"^event_id:(\d+)$", re.I)


def _parse_iso_bound(value: str, *, is_end: bool) -> datetime | None:
    """Parse a date/datetime bound and expand date-only end bounds."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "T" not in text and " " not in text:
        dt = datetime.fromisoformat(text)
        if is_end:
            dt = dt + timedelta(days=1) - timedelta(milliseconds=1)
        return dt.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _timestamp_in_window(timestamp_ms: int, start_ms: int | None, end_ms: int | None) -> bool:
    if start_ms is not None and timestamp_ms < start_ms:
        return False
    if end_ms is not None and timestamp_ms > end_ms:
        return False
    return True


def _normalize_match_mode(match_mode: str) -> str:
    mode = str(match_mode or "substring").strip().lower()
    return mode if mode in {"substring", "exact"} else "substring"


def _string_candidates(hit: dict[str, Any]) -> list[str]:
    values: list[str] = []
    fields = hit.get("fields", {}) or {}
    if isinstance(fields, dict):
        values.extend(str(v) for v in fields.values() if v not in (None, ""))
    timestamps = hit.get("timestamps", {}) or {}
    if isinstance(timestamps, dict):
        values.extend(str(v) for v in timestamps.values() if v not in (None, ""))
    for key in ("artifact_type", "location", "source_path", "hash"):
        value = hit.get(key)
        if value not in (None, ""):
            values.append(str(value))
    return values


def _path_variants(value: str) -> set[str]:
    """Return lower-cased raw / basename / stem variants for exact-like matching."""
    text = str(value or "").strip().strip("\"'")
    if not text:
        return set()
    lowered = text.lower()
    tokens = {lowered}
    for sep in ("\\", "/"):
        if sep in text:
            tail = text.rsplit(sep, 1)[-1].strip().strip("\"'")
            if tail:
                tokens.add(tail.lower())
                if "." in tail:
                    tokens.add(tail.rsplit(".", 1)[0].lower())
    if "." in text and "\\" not in text and "/" not in text:
        tokens.add(text.rsplit(".", 1)[0].lower())
    return {t for t in tokens if t}


def hit_matches_keyword(hit: dict[str, Any], keyword: str, match_mode: str = "substring") -> bool:
    """Apply composition-layer match semantics to an already returned hit."""
    mode = _normalize_match_mode(match_mode)
    needle = str(keyword or "").strip().lower()
    if not needle:
        return False
    if mode == "substring":
        return True

    for value in _string_candidates(hit):
        variants = _path_variants(value)
        if needle in variants:
            return True
    return False


def _seed_label(seed_spec: str) -> str:
    return str(seed_spec or "").strip()


def _parse_seed_spec(seed_spec: str) -> dict[str, Any]:
    raw = _seed_label(seed_spec)
    match = _EVENT_ID_SPEC_RE.match(raw)
    if match:
        return {"kind": "event_id", "value": int(match.group(1)), "label": raw}
    return {"kind": "keyword", "value": raw, "label": raw}


def _hit_has_in_range_events(
    hit: dict[str, Any],
    axiom: "AxiomMfdbConnector",
    start_date: str,
    end_date: str,
) -> bool:
    return bool(extract_hit_events([hit], "__probe__", axiom, start_date=start_date, end_date=end_date))


def search_keyword_hits(
    axiom: "AxiomMfdbConnector",
    keyword: str,
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
    match_mode: str = "substring",
    page_size: int = 200,
) -> dict[str, Any]:
    """Search hits under the requested match semantics.

    ``substring`` delegates directly to ``axiom.search``.
    ``exact`` performs a deterministic post-filter over the full substring
    candidate set and returns exact-filtered totals/hits.
    """
    mode = _normalize_match_mode(match_mode)
    filters = {"start_date": start_date, "end_date": end_date}
    if mode == "substring":
        result = axiom.search(keyword=keyword, filters=filters, limit=limit, offset=offset)
        result["match_mode"] = mode
        return result

    page = max(1, min(page_size, max(limit, 1)))
    first_page = axiom.search(keyword=keyword, filters=filters, limit=page, offset=0)
    total_candidates = int(first_page.get("total", len(first_page.get("hits", []))))
    matched: list[dict[str, Any]] = []
    matched_total = 0

    def consume(hits: list[dict[str, Any]]) -> None:
        nonlocal matched_total
        for hit in hits:
            if hit_matches_keyword(hit, keyword, match_mode=mode):
                matched_total += 1
                if matched_total > offset and len(matched) < limit:
                    matched.append(hit)

    consume(first_page.get("hits", []) or [])
    cursor = len(first_page.get("hits", []) or [])
    while cursor < total_candidates:
        page_result = axiom.search(keyword=keyword, filters=filters, limit=page, offset=cursor)
        hits = page_result.get("hits", []) or []
        if not hits:
            break
        consume(hits)
        cursor += len(hits)

    return {
        "hits": matched,
        "total": matched_total,
        "returned": len(matched),
        "match_mode": mode,
        "candidate_total": total_candidates,
        "candidate_returned": cursor,
    }


def search_seed_hits(
    axiom: "AxiomMfdbConnector",
    seed_spec: str,
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
    match_mode: str = "substring",
    page_size: int = 200,
) -> dict[str, Any]:
    spec = _parse_seed_spec(seed_spec)
    if spec["kind"] == "keyword":
        result = search_keyword_hits(
            axiom,
            keyword=spec["value"],
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
            match_mode=match_mode,
            page_size=page_size,
        )
        result["seed_kind"] = "keyword"
        return result

    aq = getattr(axiom, "artifact_queries", None)
    if aq is None or not hasattr(aq, "query_event_logs"):
        return {"hits": [], "total": 0, "returned": 0, "match_mode": "event_id", "seed_kind": "event_id"}

    rows = aq.query_event_logs(event_ids=[spec["value"]], limit=0) or []
    hit_ids = [int(r["hit_id"]) for r in rows if isinstance(r, dict) and isinstance(r.get("hit_id"), int)]
    hydrated = axiom._hydrate_hits(hit_ids) if hit_ids and hasattr(axiom, "_hydrate_hits") else rows
    filtered = [h for h in hydrated if _hit_has_in_range_events(h, axiom, start_date, end_date)]
    returned = filtered[offset:offset + limit]
    return {
        "hits": returned,
        "total": len(filtered),
        "returned": len(returned),
        "match_mode": "event_id",
        "seed_kind": "event_id",
        "truncated": len(filtered) > offset + len(returned),
    }


def extract_hit_events(
    hits: list[dict[str, Any]],
    keyword: str,
    axiom: "AxiomMfdbConnector",
    start_date: str = "",
    end_date: str = "",
) -> list[dict[str, Any]]:
    """Expand hit timestamp fields into chronological events within bounds."""
    start_bound = _parse_iso_bound(start_date, is_end=False)
    end_bound = _parse_iso_bound(end_date, is_end=True)
    start_ms = int(start_bound.timestamp() * 1000) if start_bound is not None else None
    end_ms = int(end_bound.timestamp() * 1000) if end_bound is not None else None

    events: list[dict[str, Any]] = []
    for hit in hits:
        ts_fields = hit.get("timestamps", {}) or {}
        for ts_name, ts_val in ts_fields.items():
            ms = axiom._iso_to_ms(ts_val) if ts_val else None
            if ms is None or not _timestamp_in_window(ms, start_ms, end_ms):
                continue
            events.append({
                "keyword": keyword,
                "hit_id": hit.get("hit_id"),
                "timestamp": ts_val,
                "timestamp_ms": ms,
                "time_field": ts_name,
                "artifact_type": hit.get("artifact_type", ""),
                "fields": hit.get("fields", {}) if isinstance(hit.get("fields"), dict) else {},
            })
    events.sort(key=lambda e: (e.get("timestamp_ms", 0), e.get("hit_id") or 0, e.get("time_field", "")))
    return events


def correlate_keywords(
    axiom: "AxiomMfdbConnector",
    kw_list: list[str],
    start_date: str = "",
    end_date: str = "",
    window_minutes: int = 5,
    limit: int = 100,
    offset: int = 0,
    max_limit: int = _DEFAULT_CORRELATE_MAX_LIMIT,
    match_mode: str = "substring",
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
        spec = _parse_seed_spec(kw)
        result = search_seed_hits(
            axiom,
            seed_spec=kw,
            start_date=start_date,
            end_date=end_date,
            limit=cap,
            offset=offset,
            match_mode=match_mode,
        )
        hits = result.get("hits", [])
        true_total = result.get("total", len(hits))

        events = extract_hit_events(
            hits,
            spec["label"],
            axiom,
            start_date=start_date,
            end_date=end_date,
        )

        sampled_first_event = min(events, key=lambda e: e.get("timestamp_ms", 0)) if events else None
        sampled_last_event = max(events, key=lambda e: e.get("timestamp_ms", 0)) if events else None

        artifact_counts: dict[str, int] = {}
        for h in hits:
            at = h.get("artifact_type", "unknown")
            artifact_counts[at] = artifact_counts.get(at, 0) + 1

        per_keyword[spec["label"]] = {
            "total_hits": true_total,
            "returned_hits": len(hits),
            "truncated": true_total > len(hits),
            "match_mode": result.get("match_mode", _normalize_match_mode(match_mode)),
            "seed_kind": result.get("seed_kind", spec["kind"]),
            "events_with_timestamps": len(events),
            "artifact_types": artifact_counts,
            "sampled_first_event": sampled_first_event,
            "sampled_last_event": sampled_last_event,
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
