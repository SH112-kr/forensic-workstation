"""Shared timeline event schema for conservative artifact correlation.

The schema keeps timestamp meaning, confidence, and corroboration state next to
each event so cross-artifact ordering does not silently become overclaiming.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def make_timeline_event(
    *,
    event_time: str,
    event_time_type: str,
    source_artifact: str,
    sequence_role: str,
    actor: str = "",
    asset: str = "",
    object: str = "",
    confidence: str = "moderate",
    corroboration_state: str = "uncorroborated",
    source_path: str = "",
    timezone_note: str = "UTC",
    notes: str = "",
    raw_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_time": event_time or "",
        "event_time_type": event_time_type,
        "timezone": timezone_note,
        "source_artifact": source_artifact,
        "sequence_role": sequence_role,
        "actor": actor or "",
        "asset": asset or "",
        "object": object or "",
        "confidence": confidence,
        "corroboration_state": corroboration_state,
        "source_path": source_path or "",
        "notes": notes or "",
        "raw_ref": raw_ref or {},
    }


def sort_timeline_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=_sort_key)


def summarize_timeline(events: list[dict[str, Any]]) -> dict[str, Any]:
    roles: dict[str, int] = {}
    sources: dict[str, int] = {}
    for event in events:
        roles[event.get("sequence_role", "unknown")] = roles.get(event.get("sequence_role", "unknown"), 0) + 1
        sources[event.get("source_artifact", "unknown")] = sources.get(event.get("source_artifact", "unknown"), 0) + 1
    ordered = sort_timeline_events(events)
    return {
        "event_count": len(events),
        "first_event_time": ordered[0].get("event_time", "") if ordered else "",
        "last_event_time": ordered[-1].get("event_time", "") if ordered else "",
        "sequence_role_counts": roles,
        "source_artifact_counts": sources,
    }


def build_timeline_chains(
    events: list[dict[str, Any]],
    *,
    window_seconds: int = 1800,
    max_chains: int = 25,
) -> list[dict[str, Any]]:
    ordered = sort_timeline_events(events)
    chains: list[dict[str, Any]] = []
    for idx, event in enumerate(ordered):
        if event.get("sequence_role") not in {"remote_access", "execution", "download", "persistence"}:
            continue
        base_time = _parse_sortable_time(event.get("event_time", ""))
        if base_time is None:
            continue
        related = []
        for other in ordered:
            other_time = _parse_sortable_time(other.get("event_time", ""))
            if other_time is None:
                continue
            delta = abs((other_time - base_time).total_seconds())
            if delta <= window_seconds and _events_share_context(event, other):
                related.append(other)
        if len(related) < 2:
            continue
        chains.append({
            "anchor_index": idx,
            "anchor_time": event.get("event_time", ""),
            "anchor_role": event.get("sequence_role", ""),
            "anchor_object": event.get("object", ""),
            "window_seconds": window_seconds,
            "event_count": len(related),
            "events": related[:20],
            "corroboration_state": "candidate_chain",
            "notes": "Time-near and entity-near events; this is a lead, not a final causal proof.",
        })
        if len(chains) >= max_chains:
            break
    return chains


def _events_share_context(left: dict[str, Any], right: dict[str, Any]) -> bool:
    object_left = str(left.get("object", "")).lower()
    object_right = str(right.get("object", "")).lower()
    combined_left = " ".join(str(left.get(key, "")) for key in ("object", "source_path")).lower()
    combined_right = " ".join(str(right.get(key, "")) for key in ("object", "source_path")).lower()
    for token in ("teamviewer", "powershell", "cmd.exe", "psexec", "rundll32", "wscript", "mshta", "certutil"):
        if token in combined_left and token in combined_right:
            return True
    left_actor = str(left.get("actor", "")).lower()
    right_actor = str(right.get("actor", "")).lower()
    ignored_actors = {"", "localsystem", "system", "umfd-0", "umfd-1", "umfd-2", "umfd-3", "umfd-4", "dwm-1", "dwm-2", "dwm-3", "dwm-4"}
    if left_actor not in ignored_actors and left_actor == right_actor:
        return _meaningful_object_overlap(object_left, object_right)
    return False


def _meaningful_object_overlap(left: str, right: str) -> bool:
    left_tokens = {token for token in _split_object_tokens(left) if len(token) >= 5}
    right_tokens = {token for token in _split_object_tokens(right) if len(token) >= 5}
    ignored = {"windows", "system32", "svchost.exe", "winlogon.exe", "service", "google", "update"}
    return bool((left_tokens - ignored) & (right_tokens - ignored))


def _split_object_tokens(value: str) -> list[str]:
    for char in "\\/():;[]{}":
        value = value.replace(char, " ")
    return [token.strip().lower() for token in value.split() if token.strip()]


def _sort_key(event: dict[str, Any]) -> tuple[int, str, str]:
    parsed = _parse_sortable_time(event.get("event_time", ""))
    if parsed is None:
        return (1, str(event.get("event_time", "")), str(event.get("source_artifact", "")))
    return (0, parsed.isoformat(), str(event.get("source_artifact", "")))


def _parse_sortable_time(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
