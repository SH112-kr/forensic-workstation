"""Anchor-centered temporal correlation for Windows endpoint evidence.

This module deliberately emits leads, not verdicts.  It is meant for cases
where an analyst already has a timestamped anchor, such as a browser-cache IOC,
and wants nearby Prefetch / WER / browser-cache / timeline evidence without
silently converting time proximity into causation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import re

from core.analysis.prefetch_semantic import parse_prefetch_bytes


_DEFAULT_SOURCES = {"prefetch", "wer", "browser_cache", "crashpad", "axiom_timeline"}

_LANE_BY_SOURCE = {
    "Prefetch": "execution_impact",
    "WER Report": "execution_impact",
    "WER Temp File": "execution_impact",
    "Browser Cache File": "ingress_access",
    "Browser Code Cache File": "ingress_access",
    "Crashpad File": "execution_impact",
    "Timeline": "context",
}

_IGNORED_TOKENS = {
    "http", "https", "cache", "browser", "file", "time", "event",
    "windows", "system32", "program", "programdata", "users",
}


def temporal_anchor_correlation(
    *,
    anchor_ts: str,
    anchor_label: str = "",
    anchor_entities: str = "",
    e01_connector: Any | None = None,
    axiom_connector: Any | None = None,
    window_before_minutes: int = 30,
    window_after_minutes: int = 30,
    source_filter: str = "",
    limit_per_source: int = 50,
    anchor_timezone_offset_hours: int = 0,
) -> dict[str, Any]:
    """Build an evidence-first correlation pack around an analyst anchor."""
    anchor_time = _parse_anchor_time(anchor_ts, anchor_timezone_offset_hours)
    before = max(0, min(int(window_before_minutes), 24 * 60))
    after = max(0, min(int(window_after_minutes), 24 * 60))
    limit = max(1, min(int(limit_per_source), 200))
    start = anchor_time - timedelta(minutes=before)
    end = anchor_time + timedelta(minutes=after)

    sources = _selected_sources(source_filter)
    anchor_tokens = _extract_anchor_tokens(anchor_label, anchor_entities)
    events: list[dict[str, Any]] = []
    source_status: dict[str, dict[str, Any]] = {}
    missing_sources: list[dict[str, str]] = []

    if e01_connector is None:
        for source in sorted(sources & {"prefetch", "wer", "browser_cache", "crashpad"}):
            missing_sources.append({"source": source, "reason": "mounted E01 image not available"})
    else:
        if "prefetch" in sources:
            batch = _collect_prefetch(e01_connector, start, end, limit)
            events.extend(batch["events"])
            source_status["prefetch"] = batch["status"]
        if "wer" in sources:
            batch = _collect_wer(e01_connector, start, end, limit)
            events.extend(batch["events"])
            source_status["wer"] = batch["status"]
        if "browser_cache" in sources:
            batch = _collect_browser_cache(e01_connector, start, end, limit)
            events.extend(batch["events"])
            source_status["browser_cache"] = batch["status"]
        if "crashpad" in sources:
            batch = _collect_crashpad(e01_connector, start, end, limit)
            events.extend(batch["events"])
            source_status["crashpad"] = batch["status"]

    if "axiom_timeline" in sources:
        if axiom_connector is None:
            missing_sources.append({"source": "axiom_timeline", "reason": "artifact case database not available"})
        else:
            batch = _collect_axiom_timeline(axiom_connector, start, end, limit)
            events.extend(batch["events"])
            source_status["axiom_timeline"] = batch["status"]

    annotated = [
        _annotate_event(event, anchor_time, anchor_tokens, anchor_label)
        for event in events
    ]
    annotated.sort(key=lambda e: (abs(int(e.get("delta_seconds", 0))), e.get("timestamp_utc", ""), e.get("source_artifact", "")))

    token_linked = [e for e in annotated if e.get("shared_anchor_tokens")]
    proximity_only = [e for e in annotated if not e.get("shared_anchor_tokens")]
    dominance_warning = ""
    if annotated and len(proximity_only) / len(annotated) > 0.60:
        dominance_warning = (
            "Most correlated artifacts share no secondary token with the anchor. "
            "Review for base-rate noise before making a causal claim."
        )

    return {
        "ok": True,
        "policy": "temporal_anchor_correlation_not_causation_v1",
        "anchor": {
            "timestamp_utc": _iso(anchor_time),
            "label": anchor_label,
            "entities": sorted(anchor_tokens),
        },
        "window": {
            "start_utc": _iso(start),
            "end_utc": _iso(end),
            "before_minutes": before,
            "after_minutes": after,
        },
        "summary": {
            "event_count": len(annotated),
            "token_linked_count": len(token_linked),
            "proximity_only_count": len(proximity_only),
            "source_counts": _count_by(annotated, "source_artifact"),
            "lane_counts": _count_by(annotated, "lane"),
        },
        "lanes": _group_lanes(annotated),
        "token_linked": token_linked[:limit],
        "proximity_only": proximity_only[:limit],
        "source_status": source_status,
        "missing_sources": missing_sources,
        "dominance_warning": dominance_warning,
        "refutation_prompts": _refutation_prompts(annotated, missing_sources, anchor_label),
        "strength_guide": {
            "confirmed": "Direct artifact ties the anchor entity to the later event, e.g. WER AppName/Report.wer matches the browser process and timestamp.",
            "strong_temporal": "Artifact is very close in time to the anchor, but causality remains unproven.",
            "moderate_temporal": "Artifact is within the analyst-selected window and deserves follow-up.",
            "weak_temporal": "Same broad window only; high base-rate noise risk.",
        },
        "notes": [
            "Temporal proximity is a follow-up lead, not proof of causation.",
            "Use token_linked events before proximity_only events when building a hypothesis.",
            "Missing sources are explicit so absence is not mistaken for negative evidence.",
        ],
    }


def _collect_prefetch(connector: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    scanned = 0
    errors = 0
    try:
        entries = connector.list_directory("/c:/Windows/Prefetch")
    except Exception as exc:
        return {"events": [], "status": {"scanned": 0, "returned": 0, "error": str(exc)}}

    for entry in entries:
        if entry.get("is_dir") or not str(entry.get("name", entry.get("path", ""))).lower().endswith(".pf"):
            continue
        if len(events) >= limit:
            break
        scanned += 1
        path = entry.get("path", "")
        try:
            data = connector.read_file_content(path, max_size=int(entry.get("size") or 300000))
            parsed = parse_prefetch_bytes(data, source_path=path)
            if not parsed.get("ok"):
                errors += 1
                continue
            exe = parsed.get("executable_name", "")
            for ts in parsed.get("last_run_times_utc") or []:
                dt = _parse_event_time(ts)
                if dt is None or not (start <= dt <= end):
                    continue
                events.append({
                    "timestamp": dt,
                    "source_artifact": "Prefetch",
                    "time_basis": "prefetch_last_run",
                    "event_label": f"{exe} Prefetch last run",
                    "object": exe,
                    "source_path": path,
                    "raw_ref": {
                        "run_count": parsed.get("run_count", 0),
                        "referenced_paths_sample": _interesting_paths(parsed.get("raw_referenced_paths") or []),
                    },
                })
                if len(events) >= limit:
                    break
        except Exception:
            errors += 1
    return {"events": events, "status": {"scanned": scanned, "returned": len(events), "errors": errors}}


def _collect_wer(connector: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    roots = [
        "/c:/ProgramData/Microsoft/Windows/WER/ReportArchive",
        "/c:/ProgramData/Microsoft/Windows/WER/ReportQueue",
    ]
    roots.extend(_user_wer_roots(connector))
    events: list[dict[str, Any]] = []
    scanned = 0
    errors = 0

    for root in roots:
        if len(events) >= limit:
            break
        try:
            reports = connector.find_files("Report.wer", root, limit=200)
        except Exception:
            continue
        for item in reports:
            if len(events) >= limit:
                break
            path = item.get("path", "")
            if not path:
                continue
            scanned += 1
            try:
                report = _parse_wer(connector.read_file_content(path, max_size=1048576), path)
                dt = _parse_event_time(report.get("EventTime_ISO", ""))
                if dt is None or not (start <= dt <= end):
                    continue
                app = report.get("NsAppName") or report.get("AppName") or report.get("P0") or "unknown"
                event_type = report.get("EventType", "")
                events.append({
                    "timestamp": dt,
                    "source_artifact": "WER Report",
                    "time_basis": "wer_event_time",
                    "event_label": f"{app} {event_type}".strip(),
                    "object": app,
                    "source_path": path,
                    "raw_ref": {
                        "event_type": event_type,
                        "app_path": report.get("AppPath", ""),
                        "mod_name": report.get("ModName", "") or report.get("P3", ""),
                        "report_identifier": report.get("ReportIdentifier", ""),
                    },
                })
            except Exception:
                errors += 1

    temp_events = _collect_file_timestamp_events(
        connector,
        ["/c:/ProgramData/Microsoft/Windows/WER/Temp"],
        start,
        end,
        limit=max(0, limit - len(events)),
        source_artifact="WER Temp File",
        time_basis="file_timestamp",
    )
    events.extend(temp_events["events"])
    errors += int(temp_events["status"].get("errors", 0) or 0)
    scanned += int(temp_events["status"].get("scanned", 0) or 0)
    return {"events": events[:limit], "status": {"scanned": scanned, "returned": len(events[:limit]), "errors": errors}}


def _collect_browser_cache(connector: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    roots = []
    for profile in _browser_profiles(connector):
        roots.append(f"{profile}/Cache/Cache_Data")
        roots.append(f"{profile}/Code Cache/js")
    return _collect_file_timestamp_events(
        connector,
        roots,
        start,
        end,
        limit=limit,
        source_artifact="Browser Cache File",
        time_basis="file_timestamp",
        code_cache_source="Browser Code Cache File",
    )


def _collect_crashpad(connector: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    roots = []
    for base in _browser_user_data_roots(connector):
        roots.append(f"{base}/Crashpad/reports")
        roots.append(f"{base}/Crashpad/pending")
    return _collect_file_timestamp_events(
        connector,
        roots,
        start,
        end,
        limit=limit,
        source_artifact="Crashpad File",
        time_basis="file_timestamp",
    )


def _collect_axiom_timeline(connector: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    try:
        result = connector.get_timeline(_iso(start), _iso(end), None, limit, 0)
    except Exception as exc:
        return {"events": [], "status": {"scanned": 0, "returned": 0, "error": str(exc)}}
    rows = result.get("entries") or result.get("events") or []
    events = []
    for row in rows[:limit]:
        dt = _parse_event_time(row.get("timestamp") or row.get("event_time") or "")
        if dt is None:
            continue
        label = row.get("description") or row.get("artifact_type") or "timeline event"
        events.append({
            "timestamp": dt,
            "source_artifact": "Timeline",
            "time_basis": "artifact_timestamp",
            "event_label": label,
            "object": label,
            "source_path": row.get("source_path", ""),
            "raw_ref": {"hit_id": row.get("hit_id"), "artifact_type": row.get("artifact_type", "")},
        })
    return {"events": events, "status": {"scanned": len(rows), "returned": len(events)}}


def _collect_file_timestamp_events(
    connector: Any,
    roots: list[str],
    start: datetime,
    end: datetime,
    *,
    limit: int,
    source_artifact: str,
    time_basis: str,
    code_cache_source: str = "",
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    scanned = 0
    errors = 0
    for root in roots:
        if len(events) >= limit:
            break
        try:
            entries = connector.list_directory(root)
        except Exception:
            continue
        if not entries or entries[0].get("error"):
            continue
        for entry in entries:
            if len(events) >= limit:
                break
            if entry.get("is_dir"):
                continue
            path = entry.get("path", "")
            if not path:
                continue
            scanned += 1
            try:
                info = connector.get_file_info(path)
                dt, field = _first_info_time_in_window(info, start, end)
                if dt is None:
                    continue
                source = code_cache_source if code_cache_source and "/Code Cache/" in path.replace("\\", "/") else source_artifact
                events.append({
                    "timestamp": dt,
                    "source_artifact": source,
                    "time_basis": f"{time_basis}:{field}",
                    "event_label": f"{source} timestamp {field}",
                    "object": path.rsplit("/", 1)[-1],
                    "source_path": path,
                    "raw_ref": {
                        "size": info.get("size", entry.get("size", 0)),
                        "timestamp_field": field,
                    },
                })
            except Exception:
                errors += 1
    return {"events": events, "status": {"scanned": scanned, "returned": len(events), "errors": errors}}


def _annotate_event(event: dict[str, Any], anchor_time: datetime, anchor_tokens: set[str], anchor_label: str) -> dict[str, Any]:
    dt = event["timestamp"].astimezone(timezone.utc)
    delta = int((dt - anchor_time).total_seconds())
    blob = " ".join(str(v) for v in [event.get("event_label"), event.get("object"), event.get("source_path"), event.get("raw_ref")]).lower()
    shared = sorted(token for token in anchor_tokens if token and token in blob)
    hints = _relationship_hints(anchor_label, event, delta, shared)
    out = {
        "timestamp_utc": _iso(dt),
        "delta_seconds": delta,
        "delta_human": _delta_human(delta),
        "source_artifact": event.get("source_artifact", ""),
        "lane": _LANE_BY_SOURCE.get(event.get("source_artifact", ""), "context"),
        "time_basis": event.get("time_basis", ""),
        "event_label": event.get("event_label", ""),
        "object": event.get("object", ""),
        "source_path": event.get("source_path", ""),
        "shared_anchor_tokens": shared,
        "correlation_strength": _correlation_strength(delta, shared, hints),
        "causality": "unproven",
        "relationship_hints": hints,
        "warning": "Temporal proximity is not proof of causation.",
        "raw_ref": event.get("raw_ref", {}),
    }
    return out


def _relationship_hints(anchor_label: str, event: dict[str, Any], delta: int, shared: list[str]) -> list[str]:
    hints: list[str] = []
    label = anchor_label.lower()
    source = str(event.get("source_artifact", "")).lower()
    obj = str(event.get("object", "")).lower()
    if ("cache" in label or "browser" in label or "url" in label) and "werfault" in obj and abs(delta) <= 120:
        hints.append("browser_or_url_anchor_near_werfault")
    if "wer report" in source and shared:
        hints.append("wer_report_shares_anchor_token")
    if "prefetch" in source and shared:
        hints.append("prefetch_shares_anchor_token")
    return hints


def _correlation_strength(delta: int, shared: list[str], hints: list[str]) -> str:
    adelta = abs(delta)
    if "wer_report_shares_anchor_token" in hints:
        return "confirmed_candidate"
    if shared and adelta <= 300:
        return "entity_and_temporal_correlation"
    if adelta <= 60:
        return "strong_temporal"
    if adelta <= 300:
        return "moderate_temporal"
    return "weak_temporal"


def _parse_anchor_time(value: str, offset_hours: int) -> datetime:
    if not value.strip():
        raise ValueError("anchor_ts is required")
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                parsed = None  # type: ignore[assignment]
        if parsed is None:
            raise ValueError(f"Unsupported anchor_ts format: {value}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone(timedelta(hours=offset_hours)))
    return parsed.astimezone(timezone.utc)


def _parse_event_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text[:26], fmt)
                break
            except ValueError:
                parsed = None  # type: ignore[assignment]
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_wer(data: bytes, source_path: str) -> dict[str, Any]:
    text = ""
    for encoding in ("utf-16-le", "utf-16", "utf-8-sig", "utf-8"):
        try:
            text = data.decode(encoding)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    report: dict[str, Any] = {"source_path": source_path}
    for line in text.lstrip("\ufeff").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            report[key] = value.strip()
    event_time_raw = report.get("EventTime", "")
    if event_time_raw.isdigit():
        filetime = int(event_time_raw)
        epoch_diff = 116444736000000000
        if filetime > epoch_diff:
            ts = (filetime - epoch_diff) / 10_000_000
            report["EventTime_ISO"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return report


def _browser_user_data_roots(connector: Any) -> list[str]:
    vendors = [
        "Naver/Naver Whale/User Data",
        "Google/Chrome/User Data",
        "Microsoft/Edge/User Data",
    ]
    roots: list[str] = []
    try:
        users = connector.list_directory("/c:/Users")
    except Exception:
        return roots
    for user in users:
        name = user.get("name", "")
        if not user.get("is_dir") or name in {"Public", "Default", "Default User", "All Users"}:
            continue
        for vendor in vendors:
            roots.append(f"/c:/Users/{name}/AppData/Local/{vendor}")
    return roots


def _browser_profiles(connector: Any) -> list[str]:
    profiles: list[str] = []
    for base in _browser_user_data_roots(connector):
        try:
            entries = connector.list_directory(base)
        except Exception:
            continue
        for entry in entries:
            name = entry.get("name", "")
            if entry.get("is_dir") and (name == "Default" or name.startswith("Profile ")):
                profiles.append(f"{base}/{name}")
    return profiles


def _user_wer_roots(connector: Any) -> list[str]:
    roots: list[str] = []
    try:
        users = connector.list_directory("/c:/Users")
    except Exception:
        return roots
    for user in users:
        name = user.get("name", "")
        if user.get("is_dir") and name not in {"Public", "Default", "Default User", "All Users"}:
            roots.append(f"/c:/Users/{name}/AppData/Local/Microsoft/Windows/WER/ReportArchive")
            roots.append(f"/c:/Users/{name}/AppData/Local/Microsoft/Windows/WER/ReportQueue")
    return roots


def _first_info_time_in_window(info: dict[str, Any], start: datetime, end: datetime) -> tuple[datetime | None, str]:
    for field in ("created", "modified", "accessed", "$SI_created", "$SI_modified", "$SI_mft_modified", "$SI_accessed", "$FN_created", "$FN_modified"):
        dt = _parse_event_time(info.get(field, ""))
        if dt is not None and start <= dt <= end:
            return dt, field
    return None, ""


def _extract_anchor_tokens(label: str, entities: str) -> set[str]:
    raw = f"{label} {entities}".lower()
    tokens = set()
    for token in re.findall(r"[a-z0-9][a-z0-9_.:-]{3,}", raw):
        token = token.strip("._:-")
        if token and token not in _IGNORED_TOKENS:
            tokens.add(token)
            if "." in token:
                tokens.update(part for part in token.split(".") if len(part) >= 4 and part not in _IGNORED_TOKENS)
    return tokens


def _selected_sources(source_filter: str) -> set[str]:
    if not source_filter.strip():
        return set(_DEFAULT_SOURCES)
    requested = {item.strip().lower() for item in source_filter.split(",") if item.strip()}
    aliases = {"pf": "prefetch", "prefetch": "prefetch", "wer": "wer", "browser": "browser_cache", "browser_cache": "browser_cache", "crashpad": "crashpad", "timeline": "axiom_timeline", "axiom_timeline": "axiom_timeline"}
    return {aliases[item] for item in requested if item in aliases}


def _interesting_paths(paths: list[str], limit: int = 12) -> list[str]:
    out = []
    for path in paths:
        up = path.upper()
        if any(token in up for token in ("USERS\\", "PROGRAMDATA", "APPDATA", "TEMP", "WER", "WHALE", "CHROME", "EDGE")):
            out.append(path)
        if len(out) >= limit:
            break
    return out


def _group_lanes(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    lanes = {"ingress_access": [], "execution_impact": [], "persistence_cleanup": [], "context": []}
    for event in events:
        lane = event.get("lane", "context")
        lanes.setdefault(lane, []).append(event)
    return lanes


def _count_by(events: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        value = str(event.get(key, "") or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _refutation_prompts(events: list[dict[str, Any]], missing_sources: list[dict[str, str]], anchor_label: str) -> list[str]:
    prompts = []
    if any("werfault" in str(e.get("object", "")).lower() for e in events):
        prompts.append("Verify the matching Report.wer, WER temp files, or Crashpad report to identify which process faulted.")
    if "cache" in anchor_label.lower() or "url" in anchor_label.lower():
        prompts.append("Check whether browser History, Code Cache, and network/SRUM records corroborate the cache entry.")
    if missing_sources:
        prompts.append("Do not treat missing source families as negative evidence; collect or parse them before refuting the hypothesis.")
    return prompts


def _delta_human(delta: int) -> str:
    sign = "+" if delta >= 0 else "-"
    absolute = abs(delta)
    if absolute < 60:
        return f"{sign}{absolute}s"
    minutes, seconds = divmod(absolute, 60)
    if minutes < 60:
        return f"{sign}{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{sign}{hours}h{minutes:02d}m"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
