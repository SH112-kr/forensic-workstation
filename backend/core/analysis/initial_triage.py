"""Window-first initial triage harness for Windows endpoint IR.

This module deliberately favors "what happened when?" over static-delta first
triage. It is intentionally conservative:

- scope selection is explicit and surfaced in the output
- coverage gaps block or cap specific claims
- candidate windows come before baseline diff
- baseline diff is delayed into precursor context and never treated as
  incident proof

The implementation is heuristic, not statistically calibrated. Numeric tuning
values are returned to the caller so analysts can see which policy defaults
were used.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from core.analysis.artifact_bundles import build_artifact_bundles
from core.analysis.baseline_diff import baseline_diff as run_baseline_diff
from core.analysis.case_health import case_health as build_case_health
from core.analysis.date_anchor_triage import date_anchor_triage


_APPLICABILITY = {
    "primary_domain": "windows_endpoint_ir",
    "degraded_domains": [
        "cloud_only",
        "supply_chain",
        "network_device_centric",
        "physical_access",
    ],
    "note": (
        "This harness is optimized for Windows endpoint IR. In degraded "
        "domains, treat the outputs as hints rather than as strong "
        "classification logic."
    ),
}

_POLICY_TUNABLES = {
    "default_scope_days": 14,
    "unknown_initial_scope_days": 30,
    "auto_expansion_max": 1,
    "score_margin_ratio_unknown": 0.15,
    "weak_window_min_score_ratio": 0.60,
    "weak_window_min_independent_axes": 2,
    "timeline_scan_limit": 1200,
    # P0 truncation hard gate: when the initial scan is truncated, window
    # discovery auto-expands up to max_pages × batch(400) events. Past that
    # budget the remaining count is recorded as a gap and strong
    # conclusions stay blocked.
    "timeline_scan_max_pages": 20,
    "timeline_scan_batch": 400,
    "top_window_count": 3,
    "top_bundle_count": 5,
}

_REMOTE_TOOL_TOKENS = (
    "bomgar",
    "beyondtrust",
    "teamviewer",
    "anydesk",
    "screenconnect",
    "connectwise",
    "splashtop",
    "rustdesk",
    "logmein",
    "netsupport",
    "aeroadmin",
    "ammyy",
    "ultraviewer",
    "dwservice",
    "meshcentral",
    "sshd",
    "vnc",
)

_EXECUTION_PATTERNS = (
    "prefetch",
    "userassist",
    "amcache",
    "powershell history",
    "script events",
    "process creation",
    "bam execution",          # raw BAM/DAM: user-SID execution evidence
)
_FILESYSTEM_PATTERNS = (
    "encrypted files",
    "text documents",
    "$logfile",
    "usnjrnl",
    "file signature mismatch",
    "ntfs timestamp mismatch",
)
_EVENT_PATTERNS = (
    "windows event logs",
    "event logs",
)
_NETWORK_PATTERNS = (
    "srum",
    "edge downloads",
    "internet explorer",
    "potential browser activity",
    "firewall",
    "browser",
    "rdp client destinations",   # outbound RDP pivot
)
_USER_PATTERNS = (
    "lnk files",
    "jump list",
    "recent",
    "windows search",
    "mark of the web",           # A-1: download origin (ingress)
    "zone.identifier",
    "office trusted documents",  # A-4: macro enable-content (ingress)
    "office recent documents",
    "usb devices",               # A-3: external media (ingress / exfil)
)
_PERSISTENCE_PATTERNS = (
    "system services",
    "scheduled tasks",
    "autorun",
    "startup items",
    "service events",
)

# Lane definitions follow docs/ANALYSIS_PLAYBOOK.md:
# - ingress / access
# - execution / impact
# - persistence / cleanup
_LANE_AXIS_MAP = {
    "ingress_access": ("network_session", "user_interaction"),
    "execution_impact": ("execution", "filesystem_impact"),
    "persistence_cleanup": ("persistence_identity",),
}

_LANE_FAMILY_MAP = {
    "ingress_access": ("browser", "srum"),
    "execution_impact": ("prefetch", "evtx"),
    "persistence_cleanup": ("evtx", "mft_logfile_usn"),
}



def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if len(text) == 10:
            return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if " " in text and "T" not in text:
            text = text.replace(" ", "T", 1)
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _fmt_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _meta(connector: Any) -> dict[str, Any]:
    try:
        return connector.get_metadata() or {}
    except Exception:
        return {}


def _artifact_counts(connector: Any) -> dict[str, int]:
    try:
        rows = connector.get_artifact_type_counts() or []
    except Exception:
        return {}
    counts: dict[str, int] = {}
    for row in rows:
        name = row.get("artifact_name") or row.get("artifact_type") or row.get("name")
        count = int(row.get("hit_count") or row.get("count") or 0)
        if name:
            counts[str(name)] = counts.get(str(name), 0) + count
    return counts


def _family_total(counts: dict[str, int], patterns: tuple[str, ...]) -> int:
    total = 0
    for name, count in counts.items():
        lowered = str(name).lower()
        if any(pattern in lowered for pattern in patterns):
            total += int(count or 0)
    return total


def _resolve_scope(
    connector: Any,
    *,
    scope_mode: str,
    start_date: str,
    end_date: str,
    suspected_date: str,
) -> dict[str, Any]:
    meta = _meta(connector)
    now_utc = datetime.now(timezone.utc)
    case_start = _parse_dt(meta.get("date_range_start"))
    case_end = _parse_dt(meta.get("date_range_end"))
    if case_end and case_end > now_utc + timedelta(days=365):
        case_end = now_utc
    if case_start is None and case_end is not None:
        case_start = case_end - timedelta(days=_POLICY_TUNABLES["unknown_initial_scope_days"] - 1)
    if case_end is None:
        case_end = now_utc
    if case_start is None:
        case_start = case_end - timedelta(days=_POLICY_TUNABLES["unknown_initial_scope_days"] - 1)

    source = "default"
    notes: list[str] = []
    effective_mode = scope_mode or "recent_14d"

    if start_date and end_date:
        start_dt = _parse_dt(start_date)
        end_dt = _parse_dt(end_date)
        effective_mode = "custom"
        source = "explicit"
    elif effective_mode == "suspected_date_pm_3d" and suspected_date:
        anchor = _parse_dt(suspected_date)
        start_dt = anchor - timedelta(days=3) if anchor else None
        end_dt = anchor + timedelta(days=3) if anchor else None
        source = "explicit" if anchor else "default"
        if anchor is None:
            notes.append("suspected_date could not be parsed; fell back to recent_14d.")
            effective_mode = "recent_14d"
    elif effective_mode == "full_range":
        start_dt = case_start
        end_dt = case_end
        source = "explicit"
    else:
        days = _POLICY_TUNABLES["default_scope_days"]
        start_dt = case_end - timedelta(days=days - 1)
        end_dt = case_end
        effective_mode = "recent_14d"

    if start_dt is None or end_dt is None:
        start_dt = case_end - timedelta(days=_POLICY_TUNABLES["default_scope_days"] - 1)
        end_dt = case_end
        effective_mode = "recent_14d"
        source = "default"

    if start_dt > end_dt:
        start_dt, end_dt = end_dt, start_dt
        notes.append("start_date was after end_date; values were swapped.")

    if case_start and start_dt < case_start:
        notes.append("Selected scope was clipped to the case start date.")
        start_dt = case_start
    if case_end and end_dt > case_end:
        notes.append("Selected scope was clipped to the case end date.")
        end_dt = case_end

    return {
        "mode": effective_mode,
        "source": source,
        "start_date": _fmt_date(start_dt),
        "end_date": _fmt_date(end_dt),
        "case_start_date": _fmt_date(case_start),
        "case_end_date": _fmt_date(case_end),
        "notes": notes,
    }


def _coverage_gate(
    connector: Any,
    *,
    case_start_date: str,
    case_end_date: str,
    counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    # D-2: reuse a pre-computed artifact-count map when the caller already
    # has one (initial_triage), so we don't re-query get_artifact_type_counts.
    counts = counts if counts is not None else _artifact_counts(connector)
    case_start = _parse_dt(case_start_date)
    case_end = _parse_dt(case_end_date)
    span_days = max((case_end - case_start).days, 0) if case_start and case_end else 0

    evtx_rows = _family_total(counts, ("windows event logs",))
    prefetch_rows = _family_total(counts, ("prefetch",))
    fs_rows = _family_total(counts, ("$logfile", "usnjrnl"))
    srum_rows = _family_total(counts, ("srum",))
    browser_rows = _family_total(counts, ("edge downloads", "history", "potential browser activity"))

    statuses: dict[str, str] = {}
    blocked: list[str] = []
    capped: list[dict[str, str]] = []

    if evtx_rows <= 0:
        statuses["evtx"] = "missing"
        blocked.append("evtx_density_gate")
        capped.append({"claim": "evtx_sequence_coverage", "cap": "moderate"})
    elif span_days >= 7 and evtx_rows < 100:
        statuses["evtx"] = "thin"
        capped.append({"claim": "evtx_sequence_coverage", "cap": "moderate"})
    else:
        statuses["evtx"] = "present"

    if prefetch_rows <= 0:
        statuses["prefetch"] = "missing"
        capped.append({"claim": "prefetch_execution_coverage", "cap": "moderate"})
    else:
        statuses["prefetch"] = "present"

    if fs_rows <= 0:
        statuses["mft_logfile_usn"] = "missing"
        blocked.extend([
            "mft_burst_gate",
            "high_volume_file_op_gate",
            "mass_file_modification_gate",
        ])
        capped.append({"claim": "mft_filesystem_coverage", "cap": "low"})
    else:
        statuses["mft_logfile_usn"] = "present"

    if srum_rows <= 0:
        statuses["srum"] = "missing"
        blocked.extend([
            "srum_network_coverage_gate",
            "srum_transfer_volume_gate",
        ])
        capped.append({"claim": "srum_network_coverage", "cap": "moderate"})
    else:
        statuses["srum"] = "present"

    if browser_rows <= 0:
        statuses["browser"] = "missing"
        blocked.append("user_agent_artifact_gate")
    else:
        statuses["browser"] = "present"

    core_missing = sum(
        1 for key in ("evtx", "prefetch", "mft_logfile_usn", "srum")
        if statuses.get(key) == "missing"
    )
    if core_missing >= 2:
        capped.append({"claim": "overall_case_confidence", "cap": "moderate"})

    return {
        "statuses": statuses,
        "blocked_claims": sorted(set(blocked)),
        "capped_confidence_claims": capped,
    }


def _sample_event(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "hit_id": entry.get("hit_id"),
        "timestamp": entry.get("timestamp"),
        "artifact_type": entry.get("artifact_type", ""),
        "description": str(entry.get("description", ""))[:160],
    }


def _entry_text(entry: dict[str, Any]) -> str:
    parts = [
        str(entry.get("artifact_type", "") or ""),
        str(entry.get("description", "") or ""),
    ]
    return " ".join(parts).lower()


def _extract_remote_tool_families(text: str) -> set[str]:
    return {token for token in _REMOTE_TOOL_TOKENS if token in text}


def _classify_entry(entry: dict[str, Any]) -> dict[str, Any]:
    artifact_type = str(entry.get("artifact_type", "") or "").lower()
    text = _entry_text(entry)
    axes: set[str] = set()
    signals: set[str] = set()
    families = _extract_remote_tool_families(text)

    if any(pattern in artifact_type for pattern in _EXECUTION_PATTERNS):
        axes.add("execution")
    if any(pattern in artifact_type for pattern in _FILESYSTEM_PATTERNS):
        axes.add("filesystem_impact")
    if any(pattern in artifact_type for pattern in _EVENT_PATTERNS):
        axes.add("event_log")
    if any(pattern in artifact_type for pattern in _NETWORK_PATTERNS):
        axes.add("network_session")
    if any(pattern in artifact_type for pattern in _USER_PATTERNS):
        axes.add("user_interaction")
    if any(pattern in artifact_type for pattern in _PERSISTENCE_PATTERNS):
        axes.add("persistence_identity")

    if families:
        signals.add("remote_admin_tool_exec")
        axes.update({"network_session", "execution"})
    if "4648" in text:
        signals.add("explicit_credential_reuse")
        axes.add("event_log")
    if "7045" in text:
        signals.add("remote_service_or_task_activity")
        axes.update({"event_log", "persistence_identity"})
    if "consent.exe" in text:
        signals.add("consent_exe_elevation")
        axes.add("user_interaction")
    if "edge downloads" in artifact_type or "browser" in artifact_type:
        axes.add("network_session")
    if "lnk files" in artifact_type or "jump list" in artifact_type:
        axes.add("user_interaction")

    return {
        "axes": axes,
        "signals": signals,
        "families": families,
    }


def _bucket_start(ts: datetime, bucket_minutes: int) -> datetime:
    total_minutes = ts.hour * 60 + ts.minute
    bucket_total = (total_minutes // bucket_minutes) * bucket_minutes
    return ts.replace(
        hour=bucket_total // 60,
        minute=bucket_total % 60,
        second=0,
        microsecond=0,
    )


def _collect_timeline_entries(
    connector: Any,
    *,
    start_date: str,
    end_date: str,
    max_events: int,
) -> dict[str, Any]:
    if not hasattr(connector, "get_timeline"):
        return {
            "entries": [],
            "scanned_entries": 0,
            "total_events": 0,
            "truncated": False,
            "notes": ["Connector does not expose get_timeline; window discovery is unavailable."],
        }

    batch = min(400, max(100, max_events))
    offset = 0
    total_events = None
    entries: list[dict[str, Any]] = []
    notes: list[str] = []

    while len(entries) < max_events:
        result = connector.get_timeline(
            start_date=start_date,
            end_date=end_date,
            limit=min(batch, max_events - len(entries)),
            offset=offset,
        )
        if total_events is None:
            total_events = int(result.get("total_events", 0) or 0)
            diagnostic = result.get("diagnostic")
            if diagnostic:
                notes.append(str(diagnostic))
        chunk = result.get("entries") or []
        if not chunk:
            break
        entries.extend(chunk)
        offset += len(chunk)
        if total_events is not None and offset >= total_events:
            break
        if len(chunk) < min(batch, max_events - len(entries)):
            break

    return {
        "entries": entries,
        "scanned_entries": len(entries),
        "total_events": int(total_events or len(entries)),
        "truncated": bool(total_events and total_events > len(entries)),
        "notes": notes,
    }


def _window_score(axis_counts: Counter[str], signals: set[str]) -> int:
    return sum(min(int(count or 0), 5) for count in axis_counts.values())


def _window_status(axis_counts: Counter[str], score: int) -> str:
    non_persistence_axes = [
        axis for axis, count in axis_counts.items()
        if count > 0 and axis != "persistence_identity"
    ]
    if axis_counts.get("filesystem_impact", 0) > 0 and len(non_persistence_axes) >= 2:
        return "multi_axis"
    if len(non_persistence_axes) >= 3:
        return "multi_axis"
    if len(non_persistence_axes) >= 2 or score >= 20:
        return "candidate"
    return "context-only"


def _build_windows(entries: list[dict[str, Any]], bucket_minutes: int) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for entry in entries:
        ts = _parse_dt(entry.get("timestamp"))
        if ts is None:
            continue
        bucket_dt = _bucket_start(ts, bucket_minutes)
        bucket_key = bucket_dt.isoformat()
        analysis = _classify_entry(entry)
        bucket = buckets.setdefault(bucket_key, {
            "_start_dt": bucket_dt,
            "_end_dt": bucket_dt + timedelta(minutes=bucket_minutes),
            "axis_counts": Counter(),
            "matched_signals": set(),
            "tool_families": set(),
            "sample_events": [],
            "entry_count": 0,
        })
        bucket["entry_count"] += 1
        for axis in analysis["axes"]:
            bucket["axis_counts"][axis] += 1
        bucket["matched_signals"].update(analysis["signals"])
        bucket["tool_families"].update(analysis["families"])
        if len(bucket["sample_events"]) < 5:
            bucket["sample_events"].append(_sample_event(entry))

    windows: list[dict[str, Any]] = []
    for bucket in buckets.values():
        score = _window_score(bucket["axis_counts"], bucket["matched_signals"])
        status = _window_status(bucket["axis_counts"], score)
        independent_axes = sum(1 for _, count in bucket["axis_counts"].items() if count > 0)
        windows.append({
            "bucket_minutes": bucket_minutes,
            "status": status,
            "score": score,
            "independent_axes": independent_axes,
            "axis_counts": dict(bucket["axis_counts"]),
            "matched_signals": sorted(bucket["matched_signals"]),
            "tool_families": sorted(bucket["tool_families"]),
            "entry_count": bucket["entry_count"],
            "start": _fmt_ts(bucket["_start_dt"]),
            "end": _fmt_ts(bucket["_end_dt"]),
            "_start_dt": bucket["_start_dt"],
            "_end_dt": bucket["_end_dt"],
            "sample_events": bucket["sample_events"],
        })
    return windows


def _overlaps(existing: dict[str, Any], candidate: dict[str, Any]) -> bool:
    latest_start = max(existing["_start_dt"], candidate["_start_dt"])
    earliest_end = min(existing["_end_dt"], candidate["_end_dt"])
    if latest_start >= earliest_end:
        return False
    overlap = (earliest_end - latest_start).total_seconds()
    shorter = min(
        (existing["_end_dt"] - existing["_start_dt"]).total_seconds(),
        (candidate["_end_dt"] - candidate["_start_dt"]).total_seconds(),
    )
    return overlap >= shorter / 2.0


def _select_top_windows(
    windows: list[dict[str, Any]],
    *,
    top_window_count: int,
) -> list[dict[str, Any]]:
    status_order = {"multi_axis": 0, "candidate": 1, "context-only": 2}
    ranked = sorted(
        windows,
        key=lambda item: (
            status_order.get(item.get("status", "context-only"), 9),
            -int(item.get("score", 0) or 0),
            -int(item.get("independent_axes", 0) or 0),
            item.get("start", ""),
            item.get("bucket_minutes", 0),
        ),
    )
    selected: list[dict[str, Any]] = []
    for candidate in ranked:
        if any(_overlaps(existing, candidate) for existing in selected):
            continue
        selected.append(candidate)
        if len(selected) >= top_window_count:
            break
    for item in selected:
        item.pop("_start_dt", None)
        item.pop("_end_dt", None)
    return selected


def _precursor_horizon_days() -> int:
    return _POLICY_TUNABLES["unknown_initial_scope_days"]


def _summarize_day_anchor(connector: Any, day: str) -> dict[str, Any]:
    anchor = date_anchor_triage(connector, start_date=day, end_date=day, limit_per_query=5)
    sections = []
    for section in anchor.get("sections", []):
        first_snippet = ""
        for query in section.get("queries", []):
            hits = query.get("hits") or []
            if hits:
                first_snippet = hits[0].get("snippet", "")
                break
        sections.append({
            "section_id": section.get("section_id"),
            "total_hits": int(section.get("total_hits", 0) or 0),
            "first_hit": first_snippet,
        })
    return {
        "day": day,
        "total_hits": sum(s["total_hits"] for s in sections),
        "sections": sections,
    }


def _compact_case_health(health: dict[str, Any]) -> dict[str, Any]:
    checks = health.get("checks") or []
    failed = [
        {
            "check_name": check.get("check_name"),
            "severity": check.get("severity"),
            "detail": check.get("detail"),
        }
        for check in checks
        if not check.get("passed", False)
    ]
    return {
        "overall_status": health.get("overall_status", "unknown"),
        "failed_checks": failed,
        "notes": list(health.get("notes", []) or []),
    }


def _baseline_summary(diff: dict[str, Any]) -> dict[str, Any]:
    categories: dict[str, Any] = {}
    for category, data in (diff.get("categories") or {}).items():
        categories[category] = {
            "net_new_count": int(data.get("net_new_count", 0) or 0),
            "sample": list((data.get("net_new") or [])[:10]),
        }
    return {
        "reference_source": diff.get("reference_source", ""),
        "total_net_new": int((diff.get("summary") or {}).get("total_net_new", 0) or 0),
        "categories": categories,
    }


def _build_precursor_context(
    connector: Any,
    *,
    selected_scope: dict[str, Any],
    top_windows: list[dict[str, Any]],
    include_baseline_diff: bool,
    reference_aq: Any | None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "baseline_diff_deferred": True,
        "status": "historical_context",
        "search_window": {},
        "bridge_tokens": [],
        "bridged_precursors": [],
        "notes": [
            "baseline_diff is delayed into precursor_context and is not incident proof.",
        ],
    }

    if not top_windows:
        if include_baseline_diff and hasattr(connector, "artifact_queries"):
            diff = run_baseline_diff(connector.artifact_queries, reference_aq=reference_aq)
            context["baseline_diff"] = _baseline_summary(diff)
            if context["baseline_diff"]["total_net_new"] > 0:
                context["status"] = "candidate_only"
                context["notes"].append(
                    "Static delta exists but no multi_axis window was established; keep root cause as candidate only."
                )
        return context

    earliest = min(_parse_dt(window.get("start")) for window in top_windows if _parse_dt(window.get("start")))
    horizon_days = _precursor_horizon_days()
    precursor_start = _parse_dt(selected_scope.get("case_start_date")) or earliest - timedelta(days=horizon_days)
    precursor_start = max(precursor_start, earliest - timedelta(days=horizon_days))
    precursor_end = earliest

    incident_tokens = {
        token
        for window in top_windows
        for token in (window.get("tool_families") or [])
    }

    precursor_timeline = _collect_timeline_entries(
        connector,
        start_date=_fmt_date(precursor_start),
        end_date=_fmt_date(precursor_end),
        max_events=min(600, _POLICY_TUNABLES["timeline_scan_limit"]),
    )
    precursor_tokens: set[str] = set()
    for entry in precursor_timeline.get("entries", []):
        precursor_tokens.update(_extract_remote_tool_families(_entry_text(entry)))

    bridge_tokens = sorted(incident_tokens & precursor_tokens)
    context["search_window"] = {
        "start_date": _fmt_date(precursor_start),
        "end_date": _fmt_date(precursor_end),
        "horizon_days": horizon_days,
    }
    context["bridge_tokens"] = bridge_tokens

    diff_summary = None
    if include_baseline_diff and hasattr(connector, "artifact_queries"):
        diff = run_baseline_diff(connector.artifact_queries, reference_aq=reference_aq)
        diff_summary = _baseline_summary(diff)
        context["baseline_diff"] = diff_summary

    bridged: list[dict[str, Any]] = []
    if diff_summary and bridge_tokens:
        for category, data in diff_summary["categories"].items():
            for value in data.get("sample", []):
                lowered = str(value).lower()
                matches = [token for token in bridge_tokens if token in lowered]
                if matches:
                    bridged.append({
                        "source": "baseline_diff",
                        "category": category,
                        "value": value,
                        "bridge_tokens": matches,
                    })

    strong_enough = (
        bool(top_windows)
        and top_windows[0].get("status") == "multi_axis"
        and int(top_windows[0].get("independent_axes", 0) or 0) >= 2
    )

    if bridged and strong_enough:
        context["status"] = "bridged_precursor"
        context["bridged_precursors"] = bridged[:10]
    elif bridged:
        context["status"] = "candidate_bridge"
        context["bridged_precursors"] = bridged[:10]
        context["notes"].append(
            "Bridge tokens matched baseline_diff samples, but top window is not multi_axis with multi-axis corroboration. Treat as candidate only."
        )
    elif bridge_tokens:
        context["status"] = "candidate_bridge"
        context["notes"].append(
            "Remote-tool identity recurred before and during the incident window, but no static-delta item matched the bridge token."
        )
    elif diff_summary and diff_summary["total_net_new"] > 0:
        context["status"] = "candidate_only"

    return context


def _anchoring_warnings(
    top_windows: list[dict[str, Any]],
    bundles: list[dict[str, Any]],
    precursor_context: dict[str, Any],
    timeline_scan: dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    if not top_windows and precursor_context.get("status") in {"candidate_only", "candidate_bridge"}:
        warnings.append(
            "Static delta exists without an multi_axis window. Treat precursor context as supporting evidence, not as the case verdict."
        )
    if bundles:
        top_bundle = bundles[0]
        if top_bundle.get("bundle_id") == "persistence_evidence":
            warnings.append(
                "Persistence evidence ranks highly in the current case. Review execution and impact windows before locking onto a persistence-only hypothesis."
            )
    if timeline_scan.get("truncated"):
        warnings.append(
            "Window discovery used a capped timeline sample. Ranking is relative and may miss weaker windows outside the sampled set."
        )
    return warnings


def _basis_window(top_windows: list[dict[str, Any]]) -> dict[str, Any]:
    if top_windows:
        return top_windows[0]

    return {
        "axis_counts": {},
        "matched_signals": [],
        "tool_families": [],
        "entry_count": 0,
        "independent_axes": 0,
        "status": "not_seen",
    }


def _build_lane_evidence_summary(
    top_windows: list[dict[str, Any]],
    coverage_gate: dict[str, Any],
) -> dict[str, Any]:
    """Return per-lane artifact factual summary — counts and families seen, no verdict labels."""
    statuses = coverage_gate.get("statuses", {}) or {}
    summary: dict[str, Any] = {}
    for lane, axes in _LANE_AXIS_MAP.items():
        event_count = 0
        for window in top_windows:
            axis_counts = window.get("axis_counts") or {}
            event_count += sum(int(axis_counts.get(axis, 0) or 0) for axis in axes)
        families_seen = [
            family
            for family in _LANE_FAMILY_MAP[lane]
            if statuses.get(family) in {"present", "thin"}
        ]
        if lane == "ingress_access" and any(w.get("tool_families") for w in top_windows):
            families_seen.append("remote_tool_family")
        summary[lane] = {
            "artifact_families_seen": families_seen,
            "event_count": event_count,
        }
    return summary


def _build_lane_state_board(
    top_windows: list[dict[str, Any]],
    coverage_gate: dict[str, Any],
) -> dict[str, Any]:
    """Return conservative per-lane state and strong-conclusion gate.

    This is deliberately derived from window axes and coverage only. It does
    not classify the incident family; it only says whether the three playbook
    lanes have enough corroboration to support a strong end-to-end conclusion.
    """
    statuses = coverage_gate.get("statuses", {}) or {}
    blocked_claims = set(coverage_gate.get("blocked_claims", []) or [])
    capped_claims = {
        str(item.get("claim", ""))
        for item in coverage_gate.get("capped_confidence_claims", []) or []
        if isinstance(item, dict)
    }
    blocked_by_lane = {
        "ingress_access": {"srum_network_coverage_gate"},
        "execution_impact": {"mass_file_modification_gate"},
        "persistence_cleanup": set(),
    }

    board: dict[str, Any] = {}
    for lane, axes in _LANE_AXIS_MAP.items():
        axis_total = 0
        matched: list[str] = []
        for window in top_windows:
            axis_counts = window.get("axis_counts") or {}
            for axis in axes:
                count = int(axis_counts.get(axis, 0) or 0)
                axis_total += count
                if count and axis not in matched:
                    matched.append(axis)

        families = [
            family
            for family in _LANE_FAMILY_MAP[lane]
            if statuses.get(family) in {"present", "thin"}
        ]
        if lane == "ingress_access" and any(w.get("tool_families") for w in top_windows):
            families.append("remote_tool_family")

        lane_blocked = bool(blocked_claims & blocked_by_lane.get(lane, set()))
        if axis_total >= 2 and not lane_blocked:
            state = "confirmed"
        elif axis_total >= 1:
            state = "suggested"
        elif families:
            state = "unverified"
        else:
            state = "not_seen"

        basis = []
        if matched:
            basis.append("matched axes: " + ", ".join(matched[:4]))
        if families:
            basis.append("available families: " + ", ".join(families[:4]))
        if lane_blocked:
            basis.append("coverage gate blocks one or more claims for this lane")

        entry = {
            "state": state,
            "basis": basis,
            "axis_event_count": axis_total,
            "artifact_families_seen": families,
        }
        if state in {"unverified", "not_seen"}:
            # C-6: share a stable id with investigation_gap / negative_evidence
            # for the same (lane, state) coverage gap.
            from core.analysis.investigation_gap import make_gap_id
            entry["gap_id"] = make_gap_id("lane", lane, state)
        board[lane] = entry

    blocked_lanes = [
        lane for lane in _LANE_AXIS_MAP
        if board[lane]["state"] in {"unverified", "not_seen"}
    ]
    board["blocked_lanes"] = blocked_lanes
    board["allow_strong_conclusion"] = (
        not blocked_lanes
        and all(board[lane]["state"] in {"confirmed", "suggested"} for lane in _LANE_AXIS_MAP)
        and "overall_case_confidence" not in capped_claims
    )
    if "overall_case_confidence" in capped_claims:
        board.setdefault("notes", []).append(
            "Coverage capped overall case confidence; keep conclusions qualified."
        )
    return board


def initial_triage(
    connector: Any,
    *,
    scope_mode: str = "recent_14d",
    start_date: str = "",
    end_date: str = "",
    suspected_date: str = "",
    top_window_count: int = 3,
    timeline_scan_limit: int = _POLICY_TUNABLES["timeline_scan_limit"],
    include_baseline_diff: bool = True,
    reference_aq: Any | None = None,
) -> dict[str, Any]:
    """Run a window-first initial triage pass against the active connector."""
    selected_scope = _resolve_scope(
        connector,
        scope_mode=scope_mode,
        start_date=start_date,
        end_date=end_date,
        suspected_date=suspected_date,
    )

    health = build_case_health({"axiom:active": connector})
    # D-2: compute artifact counts once and share them with the coverage gate
    # instead of re-querying get_artifact_type_counts inside _coverage_gate.
    artifact_counts = _artifact_counts(connector)
    coverage_gate = _coverage_gate(
        connector,
        case_start_date=selected_scope["case_start_date"],
        case_end_date=selected_scope["case_end_date"],
        counts=artifact_counts,
    )

    bundles = build_artifact_bundles(connector).get("artifact_bundles", [])[:_POLICY_TUNABLES["top_bundle_count"]]
    initial_budget = max(200, min(timeline_scan_limit, 4000))
    timeline_scan = _collect_timeline_entries(
        connector,
        start_date=selected_scope["start_date"],
        end_date=selected_scope["end_date"],
        max_events=initial_budget,
    )

    # P0 truncation hard gate — auto-expand the scan instead of silently
    # discovering windows over a noise-only prefix of the timeline.
    scan_hard_cap = (
        _POLICY_TUNABLES["timeline_scan_max_pages"]
        * _POLICY_TUNABLES["timeline_scan_batch"]
    )
    auto_expanded = False
    if timeline_scan.get("truncated") and scan_hard_cap > initial_budget:
        auto_expanded = True
        timeline_scan = _collect_timeline_entries(
            connector,
            start_date=selected_scope["start_date"],
            end_date=selected_scope["end_date"],
            max_events=scan_hard_cap,
        )
        timeline_scan.setdefault("notes", []).append(
            f"Window discovery auto-expanded beyond the initial "
            f"{initial_budget}-event budget because the scope holds more "
            f"events; scanned {timeline_scan.get('scanned_entries', 0)} of "
            f"{timeline_scan.get('total_events', 0)}."
        )
    remaining_unscanned = max(
        0,
        int(timeline_scan.get("total_events", 0) or 0)
        - int(timeline_scan.get("scanned_entries", 0) or 0),
    )

    windows: list[dict[str, Any]] = []
    for bucket_minutes in (5, 30, 120):
        windows.extend(_build_windows(timeline_scan.get("entries", []), bucket_minutes))

    top_windows = _select_top_windows(
        windows,
        top_window_count=max(1, min(top_window_count, 5)),
    )

    lane_evidence_summary = _build_lane_evidence_summary(top_windows, coverage_gate)
    lane_state_board = _build_lane_state_board(top_windows, coverage_gate)
    if remaining_unscanned > 0:
        # Truncated past the page budget: evidence may sit in the unscanned
        # tail, so strong conclusions stay blocked (pagination_required).
        lane_state_board["allow_strong_conclusion"] = False
        lane_state_board["pagination_required"] = True
        lane_state_board.setdefault("notes", []).append(
            f"Timeline scan truncated at the {scan_hard_cap}-event page "
            f"budget with {remaining_unscanned} events unscanned; strong "
            "conclusions are blocked until the remaining range is reviewed "
            "(slice_timeline / narrower date scope)."
        )
    precursor_context = _build_precursor_context(
        connector,
        selected_scope=selected_scope,
        top_windows=top_windows,
        include_baseline_diff=include_baseline_diff,
        reference_aq=reference_aq,
    )

    anchor_days = []
    seen_days: set[str] = set()
    for window in top_windows[:2]:
        day = str(window.get("start", ""))[:10]
        if len(day) == 10 and day not in seen_days:
            anchor_days.append(_summarize_day_anchor(connector, day))
            seen_days.add(day)

    warnings = _anchoring_warnings(top_windows, bundles, precursor_context, timeline_scan)

    notes = [
        "Window discovery runs before baseline diff so static delta cannot monopolize the first view of the case.",
        "Classification is heuristic and intentionally conservative. Unknown is preferred over forced incident typing.",
        "Numeric policy values are analyst defaults, not empirically calibrated thresholds.",
    ]
    notes.extend(selected_scope.get("notes", []))
    notes.extend(timeline_scan.get("notes", []))

    return {
        "ok": True,
        "tool": "initial_triage_pack",
        "applicability": dict(_APPLICABILITY),
        "policy_mode": "heuristic",
        "selected_scope": selected_scope,
        "case_health": _compact_case_health(health),
        "coverage_gate": coverage_gate,
        "artifact_bundles": bundles,
        "window_discovery": {
            "bucket_sizes_minutes": [5, 30, 120],
            "scanned_entries": timeline_scan.get("scanned_entries", 0),
            "total_events_in_scope": timeline_scan.get("total_events", 0),
            "sample_truncated": bool(timeline_scan.get("truncated", False)),
            "auto_expanded": auto_expanded,
            "scan_budget": scan_hard_cap,
            "remaining_unscanned": remaining_unscanned,
            "top_windows": top_windows,
        },
        "lane_evidence_summary": lane_evidence_summary,
        "lane_state_board": lane_state_board,
        "anchor_days": anchor_days,
        "precursor_context": precursor_context,
        "anchoring_warnings": warnings,
        "analyst_tunable_params_used": {
            "scope_mode": selected_scope.get("mode"),
            "timeline_scan_limit": max(200, min(timeline_scan_limit, 4000)),
            "top_window_count": max(1, min(top_window_count, 5)),
            "policy_defaults": dict(_POLICY_TUNABLES),
        },
        "notes": notes,
    }
