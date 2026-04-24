"""Auto-extract deterministic seed entities and cluster their co-occurrence.

T3 in the Codex roadmap. This module does not invent new detection logic:
it composes existing findings + baseline diff outputs into a seed catalog,
then runs shared correlation over the extracted seeds.
"""

from __future__ import annotations

import re
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from core.analysis.correlator import correlate_keywords


_EXECUTABLE_EXTS = {".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".js", ".hta", ".msi"}
_WINDOW_SAMPLE_CAP = 5
_SEED_CAP = 12
_DERIVED_FROM_CAP = 8
_EVENT_ID_RE = re.compile(r"\bEID\s+(\d+)\b", re.I)


def _basename_token(value: Any) -> str:
    text = str(value or "").strip().strip("\"'")
    if not text:
        return ""
    tail = text.replace("/", "\\").rsplit("\\", 1)[-1].strip().strip("\"'")
    return tail.lower()


def _candidate_basename(value: Any) -> str:
    token = _basename_token(value)
    if not token:
        return ""
    ext = os.path.splitext(token)[1].lower()
    if ext not in _EXECUTABLE_EXTS:
        return ""
    return token


def _parse_bound(value: str, *, is_end: bool) -> datetime | None:
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


def _timestamp_in_period(value: Any, start_date: str, end_date: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    try:
        current = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        try:
            current = datetime.fromisoformat(text.split(" UTC", 1)[0])
        except Exception:
            return True
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    start = _parse_bound(start_date, is_end=False)
    end = _parse_bound(end_date, is_end=True)
    if start is not None and current < start:
        return False
    if end is not None and current > end:
        return False
    return True


def _is_user_writable_path(value: Any) -> bool:
    lowered = str(value or "").replace("/", "\\").lower()
    return any(part in lowered for part in ("\\programdata\\", "\\users\\", "\\appdata\\", "\\temp\\", "\\public\\"))


def _event_seed_from_detail(detail: dict[str, Any]) -> str:
    artifact = str(detail.get("artifact_type", ""))
    match = _EVENT_ID_RE.search(artifact)
    if match:
        return f"event_id:{match.group(1)}"
    event_id = detail.get("Event ID") or detail.get("event_id")
    if isinstance(event_id, int):
        return f"event_id:{event_id}"
    if isinstance(event_id, str) and event_id.isdigit():
        return f"event_id:{event_id}"
    return ""


def _add_seed(
    catalog: dict[str, dict[str, Any]],
    token: str,
    *,
    source: str,
    source_kind: str,
    rationale: str,
    derived_from: dict[str, Any],
) -> None:
    seed = str(token or "").strip().lower()
    if not seed:
        return
    entry = catalog.setdefault(seed, {
        "token": seed,
        "seed_kind": "event_id" if seed.startswith("event_id:") else "keyword",
        "sources": [],
        "source_kinds": [],
        "rationales": [],
        "derived_from": [],
        "score": 0,
    })
    if source not in entry["sources"]:
        entry["sources"].append(source)
    if source_kind not in entry["source_kinds"]:
        entry["source_kinds"].append(source_kind)
    if rationale not in entry["rationales"]:
        entry["rationales"].append(rationale)
    if len(entry["derived_from"]) < _DERIVED_FROM_CAP:
        entry["derived_from"].append(derived_from)
    entry["score"] += 3 if source_kind == "finding_event_id" else 2 if source_kind.startswith("finding_") else 1


def _extract_from_findings(findings_payload: dict[str, Any], start_date: str = "", end_date: str = "") -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for finding in findings_payload.get("findings", []) or []:
        rule_name = str(finding.get("rule_name") or finding.get("rule_id") or "")
        for pattern_name in (finding.get("matched_patterns", {}) or {}).keys():
            match = re.search(r"Event ID\s+(\d+)", str(pattern_name), re.I)
            if not match:
                continue
            _add_seed(
                catalog,
                f"event_id:{match.group(1)}",
                source=rule_name or "finding",
                source_kind="finding_event_id",
                rationale="event id extracted from finding matched_patterns",
                derived_from={
                    "source": "find_suspicious",
                    "rule_name": rule_name,
                    "pattern": pattern_name,
                },
            )
        for detail in finding.get("details", []) or []:
            if not isinstance(detail, dict):
                continue
            if not _timestamp_in_period(detail.get("timestamp", ""), start_date, end_date):
                continue
            base_ptr = {
                "source": "find_suspicious",
                "rule_name": rule_name,
                "hit_id": detail.get("hit_id"),
                "artifact_type": detail.get("artifact_type", ""),
                "timestamp": detail.get("timestamp", ""),
            }
            event_seed = _event_seed_from_detail(detail)
            if event_seed:
                _add_seed(
                    catalog,
                    event_seed,
                    source=rule_name or "finding",
                    source_kind="finding_event_id",
                    rationale="event id extracted from structured finding detail",
                    derived_from=base_ptr,
                )
            for field in ("ImagePath", "ProcessName", "Full Path", "Path", "File Name"):
                raw_value = detail.get(field)
                if not _is_user_writable_path(raw_value):
                    continue
                token = _candidate_basename(detail.get(field))
                if token:
                    _add_seed(
                        catalog,
                        token,
                        source=rule_name or "finding",
                        source_kind="finding_path_basename",
                        rationale=f"basename extracted from finding field '{field}'",
                        derived_from={**base_ptr, "field": field, "value": raw_value or ""},
                    )
    return catalog


def _extract_from_baseline_diff(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    cats = payload.get("categories", {}) or {}
    for category in ("services", "startup_items"):
        entry = cats.get(category, {}) or {}
        for raw in entry.get("net_new", []) or []:
            token = _candidate_basename(raw)
            if not token:
                continue
            if os.path.splitext(token)[1].lower() == ".sys":
                continue
            _add_seed(
                catalog,
                token,
                source="baseline_diff",
                source_kind=f"baseline_{category}_basename",
                rationale=f"net-new {category[:-1] if category.endswith('s') else category} basename from baseline diff",
                derived_from={
                    "source": "baseline_diff",
                    "category": category,
                    "value": raw,
                },
            )
    return catalog


def _merge_catalogs(*catalogs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for catalog in catalogs:
        for token, entry in catalog.items():
            target = merged.setdefault(token, {
                "token": token,
                "seed_kind": entry.get("seed_kind", "keyword"),
                "sources": [],
                "source_kinds": [],
                "rationales": [],
                "derived_from": [],
                "score": 0,
            })
            for key in ("sources", "source_kinds", "rationales"):
                for item in entry.get(key, []):
                    if item not in target[key]:
                        target[key].append(item)
            for ptr in entry.get("derived_from", []):
                if len(target["derived_from"]) >= _DERIVED_FROM_CAP:
                    break
                if ptr not in target["derived_from"]:
                    target["derived_from"].append(ptr)
            target["score"] += int(entry.get("score", 0))
    ranked = sorted(
        merged.values(),
        key=lambda x: (-int(x.get("score", 0)), x.get("token", "")),
    )
    return ranked


def _bucket_seed(entry: dict[str, Any]) -> tuple[str, str]:
    kinds = set(entry.get("source_kinds", []))
    if "finding_event_id" in kinds:
        return "priority", "structured finding event id"
    if any(k.startswith("finding_") for k in kinds):
        return "priority", "finding-derived user-writable basename"
    if len(kinds) >= 2 and any(not k.startswith("baseline_") for k in kinds):
        return "priority", "supported by multiple deterministic sources"
    return "context", "baseline-only or low-specificity support"


def _context_bucket_seed(entry: dict[str, Any], entity_token: str | None) -> tuple[str, str]:
    token = str(entry.get("token", ""))
    if entity_token and token == entity_token:
        sources = {str(source) for source in entry.get("sources", []) if str(source)}
        if sources <= {"baseline_diff"}:
            return "baseline_common", "baseline-only token declined entity-adjacent promotion"
        return "entity_adjacent", "primary entity basename surfaced with non-baseline source"
    if any(k.startswith("baseline_") for k in entry.get("source_kinds", [])):
        return "baseline_common", "baseline-only context with no direct finding support"
    return "other_context", "non-priority context retained for model visibility"


def _cluster_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, ...], dict[str, Any]] = {}
    for window in windows:
        keywords = tuple(sorted(window.get("keywords_present", []) or []))
        if len(keywords) < 2:
            continue
        entry = buckets.setdefault(keywords, {
            "keywords_present": list(keywords),
            "occurrence_count": 0,
            "max_event_count": 0,
            "sample_starts": [],
        })
        entry["occurrence_count"] += 1
        entry["max_event_count"] = max(entry["max_event_count"], int(window.get("event_count", 0)))
        if len(entry["sample_starts"]) < _WINDOW_SAMPLE_CAP:
            entry["sample_starts"].append(window.get("start", ""))
    ranked = sorted(
        buckets.values(),
        key=lambda x: (-int(x["occurrence_count"]), -int(x["max_event_count"]), x["keywords_present"]),
    )
    return ranked


def _recommended_entity_token(
    selected: list[dict[str, Any]],
    entity_adjacent_context: list[dict[str, Any]],
) -> str:
    recommended = _recommended_entity_tokens(selected, entity_adjacent_context, limit=1)
    return recommended[0] if recommended else ""


def _recommended_entity_tokens(
    selected: list[dict[str, Any]],
    entity_adjacent_context: list[dict[str, Any]],
    *,
    limit: int = 3,
) -> list[str]:
    """Return a short, diverse set of entity candidates.

    We prefer non-event seeds backed by different rule sources so one dominant
    rule does not collapse the analyst into a single hypothesis too early.
    """
    ordered: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    for entry in entity_adjacent_context + selected:
        token = str(entry.get("token", ""))
        if not token or token.startswith("event_id:") or token in seen_tokens:
            continue
        ordered.append(entry)
        seen_tokens.add(token)

    picks: list[str] = []
    used_sources: set[str] = set()
    for entry in ordered:
        token = str(entry.get("token", ""))
        sources = {
            str(src) for src in entry.get("sources", [])
            if str(src) and str(src) != "baseline_diff"
        }
        if picks and sources and sources.issubset(used_sources):
            continue
        picks.append(token)
        used_sources.update(sources)
        if len(picks) >= limit:
            return picks

    for entry in ordered:
        token = str(entry.get("token", ""))
        if token in picks:
            continue
        picks.append(token)
        if len(picks) >= limit:
            break
    return picks


def auto_seed_entities(
    axiom: Any,
    start_date: str = "",
    end_date: str = "",
    findings_payload: dict[str, Any] | None = None,
    baseline_payload: dict[str, Any] | None = None,
    window_minutes: int = 60,
    limit_per_seed: int = 200,
    max_seeds: int = _SEED_CAP,
    match_mode: str = "exact",
) -> dict[str, Any]:
    """Build a deterministic seed catalog, then cluster their co-occurrence."""
    from core.analysis.baseline_diff import baseline_diff
    from core.analysis.suspicious import find_suspicious

    notes: list[str] = [
        "Seeds are deterministic compositions over existing findings and baseline diff outputs.",
        "event_id:<n> seeds use structured Windows Event Log queries; basename seeds come from executable/script-like values only.",
        "Built-in baseline is noisy; baseline-derived seeds are intentionally restricted to executable/script basenames.",
    ]

    if findings_payload is None:
        aq = getattr(axiom, "artifact_queries", None)
        findings_payload = find_suspicious(aq, rules="") if aq is not None else {"findings": []}
    if baseline_payload is None:
        aq = getattr(axiom, "artifact_queries", None)
        baseline_payload = baseline_diff(aq) if aq is not None else {"categories": {}}

    findings_catalog = _extract_from_findings(findings_payload or {"findings": []}, start_date=start_date, end_date=end_date)
    baseline_catalog = _extract_from_baseline_diff(baseline_payload or {"categories": {}})
    merged = _merge_catalogs(findings_catalog, baseline_catalog)
    selected = merged[:max(1, max_seeds)]
    seed_tokens = [entry["token"] for entry in selected]

    corr = correlate_keywords(
        axiom,
        seed_tokens,
        start_date=start_date,
        end_date=end_date,
        window_minutes=window_minutes,
        limit=limit_per_seed,
        match_mode=match_mode,
    ) if seed_tokens else {
        "per_keyword": {},
        "co_occurrence_windows": [],
        "truncated": False,
    }

    clusters = _cluster_windows(corr.get("co_occurrence_windows", []) or [])
    for idx, entry in enumerate(selected, start=1):
        entry["rank"] = idx
        bucket, reason = _bucket_seed(entry)
        entry["bucket"] = bucket
        entry["bucket_reason"] = reason

    entity_token = ""
    findings_entity_candidates = [x["token"] for x in selected if not x["token"].startswith("event_id:")]
    if findings_entity_candidates:
        entity_token = findings_entity_candidates[0]

    truncation_warnings: list[str] = []
    for token, data in (corr.get("per_keyword", {}) or {}).items():
        if data.get("truncated"):
            truncation_warnings.append(
                f"seed '{token}' returned {data.get('returned_hits')} of {data.get('total_hits')} hits; "
                "clusters reflect the returned sample."
            )

    priority_seed_catalog = [x for x in selected if x.get("bucket") == "priority"]
    context_seed_catalog = [x for x in selected if x.get("bucket") == "context"]
    entity_adjacent_context: list[dict[str, Any]] = []
    baseline_common_context: list[dict[str, Any]] = []
    other_context_catalog: list[dict[str, Any]] = []
    for entry in context_seed_catalog:
        context_bucket, context_reason = _context_bucket_seed(entry, entity_token or None)
        entry["context_bucket"] = context_bucket
        entry["context_bucket_reason"] = context_reason
        if context_bucket == "entity_adjacent":
            entity_adjacent_context.append(entry)
        elif context_bucket == "baseline_common":
            baseline_common_context.append(entry)
        else:
            other_context_catalog.append(entry)

    recommended_entities = _recommended_entity_tokens(selected, entity_adjacent_context)
    recommended_entity = recommended_entities[0] if recommended_entities else ""
    recommended_priority_seed_keywords = [str(x.get("token", "")) for x in priority_seed_catalog if str(x.get("token", ""))]

    source_counts: dict[str, int] = {}
    for entry in selected:
        for src in entry.get("sources", []):
            source_counts[str(src)] = source_counts.get(str(src), 0) + 1
    recommendation_warnings: list[str] = []
    meaningful_sources = {k: v for k, v in source_counts.items() if k and k != "baseline_diff"}
    if meaningful_sources:
        top_src, top_count = sorted(meaningful_sources.items(), key=lambda x: (-x[1], x[0]))[0]
        if top_count / max(len(selected), 1) >= 0.5 and len(meaningful_sources) > 1:
            recommendation_warnings.append(
                f"Seed selection is dominated by source '{top_src}' ({top_count}/{len(selected)} selected seeds). "
                "Review alternate recommended_entities before focusing on one tool or path."
            )

    return {
        "ok": True,
        "period": {"start": start_date, "end": end_date},
        "match_semantics": {
            "mode": match_mode,
            "seed_kinds": {
                "event_id": "structured Windows Event Log event id seed",
                "keyword": "exact-like basename or keyword seed under the selected match mode",
            },
        },
        "seed_catalog": selected,
        "priority_seed_catalog": priority_seed_catalog,
        "context_seed_catalog": context_seed_catalog,
        "entity_adjacent_context": entity_adjacent_context,
        "baseline_common_context": baseline_common_context,
        "other_context_catalog": other_context_catalog,
        "recommended": {
            "entity_value": recommended_entity,
            "recommended_entities": recommended_entities,
            "priority_seed_keywords": recommended_priority_seed_keywords,
            "priority_seed_keywords_csv": ",".join(recommended_priority_seed_keywords),
        },
        "co_occurrence_clusters": clusters[:20],
        "summary": {
            "selected_seed_count": len(selected),
            "available_seed_count": len(merged),
            "cluster_count": len(clusters),
            "priority_seed_count": len(priority_seed_catalog),
            "context_seed_count": len(context_seed_catalog),
            "entity_adjacent_context_count": len(entity_adjacent_context),
            "baseline_common_context_count": len(baseline_common_context),
            "other_context_count": len(other_context_catalog),
        },
        "recommendation_warnings": recommendation_warnings,
        "truncation_warnings": truncation_warnings,
        "notes": notes,
    }
