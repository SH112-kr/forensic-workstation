"""Compose an entity-centric story from timeline, correlation, graph and findings.

T2 in the Codex roadmap. This is deliberately a composition layer:
it does not invent new detections or confidence scores. Instead it
assembles a deterministic narrative scaffold an analyst can read or
drop into a report draft.

Output shape (stable for callers):
  {
    "ok": True,
    "entity": {"value": str, "seed_keywords": [str, ...]},
    "match_semantics": {"mode": str, "entity": str, "seed_keywords": str},
    "sampling_scope": {"timeline": str, "windows": str, "graph": str},
    "period": {"start": str, "end": str},
    "summary": {"event_count": int, "co_occurrence_windows": int},
    "phases": [{"kind": str, "title": str, "derived_from": [...], ...}],
    "timeline_excerpt": [{"timestamp": str, "hit_id": int|None, ...}],
    "nearby_entities": [{"node_id": str, "type": str, "label": str, ...}],
    "supporting_findings": [{"rule_name": str, "severity": str, ...}],
    "truncation_warnings": [str, ...],
    "notes": [str, ...],
  }
"""

from __future__ import annotations

from typing import Any

from core.analysis.correlator import correlate_keywords, extract_hit_events, search_keyword_hits


_TIMELINE_EXCERPT_CAP = 25
_BURST_CAP = 10
_NEARBY_ENTITY_CAP = 15
_FINDING_CAP = 10


def _as_list(value: list[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _normalize_seed_keywords(entity_value: str, seed_keywords: list[str] | str | None) -> list[str]:
    seeds: list[str] = []
    seen: set[str] = set()
    for raw in [entity_value] + _as_list(seed_keywords):
        s = str(raw).strip()
        if not s or s in seen:
            continue
        seeds.append(s)
        seen.add(s)
    return seeds


def _pointer(period: str, event: dict[str, Any]) -> dict[str, Any]:
    return {
        "period": period,
        "hit_id": event.get("hit_id"),
        "timestamp": event.get("timestamp", ""),
        "keyword": event.get("keyword", ""),
    }


def _event_excerpt(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    excerpt = []
    for ev in events[:_TIMELINE_EXCERPT_CAP]:
        excerpt.append({
            "timestamp": ev.get("timestamp", ""),
            "hit_id": ev.get("hit_id"),
            "artifact_type": ev.get("artifact_type", ""),
            "time_field": ev.get("time_field", ""),
            "keyword": ev.get("keyword", ""),
        })
    return excerpt


def _story_phases(
    entity_value: str,
    period_label: str,
    entity_events: list[dict[str, Any]],
    co_occurrence_windows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not entity_events:
        return [{
            "kind": "no_activity",
            "title": f"No timestamped activity observed for '{entity_value}' in {period_label}.",
            "derived_from": [],
        }]

    phases: list[dict[str, Any]] = []
    first_event = entity_events[0]
    phases.append({
        "kind": "first_seen",
        "title": f"First observed '{entity_value}' activity.",
        "timestamp": first_event["timestamp"],
        "derived_from": [_pointer(period_label, first_event)],
    })

    if len(entity_events) >= 2:
        gaps = []
        for prev, cur in zip(entity_events, entity_events[1:]):
            gap_seconds = (cur["timestamp_ms"] - prev["timestamp_ms"]) / 1000.0
            gaps.append((gap_seconds, prev, cur))
        longest_gap, gap_start, gap_end = max(gaps, key=lambda item: item[0])
        if longest_gap > 0:
            phases.append({
                "kind": "dormant_period",
                "title": f"Longest quiet period for '{entity_value}' before later activity resumed.",
                "gap_seconds": longest_gap,
                "gap_days": round(longest_gap / 86400.0, 2),
                "derived_from": [_pointer(period_label, gap_start), _pointer(period_label, gap_end)],
            })
            phases.append({
                "kind": "reactivation",
                "title": f"'{entity_value}' activity resumed after the longest quiet period.",
                "timestamp": gap_end["timestamp"],
                "derived_from": [_pointer(period_label, gap_end)],
            })

    if co_occurrence_windows:
        top_windows = sorted(
            co_occurrence_windows,
            key=lambda w: (-int(w.get("event_count", 0)), w.get("start", "")),
        )[:_BURST_CAP]
        phases.append({
            "kind": "repeat_bursts",
            "title": f"Repeated co-occurrence bursts involving '{entity_value}'.",
            "window_count": len(co_occurrence_windows),
            "bursts": [
                {
                    "timestamp": w.get("start", ""),
                    "keywords_present": w.get("keywords_present", []),
                    "event_count": w.get("event_count", 0),
                }
                for w in top_windows
            ],
            "derived_from": [
                {"period": period_label, "hit_id": None, "timestamp": w.get("start", ""), "keyword": ",".join(w.get("keywords_present", []))}
                for w in top_windows
            ],
        })

    return phases


def _match_story_nodes(graph: dict[str, Any], entity_keyword: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (matching_nodes, nearby_neighbor_nodes) for the entity keyword."""
    needle = entity_keyword.lower()
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []
    by_id = {n["id"]: n for n in nodes if isinstance(n, dict) and n.get("id")}

    matching: list[dict[str, Any]] = []
    for node in nodes:
        normalized = str(node.get("normalized_value", "")).lower()
        raws = " ".join(str(c.get("raw", "")) for c in node.get("collapsed_from", []) if isinstance(c, dict)).lower()
        if needle in normalized or needle in raws:
            matching.append(node)

    neighbor_ids: set[str] = set()
    entity_ids = {n["id"] for n in matching}
    for edge in edges:
        src = edge.get("source")
        dst = edge.get("target")
        if src in entity_ids and dst in by_id:
            neighbor_ids.add(dst)
        if dst in entity_ids and src in by_id:
            neighbor_ids.add(src)
    neighbor_ids -= entity_ids

    nearby = [by_id[nid] for nid in sorted(neighbor_ids)]
    return matching, nearby[:_NEARBY_ENTITY_CAP]


def _filter_findings(entity_keyword: str, findings_payload: dict[str, Any], entity_hit_ids: set[int]) -> list[dict[str, Any]]:
    needle = entity_keyword.lower()
    matches: list[dict[str, Any]] = []
    for finding in findings_payload.get("findings", []) or []:
        text_parts = [
            str(finding.get("rule_name", "")),
            str(finding.get("query_description", "") or finding.get("description", "")),
        ]
        detail_hit_ids: set[int] = set()
        for detail in finding.get("details", []) or []:
            if not isinstance(detail, dict):
                continue
            detail_hit_id = detail.get("hit_id")
            if isinstance(detail_hit_id, int):
                detail_hit_ids.add(detail_hit_id)
            text_parts.append(" ".join(str(v) for v in detail.values()))
        for art in finding.get("supporting_artifacts", []) or []:
            if not isinstance(art, dict):
                continue
            art_hit_id = art.get("hit_id")
            if isinstance(art_hit_id, int):
                detail_hit_ids.add(art_hit_id)
            text_parts.append(" ".join(str(v) for v in art.values()))

        blob = " ".join(text_parts).lower()
        if needle not in blob and not (entity_hit_ids & detail_hit_ids):
            continue
        matches.append({
            "rule_name": finding.get("rule_name") or finding.get("rule_id", ""),
            "query_description": finding.get("query_description", ""),
            "matching_count": finding.get("matching_count", 0),
        })
    matches.sort(key=lambda x: (-int(x.get("matching_count") or 0), x.get("rule_name", "")))
    return matches[:_FINDING_CAP]


def entity_story(
    axiom: Any,
    entity_value: str,
    start_date: str = "",
    end_date: str = "",
    seed_keywords: list[str] | str | None = None,
    window_minutes: int = 60,
    limit_per_keyword: int = 200,
    findings_payload: dict[str, Any] | None = None,
    match_key: str = "raw",
    graph_limit_per_node_type: int = 200,
    match_mode: str = "substring",
) -> dict[str, Any]:
    """Build an entity-centric story scaffold over one analysis period."""
    from core.analysis.entity_graph import build_entity_graph
    from core.analysis.suspicious import find_suspicious

    seeds = _normalize_seed_keywords(entity_value, seed_keywords)
    if not seeds:
        return {
            "ok": False,
            "error": "entity_value is empty after normalization",
            "entity": {"value": entity_value, "seed_keywords": []},
        }

    entity_keyword = seeds[0]
    search_result = search_keyword_hits(
        axiom,
        keyword=entity_keyword,
        start_date=start_date,
        end_date=end_date,
        limit=limit_per_keyword,
        offset=0,
        match_mode=match_mode,
    )
    entity_hits = search_result.get("hits", []) or []
    entity_events = extract_hit_events(
        entity_hits,
        entity_keyword,
        axiom,
        start_date=start_date,
        end_date=end_date,
    )
    entity_hit_ids = {int(h["hit_id"]) for h in entity_hits if isinstance(h.get("hit_id"), int)}

    corr = correlate_keywords(
        axiom,
        seeds,
        start_date=start_date,
        end_date=end_date,
        window_minutes=window_minutes,
        limit=limit_per_keyword,
        match_mode=match_mode,
    )
    windows = [
        w for w in (corr.get("co_occurrence_windows", []) or [])
        if entity_keyword in (w.get("keywords_present", []) or [])
    ]

    graph_notes: list[str] = []
    nearby_entities: list[dict[str, Any]] = []
    try:
        graph = build_entity_graph(
            axiom_cases=[("active", axiom)],
            match_key=match_key,
            limit_per_node_type=graph_limit_per_node_type,
        )
        if graph.get("ok"):
            _, nearby = _match_story_nodes(graph, entity_keyword)
            nearby_entities = [
                {
                    "node_id": n.get("id", ""),
                    "type": n.get("type", ""),
                    "label": n.get("label", ""),
                    "normalized_value": n.get("normalized_value", ""),
                    "sample_hit_ids": n.get("sample_hit_ids", []),
                }
                for n in nearby
            ]
            if graph.get("warnings"):
                graph_notes.extend(graph.get("warnings", [])[:5])
        else:
            graph_notes.append(graph.get("error", "entity graph unavailable"))
    except Exception as exc:
        graph_notes.append(f"entity graph unavailable: {exc}")

    findings = findings_payload
    if findings is None:
        try:
            aq = getattr(axiom, "artifact_queries", None)
            findings = find_suspicious(aq, rules="") if aq is not None else {"findings": []}
        except Exception as exc:
            findings = {"findings": []}
            graph_notes.append(f"supporting findings unavailable: {exc}")
    supporting_findings = _filter_findings(entity_keyword, findings or {"findings": []}, entity_hit_ids)

    phases = _story_phases(
        entity_value=entity_value,
        period_label="analysis_period",
        entity_events=entity_events,
        co_occurrence_windows=windows,
    )

    truncation_warnings: list[str] = []
    if search_result.get("total", len(entity_hits)) > len(entity_hits):
        truncation_warnings.append(
            f"entity keyword '{entity_keyword}' returned {len(entity_hits)} of "
            f"{search_result.get('total')} hits; story phases are based on the returned sample."
        )
    for kw, entry in (corr.get("per_keyword", {}) or {}).items():
        if entry.get("truncated"):
            truncation_warnings.append(
                f"keyword '{kw}' returned {entry.get('returned_hits')} of {entry.get('total_hits')} hits; "
                "co-occurrence windows and nearby context reflect only the returned sample."
            )

    return {
        "ok": True,
        "entity": {"value": entity_value, "seed_keywords": seeds},
        "match_semantics": {
            "mode": str(match_mode or "substring").strip().lower() or "substring",
            "entity": "substring keyword presence across string fragments"
            if str(match_mode or "substring").strip().lower() != "exact"
            else "exact-like whole-value or basename/stem equality over returned string fragments",
            "seed_keywords": "same mode as entity_value; correlation still uses generic search terms unless constrained upstream",
        },
        "sampling_scope": {
            "timeline": "timeline_excerpt and phases reflect returned entity hits within limit_per_keyword",
            "windows": "co_occurrence_windows reflect returned hits within limit_per_keyword",
            "graph": "nearby_entities reflect graph expansion under match_key and graph_limit_per_node_type",
        },
        "period": {"start": start_date, "end": end_date},
        "summary": {
            "event_count": len(entity_events),
            "co_occurrence_windows": len(windows),
            "entity_hit_count": int(search_result.get("total", len(entity_hits))),
        },
        "phases": phases,
        "timeline_excerpt": _event_excerpt(entity_events),
        "nearby_entities": nearby_entities,
        "supporting_findings": supporting_findings,
        "truncation_warnings": truncation_warnings,
        "notes": [
            "Composition tool — story structure is assembled from existing keyword search, correlation, entity-graph and suspicious-finding outputs.",
            "Phase labels describe observed chronology only. They are not anomaly verdicts or attribution.",
            *graph_notes,
        ],
    }
