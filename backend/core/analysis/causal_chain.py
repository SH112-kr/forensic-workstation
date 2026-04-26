"""Lightweight causal-chain candidate builder.

This is not a full graph engine. It emits auditable candidate edges from a
timeline so downstream analysis can distinguish temporal proximity from real
causation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_causal_chain_candidates(connector: Any, *, limit: int = 500) -> dict[str, Any]:
    entries = _timeline_entries(connector, limit=limit)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    normalized = []
    for entry in entries:
        ts = _parse_ts(entry.get("timestamp", ""))
        kind = _classify_entry(entry)
        node_id = f"event:{entry.get('hit_id', len(normalized))}"
        nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "timestamp": entry.get("timestamp", ""),
            "artifact_type": entry.get("artifact_type", ""),
            "description": entry.get("description", ""),
            "hit_id": entry.get("hit_id"),
        }
        normalized.append((node_id, ts, kind, entry))

    normalized.sort(key=lambda x: x[1] or datetime.min.replace(tzinfo=timezone.utc))
    for idx, (src_id, src_ts, src_kind, src) in enumerate(normalized):
        if src_ts is None:
            continue
        for tgt_id, tgt_ts, tgt_kind, tgt in normalized[idx + 1: idx + 15]:
            if tgt_ts is None:
                continue
            delta = (tgt_ts - src_ts).total_seconds()
            if delta < 0 or delta > 1800:
                continue
            edge_type = _candidate_edge(src_kind, tgt_kind)
            if not edge_type:
                continue
            edges.append({
                "source": src_id,
                "target": tgt_id,
                "edge_type": edge_type,
                "correlation_type": "temporal_proximity",
                "causal_strength": "candidate",
                "time_delta_seconds": int(delta),
                "warning": "Temporal proximity is not proof of causation.",
            })

    return {
        "causal_chain": {
            "nodes": list(nodes.values()),
            "edges": edges[:200],
            "edge_count": min(len(edges), 200),
            "truncated": len(edges) > 200,
            "policy": "causal_candidates_not_causal_claims_v1",
            "notes": [
                "Edges are candidates only unless another artifact directly confirms parent/child or write/execute.",
                "Each edge records correlation_type so the UI/LLM cannot silently treat correlation as causation.",
            ],
        }
    }


def _timeline_entries(connector: Any, *, limit: int) -> list[dict[str, Any]]:
    try:
        timeline = connector.get_timeline(limit=limit) or {}
        return list(timeline.get("entries", []) or [])
    except Exception:
        return []


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or "").replace("Z", "+00:00")
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _classify_entry(entry: dict[str, Any]) -> str:
    blob = " ".join(str(v) for v in entry.values()).lower()
    if "4624" in blob or "logon" in blob or "remote" in blob:
        return "access"
    if "prefetch" in blob or "4688" in blob or "process" in blob or ".exe" in blob:
        return "execution"
    if "service" in blob or "scheduled task" in blob or "run key" in blob:
        return "persistence"
    if "encrypted" in blob or "ransom" in blob or "signature mismatch" in blob:
        return "impact"
    if "1102" in blob or "cleared" in blob or "vss" in blob or "usn" in blob:
        return "cleanup"
    return "context"


def _candidate_edge(src_kind: str, tgt_kind: str) -> str:
    allowed = {
        ("access", "execution"): "access_before_execution",
        ("execution", "persistence"): "execution_before_persistence",
        ("execution", "impact"): "execution_before_impact",
        ("persistence", "execution"): "persistence_before_execution",
        ("impact", "cleanup"): "impact_before_cleanup",
        ("execution", "cleanup"): "execution_before_cleanup",
    }
    return allowed.get((src_kind, tgt_kind), "")
