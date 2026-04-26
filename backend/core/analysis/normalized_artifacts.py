"""Source-attributed normalized artifact records.

This is the in-memory contract used before a persistent store such as SQLite
or DuckDB is introduced. It keeps provenance and temporal layer as first-class
fields so MFDB/KAPE/E01/VSS records never get merged into context-free facts.
"""

from __future__ import annotations

from typing import Any


NORMALIZED_ARTIFACT_SCHEMA_VERSION = "fw.normalized_artifact.v1"


def normalize_connector_artifacts(
    connector: Any,
    *,
    source_id: str = "active",
    temporal_layer: str = "live",
    limit: int = 1000,
) -> dict[str, Any]:
    """Normalize timeline/search rows into source-attributed records."""
    meta = _safe_metadata(connector)
    rows = _rows(connector, limit=limit)
    source_type = str(meta.get("source_type") or "unknown").lower()
    parser_id = _parser_id(source_type)

    records = []
    for idx, row in enumerate(rows):
        hit_id = row.get("hit_id")
        artifact_id = f"{source_id}:{temporal_layer}:{hit_id if hit_id is not None else idx}"
        records.append({
            "schema_version": NORMALIZED_ARTIFACT_SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "source_id": source_id,
            "temporal_layer": temporal_layer,
            "artifact_type": row.get("artifact_type", ""),
            "timestamp": row.get("timestamp", ""),
            "message": row.get("description", ""),
            "value": _value_projection(row),
            "source_chain": [{
                "adapter": source_type or "unknown",
                "parser": parser_id,
                "source_path": meta.get("source_path", ""),
                "hit_id": hit_id,
            }],
            "parser_status": {
                "status": "ok",
                "error": "",
            },
            "conflict_flags": [],
        })

    return {
        "ok": True,
        "schema_version": NORMALIZED_ARTIFACT_SCHEMA_VERSION,
        "source_id": source_id,
        "temporal_layer": temporal_layer,
        "record_count": len(records),
        "records": records,
        "notes": [
            "source_chain is preserved so normalized records do not lose adapter/parser provenance.",
            "temporal_layer separates live, E01 image state, and VSS snapshots while preserving a common schema.",
        ],
    }


def summarize_temporal_layers(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Return counts and first/last timestamps per temporal layer."""
    layers: dict[str, dict[str, Any]] = {}
    for record in records:
        layer = str(record.get("temporal_layer") or "unknown")
        entry = layers.setdefault(layer, {
            "temporal_layer": layer,
            "count": 0,
            "artifact_types": {},
            "first_timestamp": "",
            "last_timestamp": "",
        })
        entry["count"] += 1
        art = str(record.get("artifact_type") or "unknown")
        entry["artifact_types"][art] = entry["artifact_types"].get(art, 0) + 1
        ts = str(record.get("timestamp") or "")
        if ts:
            if not entry["first_timestamp"] or ts < entry["first_timestamp"]:
                entry["first_timestamp"] = ts
            if not entry["last_timestamp"] or ts > entry["last_timestamp"]:
                entry["last_timestamp"] = ts
    return {
        "ok": True,
        "layer_count": len(layers),
        "layers": sorted(layers.values(), key=lambda x: x["temporal_layer"]),
        "policy": "vss_and_e01_are_temporal_layers_not_context_free_merges",
    }


def _safe_metadata(connector: Any) -> dict[str, Any]:
    try:
        return connector.get_metadata() or {}
    except Exception:
        return {}


def _rows(connector: Any, *, limit: int) -> list[dict[str, Any]]:
    try:
        timeline = connector.get_timeline(limit=limit) or {}
        entries = list(timeline.get("entries", []) or [])
        if entries:
            return entries
    except Exception:
        pass
    try:
        search = connector.search(keyword="", filters={}, limit=limit) or {}
        return list(search.get("hits", []) or [])
    except Exception:
        return []


def _parser_id(source_type: str) -> str:
    if "mfdb" in source_type or "axiom" in source_type:
        return "axiom_mfdb_adapter"
    if "kape" in source_type:
        return "kape_csv_adapter"
    if "e01" in source_type or "ex01" in source_type:
        return "e01_derived_adapter"
    if "fixture" in source_type:
        return "regression_fixture_adapter"
    return "unknown_adapter"


def _value_projection(row: dict[str, Any]) -> dict[str, Any]:
    fields = row.get("fields")
    if isinstance(fields, dict):
        return dict(fields)
    projected = {}
    for key in ("source_path", "description", "time_field"):
        if row.get(key):
            projected[key] = row.get(key)
    return projected
