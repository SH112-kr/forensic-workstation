from __future__ import annotations


def test_normalized_artifacts_preserve_source_and_temporal_layer():
    from regression.fixtures import load
    from core.analysis.normalized_artifacts import (
        NORMALIZED_ARTIFACT_SCHEMA_VERSION,
        normalize_connector_artifacts,
    )

    connector = load("case_ransomware_inc_like")
    result = normalize_connector_artifacts(
        connector,
        source_id="fixture:ransomware",
        temporal_layer="e01_live",
        limit=10,
    )

    assert result["schema_version"] == NORMALIZED_ARTIFACT_SCHEMA_VERSION
    assert result["record_count"] == 10
    record = result["records"][0]
    assert record["source_id"] == "fixture:ransomware"
    assert record["temporal_layer"] == "e01_live"
    assert record["source_chain"][0]["parser"] == "regression_fixture_adapter"
    assert record["parser_status"]["status"] == "ok"


def test_temporal_layer_summary_keeps_vss_layers_separate():
    from core.analysis.normalized_artifacts import summarize_temporal_layers

    records = [
        {"temporal_layer": "vss_2026-04-01", "artifact_type": "Prefetch", "timestamp": "2026-04-01T00:00:00Z"},
        {"temporal_layer": "vss_2026-04-01", "artifact_type": "EVTX", "timestamp": "2026-04-01T01:00:00Z"},
        {"temporal_layer": "e01_live", "artifact_type": "Prefetch", "timestamp": "2026-04-12T00:00:00Z"},
    ]

    summary = summarize_temporal_layers(records)

    assert summary["policy"] == "vss_and_e01_are_temporal_layers_not_context_free_merges"
    assert summary["layer_count"] == 2
    layers = {layer["temporal_layer"]: layer for layer in summary["layers"]}
    assert layers["vss_2026-04-01"]["count"] == 2
    assert layers["e01_live"]["artifact_types"]["Prefetch"] == 1
