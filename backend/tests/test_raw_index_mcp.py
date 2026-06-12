from __future__ import annotations

import asyncio
import json
import os

import mcp_bridge


def _run(coro):
    return asyncio.run(coro)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


def _seed_raw_connector(db_path):
    from core.connectors.raw_image_index import RawImageIndexConnector
    from core.raw_index.store import RawIndexStore

    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="unit",
        source_path="/c:/Tools/agent.exe",
        primary_path="/c:/Tools/agent.exe",
        description="File System Entry /c:/Tools/agent.exe",
        strings={"Name": "agent.exe", "Path": "/c:/Tools/agent.exe"},
        times={"Modified": (1791072000000, "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()
    connector = RawImageIndexConnector()
    connector.connect(str(db_path))
    return connector


def _seed_multi_keyword_raw_connector(db_path):
    from core.connectors.raw_image_index import RawImageIndexConnector
    from core.raw_index.store import RawIndexStore

    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha-one.exe", "alpha-two.exe", "beta-one.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="unit",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()
    connector = RawImageIndexConnector()
    connector.connect(str(db_path))
    return connector


def _seed_multi_timed_raw_connector(db_path):
    from core.connectors.raw_image_index import RawImageIndexConnector
    from core.raw_index.store import RawIndexStore

    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    for index, name in enumerate(("alpha-one.exe", "alpha-two.exe", "alpha-three.exe")):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="unit",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            times={
                "Modified": (
                    1791072000000 + index,
                    f"2026-10-04T00:00:00.00{index}Z",
                )
            },
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()
    connector = RawImageIndexConnector()
    connector.connect(str(db_path))
    return connector


def _seed_failed_raw_connector(db_path):
    from core.connectors.raw_image_index import RawImageIndexConnector
    from core.raw_index.store import RawIndexStore

    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    store.finish_parser_run(
        run_id,
        status="failed",
        coverage_status="not_evaluable",
        finished_at="2026-06-04T00:00:01Z",
        error="simulated parser failure",
    )
    store.close()
    connector = RawImageIndexConnector()
    connector.connect(str(db_path))
    return connector


def test_open_raw_index_sets_raw_connector(monkeypatch, tmp_path):
    from core.raw_index.store import RawIndexStore

    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    store.close()

    captured = {}

    class _State:
        def set(self, name, connector):
            captured[name] = connector

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", _State())

    result = _run(mcp_bridge.open_raw_index(str(db_path)))

    assert result["source_type"] == "raw_image_sidecar"
    assert "raw_index" in captured


def test_open_raw_index_reports_stale_sidecar_as_not_evaluable(monkeypatch, tmp_path):
    from core.raw_index.store import RawIndexStore

    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    store._conn().execute(
        "UPDATE raw_index_metadata SET value = ? WHERE key = ?",
        ("999", "schema_version"),
    )
    store._conn().commit()
    store.close()
    state = _State()

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)

    result = _run(mcp_bridge.open_raw_index(str(db_path)))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "stale_raw_index_sidecar"
    assert "raw_index" not in state.captured


def test_open_raw_index_reports_missing_sidecar_as_not_evaluable(monkeypatch, tmp_path):
    db_path = tmp_path / "missing-raw-index.sqlite"
    state = _State()

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)

    result = _run(mcp_bridge.open_raw_index(str(db_path)))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "missing_raw_index_sidecar"
    assert "raw_index" not in state.captured


def test_get_summary_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_summary())

    assert result["ok"] is True
    assert result["summary_scope"] == "raw_image_sidecar"
    assert result["parsed_case_loaded"] is False
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage"]["status"] == "searched"
    assert result["schema_version"]


def test_get_summary_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_summary())

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["summary_scope"] == "raw_image_sidecar"
    assert result["coverage"]["status"] == "not_evaluable"
    assert result["coverage"]["gaps"][0]["error"] == "simulated parser failure"


def test_coverage_explainer_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.coverage_explainer("File System Entry"))

    assert result["ok"] is True
    assert result["source_type"] == "raw_image_sidecar"
    assert result["case_context"]["case_format"] == "raw_image_sidecar"
    assert result["coverage"][0]["artifact_type"] == "File System Entry"
    assert result["coverage"][0]["status"] == "searched"
    assert result["coverage"][0]["record_count"] == 1
    assert result["coverage"][0]["cases"] == ["raw_index"]
    assert result["raw_index_coverage"]["status"] == "searched"


def test_coverage_explainer_reports_raw_unsupported_family_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.coverage_explainer("Prefetch"))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage"][0]["artifact_type"] == "Prefetch"
    assert result["coverage"][0]["status"] == "not_evaluable"
    assert result["coverage"][0]["reason"] == "raw_artifact_family_not_indexed"
    assert result["summary"]["not_evaluable"] == 1


def test_coverage_explainer_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.coverage_explainer())

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_explain_zero_results_uses_active_raw_index_coverage(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.explain_zero_results(
        "search_artifacts",
        '{"artifact_type": "Prefetch", "keyword": "prefetch"}',
    ))

    causes = [cause["cause"] for cause in result["likely_causes"]]
    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["case_context"]["case_format"] == "raw_image_sidecar"
    assert "raw_artifact_family_not_indexed" in causes
    assert "no_cases_loaded" not in causes
    assert result["coverage"][0]["artifact_type"] == "Prefetch"
    assert result["coverage"][0]["status"] == "not_evaluable"
    assert any(
        suggestion["tool_name"] == "coverage_explainer"
        and suggestion["params"] == {"artifact_types": "Prefetch"}
        for suggestion in result["suggested_queries"]
    )


def test_explain_zero_results_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.explain_zero_results(
        "search_artifacts",
        '{"keyword": "agent.exe"}',
    ))

    causes = [cause["cause"] for cause in result["likely_causes"]]
    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert "raw_index_not_evaluable" in causes
    assert "no_cases_loaded" not in causes
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_compare_cases_includes_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.compare_cases())

    assert result["ok"] is True
    assert result["case_count"] == 1
    assert result["metadata"][0]["case_id"] == "raw_index"
    assert result["metadata"][0]["source_type"] == "raw_image_sidecar"
    assert result["artifact_counts"]["matrix"]["File System Entry"] == {
        "raw_index": 1,
    }
    assert result["artifact_counts"]["results"][0]["case_id"] == "raw_index"


def test_compare_cases_preserves_raw_index_not_evaluable_counts(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.compare_cases())

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["case_count"] == 1
    assert result["artifact_counts"]["results"][0]["ok"] is False
    assert result["artifact_counts"]["results"][0]["coverage"]["status"] == (
        "not_evaluable"
    )
    assert result["artifact_counts"]["results"][0]["coverage"]["gaps"][0][
        "error"
    ] == "simulated parser failure"


def test_pivot_across_cases_includes_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.pivot_across_cases(
        entity_type="keyword",
        entity_value="agent.exe",
        limit_per_case=10,
    ))

    assert result["ok"] is True
    assert result["case_count"] == 1
    assert result["per_case_counts"] == {"raw_index": 1}
    assert result["total"] == 1
    assert result["hits"][0]["case_id"] == "raw_index"
    assert result["hits"][0]["source_type"] == "raw_image_sidecar"


def test_pivot_across_cases_preserves_raw_index_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.pivot_across_cases(
        entity_type="keyword",
        entity_value="agent.exe",
        limit_per_case=10,
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["case_count"] == 1
    assert result["per_case"][0]["case_id"] == "raw_index"
    assert result["per_case"][0]["coverage"]["status"] == "not_evaluable"
    assert result["per_case"][0]["coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_search_artifacts_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="agent.exe",
        artifact_type="File System Entry",
        limit=10,
    ))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"
    assert result["search_strategy"]["revalidated"] is True


def test_search_artifacts_uses_raw_index_date_filters(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="agent.exe",
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    ))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["date_filter"] == "artifact_times"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_artifacts_uses_raw_index_exact_keyword_union(monkeypatch, tmp_path):
    raw = _seed_multi_keyword_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keywords="alpha,beta",
        artifact_type="File System Entry",
        limit=1,
    ))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total"] == 3
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["returned"] == 1
    assert result["truncated"] is True
    assert result["search_strategy"]["keyword_mode"] == "or"
    assert result["search_strategy"]["index"] in {
        "materialized_like_or",
        "fts5_trigram_or",
    }


def test_search_artifacts_all_cases_includes_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="agent.exe",
        artifact_type="File System Entry",
        limit=10,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["per_case_totals"] == {"raw_index": 1}
    assert result["returned"] == 1
    assert result["hits"][0]["case_id"] == "raw_index"
    assert result["hits"][0]["source_type"] == "raw_image_sidecar"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_artifacts_all_cases_fetches_enough_for_offset(monkeypatch, tmp_path):
    raw = _seed_multi_keyword_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="alpha",
        artifact_type="File System Entry",
        limit=1,
        offset=1,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["returned"] == 1
    assert result["hits"][0]["fields"]["Name"] == "alpha-two.exe"


def test_search_artifacts_all_cases_preserves_exact_raw_total(monkeypatch, tmp_path):
    raw = _seed_multi_keyword_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="alpha",
        artifact_type="File System Entry",
        limit=1,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["per_case_totals"] == {"raw_index": 2}
    assert result["merged_total"] == 2
    assert result["returned"] == 1


def test_search_artifacts_all_cases_applies_raw_keyword_union(monkeypatch, tmp_path):
    raw = _seed_multi_keyword_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keywords="alpha,beta",
        artifact_type="File System Entry",
        limit=10,
        all_cases=True,
    ))

    names = {hit["fields"]["Name"] for hit in result["hits"]}
    assert result["case_count"] == 1
    assert result["query"]["keywords"] == ["alpha", "beta"]
    assert result["per_case_totals"] == {"raw_index": 3}
    assert result["merged_total"] == 3
    assert names == {"alpha-one.exe", "alpha-two.exe", "beta-one.exe"}


def test_search_artifacts_all_cases_preserves_raw_not_evaluable(monkeypatch, tmp_path):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_artifacts(
        keyword="agent.exe",
        artifact_type="File System Entry",
        limit=10,
        all_cases=True,
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["case_count"] == 1
    assert result["merged_total"] == 0
    assert result["hits"] == []
    assert result["per_case"][0]["ok"] is False
    assert result["per_case"][0]["coverage"]["status"] == "not_evaluable"
    assert result["per_case"][0]["coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_get_artifact_types_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_artifact_types())

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total_types"] == 1
    assert result["artifact_types"][0]["artifact_name"] == "File System Entry"
    assert result["artifact_types"][0]["count_accuracy"] == "exact"


def test_get_artifact_types_preserves_raw_index_not_evaluable_coverage(monkeypatch, tmp_path):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_artifact_types())

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["total_types"] == 0
    assert result["coverage"]["status"] == "not_evaluable"
    assert result["coverage"]["gaps"][0]["error"] == "simulated parser failure"


def test_build_timeline_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=10,
    ))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total_events"] == 1
    assert result["total_is_estimated"] is False
    assert result["entries"][0]["artifact_type"] == "File System Entry"


def test_build_timeline_uses_raw_index_keyword_filter(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        keywords="agent.exe",
        limit=10,
    ))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total_events"] == 1
    assert result["total_is_estimated"] is False
    assert result["timeline_strategy"]["keyword_filter"] == "search_text"
    assert result["entries"][0]["artifact_type"] == "File System Entry"


def test_build_timeline_all_cases_includes_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=10,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["merged_total"] == 1
    assert result["returned"] == 1
    assert result["entries"][0]["case_id"] == "raw_index"
    assert result["entries"][0]["source_type"] == "raw_image_sidecar"
    assert result["entries"][0]["artifact_type"] == "File System Entry"


def test_build_timeline_all_cases_fetches_enough_for_offset(monkeypatch, tmp_path):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=1,
        offset=1,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["returned"] == 1
    assert result["entries"][0]["description"].endswith("alpha-two.exe")


def test_build_timeline_all_cases_preserves_exact_raw_total(monkeypatch, tmp_path):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=1,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["per_case_totals"] == {"raw_index": 3}
    assert result["merged_total"] == 3
    assert result["returned"] == 1


def test_build_timeline_all_cases_applies_raw_index_keyword_filter(
    monkeypatch,
    tmp_path,
):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        keywords="alpha-two.exe",
        limit=10,
        all_cases=True,
    ))

    assert result["case_count"] == 1
    assert result["merged_total"] == 1
    assert result["returned"] == 1
    assert result["query"]["keywords"] == ["alpha-two.exe"]
    assert result["entries"][0]["case_id"] == "raw_index"
    assert result["entries"][0]["description"].endswith("alpha-two.exe")


def test_build_timeline_all_cases_preserves_raw_not_evaluable(monkeypatch, tmp_path):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=10,
        all_cases=True,
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["case_count"] == 1
    assert result["merged_total"] == 0
    assert result["entries"] == []
    assert result["per_case"][0]["ok"] is False
    assert result["per_case"][0]["coverage"]["status"] == "not_evaluable"
    assert result["per_case"][0]["coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_date_anchor_triage_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.date_anchor_triage(
        start_date="2026-10-04",
        end_date="2026-10-04",
        limit_per_query=5,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["period"] == {"start": "2026-10-04", "end": "2026-10-04"}
    assert result["sections"] == []
    assert result["coverage_gap"]["reason"] == (
        "raw_date_anchor_triage_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"


def test_date_anchor_triage_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.date_anchor_triage())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == (
        "raw_date_anchor_triage_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["sections"] == []


def test_slice_timeline_preserves_raw_index_not_evaluable_coverage(monkeypatch, tmp_path):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.slice_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        path="agent.exe",
        limit=10,
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage"]["status"] == "not_evaluable"
    assert result["coverage"]["gaps"][0]["error"] == "simulated parser failure"
    assert result["entries"] == []


def test_slice_timeline_all_cases_includes_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.slice_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        path="agent.exe",
        limit=10,
        all_cases=True,
    ))

    assert result["ok"] is True
    assert result["per_case"][0]["case_id"] == "raw_index"
    assert result["entries"][0]["case_id"] == "raw_index"
    assert result["entries"][0]["source_type"] == "raw_image_sidecar"
    assert result["entries"][0]["artifact_type"] == "File System Entry"
    assert result["returned"] == 1


def test_slice_timeline_all_cases_preserves_raw_index_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.slice_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        path="agent.exe",
        limit=10,
        all_cases=True,
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["per_case"][0]["case_id"] == "raw_index"
    assert result["per_case"][0]["coverage"]["status"] == "not_evaluable"
    assert result["per_case"][0]["coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["entries"] == []


def test_get_hit_detail_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_hit_detail(1))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_by_hash_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.search_by_hash("deadbeef", limit=10, offset=2))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["query"] == {"hash": "deadbeef"}
    assert result["total"] == 0
    assert result["returned"] == 0
    assert result["offset"] == 2
    assert result["limit"] == 10
    assert result["hits"] == []
    assert result["coverage_gap"]["reason"] == "raw_hash_search_unsupported"


async def _catching_passthrough(_tool_name, _params, fn, timeout_seconds=0):
    try:
        return fn()
    except Exception as exc:
        return {"error": str(exc)}


def test_extract_iocs_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.extract_iocs(
        ioc_types="ip,domain",
        exclude_private_ips=True,
        exclude_known_good=True,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_ioc_extraction_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["iocs"] == []


def test_extract_iocs_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.extract_iocs())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_ioc_extraction_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_build_entity_graph_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_entity_graph(
        entity_types="file,process",
        edge_types="executed",
        all_cases=False,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_entity_graph_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["nodes"] == []
    assert result["edges"] == []


def test_build_entity_graph_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.build_entity_graph())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_entity_graph_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["nodes"] == []
    assert result["edges"] == []


def test_baseline_diff_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.baseline_diff(categories="services,users"))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["categories"] == ["services", "users"]
    assert result["coverage_gap"]["reason"] == "raw_baseline_diff_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_baseline_diff_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.baseline_diff())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_baseline_diff_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_find_suspicious_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.find_suspicious(
        rules="evtx_eid_7045_service_installs",
        score_strength=True,
        include_provenance=True,
        apply_suppressions=True,
        include_rule_coverage=True,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["rules_requested"] == ["evtx_eid_7045_service_installs"]
    assert result["rules_executed"] == 0
    assert result["findings"] == []
    assert result["zero_result_rules"] == []
    assert result["coverage_gap"]["reason"] == "raw_find_suspicious_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_find_suspicious_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.find_suspicious())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_find_suspicious_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["unevaluable_rules"][0]["reason"] == (
        "raw_find_suspicious_unsupported"
    )


def test_map_to_mitre_maps_custom_findings_without_axiom_in_raw_only(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)
    custom = json.dumps([
        {
            "technique_id": "T1572",
            "rule_name": "ssh_tunnel",
            "severity": "critical",
            "description": "Synthetic tunnel finding",
            "matching_count": 1,
        }
    ])

    result = _run(mcp_bridge.map_to_mitre(custom_findings=custom))

    assert result.get("ok") is True
    assert result["status"] == "partial"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["auto_findings_evaluated"] is False
    assert result["custom_findings_mapped"] == 1
    assert result["coverage_gap"]["reason"] == (
        "raw_mitre_auto_detection_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["attack_phases"] == 1
    assert result["narrative"][0]["techniques"][0]["id"] == "T1572"


def test_map_to_mitre_reports_raw_auto_detection_unsupported_without_custom(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.map_to_mitre())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["auto_findings_evaluated"] is False
    assert result["custom_findings_mapped"] == 0
    assert result["attack_phases"] == 0
    assert result["narrative"] == []
    assert result["summary"] == {}
    assert result["coverage_gap"]["reason"] == (
        "raw_mitre_auto_detection_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_get_tagged_hits_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_tagged_hits(tag_name="interesting"))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["tag_name"] == "interesting"
    assert result["total_tagged"] == 0
    assert result["returned"] == 0
    assert result["truncated"] is False
    assert result["hits"] == []
    assert result["coverage_gap"]["reason"] == "raw_tagged_hits_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_get_tagged_hits_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_tagged_hits())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_tagged_hits_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["hits"] == []


def test_generate_report_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    report_path = tmp_path / "report.html"
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.generate_report(output_path=str(report_path)))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["output_path"] == str(report_path)
    assert result["coverage_gap"]["reason"] == "raw_report_generation_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert not report_path.exists()


def test_generate_report_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    report_path = tmp_path / "report.html"
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.generate_report(output_path=str(report_path)))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_report_generation_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert not report_path.exists()


def test_srum_by_process_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.srum_by_process(
        process_name="agent.exe",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
        offset=2,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["processes"] == ["agent.exe"]
    assert result["results"] == {}
    assert result["coverage_gap"]["reason"] == "raw_srum_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_srum_by_process_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.srum_by_process(process_names="agent.exe,helper.exe"))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["processes"] == ["agent.exe", "helper.exe"]
    assert result["coverage_gap"]["reason"] == "raw_srum_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["results"] == {}


def test_compare_case_image_entity_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.compare_case_image_entity(
        entity_value="agent.exe",
        start_date="2026-10-01",
        end_date="2026-10-31",
        image_path_hints=r"C:\Tools\agent.exe",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["entity_value"] == "agent.exe"
    assert result["mfdb"]["total_hits"] == 0
    assert result["mounted_image"]["checked_paths"] == 0
    assert result["coverage_gap"]["reason"] == (
        "raw_case_image_compare_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"


def test_compare_case_image_entity_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.compare_case_image_entity(entity_value="agent.exe"))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == (
        "raw_case_image_compare_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["joined_assessment"]["has_artifact_history"] is False


def test_initial_triage_pack_reports_raw_sidecar_unsupported_without_e01(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:") or key == "e01":
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.initial_triage_pack(
        scope_mode="custom",
        start_date="2026-10-01",
        end_date="2026-10-31",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["mode"] == "raw_sidecar_unsupported_for_initial_triage"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == (
        "raw_initial_triage_pack_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["analysis_blockers"]


def test_initial_triage_pack_preserves_raw_sidecar_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:") or key == "e01":
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.initial_triage_pack())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == (
        "raw_initial_triage_pack_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_assess_evidence_strength_auto_findings_reports_raw_index_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.assess_evidence_strength())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["findings"] == []
    assert result["coverage_gap"]["reason"] == "raw_find_suspicious_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["strength_rollup"] == {
        "confirmed": 0,
        "strong": 0,
        "moderate": 0,
        "weak": 0,
    }


def test_assess_evidence_strength_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.assess_evidence_strength())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_find_suspicious_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["strength_rollup"] == {
        "confirmed": 0,
        "strong": 0,
        "moderate": 0,
        "weak": 0,
    }


def test_assess_evidence_strength_scores_supplied_raw_gap_payload(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    payload = {
        "ok": False,
        "status": "not_evaluable",
        "source_type": "raw_image_sidecar",
        "findings": [],
        "coverage_gap": {
            "status": "not_evaluable",
            "reason": "raw_find_suspicious_unsupported",
        },
        "raw_index_coverage": {"status": "searched", "gaps": []},
    }

    result = _run(mcp_bridge.assess_evidence_strength(json.dumps(payload)))

    assert result["coverage_gap"]["reason"] == "raw_find_suspicious_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["strength_rollup"] == {
        "confirmed": 0,
        "strong": 0,
        "moderate": 0,
        "weak": 0,
    }


def test_investigation_gap_report_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.investigation_gap_report())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == (
        "raw_investigation_gap_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["findings_available"] is False
    assert set(result["skipped_sections"]) == {
        "detection_gaps",
        "corroboration_gaps",
    }
    assert result["substrate_gaps"] == []
    assert result["detection_gaps"] == []
    assert result["corroboration_gaps"] == []
    assert result["truncation_gaps"] == []
    assert result["bucket_gaps"] is None
    assert result["recommended_next_queries"] == []


def test_investigation_gap_report_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.investigation_gap_report())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == (
        "raw_investigation_gap_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_investigation_gap_report_preserves_supplied_raw_detection_gaps(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)
    payload = {
        "findings": [],
        "unevaluable_rules": [
            {
                "rule_name": "raw_sidecar_detection_rules",
                "reason": "raw_find_suspicious_unsupported",
            },
        ],
    }

    result = _run(mcp_bridge.investigation_gap_report(
        findings_json=json.dumps(payload),
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["findings_available"] is True
    assert result["skipped_sections"] == []
    assert result["detection_gaps"][0]["rule_name"] == (
        "raw_sidecar_detection_rules"
    )
    assert result["detection_gaps"][0]["reason"] == (
        "raw_find_suspicious_unsupported"
    )
    assert result["coverage_gap"]["reason"] == (
        "raw_investigation_gap_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"


def test_hunt_evtx_rules_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.hunt_evtx_rules(
        rule_ids="fw-evtx-001,fw-evtx-006",
        severity_min="medium",
        limit_per_rule=5,
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["rule_ids_requested"] == ["fw-evtx-001", "fw-evtx-006"]
    assert result["rules_evaluated"] == 0
    assert result["rules_fired"] == 0
    assert result["total_hits"] == 0
    assert result["results"] == []
    assert result["coverage_gap"]["reason"] == "raw_evtx_hunt_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_hunt_evtx_rules_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.hunt_evtx_rules())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_evtx_hunt_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["results"] == []


def test_detect_anti_forensics_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.detect_anti_forensics(max_details_per_rule=7))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["detail_cap_per_rule"] == 7
    assert result["rules_fired"] == 0
    assert result["total_hits"] == 0
    assert result["rules"] == []
    assert result["coverage_gap"]["reason"] == "raw_anti_forensics_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_detect_anti_forensics_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.detect_anti_forensics())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_anti_forensics_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["rules"] == []


def test_correlate_keywords_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.correlate(
        keywords="alpha-one.exe,alpha-two.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
        window_minutes=5,
        limit=10,
    ))

    assert result["mode"] == "multi_keyword_correlation"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["count_accuracy"] == "exact"
    assert result["per_keyword"]["alpha-one.exe"]["total_hits"] == 1
    assert result["per_keyword"]["alpha-two.exe"]["total_hits"] == 1
    assert result["per_keyword"]["alpha-one.exe"]["truncated"] is False
    assert result["co_occurrence_windows"][0]["keywords_present"] == [
        "alpha-one.exe",
        "alpha-two.exe",
    ]
    assert result["raw_index_coverage"]["status"] == "searched"


def test_correlate_keywords_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.correlate(
        keywords="alpha-one.exe,alpha-two.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_correlate_not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["per_keyword"] == {}
    assert result["co_occurrence_windows"] == []


def test_correlate_event_id_seed_reports_raw_index_unsupported(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.correlate(
        keywords="event_id:4648,agent.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == (
        "raw_correlate_event_id_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["per_keyword"] == {}
    assert result["co_occurrence_windows"] == []


def test_correlate_pivot_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.correlate(
        pivot_field="user",
        pivot_value="analyst",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_correlate_pivot_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_behavioral_delta_pack_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.behavioral_delta_pack(
        entity_value="alpha-one.exe",
        baseline_start="2026-10-01",
        baseline_end="2026-10-02",
        incident_start="2026-10-04",
        incident_end="2026-10-04",
        seed_keywords="alpha-two.exe",
        window_minutes=5,
        limit_per_keyword=10,
    ))

    assert result["ok"] is True
    assert result["source_type"] == "raw_image_sidecar"
    assert result["count_accuracy"] == "exact"
    assert result["entity"]["seed_keywords"] == ["alpha-one.exe", "alpha-two.exe"]
    assert result["baseline"]["per_keyword_totals"]["alpha-one.exe"] == 0
    assert result["incident"]["per_keyword_totals"]["alpha-one.exe"] == 1
    assert result["incident"]["co_occurrence_windows"] >= 1
    assert result["raw_index_coverage"]["status"] == "searched"
    assert any(
        claim["kind"] == "entity_net_new_in_incident"
        for claim in result["claims"]
    )


def test_behavioral_delta_pack_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.behavioral_delta_pack(
        entity_value="alpha-one.exe",
        baseline_start="2026-10-01",
        baseline_end="2026-10-02",
        incident_start="2026-10-04",
        incident_end="2026-10-04",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_behavioral_delta_not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["claims"] == []


def test_behavioral_delta_pack_event_id_seed_reports_raw_index_unsupported(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.behavioral_delta_pack(
        entity_value="agent.exe",
        baseline_start="2026-10-01",
        baseline_end="2026-10-02",
        incident_start="2026-10-04",
        incident_end="2026-10-04",
        seed_keywords="event_id:4648",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == (
        "raw_behavioral_delta_event_id_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["claims"] == []


def test_entity_story_pack_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_multi_timed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.entity_story_pack(
        entity_value="alpha-one.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
        seed_keywords="alpha-two.exe",
        window_minutes=5,
        limit_per_keyword=10,
    ))

    assert result["ok"] is True
    assert result["source_type"] == "raw_image_sidecar"
    assert result["count_accuracy"] == "exact"
    assert result["entity"]["seed_keywords"] == ["alpha-one.exe", "alpha-two.exe"]
    assert result["summary"]["event_count"] == 1
    assert result["summary"]["entity_hit_count"] == 1
    assert result["summary"]["co_occurrence_windows"] >= 1
    assert result["phases"][0]["kind"] == "first_seen"
    assert result["timeline_excerpt"][0]["keyword"] == "alpha-one.exe"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_entity_story_pack_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.entity_story_pack(
        entity_value="alpha-one.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_entity_story_not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["phases"] == []
    assert result["timeline_excerpt"] == []


def test_entity_story_pack_event_id_seed_reports_raw_index_unsupported(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.entity_story_pack(
        entity_value="agent.exe",
        start_date="2026-10-04",
        end_date="2026-10-04",
        seed_keywords="event_id:4648",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == (
        "raw_entity_story_event_id_unsupported"
    )
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["phases"] == []
    assert result["timeline_excerpt"] == []


def test_auto_seed_entities_pack_reports_raw_index_unsupported_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.auto_seed_entities_pack(
        start_date="2026-10-01",
        end_date="2026-10-04",
        window_minutes=5,
        limit_per_seed=10,
        max_seeds=4,
        match_mode="exact",
    ))

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_auto_seed_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"
    assert result["summary"]["selected_seed_count"] == 0
    assert result["summary"]["available_seed_count"] == 0
    assert result["seed_catalog"] == []
    assert result["priority_seed_catalog"] == []
    assert result["co_occurrence_clusters"] == []


def test_auto_seed_entities_pack_preserves_raw_index_not_evaluable_coverage(
    monkeypatch,
    tmp_path,
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _catching_passthrough)
    for key in list(mcp_bridge._connectors):
        if key == "axiom" or key.startswith("axiom:"):
            monkeypatch.delitem(mcp_bridge._connectors, key, raising=False)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.auto_seed_entities_pack())

    assert result.get("ok") is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_auto_seed_unsupported"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )
    assert result["seed_catalog"] == []


class _State:
    def __init__(self):
        self.captured = {}

    def set(self, name, connector):
        self.captured[name] = connector


class _StubImage:
    def __init__(self):
        self.list_calls = 0

    def is_connected(self):
        return True

    def get_metadata(self):
        return {
            "image_path": "unit-image",
            "hostname": "",
            "volumes": ["/c:"],
        }

    def list_directory(self, path="/"):
        self.list_calls += 1
        if path == "/c:":
            return [
                {"name": "Tools", "path": "/c:/Tools", "is_dir": True},
            ]
        if path == "/c:/Tools":
            return [
                {
                    "name": "agent.exe",
                    "path": "/c:/Tools/agent.exe",
                    "is_dir": False,
                    "size": 42,
                },
            ]
        return []


class _MultiRootImage(_StubImage):
    def get_metadata(self):
        meta = super().get_metadata()
        meta["volumes"] = ["/c:", "/d:"]
        return meta

    def list_directory(self, path="/"):
        self.list_calls += 1
        if path == "/c:":
            return [
                {
                    "name": "c-tool.exe",
                    "path": "/c:/c-tool.exe",
                    "is_dir": False,
                    "size": 1,
                },
            ]
        if path == "/d:":
            return [
                {
                    "name": "d-tool.exe",
                    "path": "/d:/d-tool.exe",
                    "is_dir": False,
                    "size": 1,
                },
            ]
        return []


class _PartialImage(_StubImage):
    def list_directory(self, path="/"):
        self.list_calls += 1
        if path == "/c:":
            return [
                {
                    "name": "agent.exe",
                    "path": "/c:/Tools/agent.exe",
                    "is_dir": False,
                    "size": 42,
                },
                {"name": "Broken", "path": "/c:/Broken", "is_dir": True},
            ]
        if path == "/c:/Broken":
            return [{"error": "simulated unreadable directory"}]
        return []


def test_build_raw_file_index_indexes_mounted_image(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="agent.exe")

    assert result["status"] == "indexed"
    assert result["indexed_files"] == 1
    assert result["source_type"] == "raw_image_sidecar"
    assert result["db_path"].startswith(str(tmp_path / "cache"))
    assert result["fingerprint"]
    assert search["total"] == 1
    assert search["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"
    assert "raw_index" in state.captured


def test_build_raw_file_index_background_returns_job_then_completes(monkeypatch, tmp_path):
    import time

    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    started = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
        background=True,
    ))
    # Returns immediately with a job handle, not the build result.
    assert started["status"] == "indexing_started"
    assert started["job_id"]
    assert "indexed_files" not in started
    job_id = started["job_id"]

    status = None
    for _ in range(400):  # up to ~20s; legacy-walk stub finishes near-instantly
        status = _run(mcp_bridge.raw_file_index_status(job_id=job_id))
        if status["status"] != "running":
            break
        time.sleep(0.05)

    assert status is not None
    assert status["status"] == "completed"
    assert status["result"]["status"] == "indexed"
    assert status["result"]["indexed_files"] == 1
    # the background thread connected the sidecar into shared state
    assert "raw_index" in state.captured
    search = state.captured["raw_index"].search(keyword="agent.exe")
    assert search["total"] == 1


def test_raw_file_index_status_unknown_job_is_not_found(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    result = _run(mcp_bridge.raw_file_index_status(job_id="does-not-exist"))
    assert result["ok"] is False
    assert result["status"] == "not_found"


def test_build_raw_file_index_preserves_partial_status(monkeypatch, tmp_path):
    state = _State()
    image = _PartialImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="agent.exe")

    assert result["ok"] is True
    assert result["status"] == "partial"
    assert result["indexed_files"] == 1
    assert result["coverage"]["status"] == "coverage_gap"
    assert result["coverage_gaps"][0]["path"] == "/c:/Broken"
    assert search["total"] == 1
    assert search["coverage"]["status"] == "coverage_gap"


def test_build_raw_file_index_propagates_indexer_not_evaluable(monkeypatch, tmp_path):
    from core.raw_index import file_indexer as file_indexer_module

    def not_evaluable_indexer(_image, store, *, roots, started_at, workers=0, progress=None):
        run_id = store.start_parser_run(
            "file_indexer",
            ",".join(roots),
            started_at=started_at,
        )
        store.finish_parser_run(
            run_id,
            status="not_evaluable",
            coverage_status="not_evaluable",
            finished_at=started_at,
            error="simulated parser failure",
        )
        return {
            "ok": False,
            "status": "not_evaluable",
            "indexed_files": 0,
            "coverage_gaps": [
                {
                    "status": "not_evaluable",
                    "reason": "simulated_parser_failure",
                    "error": "simulated parser failure",
                }
            ],
            "parser_run_id": run_id,
        }

    state = _State()
    image = _StubImage()
    monkeypatch.setattr(
        file_indexer_module,
        "index_file_listing",
        not_evaluable_indexer,
    )
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["indexed_files"] == 0
    assert result["coverage_gaps"][0]["reason"] == "simulated_parser_failure"
    assert "raw_index" not in state.captured


def test_build_raw_file_index_reports_indexer_exception_as_not_evaluable(
    monkeypatch,
    tmp_path,
):
    from core.raw_index import file_indexer as file_indexer_module

    def failing_indexer(_image, _store, *, roots, started_at, workers=0, progress=None):
        raise RuntimeError("simulated file indexer crash")

    state = _State()
    image = _StubImage()
    monkeypatch.setattr(
        file_indexer_module,
        "index_file_listing",
        failing_indexer,
    )
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage_gap"]["reason"] == "raw_file_indexer_exception"
    assert result["coverage_gap"]["error"] == "simulated file indexer crash"
    assert result["performance"] == {
        "sidecar_reused": False,
        "reindexed": True,
    }
    assert "raw_index" not in state.captured


def test_build_raw_file_index_batches_metadata_and_file_records(monkeypatch, tmp_path):
    from core.raw_index import store as store_module

    class _TracingStore(store_module.RawIndexStore):
        statements: list[str] = []

        def open(self) -> None:
            super().open()
            self._conn().set_trace_callback(type(self).statements.append)

    state = _State()
    image = _StubImage()
    monkeypatch.setattr(store_module, "RawIndexStore", _TracingStore)
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    commit_count = sum(
        1
        for statement in _TracingStore.statements
        if statement.strip().upper() == "COMMIT"
    )

    assert result["status"] == "indexed"
    assert result["indexed_files"] == 1
    assert commit_count == 1


def test_build_raw_file_index_reuses_existing_sidecar(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["status"] == "opened_existing"
    assert image.list_calls == first_call_count
    assert "raw_index" in state.captured


def test_build_raw_file_index_reuses_sidecar_for_duplicate_roots(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    second = _run(mcp_bridge.build_raw_file_index(
        roots=" /c:,/c: ",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "opened_existing"
    assert second["db_path"] == first["db_path"]
    assert image.list_calls == first_call_count


def test_build_raw_file_index_reuses_sidecar_for_reordered_roots(monkeypatch, tmp_path):
    state = _State()
    image = _MultiRootImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:,/d:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    second = _run(mcp_bridge.build_raw_file_index(
        roots="/d:,/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "opened_existing"
    assert second["db_path"] == first["db_path"]
    assert image.list_calls == first_call_count


def test_build_raw_file_index_reuses_sidecar_for_drive_root_case(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    second = _run(mcp_bridge.build_raw_file_index(
        roots="/C:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "opened_existing"
    assert second["db_path"] == first["db_path"]
    assert image.list_calls == first_call_count


def test_build_raw_file_index_reuses_sidecar_for_drive_root_forms(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    second = _run(mcp_bridge.build_raw_file_index(
        roots="C:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    third = _run(mcp_bridge.build_raw_file_index(
        roots="/C:/",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "opened_existing"
    assert third["status"] == "opened_existing"
    assert second["db_path"] == first["db_path"]
    assert third["db_path"] == first["db_path"]
    assert image.list_calls == first_call_count


def test_build_raw_file_index_reuses_sidecar_for_backslash_drive_root(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    first_call_count = image.list_calls

    second = _run(mcp_bridge.build_raw_file_index(
        roots="C:\\",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "opened_existing"
    assert second["db_path"] == first["db_path"]
    assert image.list_calls == first_call_count


def test_build_raw_file_index_rejects_roots_missing_from_volume_metadata(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/z:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_index_root_not_in_mounted_volumes"
    assert result["coverage_gap"]["missing_roots"] == ["/z:"]
    assert image.list_calls == 0
    assert "raw_index" not in state.captured


def test_build_raw_file_index_reuse_checks_coverage_without_search(monkeypatch, tmp_path):
    from core.connectors import raw_image_index as raw_index_connector

    class _CountingConnector(raw_index_connector.RawImageIndexConnector):
        search_calls = 0

        def search(self, *args, **kwargs):
            type(self).search_calls += 1
            return super().search(*args, **kwargs)

    state = _State()
    image = _StubImage()
    monkeypatch.setattr(
        raw_index_connector,
        "RawImageIndexConnector",
        _CountingConnector,
    )
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    _CountingConnector.search_calls = 0

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["status"] == "opened_existing"
    assert _CountingConnector.search_calls == 0


def test_build_raw_file_index_rebuilds_empty_existing_sidecar(monkeypatch, tmp_path):
    from core.raw_index.store import RawIndexStore

    state = _State()
    image = _StubImage()
    cache_root = tmp_path / "cache"
    fingerprint = mcp_bridge._raw_image_index_fingerprint(image.get_metadata())
    db_path = mcp_bridge._raw_index_db_path(fingerprint, ["/c:"], str(cache_root))
    store = RawIndexStore(db_path)
    store.open()
    store._conn().execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("raw_image_fingerprint", fingerprint),
    )
    store._conn().execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("index_roots", "/c:"),
    )
    store._conn().commit()
    store.close()

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(cache_root),
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="agent.exe")

    assert result["status"] == "indexed"
    assert result["indexed_files"] == 1
    assert image.list_calls > 0
    assert search["total"] == 1


def test_build_raw_file_index_rebuilds_sidecar_with_mismatched_roots(monkeypatch, tmp_path):
    from core.raw_index.store import RawIndexStore

    state = _State()
    image = _StubImage()
    cache_root = tmp_path / "cache"
    fingerprint = mcp_bridge._raw_image_index_fingerprint(image.get_metadata())
    db_path = mcp_bridge._raw_index_db_path(fingerprint, ["/c:"], str(cache_root))
    store = RawIndexStore(db_path)
    store.open()
    store._conn().execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("raw_image_fingerprint", fingerprint),
    )
    store._conn().execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("index_roots", "/d:"),
    )
    run_id = store.start_parser_run(
        "file_indexer",
        "/d:",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/d:",
        source_path="/d:/stale.exe",
        primary_path="/d:/stale.exe",
        description="File System Entry /d:/stale.exe",
        strings={"Name": "stale.exe", "Path": "/d:/stale.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(cache_root),
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="agent.exe")

    assert result["status"] == "indexed"
    assert result["indexed_files"] == 1
    assert image.list_calls > 0
    assert search["total"] == 1
    assert search["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_build_raw_file_index_force_rebuild_replaces_existing_sidecar(monkeypatch, tmp_path):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    monkeypatch.setitem(
        mcp_bridge._connectors,
        "raw_index",
        state.captured["raw_index"],
    )
    second = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        force_rebuild=True,
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="agent.exe")

    assert first["status"] == "indexed"
    assert second["status"] == "indexed"
    assert first["db_path"] == second["db_path"]
    assert search["total"] == 1


def test_build_raw_file_index_force_rebuild_removes_sqlite_aux_files(
    monkeypatch,
    tmp_path,
):
    state = _State()
    image = _StubImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    aux_paths = [
        first["db_path"] + suffix
        for suffix in ("-wal", "-shm", "-journal")
    ]
    for path in aux_paths:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("stale sqlite sidecar fragment")
    monkeypatch.setitem(
        mcp_bridge._connectors,
        "raw_index",
        state.captured["raw_index"],
    )

    second = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        force_rebuild=True,
        started_at="2026-06-04T00:00:00Z",
    ))

    assert second["status"] == "indexed"
    assert first["db_path"] == second["db_path"]
    assert not any(os.path.exists(path) for path in aux_paths)


def test_build_raw_file_index_removes_orphan_sqlite_aux_files_before_indexing(
    monkeypatch,
    tmp_path,
):
    state = _State()
    image = _StubImage()
    cache_root = tmp_path / "cache"
    fingerprint = mcp_bridge._raw_image_index_fingerprint(image.get_metadata())
    db_path = mcp_bridge._raw_index_db_path(
        fingerprint,
        ["/c:"],
        str(cache_root),
    )
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    aux_paths = [
        db_path + suffix
        for suffix in ("-wal", "-shm", "-journal")
    ]
    for path in aux_paths:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("orphan sqlite sidecar fragment")

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    result = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(cache_root),
        started_at="2026-06-04T00:00:00Z",
    ))

    assert result["status"] == "indexed"
    assert result["db_path"] == db_path
    assert not any(os.path.exists(path) for path in aux_paths)


def test_build_raw_file_index_uses_root_scoped_sidecars(monkeypatch, tmp_path):
    state = _State()
    image = _MultiRootImage()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", state)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", image)

    first = _run(mcp_bridge.build_raw_file_index(
        roots="/c:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    second = _run(mcp_bridge.build_raw_file_index(
        roots="/d:",
        cache_root=str(tmp_path / "cache"),
        started_at="2026-06-04T00:00:00Z",
    ))
    search = state.captured["raw_index"].search(keyword="d-tool.exe")

    assert first["db_path"] != second["db_path"]
    assert second["status"] == "indexed"
    assert search["total"] == 1
    assert search["hits"][0]["fields"]["Path"] == "/d:/d-tool.exe"


# ── Parsed-case fallback parity (MCP mirrors api/timeline.py semantics) ──


class _RaisingRawConnector:
    def is_connected(self):
        return True

    def search(self, *args, **kwargs):
        raise RuntimeError("sidecar corrupt")

    def get_timeline(self, *args, **kwargs):
        raise RuntimeError("sidecar corrupt")


class _ParsedCaseStub:
    def is_connected(self):
        return True

    def search(self, keyword="", filters=None, limit=50, offset=0):
        return {
            "total": 1,
            "hits": [
                {
                    "hit_id": 7,
                    "artifact_type": "Shim Cache",
                    "fields": {"Path": r"C:\Tools\agent.exe"},
                }
            ],
        }

    def get_timeline(self, *args, **kwargs):
        return {
            "total_events": 1,
            "returned": 1,
            "entries": [{"hit_id": 7, "timestamp": "2026-06-01T00:00:00Z"}],
        }


def test_search_artifacts_falls_back_to_parsed_when_raw_raises(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.setitem(mcp_bridge._connectors, "axiom", _ParsedCaseStub())

    result = _run(mcp_bridge.search_artifacts(keyword="agent"))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["returned"] == 1


def test_search_artifacts_falls_back_when_raw_coverage_not_evaluable(
    monkeypatch, tmp_path
):
    raw = _seed_failed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)
    monkeypatch.setitem(mcp_bridge._connectors, "axiom", _ParsedCaseStub())

    result = _run(mcp_bridge.search_artifacts(keyword="agent"))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["returned"] == 1


def test_build_timeline_falls_back_to_parsed_when_raw_raises(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.setitem(mcp_bridge._connectors, "axiom", _ParsedCaseStub())

    result = _run(mcp_bridge.build_timeline())

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["entries"]


def test_search_artifacts_surfaces_hydration_failure_without_parsed_case(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_HYDRATION_STATE", {})
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.delitem(mcp_bridge._connectors, "axiom", raising=False)
    missing = str(tmp_path / "missing-case.mfdb")
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {"path": missing})

    result = _run(mcp_bridge.search_artifacts(keyword="agent"))

    # No parsed case could hydrate, so the degraded raw result is returned —
    # but the configured-yet-unloadable parsed case must be called out.
    assert result["status"] == "not_evaluable"
    assert "does not exist" in result["parsed_case_hydration_error"]


def test_search_artifacts_fetch_all_surfaces_raw_failure_without_parsed_case(
    monkeypatch,
):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_HYDRATION_STATE", {})
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.delitem(mcp_bridge._connectors, "axiom", raising=False)
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})

    result = _run(mcp_bridge.search_artifacts(keyword="agent", fetch_all=True))

    # The drain must not flatten the raw failure into an empty success.
    assert result["status"] == "not_evaluable"
    assert result["error"]
    assert result["coverage_gap"]["reason"] == "raw_index_exception"


def test_search_artifacts_fetch_all_falls_back_to_parsed(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.setitem(mcp_bridge._connectors, "axiom", _ParsedCaseStub())

    result = _run(mcp_bridge.search_artifacts(keyword="agent", fetch_all=True))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["returned"] == 1
    # Compact rows must not point at get_hit_detail: those hit_ids belong to
    # the parsed case while the raw sidecar stays first in line.
    assert "do NOT use get_hit_detail" in result["projection"]


def test_build_timeline_fetch_all_surfaces_raw_failure_without_parsed_case(
    monkeypatch,
):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_HYDRATION_STATE", {})
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", _RaisingRawConnector())
    monkeypatch.delitem(mcp_bridge._connectors, "axiom", raising=False)
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})

    result = _run(mcp_bridge.build_timeline(fetch_all=True))

    assert result["status"] == "not_evaluable"
    assert result["error"]


def test_raw_coverage_summary_exposes_search_index_backend(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")

    coverage = raw.get_coverage()

    assert coverage["search_index_backend"] in {"fts5_trigram", "materialized_like"}
    metadata = raw.get_metadata()
    assert metadata["search_index_backend"] == coverage["search_index_backend"]
