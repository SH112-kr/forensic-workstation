from __future__ import annotations

import asyncio

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

    def not_evaluable_indexer(_image, store, *, roots, started_at):
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
