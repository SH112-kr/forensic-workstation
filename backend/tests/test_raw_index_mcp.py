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


def test_get_artifact_types_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_artifact_types())

    assert result["source_type"] == "raw_image_sidecar"
    assert result["total_types"] == 1
    assert result["artifact_types"][0]["artifact_name"] == "File System Entry"
    assert result["artifact_types"][0]["count_accuracy"] == "exact"


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


def test_get_hit_detail_uses_active_raw_index(monkeypatch, tmp_path):
    raw = _seed_raw_connector(tmp_path / "raw-index.sqlite")
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "raw_index", raw)

    result = _run(mcp_bridge.get_hit_detail(1))

    assert result["source_type"] == "raw_image_sidecar"
    assert result["fields"]["Path"] == "/c:/Tools/agent.exe"


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
