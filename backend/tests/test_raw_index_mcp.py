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
