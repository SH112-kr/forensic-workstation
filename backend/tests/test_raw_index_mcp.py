from __future__ import annotations

import asyncio

import mcp_bridge


def _run(coro):
    return asyncio.run(coro)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


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
