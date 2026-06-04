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
