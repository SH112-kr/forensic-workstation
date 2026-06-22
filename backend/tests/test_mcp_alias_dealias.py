from __future__ import annotations

import asyncio

import mcp_bridge
from core.analysis import privacy_proxy


def _run(coro):
    return asyncio.run(coro)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0, apply_privacy=True):
    return fn()


class _AliasFakeE01:
    def __init__(self):
        self.calls = []

    def is_connected(self):
        return True

    def get_metadata(self):
        return {"image_path": r"D:\case\host.E01", "hostname": "HOST", "volumes": ["/c:"]}

    def list_directory(self, path):
        self.calls.append(("list_directory", path))
        return [{"path": f"{path}/a.exe"}]

    def find_files(self, pattern, path, limit=100):
        self.calls.append(("find_files", pattern, path, limit))
        return [{"path": f"{path}/{pattern}"}]

    def get_file_info(self, internal_path):
        self.calls.append(("get_file_info", internal_path))
        return {
            "path": internal_path,
            "size": 1,
            "created": "2026-01-01 00:00:00.000",
            "modified": "2026-01-01 00:00:00.000",
            "accessed": "2026-01-01 00:00:00.000",
        }

    def vss_get_file_info(self, snapshot_id, internal_path, volume="/c:"):
        self.calls.append(("vss_get_file_info", snapshot_id, internal_path, volume))
        return {
            "path": internal_path,
            "size": 1,
            "created": "2026-01-01 00:00:00.000",
            "modified": "2026-01-01 00:00:00.000",
            "accessed": "2026-01-01 00:00:00.000",
            "temporal_layer": f"vss:0:{snapshot_id}",
            "snapshot_id": snapshot_id,
            "snapshot_index": 0,
            "snapshot_creation_time": "2026-01-01T00:00:00Z",
            "volume": volume,
            "integrity_note": "test snapshot",
        }


def test_mcp_raw_image_tools_resolve_alias_params_before_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(privacy_proxy, "_SETTINGS_FILE", str(tmp_path / "privacy.json"))
    monkeypatch.setattr(privacy_proxy, "_PENDING_FILE", str(tmp_path / "intercepts.json"))
    monkeypatch.setattr(privacy_proxy, "_AUDIT_FILE", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(privacy_proxy, "_ALIAS_FILE", str(tmp_path / "aliases.json"))
    monkeypatch.setattr(privacy_proxy, "_FILTER_LOG_FILE", str(tmp_path / "filter_events.json"))

    fake = _AliasFakeE01()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "e01", fake)
    privacy_proxy.add_alias("alice", alias_type="PERSON")

    list_result = _run(mcp_bridge.list_files("/c:/Users/PERSON_001"))
    ts_result = _run(mcp_bridge.get_file_timestamps("/c:/Users/PERSON_001/a.exe"))
    vss_result = _run(mcp_bridge.vss_get_file_timestamps("snap-1", "/c:/Users/PERSON_001/a.exe"))

    assert list_result["path"] == "/c:/Users/alice"
    assert ts_result["path"] == "/c:/Users/alice/a.exe"
    assert vss_result["path"] == "/c:/Users/alice/a.exe"
    assert ("list_directory", "/c:/Users/alice") in fake.calls
    assert ("get_file_info", "/c:/Users/alice/a.exe") in fake.calls
    assert ("vss_get_file_info", "snap-1", "/c:/Users/alice/a.exe", "/c:") in fake.calls
