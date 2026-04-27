from __future__ import annotations

import asyncio
import os

import mcp_bridge
from core.connectors.e01_image import E01ImageConnector


def _run(coro):
    return asyncio.run(coro)


class _FakeE01:
    def is_connected(self):
        return True

    def get_metadata(self):
        return {
            "image_path": r"D:\case\host.E01",
            "hostname": "HOST",
            "volumes": ["<Volume C>"],
        }

    def list_vss_snapshots(self, volume="/c:"):
        return {
            "ok": True,
            "volume": volume,
            "snapshot_count": 1,
            "snapshots": [
                {
                    "temporal_layer": "vss:0:snap-1",
                    "snapshot_id": "snap-1",
                    "snapshot_index": 0,
                    "snapshot_creation_time": "2026-03-08T23:11:00Z",
                    "volume": volume,
                    "integrity_note": "VSS contents are historical layers.",
                }
            ],
        }

    def vss_get_file_info(self, snapshot_id, internal_path, volume="/c:"):
        return {
            "path": internal_path,
            "size": 3,
            "created": "2026-03-08 23:00:00.000",
            "modified": "2026-03-08 23:00:00.000",
            "accessed": "2026-03-08 23:00:00.000",
            "temporal_layer": f"vss:0:{snapshot_id}",
            "snapshot_id": snapshot_id,
            "snapshot_index": 0,
            "snapshot_creation_time": "2026-03-08T23:11:00Z",
            "volume": volume,
            "integrity_note": "VSS contents are historical layers.",
        }

    def vss_extract_file(self, snapshot_id, internal_path, output_path, volume="/c:"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as fh:
            fh.write(b"vss")
        return {
            "internal_path": internal_path,
            "output_path": output_path,
            "size": 3,
            "sha256": "fake",
            "execute_allowed": False,
            "source": "vss_snapshot",
            "temporal_layer": f"vss:0:{snapshot_id}",
            "snapshot_id": snapshot_id,
            "snapshot_index": 0,
            "snapshot_creation_time": "2026-03-08T23:11:00Z",
            "volume": volume,
            "integrity_note": "VSS contents are historical layers.",
        }


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


def _mock_vss_context(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": _FakeE01()})
    monkeypatch.setattr(mcp_bridge, "_workspace_root", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})
    monkeypatch.setattr(mcp_bridge, "load_allowed_evidence", lambda: {"paths": []})
    monkeypatch.setattr(mcp_bridge, "resolve_image_evidence", lambda _ref="": {})


def test_vss_guardrail_blocks_clean_baseline_and_absence_claims():
    guardrail = mcp_bridge._vss_snapshot_guardrails(total=0, parser_failures=[{"error": "parse"}])

    assert guardrail["evidence_role"] == "historical_filesystem_layer"
    assert guardrail["strong_conclusion_allowed"] is False
    assert guardrail["absence_is_negative_evidence"] is False
    assert guardrail["merge_with_current_fs_allowed"] is False
    assert guardrail["vss_is_verified_clean_baseline"] is False
    assert "zero_result_guidance" in guardrail
    assert "parser_failure_guidance" in guardrail


def test_list_vss_snapshots_attaches_temporal_guardrails(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.list_vss_snapshots())

    assert result["ok"] is True
    assert result["snapshot_count"] == 1
    assert result["snapshots"][0]["temporal_layer"] == "vss:0:snap-1"
    assert result["interpretation_guardrails"]["merge_with_current_fs_allowed"] is False


def test_vss_get_file_timestamps_keeps_snapshot_context(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.vss_get_file_timestamps("snap-1", "/c:/ProgramData/sample.tmp"))

    assert result["ok"] is True
    assert result["source"] == "vss_snapshot"
    assert result["temporal_layer"] == "vss:0:snap-1"
    assert result["evidence_context"]["snapshot_id"] == "snap-1"
    assert result["interpretation_guardrails"]["absence_is_negative_evidence"] is False


def test_vss_extract_file_defaults_to_snapshot_scoped_export(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.vss_extract_file("snap-1", "/c:/ProgramData/sample.tmp"))

    assert result["ok"] is True
    assert result["source"] == "vss_snapshot"
    assert os.path.exists(result["output_path"])
    assert os.path.normpath(os.path.join("export", "vss", "snap-1", "extract")) in os.path.normpath(result["output_path"])
    assert result["interpretation_guardrails"]["merge_with_current_fs_allowed"] is False


class _FakePath:
    def __init__(self, name, *, children=None, fail=False, parent=""):
        self.name = name
        self._children = children or []
        self._fail = fail
        self._parent = parent
        for child in self._children:
            child._parent = str(self)

    def __str__(self):
        if not self._parent:
            return f"/{self.name}".rstrip("/")
        return f"{self._parent.rstrip('/')}/{self.name}"

    def iterdir(self):
        if self._fail:
            raise RuntimeError("unreadable directory")
        return iter(self._children)

    def is_dir(self):
        return bool(self._children) or self._fail


def test_safe_vss_rglob_skips_bad_directories_and_returns_matches():
    root = _FakePath(
        "",
        children=[
            _FakePath("bad", fail=True),
            _FakePath("ProgramData", children=[_FakePath("sample.tmp")]),
        ],
    )
    connector = E01ImageConnector()

    matches = list(connector._safe_vss_rglob(root, "*.tmp", limit=10))

    assert [match.name for match in matches] == ["sample.tmp"]


class _FakeVolumePath:
    def __init__(self, exists):
        self._exists = exists

    def exists(self):
        return self._exists


class _FakeVolumeFs:
    def __init__(self, paths):
        self._paths = set(paths)

    def path(self, path):
        return _FakeVolumePath(path in self._paths)

    def __str__(self):
        return "ntfs"


class _FakeVolume:
    def __init__(self, *, size, paths=(), drive_letter=""):
        self.fs = _FakeVolumeFs(paths)
        self.size = size
        self.drive_letter = drive_letter
        self.guid = ""


class _FakeTarget:
    def __init__(self, volumes):
        self.volumes = volumes


def test_resolve_volume_prefers_windows_partition_for_c_drive_without_letter():
    small_ntfs = _FakeVolume(size=523238912)
    os_ntfs = _FakeVolume(
        size=511464963584,
        paths={"/Windows", "/Windows/System32/config/SYSTEM"},
    )
    connector = E01ImageConnector()
    connector._target = _FakeTarget([small_ntfs, os_ntfs])

    assert connector._resolve_volume("/c:") is os_ntfs


def test_resolve_volume_falls_back_to_largest_ntfs_for_c_drive():
    small_ntfs = _FakeVolume(size=100)
    large_ntfs = _FakeVolume(size=1000)
    connector = E01ImageConnector()
    connector._target = _FakeTarget([small_ntfs, large_ntfs])

    assert connector._resolve_volume("c:") is large_ntfs
