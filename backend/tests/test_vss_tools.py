from __future__ import annotations

import asyncio
import json
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

    def vss_find_files_with_coverage(self, snapshot_id, pattern, path="/", volume="/c:", limit=100):
        if pattern == "NTUSER.DAT":
            files = [
                {
                    "path": "/c:/Users/Alice/NTUSER.DAT",
                    "is_dir": False,
                    "size": 4096,
                    "temporal_layer": f"vss:0:{snapshot_id}",
                    "snapshot_id": snapshot_id,
                    "snapshot_index": 0,
                    "snapshot_creation_time": "2026-03-08T23:11:00Z",
                    "volume": volume,
                    "integrity_note": "VSS contents are historical layers.",
                }
            ]
        elif pattern == "UsrClass.dat":
            files = [
                {
                    "path": "/c:/Users/Alice/AppData/Local/Microsoft/Windows/UsrClass.dat",
                    "is_dir": False,
                    "size": 2048,
                    "temporal_layer": f"vss:0:{snapshot_id}",
                    "snapshot_id": snapshot_id,
                    "snapshot_index": 0,
                    "snapshot_creation_time": "2026-03-08T23:11:00Z",
                    "volume": volume,
                    "integrity_note": "VSS contents are historical layers.",
                }
            ]
        else:
            files = [
                {
                    "path": "/c:/ProgramData/sample.tmp",
                    "is_dir": False,
                    "size": 3,
                    "temporal_layer": f"vss:0:{snapshot_id}",
                    "snapshot_id": snapshot_id,
                    "snapshot_index": 0,
                    "snapshot_creation_time": "2026-03-08T23:11:00Z",
                    "volume": volume,
                    "integrity_note": "VSS contents are historical layers.",
                }
            ]
        return {
            "files": files[:limit],
            "coverage": {
                "paths_attempted": 2,
                "paths_succeeded": 1,
                "paths_skipped": 1,
                "skip_reasons": {
                    "access_denied": 0,
                    "io_error": 1,
                    "path_too_long": 0,
                    "symlink": 0,
                    "other": 0,
                },
                "skipped_path_samples": [{"path": "/bad", "reason": "io_error", "error": "read failed"}],
                "coverage_gap": "1 paths unexamined in snapshot snap-1.",
                "truncated": False,
            },
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
    manifest_ref = result["quarantine_manifest"]
    assert manifest_ref["ok"] is True
    assert os.path.exists(manifest_ref["manifest_path"])
    with open(manifest_ref["manifest_path"], "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["schema"] == "fw.vss_quarantine_manifest.v1"
    assert manifest["snapshot"]["snapshot_id"] == "snap-1"
    assert manifest["image"]["image_basename"] == "host.E01"
    assert manifest["interpretation_guardrails"]["manifest_is_provenance_not_verdict"] is True
    assert manifest["entries"][0]["source"]["path"] == "/c:/ProgramData/sample.tmp"
    assert manifest["entries"][0]["output"]["sha256"] == "fake"
    assert manifest["entries"][0]["purpose"] == "manual_static_analysis_extract"


def test_vss_list_files_keeps_coverage_gap_when_results_exist(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.vss_list_files("snap-1", "/c:/ProgramData", "*.tmp"))

    assert result["ok"] is True
    assert result["count"] == 1
    coverage = result["coverage"]
    assert coverage["paths_skipped"] == 1
    assert coverage["skip_reasons"]["io_error"] == 1
    assert "1 paths unexamined" in coverage["coverage_gap"]
    assert "undetected" not in coverage["coverage_gap"].lower()
    assert "may contain" not in coverage["coverage_gap"].lower()
    assert result["interpretation_guardrails"]["absence_is_negative_evidence"] is False


def test_vss_list_registry_hives_discovers_core_and_user_hives(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.vss_list_registry_hives("snap-1"))

    assert result["ok"] is True
    hive_types = {hive["hive_type"] for hive in result["hives"]}
    assert "SYSTEM" in hive_types
    assert "SOFTWARE" in hive_types
    assert "NTUSER.DAT" in hive_types
    assert "UsrClass.dat" in hive_types
    assert result["coverage"]["exact_paths_checked"] >= 5
    assert result["coverage"]["user_hive_searches"]
    assert result["interpretation_guardrails"]["vss_is_verified_clean_baseline"] is False


def test_vss_query_user_hives_queries_discovered_hive(tmp_path, monkeypatch):
    import core.connectors.registry as registry_module

    _mock_vss_context(monkeypatch, tmp_path)

    class FakeRegistryConnector:
        def connect(self, path):
            return {"status": "success", "path": path, "hive_type": "NTUSER.DAT"}

        def get_key(self, path):
            return {
                "path": path,
                "timestamp": "2026-03-08 23:10:00",
                "values": [{"name": "Sample", "type": "REG_SZ", "value": "C:\\ProgramData\\sample.exe"}],
                "subkeys": [],
            }

        def disconnect(self):
            pass

    monkeypatch.setattr(registry_module, "RegistryConnector", FakeRegistryConnector)

    result = _run(mcp_bridge.vss_query_user_hives(
        "snap-1",
        key_path=r"\Software\Microsoft\Windows\CurrentVersion\Run",
        user_filter="Alice",
    ))

    assert result["ok"] is True
    assert result["hives_queried"] == 1
    assert result["results"][0]["user"] == "Alice"
    query = result["results"][0]["query_result"]
    assert query["ok"] is True
    assert query["resolved_key_path"] == r"\Software\Microsoft\Windows\CurrentVersion\Run"
    assert query["quarantine_manifest"]["ok"] is True
    assert result["query_semantics"]["whole_hive_scan_allowed"] is False


def test_vss_query_user_hives_blocks_unbounded_keyword_search(tmp_path, monkeypatch):
    _mock_vss_context(monkeypatch, tmp_path)

    result = _run(mcp_bridge.vss_query_user_hives("snap-1", keyword="Run"))

    assert result["ok"] is False
    assert "search_root" in result["error"]
    assert result["query_semantics"]["whole_hive_scan_allowed"] is False
    assert result["interpretation_guardrails"]["absence_is_negative_evidence"] is False


def test_vss_service_persistence_gate_uses_snapshot_system_hive(tmp_path, monkeypatch):
    import core.analysis.service_persistence as service_module

    _mock_vss_context(monkeypatch, tmp_path)

    def fake_services_from_system_hive(path):
        return (
            [{
                "source": "system_hive",
                "service_name": "SampleSvc",
                "image_path": r"C:\ProgramData\sample.exe",
                "start": "Auto (2)",
                "type": "Own Process (16)",
                "account": "LocalSystem",
                "registry_key_path": r"HKLM\SYSTEM\ControlSet001\Services\SampleSvc",
            }],
            {"hive_path": path, "service_count": 1},
        )

    def fake_build_gate(services, service_filter="", limit=50, file_info_lookup=None):
        payload_info = file_info_lookup("/c:/ProgramData/sample.exe") if file_info_lookup else {}
        return {
            "ok": True,
            "summary": {"total_services_observed": len(services)},
            "candidates": [{"service_name": services[0]["service_name"], "payload_file": payload_info}],
            "reading_guide": [],
        }

    monkeypatch.setattr(service_module, "services_from_system_hive", fake_services_from_system_hive)
    monkeypatch.setattr(service_module, "build_service_persistence_gate", fake_build_gate)

    result = _run(mcp_bridge.vss_service_persistence_gate("snap-1"))

    assert result["ok"] is True
    assert result["source"] == "vss_snapshot"
    assert result["sources"][0]["source"] == "vss_system_hive"
    assert result["quarantine_manifest"]["ok"] is True
    assert result["candidates"][0]["payload_file"]["snapshot_id"] == "snap-1"
    assert result["interpretation_guardrails"]["strong_conclusion_allowed"] is False


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


def test_safe_vss_rglob_reports_skipped_directory_coverage():
    root = _FakePath(
        "",
        children=[
            _FakePath("bad", fail=True),
            _FakePath("ProgramData", children=[_FakePath("sample.tmp")]),
        ],
    )
    connector = E01ImageConnector()

    result = connector._safe_vss_rglob_with_coverage(root, "*.tmp", limit=10)

    assert [match.name for match in result["matches"]] == ["sample.tmp"]
    assert result["coverage"]["paths_skipped"] == 1
    assert result["coverage"]["skip_reasons"]["io_error"] == 1
    assert result["coverage"]["paths_succeeded"] == 2
