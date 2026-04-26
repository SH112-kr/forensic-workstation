from __future__ import annotations

import os

import pytest


class _FakeE01Connector:
    def __init__(self):
        self.calls = []
        self.exact = {
            "/c:/Windows/System32/winevt/Logs/Security.evtx": {"path": "/c:/Windows/System32/winevt/Logs/Security.evtx", "size": 1024},
            "/c:/Windows/System32/winevt/Logs/System.evtx": {"path": "/c:/Windows/System32/winevt/Logs/System.evtx", "size": 2048},
            "/c:/Windows/System32/config/SYSTEM": {"path": "/c:/Windows/System32/config/SYSTEM", "size": 4096},
            "/c:/Users/Alice/NTUSER.DAT": {"path": "/c:/Users/Alice/NTUSER.DAT", "size": 8192},
        }
        self.bounded = {
            ("/c:/Windows/Prefetch", "*.pf"): [
                {"path": "/c:/Windows/Prefetch/POWERSHELL.EXE-123.pf", "size": 512},
            ],
        }
        self.files = {
            "**/Windows/System32/winevt/Logs/*.evtx": [
                {"path": "/c:/Windows/System32/winevt/Logs/Security.evtx", "size": 1024},
                {"path": "/c:/Windows/System32/winevt/Logs/System.evtx", "size": 2048},
            ],
            "**/Windows/Prefetch/*.pf": [
                {"path": "/c:/Windows/Prefetch/POWERSHELL.EXE-123.pf", "size": 512},
            ],
            "**/Windows/System32/config/SYSTEM": [
                {"path": "/c:/Windows/System32/config/SYSTEM", "size": 4096},
            ],
        }

    def get_metadata(self):
        return {"image_path": "fixture.E01"}

    def get_file_info(self, internal_path: str):
        return self.exact.get(internal_path, {"error": "not found"})

    def list_directory(self, path: str = "/"):
        if path == "/c:/Users":
            return [
                {"name": "Alice", "path": "/c:/Users/Alice", "is_dir": True},
                {"name": "Public", "path": "/c:/Users/Public", "is_dir": True},
            ]
        if path == "/c:/Windows/Prefetch":
            return [
                {"name": "POWERSHELL.EXE-123.pf", "path": "/c:/Windows/Prefetch/POWERSHELL.EXE-123.pf", "is_dir": False, "size": 512},
            ]
        return []

    def find_files(self, pattern: str, path: str = "/", limit: int = 100):
        self.calls.append((path, pattern, limit))
        if (path, pattern) in self.bounded:
            return self.bounded[(path, pattern)]
        return self.files.get(pattern, [])


def test_build_e01_artifact_cache_indexes_high_value_artifacts():
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    connector = _FakeE01Connector()
    result = build_e01_artifact_cache(connector, source_id="disk1")

    assert result["ok"] is True
    assert result["temporal_layer"] == "e01_live"
    assert result["record_count"] == 5
    assert result["artifact_type_counts"]["EVTX Candidate"] == 2
    assert result["lane_counts"]["ingress_access"] == 2
    assert result["lane_counts"]["execution_impact"] == 1
    assert result["lane_counts"]["persistence_cleanup"] == 2
    record = result["records"][0]
    assert record["source_chain"][0]["adapter"] == "e01_image"
    assert record["source_chain"][0]["parser"] == "e01_lazy_artifact_inventory"
    assert record["value"]["mfdb_artifact_name"] == "Windows Event Logs"
    assert record["value"]["kape_tool"] == "EvtxECmd"
    assert record["parser_status"]["status"] == "indexed"
    assert not any(call[0] == "/" and call[1].startswith("**/") for call in connector.calls)


def test_build_e01_artifact_cache_records_pattern_failures():
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    class Broken(_FakeE01Connector):
        def list_directory(self, path: str = "/"):
            if "Prefetch" in path:
                raise RuntimeError("image read failed")
            return super().list_directory(path)

    result = build_e01_artifact_cache(Broken())

    assert result["parser_failures"]
    assert any("image read failed" in f["error"] for f in result["parser_failures"])


def test_build_e01_artifact_cache_can_opt_into_legacy_global_patterns():
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    connector = _FakeE01Connector()
    result = build_e01_artifact_cache(
        connector,
        include_lazy_targets=False,
        include_high_value_patterns=True,
    )

    assert result["record_count"] == 4
    assert any(call[0] == "/" and call[1] == "**/Windows/System32/winevt/Logs/*.evtx" for call in connector.calls)


def test_build_e01_artifact_cache_supports_root_mounted_ntfs_without_drive_letter():
    class RootMounted:
        def get_metadata(self):
            return {"image_path": "root.E01"}

        def get_file_info(self, internal_path: str):
            files = {
                "/$MFT": {"path": "/$MFT", "size": 262144},
                "/$LogFile": {"path": "/$LogFile", "size": 7405568},
                "/$Extend/$UsnJrnl:$J": {"path": "/$Extend/$UsnJrnl:$J", "size": 1048576},
            }
            return files.get(internal_path, {"error": "not found"})

        def list_directory(self, path: str = "/"):
            if path == "/":
                return [
                    {"name": "$MFT", "path": "/$MFT", "is_dir": False, "size": 262144},
                    {"name": "$LogFile", "path": "/$LogFile", "is_dir": False, "size": 7405568},
                    {"name": "$Extend", "path": "/$Extend", "is_dir": True},
                    {"name": "case.zip", "path": "/case.zip", "is_dir": False, "size": 100},
                    {"name": "notes.odt", "path": "/notes.odt", "is_dir": False, "size": 200},
                ]
            return []

    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    result = build_e01_artifact_cache(RootMounted())

    paths = {record["value"]["internal_path"] for record in result["records"]}
    assert "/$MFT" in paths
    assert "/$LogFile" in paths
    assert "/$Extend/$UsnJrnl:$J" in paths
    assert "/case.zip" in paths
    assert "/notes.odt" in paths
    assert result["artifact_type_counts"]["Data File Candidate"] == 2


def test_build_e01_artifact_cache_can_use_exact_paths_without_full_inventory():
    class ExactFake:
        def get_metadata(self):
            return {"image_path": "large.E01"}

        def find_files(self, pattern: str, limit: int = 100):
            raise AssertionError("full glob inventory should be skipped")

        def get_file_info(self, internal_path: str):
            if internal_path == "/c:/Documents and Settings/Jean/Desktop/m57biz.xls":
                return {"path": internal_path, "size": 1234}
            return {"error": "not found"}

    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    result = build_e01_artifact_cache(
        ExactFake(),
        include_lazy_targets=False,
        include_high_value_patterns=False,
        extra_patterns=[{
            "artifact_type": "Expected Scenario Path",
            "pattern": "/c:/Documents and Settings/Jean/Desktop/m57biz.xls",
            "exact_path": "/c:/Documents and Settings/Jean/Desktop/m57biz.xls",
            "lane": "context",
        }],
    )

    assert result["record_count"] == 1
    assert result["artifact_type_counts"]["Expected Scenario Path"] == 1


def test_real_e01_connector_optional_contract():
    """Optional integration check.

    Set FW_TEST_E01_PATH to a known-safe public/training E01 image to verify the
    actual connector. The test is skipped by default because the repository
    must not ship evidence images and dissect/libewf dependencies may be absent.
    """
    e01_path = os.environ.get("FW_TEST_E01_PATH", "")
    if not e01_path:
        pytest.skip("FW_TEST_E01_PATH not set")

    from core.connectors.e01_image import E01ImageConnector
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache

    connector = E01ImageConnector()
    try:
        meta = connector.connect(e01_path)
        assert meta["image_path"] == e01_path
        cache = build_e01_artifact_cache(connector, limit_per_pattern=10)
        assert cache["ok"] is True
        assert "records" in cache
    finally:
        connector.disconnect()


def test_e01_connector_collects_segments_case_insensitively(monkeypatch, tmp_path):
    image = tmp_path / "sample.e01"
    (tmp_path / "Sample.E01").write_bytes(b"segment1")
    (tmp_path / "Sample.E02").write_bytes(b"segment2")
    (tmp_path / "Sample.E01.txt").write_text("metadata", encoding="utf-8")

    opened = []

    class FakeEwfContainer:
        def __init__(self, fhs):
            opened.extend(os.path.basename(fh.name) for fh in fhs)

    class FakeDisks:
        def add(self, _container):
            pass

    class FakeTarget:
        def __init__(self):
            self.disks = FakeDisks()
            self._os_plugin = None

        def apply(self):
            pass

    import sys
    import types

    dissect_mod = types.ModuleType("dissect")
    target_mod = types.ModuleType("dissect.target")
    containers_mod = types.ModuleType("dissect.target.containers")
    ewf_mod = types.ModuleType("dissect.target.containers.ewf")
    target_mod.Target = FakeTarget
    ewf_mod.EwfContainer = FakeEwfContainer
    monkeypatch.setitem(sys.modules, "dissect", dissect_mod)
    monkeypatch.setitem(sys.modules, "dissect.target", target_mod)
    monkeypatch.setitem(sys.modules, "dissect.target.containers", containers_mod)
    monkeypatch.setitem(sys.modules, "dissect.target.containers.ewf", ewf_mod)

    from core.connectors.e01_image import E01ImageConnector

    connector = E01ImageConnector()
    connector._open_ewf(str(image))
    try:
        assert opened == ["Sample.E01", "Sample.E02"]
    finally:
        connector.disconnect()
