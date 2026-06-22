from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeRegistryEvtxE01:
    def find_files(self, pattern, path="/", limit=100):
        assert pattern == "*.evtx"
        assert path == "/c:/Windows/System32/winevt/Logs"
        assert limit == 25
        return [
            {"path": "/c:/Windows/System32/winevt/Logs/Security.evtx", "is_dir": False, "size": 8192},
            {"path": "/c:/Windows/System32/winevt/Logs/System.evtx", "is_dir": False, "size": 4096},
        ]

    def get_file_info(self, internal_path):
        if internal_path.endswith("/SYSTEM") or internal_path.endswith("/SOFTWARE"):
            return {
                "path": internal_path,
                "exists": True,
                "is_dir": False,
                "size": 1024,
                "modified": "2026-03-08T23:11:00Z",
            }
        return {"path": internal_path, "error": "not found"}


def test_manual_evtx_files_lists_candidate_logs_with_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeRegistryEvtxE01(), r"D:\cases\host.E01"))

    result = _run(manual.list_evtx_files(limit=25))

    assert result["analyst_only"] is True
    assert result["source"] == "evtx_file_discovery"
    assert result["returned"] == 2
    assert result["files"][0]["path"].endswith("Security.evtx")
    assert any("event log file presence" in note.lower() for note in result["coverage_notes"])
    assert any("not parsed event activity" in note.lower() for note in result["coverage_notes"])


def test_manual_registry_hives_lists_existing_core_hives(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeRegistryEvtxE01(), r"D:\cases\host.E01"))

    result = _run(manual.list_registry_hives())

    assert result["analyst_only"] is True
    assert result["source"] == "registry_hive_discovery"
    assert result["returned"] == 2
    assert {item["name"] for item in result["hives"]} == {"SYSTEM", "SOFTWARE"}
    assert any("configuration state" in note.lower() for note in result["coverage_notes"])


def test_manual_evtx_query_filters_offline_records_with_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (object(), r"D:\cases\host.E01"))
    monkeypatch.setattr(
        manual,
        "_materialize_manual_artifact",
        lambda _e01, internal_path, _tmpdir, kind: (r"C:\tmp\Security.evtx", {
            "source": "mounted_image",
            "internal_path": internal_path,
            "kind": kind,
        }),
    )

    def fake_parse(local_path, target_event_ids, parse_limit):
        assert local_path == r"C:\tmp\Security.evtx"
        assert target_event_ids == {7045}
        assert parse_limit == 5000
        return {
            "ok": True,
            "records": [
                {"event_id": 7045, "timestamp": "2026-03-08T23:11:00Z", "fields": {"ServiceName": "uploadmgr"}},
                {"event_id": 4624, "timestamp": "2026-03-08T23:12:00Z", "fields": {"TargetUserName": "alice"}},
            ],
            "record_count": 2,
            "event_id_counts": {7045: 1, 4624: 1},
            "parser_failures": [],
            "parser_backend": "unit",
            "recovery": {"chunks_failed": 0},
        }

    def fake_filter(records, *, event_ids, keyword, start_date, end_date, limit, offset):
        assert len(records) == 2
        assert event_ids == {7045}
        assert keyword == "uploadmgr"
        assert start_date == ""
        assert end_date == ""
        assert limit == 25
        assert offset == 0
        return {
            "total": 1,
            "returned": 1,
            "records": [records[0]],
            "summary": {"event_id_counts": {"7045": 1}},
            "truncated": False,
        }

    monkeypatch.setattr(manual, "_parse_manual_evtx_file", fake_parse)
    monkeypatch.setattr(manual, "_filter_manual_evtx_records", fake_filter)

    result = _run(manual.query_evtx(manual.EvtxQueryRequest(
        evtx_path="/c:/Windows/System32/winevt/Logs/Security.evtx",
        event_ids="7045",
        keyword="uploadmgr",
        limit=25,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "evtx_query"
    assert result["input_source"] == "mounted_image"
    assert result["parsed_record_count"] == 2
    assert result["event_id_counts_in_sample"][7045] == 1
    assert result["filtered"]["returned"] == 1
    assert result["filtered"]["records"][0]["fields"]["ServiceName"] == "uploadmgr"
    assert any("offline evtx" in note.lower() for note in result["coverage_notes"])
    assert any("not evidence of absence" in note.lower() for note in result["coverage_notes"])


def test_manual_registry_query_reads_direct_key_with_guardrails(monkeypatch):
    from api import manual

    class FakeRegistryConnector:
        def connect(self, local_hive):
            assert local_hive == r"C:\tmp\SYSTEM"
            return {"status": "success", "hive_type": "SYSTEM"}

        def get_key(self, key_path):
            assert key_path == r"\ControlSet001\Services\uploadmgr"
            return {
                "path": key_path,
                "timestamp": "2026-03-08 23:11:00",
                "values": [{"name": "ImagePath", "type": "REG_EXPAND_SZ", "value": r"C:\Windows\System32\svchost.exe"}],
                "subkeys": [],
            }

        def disconnect(self):
            return None

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (object(), r"D:\cases\host.E01"))
    monkeypatch.setattr(
        manual,
        "_materialize_manual_artifact",
        lambda _e01, internal_path, _tmpdir, kind: (r"C:\tmp\SYSTEM", {
            "source": "mounted_image",
            "internal_path": internal_path,
            "kind": kind,
        }),
    )
    monkeypatch.setattr(manual, "_registry_connector", lambda: FakeRegistryConnector())

    result = _run(manual.query_registry(manual.RegistryQueryRequest(
        hive_path="/c:/Windows/System32/config/SYSTEM",
        key_path=r"\ControlSet001\Services\uploadmgr",
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "registry_query"
    assert result["query_mode"] == "key"
    assert result["resolved_key_path"] == r"\ControlSet001\Services\uploadmgr"
    assert result["values"][0]["name"] == "ImagePath"
    assert any("configuration state" in note.lower() for note in result["coverage_notes"])
    assert any("does not prove execution" in note.lower() for note in result["coverage_notes"])


def test_manual_registry_query_blocks_unbounded_keyword_search(monkeypatch):
    from api import manual

    def should_not_materialize(*_args, **_kwargs):
        raise AssertionError("unbounded keyword query should be rejected before extraction")

    monkeypatch.setattr(manual, "_materialize_manual_artifact", should_not_materialize)

    result = _run(manual.query_registry(manual.RegistryQueryRequest(
        hive_path="/c:/Windows/System32/config/SYSTEM",
        keyword="uploadmgr",
    )))

    assert result["ok"] is False
    assert "search_root" in result["error"]
    assert result["query_semantics"]["search_root_required"] is True
    assert any("not evidence of absence" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_registry_evtx_lane_has_stable_discovery_and_query_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/evtx/files" in src
    assert "/api/manual/registry/hives" in src
    assert "/api/manual/evtx/query" in src
    assert "/api/manual/registry/query" in src
    assert "Load EVTX files" in src
    assert "Load registry hives" in src
    assert "Query EVTX" in src
    assert "Query registry" in src
    assert "registryEvtxLoading" in src
    assert "evtxQueryPath" in src
    assert "registryHivePath" in src
    assert "EVTX and registry discovery lists candidate source files" in src
    assert "Registry state proves captured hive contents" in src
    assert "gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))'" in src
    assert "gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px'" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
