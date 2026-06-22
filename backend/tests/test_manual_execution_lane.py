from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeExecutionE01:
    def get_file_info(self, internal_path):
        if internal_path.endswith("Amcache.hve") or internal_path.endswith("/SYSTEM"):
            return {"path": internal_path, "size": 1024, "modified": "2026-03-08T23:11:00Z"}
        return {"path": internal_path, "error": "not found"}

    def find_files(self, pattern, path="/", limit=100):
        assert pattern == "NTUSER.DAT"
        assert path == "/c:/Users"
        assert limit == 20
        return [
            {"path": "/c:/Users/alice/NTUSER.DAT", "is_dir": False, "size": 2048},
            {"path": "/c:/Users/bob/NTUSER.DAT", "is_dir": False, "size": 1024},
        ]


class _FakePrefetchE01:
    def list_directory(self, directory):
        assert directory == "/c:/Windows/Prefetch"
        return [
            {"name": "POWERSHELL.EXE-11111111.pf", "path": "/c:/Windows/Prefetch/POWERSHELL.EXE-11111111.pf", "is_dir": False, "size": 512},
            {"name": "CMD.EXE-22222222.pf", "path": "/c:/Windows/Prefetch/CMD.EXE-22222222.pf", "is_dir": False, "size": 512},
        ]

    def find_files(self, pattern, path="/", limit=100):
        raise AssertionError("list_directory should satisfy the prefetch query candidate search")

    def read_file_content(self, internal_path, max_size=0):
        assert max_size == 4 * 1024 * 1024
        return internal_path.encode("utf-8")


def test_manual_execution_sources_discovers_parser_inputs_with_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeExecutionE01(), r"D:\cases\host.E01"))

    result = _run(manual.execution_sources(limit=20))

    assert result["analyst_only"] is True
    assert result["source"] == "execution_source_discovery"
    assert result["summary"]["amcache_present"] is True
    assert result["summary"]["system_hive_present"] is True
    assert result["summary"]["user_hive_count"] == 2
    assert result["returned"] == 4
    assert any("parser inputs" in note.lower() for note in result["coverage_notes"])
    assert any("not standalone execution proof" in note.lower() for note in result["coverage_notes"])


def test_manual_prefetch_query_parses_and_filters_execution_records(monkeypatch):
    from api import manual

    def fake_parse(data, source_path):
        text = data.decode("utf-8")
        exe = "POWERSHELL.EXE" if "POWERSHELL" in text else "CMD.EXE"
        return {
            "ok": True,
            "source_path": source_path,
            "executable_name": exe,
            "run_count": 3,
            "latest_run_time_utc": "2026-03-08T23:11:00Z" if exe == "POWERSHELL.EXE" else "2026-03-07T10:00:00Z",
            "raw_referenced_paths": [
                r"\VOLUME{abc}\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                if exe == "POWERSHELL.EXE"
                else r"\VOLUME{abc}\Windows\System32\cmd.exe"
            ],
            "guardrails": {
                "standalone_verdict_allowed": False,
                "absence_is_negative_evidence": False,
                "referenced_paths_are_execution_evidence": False,
            },
        }

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakePrefetchE01(), r"D:\cases\host.E01"))
    monkeypatch.setattr(manual, "_parse_manual_prefetch_bytes", fake_parse)

    result = _run(manual.query_prefetch(manual.PrefetchQueryRequest(
        directory="/c:/Windows/Prefetch",
        pattern="*.pf",
        keyword="powershell",
        limit=10,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "prefetch_query"
    assert result["searched"]["source_path_count"] == 2
    assert result["total"] == 1
    assert result["returned"] == 1
    assert result["entries"][0]["executable_name"] == "POWERSHELL.EXE"
    assert result["entries"][0]["guardrails"]["standalone_verdict_allowed"] is False
    assert any("prefetch is execution evidence" in note.lower() for note in result["coverage_notes"])
    assert any("referenced paths" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_execution_lane_has_stable_discovery_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/execution/sources" in src
    assert "/api/manual/prefetch/query" in src
    assert "Load execution sources" in src
    assert "Query Prefetch" in src
    assert "executionLoading" in src
    assert "prefetchDirectory" in src
    assert "prefetchPattern" in src
    assert "prefetchKeyword" in src
    assert "Execution source discovery lists parser inputs" in src
    assert "Prefetch is execution evidence" in src
    assert "AmCache" in src
    assert "User hives" in src
    assert "gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px'" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
