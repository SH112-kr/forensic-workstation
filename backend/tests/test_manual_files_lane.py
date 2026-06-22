from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeManualFilesE01:
    def list_directory(self, path="/"):
        assert path == "/c:/ProgramData"
        return [
            {"name": "tool.exe", "path": "/c:/ProgramData/tool.exe", "is_dir": False, "size": 4096},
            {"name": "notes.txt", "path": "/c:/ProgramData/notes.txt", "is_dir": False, "size": 128},
            {"name": "Subdir", "path": "/c:/ProgramData/Subdir", "is_dir": True},
        ]

    def find_files(self, pattern, path="/", limit=100):
        assert pattern == "*.exe"
        assert path == "/c:/ProgramData"
        assert limit == 25
        return [
            {"path": "/c:/ProgramData/tool.exe", "is_dir": False, "size": 4096},
            {"path": "/c:/ProgramData/other.exe", "is_dir": False, "size": 2048},
        ]


def test_manual_file_browse_lists_current_filesystem_with_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeManualFilesE01(), r"D:\cases\host.E01"))

    result = _run(manual.browse_files(manual.FileBrowseRequest(path="/c:/ProgramData", limit=10)))

    assert result["analyst_only"] is True
    assert result["source"] == "current_filesystem"
    assert result["returned"] == 3
    assert result["files"][0]["name"] == "tool.exe"
    assert result["searched"]["path"] == "/c:/ProgramData"
    assert any("current filesystem" in note.lower() for note in result["coverage_notes"])
    assert any("not evidence of absence" in note.lower() for note in result["coverage_notes"])


def test_manual_file_search_filters_keyword_and_keeps_limits(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeManualFilesE01(), r"D:\cases\host.E01"))

    result = _run(manual.search_files(manual.FileSearchRequest(
        path="/c:/ProgramData",
        pattern="*.exe",
        keyword="tool",
        recursive=True,
        limit=25,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "current_filesystem"
    assert result["searched"]["limit"] == 25
    assert result["returned"] == 1
    assert result["files"][0]["path"].endswith("tool.exe")
    assert any("bounded" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_files_lane_has_stable_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/files/browse" in src
    assert "/api/manual/files/search" in src
    assert "Browse path" in src
    assert "Search current layer" in src
    assert "fileRoot" in src
    assert "filePattern" in src
    assert "Current filesystem search is bounded" in src
    assert "gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px 112px'" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
