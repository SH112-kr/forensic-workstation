from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeManualVssE01:
    def list_vss_snapshots(self, volume="/c:"):
        return {
            "ok": True,
            "volume": volume,
            "snapshot_count": 1,
            "snapshots": [
                {
                    "snapshot_id": "snap-1",
                    "snapshot_index": 0,
                    "snapshot_creation_time": "2026-03-08T23:11:00Z",
                    "temporal_layer": "vss:0:snap-1",
                }
            ],
        }

    def vss_find_files_with_coverage(self, snapshot_id, pattern, path="/", volume="/c:", limit=100):
        assert snapshot_id == "snap-1"
        assert pattern == "*.exe"
        assert path == "/c:/ProgramData"
        assert volume == "/c:"
        assert limit == 25
        return {
            "files": [
                {
                    "path": "/c:/ProgramData/tool.exe",
                    "name": "tool.exe",
                    "is_dir": False,
                    "size": 4096,
                    "snapshot_id": snapshot_id,
                    "temporal_layer": "vss:0:snap-1",
                },
                {
                    "path": "/c:/ProgramData/readme.txt",
                    "name": "readme.txt",
                    "is_dir": False,
                    "size": 64,
                    "snapshot_id": snapshot_id,
                    "temporal_layer": "vss:0:snap-1",
                },
            ],
            "coverage": {
                "paths_scanned": 10,
                "paths_skipped": 1,
                "coverage_gap": "1 paths unexamined in snapshot snap-1.",
            },
        }


def test_manual_vss_snapshots_attaches_temporal_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeManualVssE01(), r"D:\cases\host.E01"))

    result = _run(manual.list_manual_vss_snapshots(volume="/c:"))

    assert result["analyst_only"] is True
    assert result["source"] == "vss_snapshot_catalog"
    assert result["snapshot_count"] == 1
    assert result["snapshots"][0]["snapshot_id"] == "snap-1"
    assert any("historical" in note.lower() for note in result["coverage_notes"])
    assert any("verified-clean baseline" in note.lower() for note in result["guardrails"])


def test_manual_vss_search_filters_keyword_and_keeps_coverage_notes(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeManualVssE01(), r"D:\cases\host.E01"))

    result = _run(manual.search_vss_files(manual.VssFileSearchRequest(
        snapshot_id="snap-1",
        volume="/c:",
        path="/c:/ProgramData",
        pattern="*.exe",
        keyword="tool",
        recursive=True,
        limit=25,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "vss_snapshot"
    assert result["snapshot_id"] == "snap-1"
    assert result["searched"]["limit"] == 25
    assert result["returned"] == 1
    assert result["files"][0]["path"].endswith("tool.exe")
    assert result["coverage"]["paths_skipped"] == 1
    assert any("not absence evidence" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_vss_lane_has_stable_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/vss/snapshots" in src
    assert "/api/manual/vss/files/search" in src
    assert "Load snapshots" in src
    assert "Search VSS layer" in src
    assert "vssSnapshotId" in src
    assert "VSS snapshots are historical layers" in src
    assert "gridTemplateColumns: 'minmax(130px, 160px) minmax(180px, 1fr) minmax(120px, 180px)'" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
