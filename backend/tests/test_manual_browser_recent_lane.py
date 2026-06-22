from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeBrowserRecentE01:
    def find_files(self, pattern, path="/", limit=100):
        assert path == "/c:/Users"
        rows = {
            "History": [
                {"path": "/c:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", "is_dir": False, "size": 4096},
            ],
            "places.sqlite": [
                {"path": "/c:/Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite", "is_dir": False, "size": 2048},
            ],
            "*.lnk": [
                {"path": "/c:/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/doc.lnk", "is_dir": False, "size": 512},
            ],
        }
        return rows.get(pattern, [])[:limit]


def test_manual_browser_recent_sources_discovers_sensitive_user_activity_inputs(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeBrowserRecentE01(), r"D:\cases\host.E01"))

    result = _run(manual.browser_recent_sources(limit=20))

    assert result["analyst_only"] is True
    assert result["source"] == "browser_recent_source_discovery"
    assert result["summary"]["browser_history_count"] == 2
    assert result["summary"]["recent_lnk_count"] == 1
    assert result["returned"] == 3
    assert any("sensitive user-activity" in note.lower() for note in result["coverage_notes"])
    assert any("not prove download" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_browser_recent_lane_has_stable_discovery_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/browser-recent/sources" in src
    assert "Load browser/recent sources" in src
    assert "browserRecentLoading" in src
    assert "Browser / Recent source discovery lists sensitive user-activity source files only" in src
    assert "Browser history" in src
    assert "Recent LNK" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
