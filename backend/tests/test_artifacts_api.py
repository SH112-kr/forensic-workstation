from __future__ import annotations

import asyncio

import state
from api.artifacts import (
    GridRequest,
    SearchRequest,
    artifact_grid,
    get_hit_detail,
    search_artifacts,
)


def _run(coro):
    return asyncio.run(coro)


def test_artifact_grid_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            assert filters == {"artifact_type": "File System Entry"}
            assert limit == 25
            assert offset == 25
            return {
                "total": 3,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 1,
                "hits": [{
                    "hit_id": 2,
                    "fields": {"Path": "/c:/Tools/agent.exe"},
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(artifact_grid(GridRequest(
        startRow=25,
        endRow=50,
        filterModel={
            "keyword": {"filter": "agent.exe"},
            "artifact_type": {"filter": "File System Entry"},
        },
    )))

    assert result["rowData"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"
    assert result["rowCount"] == 3
    assert result["count_accuracy"] == "exact"


def test_get_hit_detail_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_hit_detail(self, hit_id):
            assert hit_id == 42
            return {
                "hit_id": 42,
                "fields": {"Path": "/c:/Tools/agent.exe"},
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_hit_detail(42))

    assert result["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_api_default_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            assert filters == {
                "artifact_type": "File System Entry",
                "start_date": "2026-10-01",
                "end_date": "2026-10-31",
            }
            assert limit == 10
            assert offset == 0
            return {
                "total": 1,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 1,
                "hits": [{
                    "hit_id": 1,
                    "timestamp": "2026-10-04T00:00:00Z",
                    "fields": {"Path": "/c:/Tools/agent.exe"},
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_artifacts(SearchRequest(
        keyword="agent.exe",
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )))

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_api_all_cases_includes_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            assert filters["artifact_type"] == "File System Entry"
            return {
                "total": 1,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 1,
                "hits": [{
                    "hit_id": 1,
                    "timestamp": "2026-10-04T00:00:00Z",
                    "fields": {"Path": "/c:/Tools/agent.exe"},
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_artifacts(SearchRequest(
        keyword="agent.exe",
        artifact_type="File System Entry",
        limit=10,
        all_cases=True,
    )))

    assert result["total"] == 1
    assert result["returned"] == 1
    assert result["hits"][0]["case_id"] == "raw_index"
    assert result["hits"][0]["source_type"] == "raw_image_sidecar"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"
