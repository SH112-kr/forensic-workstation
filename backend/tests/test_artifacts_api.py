from __future__ import annotations

import asyncio

import state
from api.artifacts import SearchRequest, search_artifacts


def _run(coro):
    return asyncio.run(coro)


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
