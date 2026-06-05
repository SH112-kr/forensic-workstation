from __future__ import annotations

import asyncio

import state
from api.cases import PivotRequest, get_compare, post_pivot


def _run(coro):
    return asyncio.run(coro)


def test_cases_compare_includes_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def get_artifact_type_counts(self):
            return [{
                "artifact_name": "File System Entry",
                "hit_count": 1,
            }]

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_compare())

    assert result["case_count"] == 1
    assert result["metadata"][0]["case_id"] == "raw_index"
    assert result["artifact_counts"]["matrix"]["File System Entry"] == {
        "raw_index": 1,
    }


def test_cases_pivot_includes_active_raw_index(monkeypatch):
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
            return {
                "total": 1,
                "returned": 1,
                "hits": [{
                    "hit_id": 7,
                    "timestamp": "2026-10-04T00:00:00Z",
                    "fields": {"Path": "/c:/Tools/agent.exe"},
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(post_pivot(PivotRequest(
        entity_type="keyword",
        entity_value="agent.exe",
        limit_per_case=10,
    )))

    assert result["case_count"] == 1
    assert result["per_case_counts"] == {"raw_index": 1}
    assert result["hits"][0]["case_id"] == "raw_index"
    assert result["hits"][0]["source_type"] == "raw_image_sidecar"
