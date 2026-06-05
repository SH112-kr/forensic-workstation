from __future__ import annotations

import asyncio

import state
from api.cases import (
    ExplainZeroRequest,
    PivotRequest,
    get_artifact_types,
    get_compare,
    get_coverage,
    get_summary,
    post_explain_zero,
    post_pivot,
)


def _run(coro):
    return asyncio.run(coro)


def test_cases_summary_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
                "case_name": "Raw Index",
                "total_hits": 2,
            }

        def get_artifact_type_counts(self):
            return [{
                "artifact_name": "File System Entry",
                "hit_count": 2,
            }]

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_summary())

    assert result["source_type"] == "raw_image_sidecar"
    assert result["source_path"] == "raw-index.sqlite"
    assert result["case_name"] == "Raw Index"
    assert result["artifact_type_count"] == 1
    assert result["artifact_types"] == {"File System Entry": 2}
    assert result["coverage"]["status"] == "searched"


def test_cases_types_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_artifact_type_counts(self):
            return [{
                "artifact_name": "File System Entry",
                "hit_count": 2,
            }]

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_artifact_types())

    assert result["artifact_types"] == [{
        "artifact_name": "File System Entry",
        "hit_count": 2,
    }]
    assert result["total_types"] == 1
    assert result["source_type"] == "raw_image_sidecar"
    assert result["coverage"]["status"] == "searched"


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


def test_cases_coverage_includes_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {"source_type": "raw_image_sidecar"}

        def get_artifact_type_counts(self):
            return [{
                "artifact_name": "File System Entry",
                "hit_count": 2,
            }]

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_coverage("File System Entry"))

    assert result["case_context"]["case_format"] == "raw_image_sidecar"
    assert result["coverage"][0]["artifact_type"] == "File System Entry"
    assert result["coverage"][0]["status"] == "searched"
    assert result["coverage"][0]["record_count"] == 2
    assert result["coverage"][0]["cases"] == ["raw_index"]


def test_cases_explain_zero_includes_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {"source_type": "raw_image_sidecar"}

        def get_artifact_type_counts(self):
            return [{
                "artifact_name": "File System Entry",
                "hit_count": 2,
            }]

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(post_explain_zero(ExplainZeroRequest(
        tool_name="search_artifacts",
        params={"artifact_type": "Prefetch"},
    )))

    causes = [c["cause"] for c in result["likely_causes"]]
    assert "raw_artifact_family_not_indexed" in causes
    assert result["case_context"]["case_format"] == "raw_image_sidecar"
