from __future__ import annotations

import asyncio

import state
from api.timeline import TimelineRequest, build_timeline


def _run(coro):
    return asyncio.run(coro)


def test_timeline_api_default_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_timeline(
            self,
            start_date="",
            end_date="",
            artifact_types=None,
            limit=200,
            offset=0,
        ):
            assert start_date == "2026-10-01"
            assert end_date == "2026-10-31"
            assert artifact_types == ["File System Entry"]
            assert limit == 10
            assert offset == 0
            return {
                "total_events": 1,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 1,
                "entries": [{
                    "hit_id": 1,
                    "timestamp": "2026-10-04T00:00:00Z",
                    "artifact_type": "File System Entry",
                    "description": "File System Entry /c:/Tools/agent.exe",
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(build_timeline(TimelineRequest(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        limit=10,
    )))

    assert result["total_events"] == 1
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["entries"][0]["artifact_type"] == "File System Entry"


def test_timeline_api_all_cases_includes_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def get_timeline(
            self,
            start_date="",
            end_date="",
            artifact_types=None,
            limit=200,
            offset=0,
        ):
            assert start_date == "2026-10-01"
            assert end_date == "2026-10-31"
            assert artifact_types == ["File System Entry"]
            return {
                "total_events": 1,
                "returned": 1,
                "entries": [{
                    "hit_id": 1,
                    "timestamp": "2026-10-04T00:00:00Z",
                    "artifact_type": "File System Entry",
                    "description": "File System Entry /c:/Tools/agent.exe",
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(build_timeline(TimelineRequest(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        limit=10,
        all_cases=True,
    )))

    assert result["total_events"] == 1
    assert result["returned"] == 1
    assert result["entries"][0]["case_id"] == "raw_index"
    assert result["entries"][0]["source_type"] == "raw_image_sidecar"
