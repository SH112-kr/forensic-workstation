from __future__ import annotations

import asyncio

import state
from api.artifacts import (
    GridRequest,
    SearchRequest,
    artifact_grid,
    get_hit_detail,
    get_tagged_hits,
    search_artifacts,
    search_by_hash,
    search_by_source,
)


def _run(coro):
    return asyncio.run(coro)


def test_get_tagged_hits_reports_raw_index_unsupported(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_tagged_hits("interesting"))

    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_tagged_hits_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_search_by_hash_reports_raw_index_unsupported(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_by_hash("deadbeef", limit=5))

    assert result["status"] == "not_evaluable"
    assert result["coverage_gap"]["reason"] == "raw_hash_search_unsupported"
    assert result["raw_index_coverage"]["status"] == "searched"


def test_get_tagged_hits_uses_axiom_when_raw_and_parsed_case_loaded(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _Axiom:
        def is_connected(self):
            return True

        def get_tagged_hits(self, tag_name=""):
            assert tag_name == "interesting"
            return {
                "total_tagged": 1,
                "hits": [{"hit_id": 7, "tag": "interesting"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_tagged_hits("interesting"))

    assert result["total_tagged"] == 1
    assert result["hits"][0]["hit_id"] == 7
    assert result.get("status") != "not_evaluable"


def test_search_by_hash_uses_axiom_when_raw_and_parsed_case_loaded(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_coverage(self):
            return {"status": "searched", "gaps": []}

    class _Axiom:
        def is_connected(self):
            return True

        def search_by_hash(self, hash_value, limit=50):
            assert hash_value == "deadbeef"
            assert limit == 5
            return {
                "total": 1,
                "hits": [{"hit_id": 9, "hash": "deadbeef"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_by_hash("deadbeef", limit=5))

    assert result["total"] == 1
    assert result["hits"][0]["hash"] == "deadbeef"
    assert result.get("status") != "not_evaluable"


def test_search_by_source_uses_active_raw_index(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "/c:/Tools"
            assert filters == {}
            assert limit == 5
            assert offset == 0
            return {
                "total": 1,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": 1,
                "hits": [{
                    "hit_id": 3,
                    "fields": {"Path": "/c:/Tools/agent.exe"},
                }],
            }

    class _State:
        _connectors = {"raw_index": _RawIndex()}

        def get(self, name):
            return self._connectors.get(name)

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_by_source("/c:/Tools", limit=5))

    assert result["total"] == 1
    assert result["count_accuracy"] == "exact"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_by_source_falls_back_to_axiom_when_raw_not_evaluable(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "/c:/Tools"
            assert filters == {}
            assert limit == 5
            assert offset == 0
            return {
                "ok": False,
                "status": "not_evaluable",
                "total": 0,
                "returned": 0,
                "hits": [],
                "coverage": {
                    "status": "not_evaluable",
                    "gaps": [{"error": "simulated source index gap"}],
                },
            }

    class _Axiom:
        def is_connected(self):
            return True

        def search_by_source(self, path_pattern, limit=50):
            assert path_pattern == "/c:/Tools"
            assert limit == 5
            return {
                "total": 1,
                "returned": 1,
                "hits": [{"hit_id": 31, "fields": {"Path": "/c:/Tools/agent.exe"}}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_by_source("/c:/Tools", limit=5))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_search_by_source_falls_back_to_axiom_when_raw_raises(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            raise RuntimeError("simulated raw source failure")

    class _Axiom:
        def is_connected(self):
            return True

        def search_by_source(self, path_pattern, limit=50):
            assert path_pattern == "/c:/Tools"
            assert limit == 5
            return {
                "total": 1,
                "returned": 1,
                "hits": [{"hit_id": 32, "fields": {"Path": "/c:/Tools/agent.exe"}}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_by_source("/c:/Tools", limit=5))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == "simulated raw source failure"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/agent.exe"


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


def test_get_hit_detail_falls_back_to_axiom_when_raw_detail_missing(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_hit_detail(self, hit_id):
            assert hit_id == 42
            return {"error": "artifact_id 42 not found"}

    class _Axiom:
        def is_connected(self):
            return True

        def get_hit_detail(self, hit_id):
            assert hit_id == 42
            return {
                "hit_id": 42,
                "fields": {"Path": "/c:/Tools/agent.exe"},
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_hit_detail(42))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "error"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == "artifact_id 42 not found"
    assert result["fields"]["Path"] == "/c:/Tools/agent.exe"


def test_get_hit_detail_falls_back_to_axiom_when_raw_raises(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def get_hit_detail(self, hit_id):
            assert hit_id == 42
            raise RuntimeError("simulated raw detail failure")

    class _Axiom:
        def is_connected(self):
            return True

        def get_hit_detail(self, hit_id):
            assert hit_id == 42
            return {
                "hit_id": 42,
                "fields": {"Path": "/c:/Tools/agent.exe"},
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(get_hit_detail(42))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == "simulated raw detail failure"
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


def test_search_api_falls_back_to_axiom_when_raw_not_evaluable(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            return {
                "ok": False,
                "status": "not_evaluable",
                "total": 0,
                "returned": 0,
                "hits": [],
                "coverage": {
                    "status": "not_evaluable",
                    "gaps": [{"error": "simulated parser failure"}],
                },
            }

    class _Axiom:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            assert filters == {
                "artifact_type": "Prefetch",
                "start_date": "",
                "end_date": "",
            }
            assert limit == 10
            assert offset == 0
            return {
                "total": 1,
                "returned": 1,
                "hits": [{"hit_id": 11, "artifact_type": "Prefetch"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_artifacts(SearchRequest(
        keyword="agent.exe",
        artifact_type="Prefetch",
        limit=10,
    )))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["hits"][0]["artifact_type"] == "Prefetch"


def test_search_api_falls_back_to_axiom_when_raw_raises(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            raise RuntimeError("simulated raw search failure")

    class _Axiom:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "agent.exe"
            assert filters == {
                "artifact_type": "Prefetch",
                "start_date": "",
                "end_date": "",
            }
            assert limit == 10
            assert offset == 0
            return {
                "total": 1,
                "returned": 1,
                "hits": [{"hit_id": 14, "artifact_type": "Prefetch"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(search_artifacts(SearchRequest(
        keyword="agent.exe",
        artifact_type="Prefetch",
        limit=10,
    )))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == "simulated raw search failure"
    assert result["hits"][0]["artifact_type"] == "Prefetch"


def test_artifact_grid_falls_back_to_axiom_when_raw_not_evaluable(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            return {
                "ok": False,
                "status": "not_evaluable",
                "total": 0,
                "returned": 0,
                "hits": [],
                "coverage": {
                    "status": "not_evaluable",
                    "gaps": [{"error": "simulated parser failure"}],
                },
            }

    class _Axiom:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "powershell.exe"
            assert filters == {"artifact_type": "Prefetch"}
            assert limit == 25
            assert offset == 0
            return {
                "total": 2,
                "returned": 1,
                "hits": [{"hit_id": 12, "artifact_type": "Prefetch"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(artifact_grid(GridRequest(
        startRow=0,
        endRow=25,
        filterModel={
            "keyword": {"filter": "powershell.exe"},
            "artifact_type": {"filter": "Prefetch"},
        },
    )))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["status"] == "not_evaluable"
    assert result["rowCount"] == 2
    assert result["rowData"][0]["artifact_type"] == "Prefetch"


def test_artifact_grid_falls_back_to_axiom_when_raw_raises(monkeypatch):
    class _RawIndex:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            raise RuntimeError("simulated raw grid failure")

    class _Axiom:
        def is_connected(self):
            return True

        def search(self, keyword="", filters=None, limit=50, offset=0):
            assert keyword == "powershell.exe"
            assert filters == {"artifact_type": "Prefetch"}
            assert limit == 25
            assert offset == 0
            return {
                "total": 2,
                "returned": 1,
                "hits": [{"hit_id": 13, "artifact_type": "Prefetch"}],
            }

    axiom = _Axiom()

    class _State:
        _connectors = {
            "raw_index": _RawIndex(),
            "axiom": axiom,
            "axiom:case": axiom,
        }

        def get(self, name):
            return self._connectors.get(name)

        def get_axiom(self):
            return axiom

    monkeypatch.setattr(state, "app_state", _State())

    result = _run(artifact_grid(GridRequest(
        startRow=0,
        endRow=25,
        filterModel={
            "keyword": {"filter": "powershell.exe"},
            "artifact_type": {"filter": "Prefetch"},
        },
    )))

    assert result["fallback_source"] == "parsed_case"
    assert result["raw_index_status"] == "not_evaluable"
    assert result["raw_index_coverage"]["gaps"][0]["error"] == "simulated raw grid failure"
    assert result["rowData"][0]["artifact_type"] == "Prefetch"


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
