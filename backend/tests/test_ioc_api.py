from __future__ import annotations

import asyncio


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


class _RawConnector:
    def __init__(self, coverage=None):
        self._coverage = coverage or {"status": "searched", "gaps": []}

    def is_connected(self):
        return True

    def get_coverage(self):
        return self._coverage


class _RawOnlyState:
    def __init__(self, coverage=None):
        self._connectors = {"raw_index": _RawConnector(coverage)}

    def get(self, name):
        return self._connectors.get(name)

    def get_axiom(self):
        raise AssertionError("raw-only API must not request AXIOM")


def test_extract_iocs_reports_raw_index_unsupported(monkeypatch):
    import state
    from api.ioc import IOCRequest, extract_iocs

    monkeypatch.setattr(state, "app_state", _RawOnlyState())

    payload = _run(extract_iocs(IOCRequest(
        ioc_types="ip,domain",
        exclude_private_ips=True,
        exclude_known_good=True,
    )))

    assert payload["ok"] is False
    assert payload["status"] == "not_evaluable"
    assert payload["source_type"] == "raw_image_sidecar"
    assert payload["ioc_types"] == ["ip", "domain"]
    assert payload["iocs"] == []
    assert payload["coverage_gap"]["reason"] == "raw_ioc_extraction_unsupported"
    assert payload["raw_index_coverage"]["status"] == "searched"


def test_extract_iocs_preserves_raw_index_not_evaluable_coverage(monkeypatch):
    import state
    from api.ioc import IOCRequest, extract_iocs

    coverage = {
        "status": "not_evaluable",
        "gaps": [{"error": "simulated parser failure"}],
    }
    monkeypatch.setattr(state, "app_state", _RawOnlyState(coverage))

    payload = _run(extract_iocs(IOCRequest()))

    assert payload["ok"] is False
    assert payload["status"] == "not_evaluable"
    assert payload["coverage_gap"]["reason"] == "raw_ioc_extraction_unsupported"
    assert payload["raw_index_coverage"]["status"] == "not_evaluable"
    assert payload["raw_index_coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_correlate_reports_raw_pivot_unsupported(monkeypatch):
    import state
    from api.ioc import CorrelateRequest, correlate

    monkeypatch.setattr(state, "app_state", _RawOnlyState())

    payload = _run(correlate(CorrelateRequest(
        pivot_field="user",
        pivot_value="analyst",
    )))

    assert payload["ok"] is False
    assert payload["status"] == "not_evaluable"
    assert payload["source_type"] == "raw_image_sidecar"
    assert payload["pivot_field"] == "user"
    assert payload["pivot_value"] == "analyst"
    assert payload["coverage_gap"]["reason"] == "raw_correlate_pivot_unsupported"
    assert payload["raw_index_coverage"]["status"] == "searched"
