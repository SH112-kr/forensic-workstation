from __future__ import annotations

from fastapi.testclient import TestClient


class _StubState:
    def get_axiom(self):
        return object()


class _RawConnector:
    def is_connected(self):
        return True

    def get_coverage(self):
        return {"status": "searched", "gaps": []}


class _RawOnlyState:
    _connectors = {"raw_index": _RawConnector()}

    def get(self, name):
        return self._connectors.get(name)

    def get_axiom(self):
        raise AssertionError("raw-only endpoint must not request AXIOM")


def test_lane_state_endpoint_returns_lane_evidence_summary(monkeypatch):
    import state
    import main
    import core.analysis.bias_remediation as bias_remediation

    monkeypatch.setattr(state, "app_state", _StubState())
    monkeypatch.setattr(
        bias_remediation,
        "build_lane_evidence_summary_surface",
        lambda *_args, **_kwargs: {
            "lane_evidence_summary": {
                "ingress_access": {"artifact_families_seen": ["evtx_4624"], "event_count": 5},
                "execution_impact": {"artifact_families_seen": ["prefetch"], "event_count": 12},
                "persistence_cleanup": {"artifact_families_seen": [], "event_count": 0},
            },
            "lane_state_board": {
                "ingress_access": {"state": "suggested"},
                "execution_impact": {"state": "confirmed"},
                "persistence_cleanup": {"state": "not_seen"},
                "blocked_lanes": ["persistence_cleanup"],
                "allow_strong_conclusion": False,
            },
        },
    )

    client = TestClient(main.app)
    response = client.get("/api/triage/lane-state")

    assert response.status_code == 200
    payload = response.json()
    assert payload["lane_evidence_summary"]["execution_impact"]["event_count"] == 12
    assert payload["lane_evidence_summary"]["ingress_access"]["artifact_families_seen"] == ["evtx_4624"]

    assert payload["lane_state_board"]["allow_strong_conclusion"] is False


def test_lane_state_endpoint_returns_empty_when_disabled(monkeypatch):
    import state
    import main
    import core.analysis.bias_remediation as bias_remediation

    monkeypatch.setattr(state, "app_state", _StubState())
    monkeypatch.setattr(
        bias_remediation,
        "build_lane_evidence_summary_surface",
        lambda *_args, **_kwargs: {},
    )

    client = TestClient(main.app)
    response = client.get("/api/triage/lane-state")

    assert response.status_code == 200
    assert response.json() == {}


def test_lane_state_endpoint_reports_raw_index_unsupported(monkeypatch):
    import state
    import main

    monkeypatch.setattr(state, "app_state", _RawOnlyState())

    client = TestClient(main.app)
    response = client.get("/api/triage/lane-state")

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert payload["status"] == "not_evaluable"
    assert payload["source_type"] == "raw_image_sidecar"
    assert payload["lane_evidence_summary"] == {}
    assert payload["lane_state_board"]["allow_strong_conclusion"] is False
    assert payload["coverage_gap"]["reason"] == "raw_lane_state_unsupported"
    assert payload["raw_index_coverage"]["status"] == "searched"
