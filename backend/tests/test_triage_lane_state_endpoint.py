from __future__ import annotations

from fastapi.testclient import TestClient


class _StubState:
    def get_axiom(self):
        return object()


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
        },
    )

    client = TestClient(main.app)
    response = client.get("/api/triage/lane-state")

    assert response.status_code == 200
    payload = response.json()
    assert payload["lane_evidence_summary"]["execution_impact"]["event_count"] == 12
    assert payload["lane_evidence_summary"]["ingress_access"]["artifact_families_seen"] == ["evtx_4624"]

    # Old verdict fields must be absent
    assert "lane_state_board" not in payload
    assert "allow_strong_conclusion" not in payload


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
