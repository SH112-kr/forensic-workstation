from __future__ import annotations

from api import ioc as ioc_api
from core.analysis.ioc_graph import build_analysis_session_graph, build_ioc_mitre_graph


class _SearchableConnector:
    def is_connected(self):
        return True

    def get_metadata(self):
        return {"case_name": "Raw Demo"}

    def search(self, keyword="", filters=None, limit=50, offset=0):
        return {
            "hits": [
                {
                    "artifact_type": "Browser History",
                    "description": "Visited http://evil.example.com/a.exe from 9.9.9.9",
                    "location": r"C:\Users\Analyst\History",
                    "fields": {"sha256": "a" * 64},
                },
                {
                    "artifact_type": "Event Logs",
                    "description": "Private 10.0.0.5 and known good microsoft.com should be filtered",
                    "location": "",
                    "fields": {},
                },
            ]
        }


def test_ioc_graph_builds_raw_fallback_without_mitre_overclaim():
    graph = build_ioc_mitre_graph(
        {"raw_index": _SearchableConnector()},
        exclude_private_ips=True,
        exclude_known_good=True,
    )

    assert graph["ok"] is True
    assert graph["source_mode"] == "raw_image_sidecar"
    assert any(n["type"] == "ioc" and n["label"] == "evil.example.com" for n in graph["nodes"])
    assert any(n["type"] == "ioc" and n["label"] == "9.9.9.9" for n in graph["nodes"])
    assert not any(n["type"] == "ioc" and n["label"] == "10.0.0.5" for n in graph["nodes"])
    assert not any(n["type"] == "ioc" and n["label"] == "microsoft.com" for n in graph["nodes"])
    assert not any(e["type"] == "maps_to_mitre" and e["source"].startswith("ioc:") for e in graph["edges"])
    assert any("parsed AXIOM/KAPE" in w for w in graph["warnings"])


def test_analysis_session_graph_uses_only_accumulated_mcp_events():
    events = [
        {
            "type": "response",
            "tool": "extract_iocs",
            "result": {
                "iocs": [
                    {
                        "ioc_type": "domain",
                        "value": "evil.example.com",
                        "count": 2,
                        "source_artifact_types": ["Browser History"],
                    }
                ]
            },
        },
        {
            "type": "response",
            "tool": "find_suspicious",
            "result": {
                "findings": [
                    {
                        "rule_name": "powershell_scriptblock",
                        "severity": "high",
                        "matching_count": 3,
                        "mitre_techniques": ["T1059.001"],
                        "details": [{"artifact_type": "Windows Event Logs"}],
                    }
                ]
            },
        },
    ]

    graph = build_analysis_session_graph(events)

    assert graph["source_mode"] == "analysis_session"
    assert any(n["type"] == "tool" and n["label"] == "extract_iocs" for n in graph["nodes"])
    assert any(n["type"] == "ioc" and n["label"] == "evil.example.com" for n in graph["nodes"])
    assert any(n["type"] == "mitre" and n["label"] == "T1059.001" for n in graph["nodes"])
    assert not any(e["type"] == "maps_to_mitre" and e["source"].startswith("ioc:") for e in graph["edges"])


def test_manual_observation_store_round_trips_without_global_state(tmp_path, monkeypatch):
    store_path = tmp_path / "manual_graph.json"
    monkeypatch.setattr(ioc_api, "_manual_graph_store_path", lambda: str(store_path))

    item = ioc_api._new_manual_graph_observation(
        ioc_api.ManualGraphObservationRequest(
            node_type="ioc",
            value="8.8.8.8",
            ioc_type="ipv4",
            source_label="Firewall",
            note="external analyst note",
        )
    )
    ioc_api._write_manual_graph_observations([item])
    loaded = ioc_api._read_manual_graph_observations()

    assert loaded == [item]
    assert loaded[0]["source_type"] == "analyst_external"
    assert loaded[0]["visibility"] == "analyst_only"
