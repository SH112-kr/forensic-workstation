"""Tests for the B-1 Sigma YAML subset loader."""

from __future__ import annotations

import pytest

from core.analysis import sigma_loader as sl


# ── convert_sigma_rule: supported subset ───────────────────────────────────

def test_convert_basic_eventid_and_contains():
    doc = {
        "title": "Test rule",
        "id": "abc-123",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4688,
                          "CommandLine|contains": ["whoami", "nltest"]},
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.t1059.001", "attack.execution"],
    }
    out = sl.convert_sigma_rule(doc, source_file="t.yml")
    assert out["ok"] is True
    rule = out["rule"]
    assert rule["event_ids"] == [4688]
    assert "whoami" in rule["any"] and "nltest" in rule["any"]
    assert rule["severity"] == "high"
    assert "T1059.001" in rule["mitre"]
    assert rule["provenance"]["origin"] == "sigma-community"
    assert rule["id"].startswith("sigma:")


def test_convert_eventid_list():
    doc = {"title": "x", "logsource": {"product": "windows"},
           "detection": {"selection": {"EventID": [4624, 4625]},
                         "condition": "selection"}}
    out = sl.convert_sigma_rule(doc)
    assert out["ok"] is True
    assert out["rule"]["event_ids"] == [4624, 4625]


# ── convert_sigma_rule: declined features (not approximated) ───────────────

@pytest.mark.parametrize("doc,expected_reason", [
    ({"logsource": {"product": "linux"},
      "detection": {"selection": {"EventID": 1}, "condition": "selection"}},
     "non_windows_logsource"),
    ({"logsource": {"product": "windows"},
      "detection": {"selection": {"EventID": 1}, "condition": "1 of them"}},
     "unsupported_condition"),
    ({"logsource": {"product": "windows"},
      "detection": {"selection": {"CommandLine|re": "foo.*"}, "condition": "selection"}},
     "unsupported_modifier"),
    ({"logsource": {"product": "windows"},
      "detection": {"selection": {"Image|contains|all": ["a", "b"]}, "condition": "selection"}},
     "unsupported_modifier"),
    ({"logsource": {"product": "windows"},
      "detection": {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}},
     "no_event_id"),
])
def test_declined_features_have_reasons(doc, expected_reason):
    out = sl.convert_sigma_rule(doc)
    assert out["ok"] is False
    assert out["reason"] == expected_reason


# ── load_sigma_dir over the shipped sample ─────────────────────────────────

def test_load_sigma_dir_loads_sample():
    import os
    from core.analysis.evtx_rules import _sigma_dir

    result = sl.load_sigma_dir(_sigma_dir())
    assert result["stats"]["ok"] is True
    ids = {r["id"] for r in result["rules"]}
    assert any("sampledelete01" in i for i in ids)
    sample = next(r for r in result["rules"] if "sampledelete01" in r["id"])
    assert sample["event_ids"] == [4688]
    assert "shadowcopy delete" in sample["any"]


def test_load_sigma_dir_missing_dir_is_graceful():
    result = sl.load_sigma_dir("/no/such/sigma/dir")
    assert result["stats"]["ok"] is True
    assert result["rules"] == []


# ── hunt_evtx_rules integration ────────────────────────────────────────────

def test_hunt_evtx_rules_includes_sigma_load_stats():
    from core.analysis.evtx_rules import hunt_evtx_rules

    class _AQ:
        def query_event_logs(self, event_ids=None, limit=0, **kw):
            return []

    out = hunt_evtx_rules(_AQ(), include_sigma=True)
    assert "sigma_load" in out
    assert out["rule_pack"] == "builtin+sigma"
    assert out["sigma_load"]["stats"]["ok"] is True


def test_sigma_rule_fires_and_keeps_provenance():
    from core.analysis.evtx_rules import hunt_evtx_rules

    class _AQ:
        def query_event_logs(self, event_ids=None, limit=0, **kw):
            if event_ids and 4688 in event_ids:
                return [{"hit_id": 1, "Event ID": 4688,
                         "Event Data": "cmd: wmic shadowcopy delete /nointeractive",
                         "Provider Name": "Microsoft-Windows-Security-Auditing"}]
            return []

    out = hunt_evtx_rules(_AQ(), include_sigma=True)
    sigma_hits = [r for r in out["results"]
                  if r.get("provenance", {}).get("origin") == "sigma-community"
                  and r.get("match_count")]
    assert sigma_hits, "sample Sigma rule did not fire on matching event"
    assert sigma_hits[0]["rule_id"].startswith("sigma:")


def test_hunt_evtx_rules_can_disable_sigma():
    from core.analysis.evtx_rules import hunt_evtx_rules

    class _AQ:
        def query_event_logs(self, event_ids=None, limit=0, **kw):
            return []

    out = hunt_evtx_rules(_AQ(), include_sigma=False)
    assert "sigma_load" not in out
    assert out["rule_pack"] == "builtin"
