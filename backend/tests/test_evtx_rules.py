"""Unit tests for core.analysis.evtx_rules (lightweight Sigma-style pack)."""

from __future__ import annotations

from core.analysis.evtx_rules import BUILTIN_RULES, _rule_matches, hunt_evtx_rules


def test_every_rule_has_required_fields():
    required = {"id", "title", "severity", "event_ids", "any", "mitre", "tags"}
    for rule in BUILTIN_RULES:
        missing = required - set(rule.keys())
        assert not missing, f"Rule {rule.get('id')} missing fields: {missing}"
        assert rule["severity"] in {"low", "medium", "high", "critical"}
        assert isinstance(rule["event_ids"], list) and rule["event_ids"]
        assert rule["mitre"], f"Rule {rule['id']} has no MITRE technique"


def test_rule_id_uniqueness():
    ids = [r["id"] for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids)), "Duplicate rule ids found"


def test_matcher_any_mode():
    rule = {"event_ids": [4674], "any": ["SeDebug", "SeTcb"]}
    assert _rule_matches(rule, {"Event Data": "SeDebug privilege used"})
    assert _rule_matches(rule, {"Event Data": "SeTcb assigned"})
    assert not _rule_matches(rule, {"Event Data": "SeChangeNotifyPrivilege used"})


def test_matcher_eid_only_when_any_empty():
    rule = {"event_ids": [4625], "any": []}
    # Any row is acceptable — the connector pre-filtered by EID, we don't gate further.
    assert _rule_matches(rule, {"foo": "bar"})


class _FakeAQ:
    """Minimal ArtifactQueries stand-in for hunt_evtx_rules."""

    def __init__(self, rows_by_eid: dict[int, list[dict]]):
        self.rows = rows_by_eid

    def query_event_logs(self, event_ids=None, limit=0, provider=""):
        out: list[dict] = []
        for eid in event_ids or []:
            out.extend(self.rows.get(eid, []))
        return out


def test_hunt_returns_only_fired_rules():
    aq = _FakeAQ({
        4625: [{"hit_id": 1, "Event ID": 4625, "Event Data": "failed login"}],
        4720: [{"hit_id": 2, "Event ID": 4720, "Event Data": "new account"}],
    })
    r = hunt_evtx_rules(aq, limit_per_rule=5)
    fired_ids = {res["rule_id"] for res in r["results"] if res.get("match_count")}
    assert "fw-evtx-001" in fired_ids  # 4625 failed logon
    assert "fw-evtx-002" in fired_ids  # 4720 account create
    # Rules whose EIDs returned no rows should be absent from results.
    assert all(r.get("match_count", 0) > 0 for r in r["results"])


def test_severity_filter_skips_low():
    aq = _FakeAQ({4625: [{"Event ID": 4625}], 4776: [{"Event ID": 4776}]})
    r = hunt_evtx_rules(aq, severity_min="medium")
    fired_ids = {res["rule_id"] for res in r["results"]}
    # fw-evtx-005 (NTLM auth, 4776) is low severity — should be filtered out.
    assert "fw-evtx-005" not in fired_ids
    assert "fw-evtx-001" in fired_ids
