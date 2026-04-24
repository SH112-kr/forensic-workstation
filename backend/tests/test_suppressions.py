"""Unit tests for core.analysis.suppressions."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from core.analysis import suppressions as sup


def _patch_store(tmp_path, monkeypatch):
    store = str(tmp_path / "suppressions.json")
    monkeypatch.setattr(sup, "_STORE", store)
    return store


def test_add_and_list(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    r = sup.add_suppression("evtx_eid_4624_type10_rdp_logons", reason="Admin jump box", analyst="Alice")
    assert r["ok"] is True
    lst = sup.list_suppressions()
    assert lst["count"] == 1
    assert lst["entries"][0]["rule_id"] == "evtx_eid_4624_type10_rdp_logons"
    assert lst["entries"][0]["analyst"] == "Alice"


def test_add_replaces_same_rule_id(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    sup.add_suppression("rule_x", reason="first")
    sup.add_suppression("rule_x", reason="updated")
    lst = sup.list_suppressions()
    assert lst["count"] == 1
    assert lst["entries"][0]["reason"] == "updated"


def test_reason_required(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    r = sup.add_suppression("rule_x", reason="  ")
    assert r["ok"] is False
    assert "reason" in r["error"].lower()


def test_remove(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    sup.add_suppression("rule_x", reason="test")
    r = sup.remove_suppression("rule_x")
    assert r["ok"] is True
    assert r["removed"] == 1
    assert sup.list_suppressions()["count"] == 0


def test_apply_moves_findings_to_suppressed_without_dropping(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    sup.add_suppression("rule_x", reason="tuned out")
    payload = {
        "findings": [
            {"rule_name": "rule_x", "severity": "high", "matching_count": 5},
            {"rule_name": "rule_y", "severity": "critical", "matching_count": 1},
        ],
    }
    sup.apply_suppressions(payload)
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_name"] == "rule_y"
    assert len(payload["suppressed"]) == 1
    # Suppressed finding retains all original fields PLUS the suppression entry.
    suppressed = payload["suppressed"][0]
    assert suppressed["rule_name"] == "rule_x"
    assert suppressed["matching_count"] == 5
    assert suppressed["suppression"]["reason"] == "tuned out"
    assert payload["suppression_summary"]["suppressed_in_this_run"] == 1


def test_expired_suppression_is_not_applied(tmp_path, monkeypatch):
    _patch_store(tmp_path, monkeypatch)
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    sup.add_suppression("rule_expired", reason="old", expires_at=past)
    payload = {"findings": [{"rule_name": "rule_expired", "severity": "medium"}]}
    sup.apply_suppressions(payload)
    # Expired entry should NOT suppress the finding.
    assert len(payload["findings"]) == 1
    assert len(payload["suppressed"]) == 0
    # And we should get a note so it's visible.
    assert "suppression_notes" in payload
    assert any("expired" in n.lower() for n in payload["suppression_notes"])
