"""Tests for investigation_gap_report composition.

Covers:
  1. findings_payload=None -> findings_available=False and skipped_sections
     lists the two sections that require findings.
  2. truncation_gaps surfaces mandatory pagination gaps for capped findings.
  3. snapshot_slug pointing at hit_ids absent from every loaded case ->
     bucket_gaps.stale_references flags them.
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest import mock

import pytest

from core.analysis.investigation_gap import investigation_gap_report


class _StubConnector:
    def __init__(self, source_type="kape", source_path="C:/cases/a",
                 artifact_counts=None, search_hits=None):
        self._source_type = source_type
        self._source_path = source_path
        self._artifact_counts = artifact_counts or [
            {"artifact_name": "Windows Event Logs", "hit_count": 50_000},
            {"artifact_name": "Prefetch Files - Windows 8/10/11", "hit_count": 500},
            {"artifact_name": "AmCache File Entries", "hit_count": 2000},
            {"artifact_name": "System Services", "hit_count": 200},
            {"artifact_name": "Scheduled Tasks", "hit_count": 150},
        ]
        self._search_hits = search_hits or []

    def is_connected(self): return True
    def get_metadata(self):
        return {
            "source_type": self._source_type,
            "source_path": self._source_path,
            "date_range_start": "2026-03-01T00:00:00",
            "date_range_end": "2026-04-15T00:00:00",
            "case_name": "stub",
        }
    def get_artifact_type_counts(self): return list(self._artifact_counts)
    def search(self, keyword="", limit=50, offset=0, **_):
        return {"hits": list(self._search_hits)[:limit], "total": len(self._search_hits)}


# ── (1) findings_available + skipped_sections ────────────────────────────

def test_no_findings_payload_sets_findings_available_false():
    connectors = {"axiom:a": _StubConnector()}
    r = investigation_gap_report(connectors, findings_payload=None)
    assert r["ok"] is True
    assert r["findings_available"] is False
    # Only findings-dependent sections are skipped.
    assert set(r["skipped_sections"]) == {"detection_gaps", "corroboration_gaps"}
    assert r["detection_gaps"] == []
    assert r["corroboration_gaps"] == []
    assert r["truncation_gaps"] == []
    # A note must make the absence explicit so a consumer can't read it as "clean".
    assert any("findings_payload was not supplied" in n for n in r["notes"])


def test_with_findings_payload_no_skipped_sections():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    assert r["findings_available"] is True
    assert r["skipped_sections"] == []


# ── corroboration_gaps emits facts, no hint field ─────────────────────────

def test_corroboration_gaps_emits_required_fields_no_hint():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "overall_strength": "weak",
                "absent_corroboration": ["no_event_log_7045"],
                "details": [],
            },
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    corr = [c for c in r["corroboration_gaps"]
            if c["rule_name"] == "evtx_eid_7045_service_installs"]
    assert corr, "finding should appear in corroboration_gaps"
    gap = corr[0]
    assert "rule_name" in gap
    assert "absent_corroboration" in gap
    assert "hint" not in gap
    assert "overall_strength" not in gap


# ── (2) truncation_gaps ───────────────────────────────────────────────────

def test_truncated_finding_generates_mandatory_pivot():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "overall_strength": "strong",
                "matching_count": 248,
                "returned_count": 20,
                "truncated": True,
                "detail_cap": 20,
                "details": [],
            }
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    assert len(r["truncation_gaps"]) == 1
    pivot = r["truncation_gaps"][0]
    assert pivot["rule_name"] == "evtx_eid_7045_service_installs"
    assert pivot["severity"] == "mandatory"
    assert pivot["remaining_unseen"] == 228
    assert pivot["matching_count"] == 248
    assert pivot["returned_count"] == 20
    assert pivot["suggested_pivots"][0]["tool_name"] == "find_suspicious"
    assert pivot["suggested_pivots"][0]["params"]["rules"] == "evtx_eid_7045_service_installs"


def test_non_truncated_finding_does_not_generate_truncation_pivot():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_1102_audit_log_cleared",
                "overall_strength": "confirmed",
                "matching_count": 3,
                "returned_count": 3,
                "truncated": False,
                "detail_cap": 20,
                "details": [],
            }
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    assert r["truncation_gaps"] == []


def test_truncation_gaps_absent_when_findings_not_supplied():
    connectors = {"axiom:a": _StubConnector()}
    r = investigation_gap_report(connectors, findings_payload=None)
    assert r["truncation_gaps"] == []


def test_multiple_truncated_findings_each_generate_pivot():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "overall_strength": "strong",
                "matching_count": 248,
                "returned_count": 20,
                "truncated": True,
                "detail_cap": 20,
                "details": [],
            },
            {
                "rule_name": "evtx_eid_4624_type10_rdp_logons",
                "overall_strength": "high",
                "matching_count": 50,
                "returned_count": 20,
                "truncated": True,
                "detail_cap": 20,
                "details": [],
            },
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    assert len(r["truncation_gaps"]) == 2
    rule_names = {p["rule_name"] for p in r["truncation_gaps"]}
    assert rule_names == {"evtx_eid_7045_service_installs", "evtx_eid_4624_type10_rdp_logons"}


# ── (3) bucket_gaps flags stale hit_ids ──────────────────────────────────

def test_stale_bucket_hit_ids_are_flagged():
    connector = _StubConnector(search_hits=[
        {"hit_id": 1, "timestamp": "2026-04-01", "artifact_type": "Prefetch"},
        {"hit_id": 2, "timestamp": "2026-04-02", "artifact_type": "Prefetch"},
        {"hit_id": 3, "timestamp": "2026-04-03", "artifact_type": "Prefetch"},
    ])
    connectors = {"axiom:a": connector}

    with tempfile.TemporaryDirectory() as td:
        state_dir = os.path.join(td, "snapshots")
        os.makedirs(state_dir, exist_ok=True)

        snap_path = os.path.join(state_dir, "stale_test.json")
        snap_payload = {
            "slug": "stale_test",
            "name": "Stale Test",
            "saved_at": "2026-04-20T00:00:00",
            "case_ids": ["a"],
            "active_case_id": "a",
            "tagged_hits": [],
            "tagged_hits_by_bucket": {"payload_files": [2, 999]},
            "bucket_display_names": {"payload_files": "Payload Files"},
            "bucket_hypotheses": {},
            "schema": "fw.case_snapshot.v2",
        }
        with open(snap_path, "w", encoding="utf-8") as f:
            json.dump(snap_payload, f)

        with mock.patch("core.analysis.case_snapshot._STATE_DIR", state_dir):
            r = investigation_gap_report(
                connectors,
                findings_payload=None,
                snapshot_slug="stale_test",
            )

    bg = r["bucket_gaps"]
    assert bg is not None and bg["ok"] is True
    assert bg["verification_capped"] is False
    stale = [s for s in bg["stale_references"] if s["bucket"] == "payload_files"]
    assert stale, "bucket with hit_id 999 absent from the case must flag stale"
    assert 999 in stale[0]["stale_hit_ids"]
    assert 2 not in stale[0]["stale_hit_ids"]


def test_missing_snapshot_returns_error_without_crashing():
    connectors = {"axiom:a": _StubConnector()}
    with tempfile.TemporaryDirectory() as td:
        with mock.patch("core.analysis.case_snapshot._STATE_DIR", td):
            r = investigation_gap_report(
                connectors,
                findings_payload=None,
                snapshot_slug="does_not_exist",
            )
    assert r["ok"] is True
    assert r["bucket_gaps"]["ok"] is False
    assert "Snapshot not found" in r["bucket_gaps"]["error"] \
        or "does_not_exist" in r["bucket_gaps"]["error"]


# ── smoke + schema stability ─────────────────────────────────────────────

def test_top_level_keys_are_stable():
    r = investigation_gap_report({"axiom:a": _StubConnector()}, findings_payload=None)
    required = {
        "ok", "findings_available", "skipped_sections", "substrate_gaps",
        "detection_gaps", "corroboration_gaps", "truncation_gaps",
        "bucket_gaps", "recommended_next_queries", "notes",
    }
    assert required.issubset(set(r.keys()))
    # pivots_not_attempted is gone — replaced by truncation_gaps
    assert "pivots_not_attempted" not in r


def test_substrate_gap_surfaced_when_high_value_family_missing():
    thin = _StubConnector(artifact_counts=[
        {"artifact_name": "Windows Event Logs", "hit_count": 50_000},
    ])
    r = investigation_gap_report({"axiom:a": thin}, findings_payload=None)
    names = [g["check_name"] for g in r["substrate_gaps"]]
    assert "high_value_families_empty" in names
    # recommended_next_queries is always empty — LLM decides next steps
    assert r["recommended_next_queries"] == []


def test_findings_payload_accepts_json_string():
    connectors = {"axiom:a": _StubConnector()}
    payload = json.dumps({"findings": [], "unevaluable_rules": []})
    r = investigation_gap_report(connectors, findings_payload=payload)
    assert r["findings_available"] is True


def test_malformed_json_string_falls_back_to_absent():
    connectors = {"axiom:a": _StubConnector()}
    r = investigation_gap_report(connectors, findings_payload="{not valid json")
    assert r["findings_available"] is False
    assert "detection_gaps" in r["skipped_sections"]


def test_schema_stability_with_truncation_gaps():
    connectors = {"axiom:a": _StubConnector()}
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "overall_strength": "strong",
                "matching_count": 100,
                "returned_count": 20,
                "truncated": True,
                "detail_cap": 20,
                "details": [],
            }
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    required = {
        "ok", "findings_available", "skipped_sections", "substrate_gaps",
        "detection_gaps", "corroboration_gaps", "truncation_gaps",
        "bucket_gaps", "recommended_next_queries", "notes",
    }
    assert required.issubset(set(r.keys()))


# ── Codex R14b post-review additions ──────────────────────────────────────

@pytest.mark.parametrize("bad_payload", [
    {"findings": "bad"},
    {"findings": [1, 2, 3]},
    {"findings": None},
    {"findings": {"k": "v"}},
    {},
])
def test_malformed_dict_payload_falls_back_to_absent(bad_payload):
    connectors = {"axiom:a": _StubConnector()}
    r = investigation_gap_report(connectors, findings_payload=bad_payload)
    assert r["ok"] is True
    assert r["findings_available"] is False
    assert "detection_gaps" in r["skipped_sections"]


def test_bucket_verification_capped_suppresses_stale_flags():
    per_case_cap = 50_000
    many_hits = [{"hit_id": i} for i in range(per_case_cap)]
    connector = _StubConnector(search_hits=many_hits)
    connectors = {"axiom:a": connector}

    with tempfile.TemporaryDirectory() as td:
        snap_path = os.path.join(td, "capped.json")
        with open(snap_path, "w", encoding="utf-8") as f:
            json.dump({
                "slug": "capped",
                "name": "Capped",
                "saved_at": "2026-04-20T00:00:00",
                "case_ids": ["a"],
                "active_case_id": "a",
                "tagged_hits": [],
                "tagged_hits_by_bucket": {"payload_files": [1, 999_999]},
                "bucket_display_names": {"payload_files": "Payload"},
                "bucket_hypotheses": {},
                "schema": "fw.case_snapshot.v2",
            }, f)
        with mock.patch("core.analysis.case_snapshot._STATE_DIR", td):
            r = investigation_gap_report(
                connectors, findings_payload=None, snapshot_slug="capped",
            )

    bg = r["bucket_gaps"]
    assert bg["ok"] is True
    assert bg["verification_capped"] is True
    assert bg["stale_references"] == []
    assert any("verification_capped" in n for n in r["notes"])


def test_bucket_gaps_handles_no_axiom_connectors():
    class _DisconnectedConnector:
        def is_connected(self): return False
        def search(self, **_): return {"hits": [], "total": 0}
        def get_metadata(self): return {}
        def get_artifact_type_counts(self): return []

    connectors = {"axiom:a": _DisconnectedConnector()}

    with tempfile.TemporaryDirectory() as td:
        snap_path = os.path.join(td, "isolated.json")
        with open(snap_path, "w", encoding="utf-8") as f:
            json.dump({
                "slug": "isolated",
                "name": "Isolated",
                "saved_at": "2026-04-20T00:00:00",
                "case_ids": ["a"],
                "active_case_id": "a",
                "tagged_hits": [],
                "tagged_hits_by_bucket": {"b1": [1, 2]},
                "bucket_display_names": {"b1": "B1"},
                "bucket_hypotheses": {},
                "schema": "fw.case_snapshot.v2",
            }, f)
        with mock.patch("core.analysis.case_snapshot._STATE_DIR", td):
            r = investigation_gap_report(
                connectors, findings_payload=None, snapshot_slug="isolated",
            )

    assert r["ok"] is True
    bg = r["bucket_gaps"]
    assert bg["ok"] is True
    assert bg["verification_capped"] is False
    b1_stale = [s for s in bg["stale_references"] if s["bucket"] == "b1"]
    assert b1_stale and set(b1_stale[0]["stale_hit_ids"]) == {1, 2}
