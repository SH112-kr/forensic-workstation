"""Tests for investigation_gap_report composition.

Codex Round-14 WAIT fixes this suite covers:
  1. findings_payload=None -> findings_available=False and skipped_sections
     lists the three sections that require findings.
  2. weak-only findings -> pivots_not_attempted is empty (we must not push
     the analyst toward corroboration-bias tool chains for weak signals).
  3. snapshot_slug pointing at hit_ids absent from every loaded case ->
     bucket_gaps.stale_references flags them.
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest import mock

import pytest

from core.analysis.investigation_gap import (
    _PIVOT_MAP,
    investigation_gap_report,
)


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
    # Codex R14b: only findings-dependent sections are skipped.
    # pivots_not_attempted still emits from anti-forensic rules independently.
    assert set(r["skipped_sections"]) == {"detection_gaps", "corroboration_gaps"}
    assert r["detection_gaps"] == []
    assert r["corroboration_gaps"] == []
    # pivots_not_attempted is NOT skipped — it may be empty here because no
    # anti-forensic rules fired on the stub, but the section is live.
    assert "pivots_not_attempted" not in r["skipped_sections"]
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


# ── (2) pivots suppressed for weak-only findings ──────────────────────────

def test_weak_finding_does_not_generate_pivot_suggestions():
    connectors = {"axiom:a": _StubConnector()}
    # Use a rule_name that IS in the pivot table so we know the suppression —
    # not a missing-entry — is what killed the pivot.
    findings = {
        "findings": [
            {
                "rule_name": "persistence_service_install",
                "overall_strength": "weak",
                "absent_corroboration": ["no_event_log_7045"],
                "details": [],
            },
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    # The finding must still show up as a corroboration gap (analyst needs
    # to see it) but no pivot tool suggestion should land.
    corr = [c for c in r["corroboration_gaps"]
            if c["rule_name"] == "persistence_service_install"]
    assert corr, "weak finding should still appear in corroboration_gaps"
    assert r["pivots_not_attempted"] == []


def test_moderate_finding_does_generate_pivot_when_mapped():
    connectors = {"axiom:a": _StubConnector()}
    # persistence_service_install is in _PIVOT_MAP.
    assert "persistence_service_install" in _PIVOT_MAP
    findings = {
        "findings": [
            {
                "rule_name": "persistence_service_install",
                "overall_strength": "moderate",
                "details": [],
            },
        ],
        "unevaluable_rules": [],
    }
    r = investigation_gap_report(connectors, findings_payload=findings)
    pivots = [p for p in r["pivots_not_attempted"]
              if p["rule_name"] == "persistence_service_install"]
    assert pivots, "moderate finding with mapped rule must surface a pivot"
    assert pivots[0]["suggested_pivots"]


# ── (3) bucket_gaps flags stale hit_ids ──────────────────────────────────

def test_stale_bucket_hit_ids_are_flagged():
    # Connector exposes hit_ids 1, 2, 3. Snapshot bucket references 2, 999
    # (stale) — we expect 999 in stale_references.
    connector = _StubConnector(search_hits=[
        {"hit_id": 1, "timestamp": "2026-04-01", "artifact_type": "Prefetch"},
        {"hit_id": 2, "timestamp": "2026-04-02", "artifact_type": "Prefetch"},
        {"hit_id": 3, "timestamp": "2026-04-03", "artifact_type": "Prefetch"},
    ])
    connectors = {"axiom:a": connector}

    with tempfile.TemporaryDirectory() as td:
        # Point case_snapshot at a clean directory so we can drop a fake file.
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
    # And hit 2 (which IS loaded) must not appear in stale_hit_ids.
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
    assert r["ok"] is True  # top-level is still OK — only bucket_gaps failed
    assert r["bucket_gaps"]["ok"] is False
    assert "Snapshot not found" in r["bucket_gaps"]["error"] \
        or "does_not_exist" in r["bucket_gaps"]["error"]


# ── smoke + schema stability ─────────────────────────────────────────────

def test_top_level_keys_are_stable():
    r = investigation_gap_report({"axiom:a": _StubConnector()}, findings_payload=None)
    required = {
        "ok", "findings_available", "skipped_sections", "substrate_gaps",
        "detection_gaps", "corroboration_gaps", "pivots_not_attempted",
        "bucket_gaps", "recommended_next_queries", "notes",
    }
    assert required.issubset(set(r.keys()))


def test_substrate_gap_surfaced_when_high_value_family_missing():
    thin = _StubConnector(artifact_counts=[
        {"artifact_name": "Windows Event Logs", "hit_count": 50_000},
        # No Prefetch / AmCache / Services / Tasks -> high-severity fail.
    ])
    r = investigation_gap_report({"axiom:a": thin}, findings_payload=None)
    names = [g["check_name"] for g in r["substrate_gaps"]]
    assert "high_value_families_empty" in names
    # And a next-query is recommended.
    assert any(q["tool_name"] == "case_health" for q in r["recommended_next_queries"])


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


# ── Codex R14b post-review additions ──────────────────────────────────────

@pytest.mark.parametrize("bad_payload", [
    {"findings": "bad"},          # str instead of list
    {"findings": [1, 2, 3]},      # list of non-dicts
    {"findings": None},            # None
    {"findings": {"k": "v"}},     # dict instead of list
    {},                             # missing key entirely
])
def test_malformed_dict_payload_falls_back_to_absent(bad_payload):
    """Codex R14b: a malformed findings shape must NOT crash downstream
    .get() calls. _load_optional_findings validates shape strictly."""
    connectors = {"axiom:a": _StubConnector()}
    r = investigation_gap_report(connectors, findings_payload=bad_payload)
    assert r["ok"] is True
    assert r["findings_available"] is False
    assert "detection_gaps" in r["skipped_sections"]


def test_pivot_params_reference_real_tool_signatures():
    """Codex R14b: every pivot suggestion's params must match the actual MCP
    tool signature. Guards against typos in _PIVOT_MAP that would only
    surface at runtime."""
    from core.analysis.investigation_gap import _PIVOT_MAP

    # Known tool signatures (name -> accepted param keys). Adding a new
    # pivot target tool? Add it here.
    known_tool_params = {
        "search_logs": {"keyword", "limit", "offset"},
        "build_timeline": {"artifact_types", "start_date", "end_date", "limit"},
        "find_suspicious": {"rules", "score_strength", "include_provenance",
                            "apply_suppressions", "include_rule_coverage"},
        "search_artifacts": {"keyword", "artifact_type", "start_date",
                              "end_date", "limit", "offset"},
        "get_file_timestamps": {"file_path"},
        "baseline_diff": {"reference_case_id", "categories"},
        "search_by_hash": {"hash_value", "limit"},
    }

    for rule_name, pivots in _PIVOT_MAP.items():
        for pivot in pivots:
            tool = pivot["tool_name"]
            assert tool in known_tool_params, \
                f"{rule_name} maps to unknown tool {tool!r}"
            bad = set(pivot.get("params", {}).keys()) - known_tool_params[tool]
            assert not bad, \
                f"{rule_name}->{tool} has unknown params {bad}"


def test_bucket_verification_capped_suppresses_stale_flags():
    """Codex R14b: when per-case cap is hit, stale references must NOT be
    reported — the union of loaded hit_ids is incomplete."""
    # Build a connector that returns exactly the cap count.
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
                # hit_id 999_999 is NOT in search_hits (which only goes 0..49999)
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
    # stale_references must be empty when capped — we cannot trust the union.
    assert bg["stale_references"] == []
    assert any("verification_capped" in n for n in r["notes"])


def test_bucket_gaps_handles_no_axiom_connectors():
    """Codex R14b: a snapshot_slug with only non-axiom or disconnected
    connectors should not crash. All bucket hit_ids become 'stale' because
    nothing is loaded, but verification_capped is False."""
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

    # Top-level must still be OK; bucket_gaps should report both hit_ids as stale.
    assert r["ok"] is True
    bg = r["bucket_gaps"]
    assert bg["ok"] is True
    assert bg["verification_capped"] is False
    b1_stale = [s for s in bg["stale_references"] if s["bucket"] == "b1"]
    assert b1_stale and set(b1_stale[0]["stale_hit_ids"]) == {1, 2}
