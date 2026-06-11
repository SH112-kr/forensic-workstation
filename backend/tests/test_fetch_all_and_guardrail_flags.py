"""Tests for D-1 fetch_all paging, C-1 guardrail disable flag, and
C-2 empty-result interpretation (SENIOR_ANALYST_PARITY_DIRECTIVES step 2)."""

from __future__ import annotations

import asyncio

import mcp_bridge


def _run(coro):
    return asyncio.run(coro)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


def _install_fixture_as_axiom(monkeypatch, fixture_name="case_paginated_evidence"):
    from regression.fixtures import load

    conn = load(fixture_name)
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setitem(mcp_bridge._connectors, "axiom", conn)
    monkeypatch.delitem(mcp_bridge._connectors, "raw_index", raising=False)
    return conn


# ── D-1: search_artifacts fetch_all ────────────────────────────────────────

def test_search_fetch_all_drains_filtered_family(monkeypatch):
    _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.search_artifacts(
        artifact_type="Encrypted Files", fetch_all=True,
    ))
    assert result["returned"] == 160
    assert result["truncated"] is False
    assert result["fetch_all"]["remaining_count"] == 0
    # Compact projection by default; full rows via get_hit_detail
    assert "projection" in result
    assert all("hit_id" in h for h in result["hits"])


def test_search_fetch_all_reports_budget_exhaustion_as_gap(monkeypatch):
    _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.search_artifacts(fetch_all=True))
    budget = result["fetch_all"]["max_pages"] * result["fetch_all"]["page_size"]
    assert result["total_estimated"] > budget
    assert result["returned"] == budget
    assert result["truncated"] is True
    assert result["fetch_all"]["remaining_count"] == result["total_estimated"] - budget
    assert "pagination_gap" in result


def test_search_fetch_all_rejects_all_cases(monkeypatch):
    _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.search_artifacts(fetch_all=True, all_cases=True))
    assert "error" in result


# ── D-1: build_timeline fetch_all ──────────────────────────────────────────

def test_timeline_fetch_all_reaches_deep_evidence(monkeypatch):
    conn = _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.build_timeline(fetch_all=True))
    assert result["returned"] == result["total_events"]
    assert result["truncated"] is False
    blob = " ".join(
        str(e.get("description", "")) for e in result["entries"]
    ).lower()
    assert "updsvc" in blob  # evidence beyond page 1 is present
    assert result["returned"] == len(conn.hits)


# ── C-2: empty_interpretation ──────────────────────────────────────────────

def test_search_empty_interpretation_uncollected_family(monkeypatch):
    _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.search_artifacts(
        artifact_type="SRUM Energy Usage",
    ))
    assert result["returned"] == 0
    assert result["empty_interpretation"]["status"] == "artifact_not_collected"


def test_search_empty_interpretation_zero_hits_on_collected_family(monkeypatch):
    _install_fixture_as_axiom(monkeypatch)
    result = _run(mcp_bridge.search_artifacts(
        keyword="zzz-no-such-token-zzz", artifact_type="Encrypted Files",
    ))
    assert result["returned"] == 0
    assert result["empty_interpretation"]["status"] == "evaluated_zero_hits"


def test_find_suspicious_empty_interpretation(monkeypatch):
    _install_fixture_as_axiom(monkeypatch, "case_empty_or_malformed")
    result = _run(mcp_bridge.find_suspicious(
        score_strength=False, include_provenance=False,
        apply_suppressions=False, include_rule_coverage=False,
    ))
    assert not result.get("findings")
    assert result["empty_interpretation"]["status"] in {
        "evaluated_zero_hits", "not_evaluable",
    }


# ── C-1: guardrail disable must be loud ────────────────────────────────────

def test_bias_surface_disabled_is_flagged(monkeypatch):
    from core.analysis import bias_remediation as br
    from regression.fixtures import load

    monkeypatch.setenv("FW_BIAS_REMEDIATION_DISABLE", "1")
    conn = load("case_empty_or_malformed")
    surface = br.build_bias_remediation_surface(conn, {"findings": []})
    assert surface["guardrails_active"] is False
    assert "guardrail_warning" in surface
    lane = br.build_lane_evidence_summary_surface(conn)
    assert lane["guardrails_active"] is False


def test_bias_surface_enabled_marks_active(monkeypatch):
    from core.analysis import bias_remediation as br
    from regression.fixtures import load

    monkeypatch.delenv("FW_BIAS_REMEDIATION_DISABLE", raising=False)
    conn = load("case_empty_or_malformed")
    surface = br.build_bias_remediation_surface(conn, {"findings": []})
    assert surface.get("guardrails_active") is True


def test_runtime_status_exposes_guardrail_state(monkeypatch):
    monkeypatch.delenv("FW_BIAS_REMEDIATION_DISABLE", raising=False)
    assert mcp_bridge._runtime_status()["guardrails_active"] is True
    monkeypatch.setenv("FW_BIAS_REMEDIATION_DISABLE", "1")
    assert mcp_bridge._runtime_status()["guardrails_active"] is False
