"""Unit tests for core.analysis.zero_results."""

from __future__ import annotations

from core.analysis.zero_results import explain_zero_results


def test_no_cases_loaded():
    r = explain_zero_results({}, tool_name="search_artifacts", params={"keyword": "admin"})
    causes = [c["cause"] for c in r["likely_causes"]]
    assert "no_cases_loaded" in causes
    # Follow-up must suggest open_case
    assert any(s["tool_name"] == "open_case" for s in r["suggested_queries"])


def test_structural_gap_detected(kape_case):
    r = explain_zero_results(
        {"axiom:b": kape_case},
        tool_name="search_artifacts",
        params={"artifact_type": "Chat Applications"},
    )
    causes = [c["cause"] for c in r["likely_causes"]]
    assert "structurally_unavailable" in causes


def test_date_after_case_window_flagged(kape_case):
    r = explain_zero_results(
        {"axiom:b": kape_case},
        tool_name="search_artifacts",
        params={"start_date": "2030-01-01", "artifact_type": "Prefetch"},
    )
    causes = [c["cause"] for c in r["likely_causes"]]
    assert "date_range_after_case" in causes
    # Suggest retry with no dates
    assert any(s["params"].get("start_date", "__"+"unset") == "" for s in r["suggested_queries"])


def test_stacked_filters_low_confidence(kape_case):
    r = explain_zero_results(
        {"axiom:b": kape_case},
        tool_name="search_artifacts",
        params={"keyword": "zzz", "artifact_type": "Prefetch", "start_date": "2026-04-01"},
    )
    causes = [c["cause"] for c in r["likely_causes"]]
    assert "filters_stacked" in causes


def test_always_suggests_coverage_explainer(kape_case):
    r = explain_zero_results({"axiom:b": kape_case}, tool_name="foo", params={})
    assert any(s["tool_name"] == "coverage_explainer" for s in r["suggested_queries"])
