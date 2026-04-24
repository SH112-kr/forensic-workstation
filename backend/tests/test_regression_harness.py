"""Tests for the LLM regression harness (Tier A5).

These tests cover the harness infrastructure: FW_FIXTURE preload gate,
fixture connector interface, ground truth schema, prompt versioning,
metrics, ingest parser, and report formatting. LLM execution itself is
manual and not tested here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ── FW_FIXTURE preload gate ────────────────────────────────────────────────

def test_preload_is_noop_without_env(monkeypatch):
    monkeypatch.delenv("FW_FIXTURE", raising=False)
    from regression import preload

    class _Stub:
        def __init__(self):
            self._connectors = {}
            self.set_called = False

        def set(self, name, c):
            self.set_called = True

    stub = _Stub()
    preload.preload_fixture_if_requested(stub)
    assert stub._connectors == {}
    assert stub.set_called is False


def test_preload_loads_known_fixture(monkeypatch, capsys):
    monkeypatch.setenv("FW_FIXTURE", "case_ransomware_inc_like")
    from regression import preload

    class _Stub:
        def __init__(self):
            self._connectors = {}

        def set(self, name, c):
            self._connectors[name] = c

    stub = _Stub()
    preload.preload_fixture_if_requested(stub)
    assert "axiom" in stub._connectors
    assert "axiom:fixture" in stub._connectors
    out = capsys.readouterr().out
    assert "Preloaded fixture: case_ransomware_inc_like" in out


def test_preload_rejects_unknown_fixture(monkeypatch):
    monkeypatch.setenv("FW_FIXTURE", "does_not_exist_fixture_abc")
    from regression import preload

    class _Stub:
        def __init__(self):
            self._connectors = {}

        def set(self, name, c):
            self._connectors[name] = c

    stub = _Stub()
    with pytest.raises(SystemExit):
        preload.preload_fixture_if_requested(stub)


# ── Fixture connector interface ────────────────────────────────────────────

FIXTURES = [
    "case_ransomware_inc_like",
    "case_benign_remote_work",
    "case_partial_evidence",
    "case_insider_data_exfil",
    "case_anti_forensics_heavy",
    "case_empty_or_malformed",
]


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_fixture_connector_satisfies_interface(fixture_name):
    from regression.fixtures import load as load_fixture

    conn = load_fixture(fixture_name)
    # Core connector interface
    assert conn.is_connected() is True
    meta = conn.get_metadata()
    assert isinstance(meta, dict)
    assert meta.get("case_name")
    counts = conn.get_artifact_type_counts()
    assert isinstance(counts, list)
    for row in counts:
        assert "artifact_name" in row or "artifact_type" in row
        assert "hit_count" in row or "count" in row
    # search
    result = conn.search(keyword="", filters={}, limit=10)
    assert isinstance(result, dict)
    assert "hits" in result
    # timeline
    tl = conn.get_timeline(limit=10)
    assert isinstance(tl, dict)
    assert "entries" in tl
    # artifact_queries property
    aq = conn.artifact_queries
    assert aq is not None
    # A few common query methods that MCP tools hit
    assert hasattr(aq, "query_services")
    assert hasattr(aq, "query_scheduled_tasks")
    assert hasattr(aq, "query_event_logs")
    assert hasattr(aq, "_query_artifact")


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_fixture_is_deterministic(fixture_name):
    from regression.fixtures import load as load_fixture

    c1 = load_fixture(fixture_name)
    c2 = load_fixture(fixture_name)
    # Same fixture called twice should yield identical metadata + counts
    assert c1.get_metadata() == c2.get_metadata()
    assert c1.get_artifact_type_counts() == c2.get_artifact_type_counts()


# ── Ground truth schema ────────────────────────────────────────────────────

GROUND_TRUTH_REQUIRED_KEYS = {
    "fixture_name",
    "case_description",
    "expected_verdict",
    "expected_confidence",
    "expected_allow_strong_conclusion",
    "prohibited_phrases",
    "required_phrases",
}


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_ground_truth_has_required_schema(fixture_name):
    from regression.ground_truth import load as load_gt

    gt = load_gt(fixture_name)
    missing = GROUND_TRUTH_REQUIRED_KEYS - set(gt.keys())
    assert not missing, f"{fixture_name} missing: {missing}"
    # expected_verdict shape
    assert "primary" in gt["expected_verdict"]
    assert isinstance(gt["expected_verdict"].get("acceptable_alternatives", []), list)


# ── Prompt ─────────────────────────────────────────────────────────────────

def test_standard_prompt_has_version_and_required_sections():
    from regression import prompt

    assert prompt.PROMPT_VERSION
    text = prompt.STANDARD_ANALYST_PROMPT
    # Must reference the LLM rule set
    assert "CLAUDE.md" in text
    # Must require hypothesis declaration
    assert "hypothesis" in text.lower()
    # Must specify JSON output format fields
    for key in (
        "verdict",
        "confidence",
        "basis",
        "investigation_incomplete",
    ):
        assert key in text


# ── Metrics ────────────────────────────────────────────────────────────────

def test_verdict_correct_accepts_primary_and_alternatives():
    from regression import metrics

    gt = {"expected_verdict": {"primary": "ransomware", "acceptable_alternatives": ["destructive"]}}
    assert metrics.verdict_correct({"verdict": "ransomware"}, gt) is True
    assert metrics.verdict_correct({"verdict": "DESTRUCTIVE"}, gt) is True
    assert metrics.verdict_correct({"verdict": "benign"}, gt) is False


def test_false_positive_only_on_benign_fixture():
    from regression import metrics

    benign = {"expected_verdict": {"primary": "benign"}}
    ransom = {"expected_verdict": {"primary": "ransomware"}}
    assert metrics.is_false_positive({"verdict": "ransomware"}, benign) is True
    assert metrics.is_false_positive({"verdict": "unknown"}, benign) is False
    # Non-benign fixture always yields False for this metric
    assert metrics.is_false_positive({"verdict": "benign"}, ransom) is False


def test_tool_diversity_counts_unique_and_shares():
    from regression import metrics

    calls = [
        {"name": "find_suspicious"},
        {"name": "find_suspicious"},
        {"name": "get_timeline"},
        {"name": "search_artifacts"},
    ]
    d = metrics.tool_diversity(calls)
    assert d["total_calls"] == 4
    assert d["unique_tools"] == 3
    assert d["top_tool_share"] == pytest.approx(0.5)
    # Empty input safe
    empty = metrics.tool_diversity([])
    assert empty["total_calls"] == 0


def test_prohibited_phrase_skipped_in_refutation_context():
    from regression import metrics

    gt = {
        "required_phrases": [],
        "prohibited_phrases": ["ransomware", "compromise"],
    }
    # Refutation context: should NOT count as violation
    refuting = "Ransomware refuted: no encrypted files. This is not a compromise."
    result = metrics.check_required_phrases(refuting, gt)
    assert result["prohibited_violations"] == []

    # Assertive context: MUST count as violation
    asserting = "This case is clearly ransomware and represents an ongoing compromise."
    result = metrics.check_required_phrases(asserting, gt)
    assert set(result["prohibited_violations"]) == {"ransomware", "compromise"}


def test_required_phrase_synonym_groups():
    from regression import metrics

    gt = {
        "required_phrases": [
            ["investigation incomplete", "structurally missing", "coverage gap", "missing coverage"],
            "blocked_lanes",
        ],
        "prohibited_phrases": [],
    }
    # Hits one synonym per group → fully matched
    text = "Coverage gap in evtx family. blocked_lanes: ingress_access."
    result = metrics.check_required_phrases(text, gt)
    assert result["required_matched"] == 2
    assert result["required_total"] == 2
    assert result["required_missing"] == []

    # Misses first group entirely
    text = "No coverage mention. blocked_lanes present."
    result = metrics.check_required_phrases(text, gt)
    assert result["required_matched"] == 1
    assert result["required_total"] == 2
    assert result["required_missing"]


def test_uncertainty_citation_detects_markers():
    from regression import metrics

    text = (
        "Evidence suggests ransomware activity. allow_strong_conclusion was "
        "false, so investigation incomplete."
    )
    result = metrics.uncertainty_cited(text)
    assert result["strong_conclusion_mentioned"] is True
    assert result["hedged_language"] is True
    assert result["total_cited"] >= 2
    # Plain text no markers
    plain = metrics.uncertainty_cited("The case is definitely ransomware.")
    assert plain["total_cited"] == 0


# ── Ingest ─────────────────────────────────────────────────────────────────

def test_ingest_parses_verdict_json(tmp_path):
    from regression import ingest

    verdict_file = tmp_path / "v.json"
    verdict_file.write_text(json.dumps({
        "verdict": "ransomware",
        "confidence": "moderate",
        "basis": ["ransom note", "encrypted files"],
        "investigation_incomplete": False,
    }))
    parsed = ingest.load_verdict(verdict_file)
    assert parsed["verdict"] == "ransomware"
    assert parsed["basis"][0] == "ransom note"


def test_ingest_extracts_tool_calls_from_session_log(tmp_path):
    from regression import ingest

    log_file = tmp_path / "session.jsonl"
    # Claude Code style streaming events — minimal shapes the parser should
    # accept. Format may evolve; parser must remain tolerant.
    events = [
        {"type": "system", "subtype": "init"},
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "find_suspicious", "input": {}},
                ],
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
                ],
            },
        },
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "tool_use", "id": "t2", "name": "get_timeline", "input": {}},
                    {"type": "text", "text": "Calling next tool."},
                ],
            },
        },
    ]
    log_file.write_text("\n".join(json.dumps(e) for e in events))
    calls = ingest.extract_tool_calls(log_file)
    names = [c["name"] for c in calls]
    assert names == ["find_suspicious", "get_timeline"]


def test_ingest_missing_session_log_returns_empty_list(tmp_path):
    from regression import ingest

    calls = ingest.extract_tool_calls(None)
    assert calls == []


def test_ingest_malformed_session_log_is_tolerant(tmp_path):
    from regression import ingest

    log_file = tmp_path / "bad.jsonl"
    log_file.write_text("not a json\n{\"type\": \"assistant\"}\n")
    # Should not raise; should skip bad lines.
    calls = ingest.extract_tool_calls(log_file)
    assert isinstance(calls, list)


# ── Report ─────────────────────────────────────────────────────────────────

def test_report_aggregate_groups_by_fixture(tmp_path):
    from regression import report

    rows = [
        {"fixture": "f1", "run_idx": 1, "verdict_correct": True, "is_fp": False,
         "total_calls": 5, "unique_tools": 4, "diversity_ratio": 0.8,
         "top_tool_share": 0.4, "uncertainty_total": 2, "final_verdict": "ransomware"},
        {"fixture": "f1", "run_idx": 2, "verdict_correct": False, "is_fp": False,
         "total_calls": 3, "unique_tools": 2, "diversity_ratio": 0.67,
         "top_tool_share": 0.67, "uncertainty_total": 1, "final_verdict": "unknown"},
    ]
    summary = report.aggregate(rows)
    assert "f1" in summary
    assert summary["f1"]["verdict_correct_count"] == 1
    assert summary["f1"]["runs"] == 2


def test_report_writes_csv_and_markdown(tmp_path):
    from regression import report

    rows = [
        {"fixture": "f1", "run_idx": 1, "verdict_correct": True, "is_fp": False,
         "total_calls": 5, "unique_tools": 4, "diversity_ratio": 0.8,
         "top_tool_share": 0.4, "uncertainty_total": 2, "final_verdict": "ransomware",
         "prompt_version": "1.0"},
    ]
    csv_path = tmp_path / "run.csv"
    md_path = tmp_path / "run.md"
    report.write_csv(rows, csv_path)
    report.write_markdown(rows, md_path, prompt_version="1.0")
    csv_text = csv_path.read_text(encoding="utf-8")
    assert "fixture" in csv_text
    assert "ransomware" in csv_text
    md_text = md_path.read_text(encoding="utf-8")
    assert "f1" in md_text
    assert "1.0" in md_text


# ── CLI ────────────────────────────────────────────────────────────────────

def test_cli_show_prompt_prints_standard_prompt(capsys):
    from regression import cli

    exit_code = cli.main(["show-prompt", "case_ransomware_inc_like"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "CLAUDE.md" in out
    assert "hypothesis" in out.lower()


def test_cli_list_fixtures_prints_all(capsys):
    from regression import cli

    exit_code = cli.main(["list-fixtures"])
    out = capsys.readouterr().out
    assert exit_code == 0
    for name in FIXTURES:
        assert name in out
