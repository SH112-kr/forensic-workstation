from __future__ import annotations

import json

import state as _state


def test_resolve_active_case_evidence_from_empty(monkeypatch, tmp_path):
    active_case = tmp_path / ".active_case.json"
    payload = {
        "path": "C:/cases/case.mfdb",
        "case_id": "case-1",
        "evidence_sources": ["baro_20260415_ssd.E01"],
        "evidence_locations": ["D:/incident/baro_20260415_ssd.E01"],
        "all_cases": [],
    }
    active_case.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(_state, "_ACTIVE_CASE_FILE", str(active_case))

    assert _state.resolve_active_case_evidence("") == _state.normalize_path("D:/incident/baro_20260415_ssd.E01")
    assert _state.resolve_active_case_evidence("active_case") == _state.normalize_path("D:/incident/baro_20260415_ssd.E01")


def test_resolve_active_case_evidence_from_basename_and_source(monkeypatch, tmp_path):
    active_case = tmp_path / ".active_case.json"
    payload = {
        "path": "C:/cases/case.mfdb",
        "case_id": "case-1",
        "evidence_sources": ["baro_20260415_ssd.E01"],
        "evidence_locations": ["D:/incident/baro_20260415_ssd.E01"],
        "all_cases": [],
    }
    active_case.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(_state, "_ACTIVE_CASE_FILE", str(active_case))

    expected = _state.normalize_path("D:/incident/baro_20260415_ssd.E01")
    assert _state.resolve_active_case_evidence("baro_20260415_ssd.E01") == expected
    assert _state.resolve_active_case_evidence("D:/incident/baro_20260415_ssd.E01") == expected


def test_resolve_active_case_evidence_requires_unique_default(monkeypatch, tmp_path):
    active_case = tmp_path / ".active_case.json"
    payload = {
        "path": "C:/cases/case.mfdb",
        "case_id": "case-1",
        "evidence_sources": ["one.E01", "two.E01"],
        "evidence_locations": ["D:/incident/one.E01", "D:/incident/two.E01"],
        "all_cases": [],
    }
    active_case.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(_state, "_ACTIVE_CASE_FILE", str(active_case))

    assert _state.resolve_active_case_evidence("") == ""


def test_resolve_active_case_evidence_finds_relative_basename_near_case(monkeypatch, tmp_path):
    case_dir = tmp_path / "incident" / "axiom" / "CaseDir"
    case_dir.mkdir(parents=True)
    case_path = case_dir / "Case.mfdb"
    case_path.write_text("", encoding="utf-8")
    evidence_dir = tmp_path / "incident" / "disk"
    evidence_dir.mkdir(parents=True)
    evidence_path = evidence_dir / "sample.E01"
    evidence_path.write_text("", encoding="utf-8")

    active_case = tmp_path / ".active_case.json"
    payload = {
        "path": str(case_path),
        "case_id": "case-1",
        "evidence_sources": ["sample.E01"],
        "evidence_locations": ["sample.E01"],
        "all_cases": [],
    }
    active_case.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(_state, "_ACTIVE_CASE_FILE", str(active_case))

    assert _state.resolve_active_case_evidence("") == _state.normalize_path(str(evidence_path))
