from __future__ import annotations

import json

import state


def test_resolve_image_evidence_prefers_selected_image_over_stale_active_case(tmp_path, monkeypatch):
    selected = tmp_path / "selected.E01"
    selected.write_bytes(b"")
    stale = tmp_path / "stale.E01"
    stale.write_bytes(b"")
    stale_case = tmp_path / "old.mfdb"
    stale_case.write_bytes(b"")

    allowed_file = tmp_path / "allowed.json"
    active_file = tmp_path / "active.json"
    allowed_file.write_text(json.dumps({"paths": [str(selected)], "source": "test"}), encoding="utf-8")
    active_file.write_text(json.dumps({
        "path": str(stale_case),
        "case_id": "old",
        "evidence_locations": [str(stale)],
        "evidence_sources": ["stale"],
        "all_cases": [],
    }), encoding="utf-8")
    monkeypatch.setattr(state, "_ALLOWED_EVIDENCE_FILE", str(allowed_file))
    monkeypatch.setattr(state, "_ACTIVE_CASE_FILE", str(active_file))

    resolved = state.resolve_image_evidence("")

    assert resolved["path"] == state.normalize_path(str(selected))
    assert resolved["source"] == "allowed_evidence"


def test_resolve_image_evidence_active_case_is_explicit(tmp_path, monkeypatch):
    selected = tmp_path / "selected.E01"
    selected.write_bytes(b"")
    active = tmp_path / "active.E01"
    active.write_bytes(b"")
    case_path = tmp_path / "case.mfdb"
    case_path.write_bytes(b"")

    allowed_file = tmp_path / "allowed.json"
    active_file = tmp_path / "active.json"
    allowed_file.write_text(json.dumps({"paths": [str(selected)], "source": "test"}), encoding="utf-8")
    active_file.write_text(json.dumps({
        "path": str(case_path),
        "case_id": "case",
        "evidence_locations": [str(active)],
        "evidence_sources": ["active"],
        "all_cases": [],
    }), encoding="utf-8")
    monkeypatch.setattr(state, "_ALLOWED_EVIDENCE_FILE", str(allowed_file))
    monkeypatch.setattr(state, "_ACTIVE_CASE_FILE", str(active_file))

    resolved = state.resolve_image_evidence("active_case")

    assert resolved["path"] == state.normalize_path(str(active))
    assert resolved["source"] == "active_case"


def test_resolve_image_evidence_accepts_vm_disk_images(tmp_path, monkeypatch):
    selected = tmp_path / "guest.vhdx"
    selected.write_bytes(b"")

    allowed_file = tmp_path / "allowed.json"
    active_file = tmp_path / "active.json"
    allowed_file.write_text(json.dumps({"paths": [str(selected)], "source": "test"}), encoding="utf-8")
    active_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(state, "_ALLOWED_EVIDENCE_FILE", str(allowed_file))
    monkeypatch.setattr(state, "_ACTIVE_CASE_FILE", str(active_file))

    resolved = state.resolve_image_evidence("guest.vhdx")

    assert resolved["path"] == state.normalize_path(str(selected))
    assert resolved["source"] == "allowed_evidence"
