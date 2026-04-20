"""Unit tests for core.analysis.case_snapshot."""

from __future__ import annotations

import json
import os

from core.analysis import case_snapshot as cs


def test_save_and_load_roundtrip(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))

    connectors = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    r = cs.save_snapshot(
        connectors,
        name="My Investigation 1",
        tagged_hits=[1, 2, 3],
        notes="Suspicious PowerShell activity",
        filters={"artifact_type": "Prefetch"},
    )
    assert r["ok"] is True
    assert r["slug"] == "my_investigation_1"
    assert r["active_case_id"] == "a"

    loaded = cs.load_snapshot("my_investigation_1")
    assert loaded["ok"] is True
    assert loaded["name"] == "My Investigation 1"
    assert loaded["tagged_hits"] == [1, 2, 3]
    assert loaded["notes"].startswith("Suspicious")
    assert loaded["filters"] == {"artifact_type": "Prefetch"}


def test_list_shows_saved_items(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    connectors = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(connectors, name="First")
    cs.save_snapshot(connectors, name="Second", tagged_hits=[10])

    result = cs.list_snapshots()
    assert result["count"] == 2
    names = {s["name"] for s in result["snapshots"]}
    assert names == {"First", "Second"}
    tagged_counts = {s["name"]: s["tagged_count"] for s in result["snapshots"]}
    assert tagged_counts == {"First": 0, "Second": 1}


def test_load_missing_returns_error(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    r = cs.load_snapshot("nonexistent")
    assert r["ok"] is False
    assert "not found" in r["error"].lower()


def test_delete_snapshot(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    connectors = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(connectors, name="Doomed")
    assert cs.list_snapshots()["count"] == 1

    cs.delete_snapshot("doomed")
    assert cs.list_snapshots()["count"] == 0


def test_slug_sanitizes_special_chars(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    connectors = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    r = cs.save_snapshot(connectors, name="Case / #42 (bad?chars)")
    # Spaces -> _, other special -> -, lowercase
    assert "/" not in r["slug"]
    assert "#" not in r["slug"]
    assert "?" not in r["slug"]
    assert r["slug"] == r["slug"].lower()
