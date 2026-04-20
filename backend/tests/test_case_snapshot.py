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


# ── v2 bucket tests ──────────────────────────────────────────────────────

def test_v1_snapshot_loads_with_empty_buckets(tmp_path, monkeypatch, mfdb_case):
    """Codex Round-9b: old v1 files must load cleanly with empty buckets."""
    import json as _json
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    # Write a v1-shape snapshot directly (no bucket fields).
    v1_payload = {
        "schema": "fw.case_snapshot.v1",
        "name": "Old Snap",
        "slug": "old_snap",
        "saved_at": "2026-01-01T00:00:00",
        "case_ids": ["a"],
        "active_case_id": "a",
        "tagged_hits": [1, 2, 3],
        "notes": "",
        "filters": {},
        "masker": {},
    }
    with open(tmp_path / "old_snap.json", "w", encoding="utf-8") as f:
        _json.dump(v1_payload, f)

    loaded = cs.load_snapshot("old_snap")
    assert loaded["ok"] is True
    # Normalization injects v2 fields in memory.
    assert loaded["tagged_hits_by_bucket"] == {}
    assert loaded["bucket_hypotheses"] == {}
    assert loaded["schema_version_normalized"] == cs.SCHEMA_VERSION_V2


def test_add_hits_to_bucket_dedups_and_stores_hypothesis(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    conns = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(conns, name="Case X")

    r = cs.add_hits_to_bucket("case_x", "Payload Files", [101, 102, 101], hypothesis="Suspected staging")
    assert r["ok"] is True
    assert r["bucket"] == "payload_files"  # slug-sanitized
    assert r["hit_count"] == 2              # deduped
    assert r["hypothesis"] == "Suspected staging"


def test_remove_hits_errors_on_missing_bucket(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    cs.save_snapshot({"axiom:a": mfdb_case, "axiom": mfdb_case}, name="Case Y")
    r = cs.remove_hits_from_bucket("case_y", "ghost_bucket", [1])
    assert r["ok"] is False
    assert "not found" in r["error"].lower()


def test_get_bucket_hits_missing_snapshot_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    r = cs.get_bucket_hits("nope", "anything")
    assert r["ok"] is False
    assert "not found" in r["error"].lower()


def test_get_bucket_hits_missing_bucket_lists_known(tmp_path, monkeypatch, mfdb_case):
    """Typoed bucket name must hard-error with the set of valid bucket slugs."""
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    conns = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(conns, name="Case Z")
    cs.add_hits_to_bucket("case_z", "payload", [1, 2])

    r = cs.get_bucket_hits("case_z", "paylaod")  # typo
    assert r["ok"] is False
    assert "payload" in r["error"]  # valid bucket listed


def test_resolve_bucket_hit_ids_raises_on_typo(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    cs.save_snapshot({"axiom:a": mfdb_case, "axiom": mfdb_case}, name="Case W")
    cs.add_hits_to_bucket("case_w", "exfil", [42, 43])
    # Valid path
    assert cs.resolve_bucket_hit_ids("case_w", "exfil") == {42, 43}
    # Typo
    import pytest
    with pytest.raises(cs.BucketNotFoundError):
        cs.resolve_bucket_hit_ids("case_w", "exfill")


def test_bucket_slug_collision_warns(tmp_path, monkeypatch, mfdb_case):
    """Codex Round-9c: two distinct labels that sanitize to the same slug
    merge intentionally, but the collision must be visible so an analyst
    who didn't mean the merge can rename."""
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    conns = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(conns, name="Case C")

    first = cs.add_hits_to_bucket("case_c", "Payload Files", [1, 2])
    assert first["ok"] is True
    assert "collision_warning" not in first

    second = cs.add_hits_to_bucket("case_c", "payload files!", [3])  # same slug
    assert second["ok"] is True
    assert "collision_warning" in second
    assert "payload_files" in second["collision_warning"]
    # Both hit sets merged under one slug
    assert second["hit_count"] == 3


def test_tagged_hits_aggregate_untouched_by_buckets(tmp_path, monkeypatch, mfdb_case):
    """Bucket edits must not modify the flat tagged_hits legacy field."""
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    conns = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    cs.save_snapshot(conns, name="Case F", tagged_hits=[1, 2, 3])
    cs.add_hits_to_bucket("case_f", "new", [99])
    loaded = cs.load_snapshot("case_f")
    assert loaded["tagged_hits"] == [1, 2, 3]
    assert loaded["tagged_hits_by_bucket"]["new"] == [99]


def test_slug_sanitizes_special_chars(tmp_path, monkeypatch, mfdb_case):
    monkeypatch.setattr(cs, "_STATE_DIR", str(tmp_path))
    connectors = {"axiom:a": mfdb_case, "axiom": mfdb_case}
    r = cs.save_snapshot(connectors, name="Case / #42 (bad?chars)")
    # Spaces -> _, other special -> -, lowercase
    assert "/" not in r["slug"]
    assert "#" not in r["slug"]
    assert "?" not in r["slug"]
    assert r["slug"] == r["slug"].lower()
