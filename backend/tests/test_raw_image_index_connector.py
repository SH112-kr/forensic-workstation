from __future__ import annotations

import sqlite3

import pytest

from core.connectors.raw_image_index import RawImageIndexConnector
from core.raw_index.store import RawIndexStore


def _seed(db_path, *, fingerprint: str = "fixture-fingerprint"):
    store = RawIndexStore(str(db_path))
    store.open()
    store._conn().execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("raw_image_fingerprint", fingerprint),
    )
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="unit",
        source_path="/c:/Temp/a.tmp",
        primary_path="/c:/Temp/a.tmp",
        description="File System Entry /c:/Temp/a.tmp",
        strings={"Path": "/c:/Temp/a.tmp", "Name": "a.tmp"},
        times={"Modified": (1791072000000, "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()


def test_raw_image_index_connector_search_and_detail(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()

    meta = conn.connect(str(db_path))
    result = conn.search(
        keyword="a.tmp",
        filters={"artifact_type": "File System Entry"},
        limit=10,
    )
    detail = conn.get_hit_detail(result["hits"][0]["hit_id"])

    assert meta["source_type"] == "raw_image_sidecar"
    assert meta["raw_image_fingerprint"] == "fixture-fingerprint"
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert detail["fields"]["Path"] == "/c:/Temp/a.tmp"
    assert "search" in conn.get_capabilities()


def test_raw_image_index_connector_timeline_is_exact(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    assert timeline["total_events"] == 1
    assert timeline["total_is_estimated"] is False
    assert timeline["returned"] == 1
    assert timeline["entries"][0]["artifact_type"] == "File System Entry"


def test_raw_image_index_connector_rejects_schema_mismatch(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE raw_index_metadata SET value = ? WHERE key = ?",
            ("999", "schema_version"),
        )

    connector = RawImageIndexConnector()

    with pytest.raises(RuntimeError, match="stale raw index"):
        connector.connect(str(db_path))


def test_raw_image_index_connector_rejects_fingerprint_mismatch(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path, fingerprint="fingerprint-a")
    connector = RawImageIndexConnector()

    with pytest.raises(RuntimeError, match="fingerprint mismatch"):
        connector.connect(str(db_path), expected_fingerprint="fingerprint-b")
