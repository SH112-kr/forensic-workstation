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


def test_raw_image_index_connector_search_applies_date_filters(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    result = conn.search(
        keyword="a.tmp",
        filters={
            "artifact_type": "File System Entry",
            "start_date": "2026-10-01",
            "end_date": "2026-10-31",
        },
        limit=10,
    )

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["date_filter"] == "artifact_times"


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


def test_raw_image_index_connector_timeline_applies_keyword_filter(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        keywords=["a.tmp"],
        limit=10,
    )

    assert timeline["total_events"] == 1
    assert timeline["total_is_estimated"] is False
    assert timeline["timeline_strategy"]["keyword_filter"] == "search_text"
    assert timeline["entries"][0]["hit_id"] == 1


def test_raw_image_index_connector_timeline_uses_fast_candidate_index(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    fts_exists = store._conn().execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = 'raw_index_search_fts'
        """
    ).fetchone()
    if not fts_exists:
        pytest.skip("SQLite FTS5 trigram accelerator is not available")
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha-one.exe", "alpha-two.exe", "beta-one.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="unit",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
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
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        keywords=["alpha", "beta"],
        limit=10,
    )

    assert timeline["total_events"] == 3
    assert timeline["total_is_estimated"] is False
    assert timeline["timeline_strategy"]["keyword_filter"] == "search_text"
    assert timeline["timeline_strategy"]["index"] == "fts5_trigram_or"
    assert timeline["timeline_strategy"]["revalidated"] is True


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
