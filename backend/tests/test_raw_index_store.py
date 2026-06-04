from __future__ import annotations

import pytest

from core.raw_index.store import RawIndexStore


def test_store_inserts_artifact_and_returns_exact_count(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    artifact_id = store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Windows/notepad.exe",
        primary_path="/c:/Windows/notepad.exe",
        description="File System Entry /c:/Windows/notepad.exe",
        strings={"Name": "notepad.exe", "Path": "/c:/Windows/notepad.exe"},
        times={"Modified": (1791072000000, "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    result = store.search(
        keyword="notepad",
        artifact_type="File System Entry",
        limit=10,
        offset=0,
    )

    assert artifact_id > 0
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["returned"] == 1
    assert result["coverage"]["status"] == "searched"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Windows/notepad.exe"


def test_search_reports_parser_failures_as_not_evaluable(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    store.finish_parser_run(
        run_id,
        status="failed",
        coverage_status="not_evaluable",
        finished_at="2026-06-04T00:00:01Z",
        error="simulated parser failure",
    )

    result = store.search(
        keyword="notepad",
        artifact_type="File System Entry",
        limit=10,
        offset=0,
    )

    assert result["total"] == 0
    assert result["total_is_estimated"] is False
    assert result["coverage"]["status"] == "not_evaluable"
    assert result["coverage"]["gaps"][0]["parser_name"] == "file_indexer"
    assert result["coverage"]["gaps"][0]["error"] == "simulated parser failure"


def test_search_rebuilds_missing_materialized_search_text(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Windows/System32/calc.exe",
        primary_path="/c:/Windows/System32/calc.exe",
        description="File System Entry /c:/Windows/System32/calc.exe",
        strings={"Name": "calc.exe", "Path": "/c:/Windows/System32/calc.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store._conn().execute("DELETE FROM raw_index_search_text")
    store._conn().commit()

    result = store.search(
        keyword="calc",
        artifact_type="File System Entry",
        limit=10,
        offset=0,
    )

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["index"] in {
        "materialized_like",
        "fts5_trigram",
    }
    assert result["search_strategy"]["revalidated"] is True
    assert result["search_strategy"]["rebuilt_search_text"] is True
    assert result["hits"][0]["fields"]["Path"] == "/c:/Windows/System32/calc.exe"


def test_search_falls_back_when_fast_candidate_index_is_stale(tmp_path):
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
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Windows/System32/mspaint.exe",
        primary_path="/c:/Windows/System32/mspaint.exe",
        description="File System Entry /c:/Windows/System32/mspaint.exe",
        strings={"Name": "mspaint.exe", "Path": "/c:/Windows/System32/mspaint.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store._conn().execute("DELETE FROM raw_index_search_fts")
    store._conn().commit()

    result = store.search(
        keyword="mspaint",
        artifact_type="File System Entry",
        limit=10,
        offset=0,
    )

    assert result["total"] == 1
    assert result["search_strategy"]["index"] == "materialized_like"
    assert result["search_strategy"]["fast_candidate_gap"] == "stale_fts"
