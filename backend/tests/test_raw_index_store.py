from __future__ import annotations

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
