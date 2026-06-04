from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.raw_index.store import RawIndexStore


def _ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


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


def test_search_loads_page_hit_details_in_batches(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha.exe", "beta.exe", "gamma.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            times={
                "Modified": (
                    _ms("2026-10-04T00:00:00Z"),
                    "2026-10-04T00:00:00Z",
                )
            },
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    result = store.search(
        artifact_type="File System Entry",
        limit=3,
    )

    string_detail_selects = [
        sql for sql in statements if "FROM raw_index_artifact_strings" in sql
    ]
    time_detail_selects = [
        sql for sql in statements if "FROM raw_index_artifact_times" in sql
    ]
    assert result["total"] == 3
    assert result["returned"] == 3
    assert result["total_is_estimated"] is False
    assert len(string_detail_selects) == 1
    assert len(time_detail_selects) == 1


def test_search_reuses_page_rows_when_hydrating_hit_details(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha.exe", "beta.exe", "gamma.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    result = store.search(
        artifact_type="File System Entry",
        limit=3,
    )

    artifact_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM raw_index_artifacts" in sql
    ]
    assert result["total"] == 3
    assert result["returned"] == 3
    assert result["total_is_estimated"] is False
    assert len(artifact_selects) == 2


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


def test_search_rebuilds_materialized_search_text_with_mismatched_ids(tmp_path):
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
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )
    missing_id = store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/beta.exe",
        primary_path="/c:/Tools/beta.exe",
        description="File System Entry /c:/Tools/beta.exe",
        strings={"Name": "beta.exe", "Path": "/c:/Tools/beta.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store._conn().execute(
        "DELETE FROM raw_index_search_text WHERE artifact_id = ?",
        (missing_id,),
    )
    store._conn().execute(
        "INSERT INTO raw_index_search_text(artifact_id, search_text) VALUES (?, ?)",
        (9999, "orphan-cache-row"),
    )
    store._conn().commit()

    result = store.search(
        keyword="beta",
        artifact_type="File System Entry",
        limit=10,
    )

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["rebuilt_search_text"] is True
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/beta.exe"


def test_search_keywords_returns_exact_union_beyond_page_limit(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha-one.exe", "alpha-two.exe", "beta-one.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    result = store.search(
        keywords=["alpha", "beta"],
        artifact_type="File System Entry",
        limit=2,
    )

    assert result["total"] == 3
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["returned"] == 2
    assert result["truncated"] is True
    assert result["search_strategy"]["keyword_mode"] == "or"
    assert result["search_strategy"]["index"] in {
        "materialized_like_or",
        "fts5_trigram_or",
    }
    assert result["search_strategy"]["revalidated"] is True


def test_search_keywords_uses_fast_candidate_index_when_available(tmp_path):
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
    for name in ("alpha-one.exe", "alpha-two.exe", "beta-one.exe"):
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            parser_run_id=run_id,
        )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    result = store.search(
        keywords=["alpha", "beta"],
        artifact_type="File System Entry",
        limit=10,
    )

    assert result["total"] == 3
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["keyword_mode"] == "or"
    assert result["search_strategy"]["index"] == "fts5_trigram_or"
    assert result["search_strategy"]["revalidated"] is True


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


def test_search_falls_back_when_fast_candidate_index_ids_mismatch(tmp_path):
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
    missing_id = store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/beta.exe",
        primary_path="/c:/Tools/beta.exe",
        description="File System Entry /c:/Tools/beta.exe",
        strings={"Name": "beta.exe", "Path": "/c:/Tools/beta.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store._conn().execute(
        "DELETE FROM raw_index_search_fts WHERE rowid = ?",
        (missing_id,),
    )
    store._conn().execute(
        "INSERT INTO raw_index_search_fts(rowid, search_text) VALUES (?, ?)",
        (9999, "orphan-cache-row"),
    )
    store._conn().commit()

    result = store.search(
        keyword="beta",
        artifact_type="File System Entry",
        limit=10,
    )

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["search_strategy"]["index"] == "materialized_like"
    assert result["search_strategy"]["fast_candidate_gap"] == "stale_fts"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/beta.exe"


def test_search_falls_back_when_fast_candidate_set_is_too_large(tmp_path):
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
    with store.batch():
        for index in range(905):
            name = f"agent-{index:04d}.exe"
            store.insert_artifact(
                artifact_type="File System Entry",
                source_ref="/c:",
                source_path=f"/c:/Tools/{name}",
                primary_path=f"/c:/Tools/{name}",
                description=f"File System Entry /c:/Tools/{name}",
                strings={"Name": name, "Path": f"/c:/Tools/{name}"},
                parser_run_id=run_id,
            )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    single = store.search(
        keyword="agent",
        artifact_type="File System Entry",
        limit=5,
    )
    multi = store.search(
        keywords=["agent", "tools"],
        artifact_type="File System Entry",
        limit=5,
    )

    assert single["total"] == 905
    assert single["returned"] == 5
    assert single["total_is_estimated"] is False
    assert single["search_strategy"]["index"] == "materialized_like"
    assert (
        single["search_strategy"]["fast_candidate_gap"]
        == "fast_candidate_too_large"
    )
    assert multi["total"] == 905
    assert multi["returned"] == 5
    assert multi["total_is_estimated"] is False
    assert multi["search_strategy"]["index"] == "materialized_like_or"
    assert (
        multi["search_strategy"]["fast_candidate_gap"]
        == "fast_candidate_too_large"
    )


def test_search_applies_exact_date_filter_from_artifact_times(tmp_path):
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
        source_path="/c:/Tools/old.exe",
        primary_path="/c:/Tools/old.exe",
        description="File System Entry /c:/Tools/old.exe",
        strings={"Name": "old.exe", "Path": "/c:/Tools/old.exe"},
        times={"Modified": (_ms("2026-09-01T00:00:00Z"), "2026-09-01T00:00:00Z")},
        parser_run_id=run_id,
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/new.exe",
        primary_path="/c:/Tools/new.exe",
        description="File System Entry /c:/Tools/new.exe",
        strings={"Name": "new.exe", "Path": "/c:/Tools/new.exe"},
        times={"Modified": (_ms("2026-10-04T00:00:00Z"), "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    result = store.search(
        keyword=".exe",
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["search_strategy"]["date_filter"] == "artifact_times"
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/new.exe"


def test_date_filtered_search_without_indexed_times_is_not_evaluable(tmp_path):
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
        source_path="/c:/Tools/notimed.exe",
        primary_path="/c:/Tools/notimed.exe",
        description="File System Entry /c:/Tools/notimed.exe",
        strings={"Name": "notimed.exe", "Path": "/c:/Tools/notimed.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    result = store.search(
        keyword=".exe",
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["coverage"]["status"] == "not_evaluable"
    assert result["coverage"]["gaps"][0]["reason"] == "raw_search_date_filter_without_indexed_times"
