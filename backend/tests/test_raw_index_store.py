from __future__ import annotations

import sqlite3
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


def test_insert_artifacts_caches_fts_availability_lookup(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

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

    fts_catalog_lookups = [
        sql
        for sql in statements
        if "FROM sqlite_master" in sql
        and "raw_index_search_fts" in sql
    ]
    assert fts_catalog_lookups
    assert len(fts_catalog_lookups) == 1


def test_insert_artifact_builds_search_text_without_reselecting_inserted_rows(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )

    search_text_reselects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and (
            "FROM raw_index_artifacts" in sql
            or "FROM raw_index_artifact_strings" in sql
            or "FROM raw_index_locations" in sql
        )
    ]
    result = store.search(keyword="alpha.exe", limit=10)

    assert search_text_reselects == []
    assert result["total"] == 1
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/alpha.exe"


def test_rebuild_search_text_loads_source_rows_in_batches(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    beta_id = 0
    for name in ("alpha.exe", "beta.exe", "gamma.exe"):
        artifact_id = store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Name": name, "Path": f"/c:/Tools/{name}"},
            parser_run_id=run_id,
        )
        if name == "beta.exe":
            beta_id = artifact_id
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store._conn().execute("DELETE FROM raw_index_search_text")
    store._conn().commit()
    store._fts_available()
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    store.rebuild_search_text()

    artifact_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM raw_index_artifacts" in sql
    ]
    string_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM raw_index_artifact_strings" in sql
    ]
    location_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM raw_index_locations" in sql
    ]
    rebuilt_text = store._conn().execute(
        "SELECT search_text FROM raw_index_search_text WHERE artifact_id = ?",
        (beta_id,),
    ).fetchone()[0]

    assert len(artifact_selects) == 1
    assert "LIMIT" in artifact_selects[0].upper()
    assert len(string_selects) == 1
    assert len(location_selects) == 1
    assert "/c:/Tools/beta.exe" in rebuilt_text


def test_rebuild_search_text_pages_large_artifact_sets(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    with store.batch():
        for index in range(901):
            name = f"tool-{index:04d}.exe"
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
    store._conn().execute("DELETE FROM raw_index_search_text")
    store._conn().commit()
    store._fts_available()
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    store.rebuild_search_text()

    artifact_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM raw_index_artifacts" in sql
    ]
    rebuilt_count = store._conn().execute(
        "SELECT COUNT(*) FROM raw_index_search_text"
    ).fetchone()[0]

    assert len(artifact_selects) == 2
    assert all("LIMIT" in sql.upper() for sql in artifact_selects)
    assert all("OFFSET" not in sql.upper() for sql in artifact_selects)
    assert rebuilt_count == 901


def test_rebuild_search_text_reuses_connection_for_chunk_work(tmp_path):
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
    store._conn().execute("DELETE FROM raw_index_search_text")
    store._conn().commit()
    store._fts_available()
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    store.rebuild_search_text()

    assert conn_calls <= 2


def test_insert_artifact_skips_fts_delete_for_new_rows(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    if not store._fts_available():
        pytest.skip("SQLite FTS5 is not available")

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )

    fts_deletes = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("DELETE")
        and "raw_index_search_fts" in sql
    ]
    result = store.search(keyword="alpha.exe", limit=10)

    assert fts_deletes == []
    assert result["total"] == 1
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/alpha.exe"


def test_insert_artifact_reuses_connection_for_hot_insert_path(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    store._fts_available()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        times={"Modified": (_ms("2026-10-04T00:00:00Z"), "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )

    assert conn_calls == 1


def test_parser_run_writes_reuse_connection_handles(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )

    assert run_id > 0
    assert conn_calls == 1

    conn_calls = 0

    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )

    assert conn_calls == 1


def test_insert_artifact_skips_data_version_probe_when_fts_freshness_unknown(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )

    data_version_probes = [
        sql for sql in statements if sql.strip().upper() == "PRAGMA DATA_VERSION"
    ]
    assert data_version_probes == []


def test_repeated_keyword_searches_cache_search_text_freshness_until_external_change(tmp_path):
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
    beta_id = store.insert_artifact(
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
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    first = store.search(keyword="alpha", limit=10)
    second = store.search(keyword="beta", limit=10)

    search_text_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_artifacts" in sql
    ]
    assert first["total"] == 1
    assert second["total"] == 1
    assert len(search_text_count_checks) == 1

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            "DELETE FROM raw_index_search_text WHERE artifact_id = ?",
            (beta_id,),
        )

    statements.clear()
    after_external_change = store.search(keyword="beta", limit=10)
    post_change_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_artifacts" in sql
    ]

    assert after_external_change["total"] == 1
    assert after_external_change["search_strategy"]["rebuilt_search_text"] is True
    assert post_change_count_checks


def test_hot_keyword_search_reuses_connection_handle(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha.exe", "beta.exe"):
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
    store.search(keyword="alpha", limit=10)
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    result = store.search(keyword="beta", limit=10)

    assert result["total"] == 1
    assert result["hits"][0]["fields"]["Path"] == "/c:/Tools/beta.exe"
    assert conn_calls <= 2


def test_repeated_searches_cache_coverage_summary_until_external_parser_run_change(tmp_path):
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
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    first = store.search(artifact_type="File System Entry", limit=10)
    second = store.search(artifact_type="File System Entry", limit=10)

    coverage_selects = [
        sql for sql in statements if "FROM raw_index_parser_runs" in sql
    ]
    assert first["coverage"]["status"] == "searched"
    assert second["coverage"]["status"] == "searched"
    assert len(coverage_selects) == 1

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            """
            INSERT INTO raw_index_parser_runs(
                parser_name, source_ref, status, started_at, finished_at,
                coverage_status, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "external_parser",
                "/c:",
                "failed",
                "2026-06-04T00:00:02Z",
                "2026-06-04T00:00:03Z",
                "not_evaluable",
                "simulated external parser failure",
            ),
        )

    statements.clear()
    changed = store.search(artifact_type="File System Entry", limit=10)
    post_change_selects = [
        sql for sql in statements if "FROM raw_index_parser_runs" in sql
    ]

    assert changed["coverage"]["status"] == "not_evaluable"
    assert changed["coverage"]["gaps"][0]["error"] == (
        "simulated external parser failure"
    )
    assert post_change_selects


def test_repeated_keyword_searches_cache_fts_freshness_until_external_change(tmp_path):
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
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )
    beta_id = store.insert_artifact(
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
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    first = store.search(keyword="alpha", limit=10)
    second = store.search(keyword="beta", limit=10)

    fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]
    assert first["search_strategy"]["index"] == "fts5_trigram"
    assert second["search_strategy"]["index"] == "fts5_trigram"
    assert len(fts_count_checks) == 1

    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/gamma.exe",
        primary_path="/c:/Tools/gamma.exe",
        description="File System Entry /c:/Tools/gamma.exe",
        strings={"Name": "gamma.exe", "Path": "/c:/Tools/gamma.exe"},
        parser_run_id=run_id,
    )
    statements.clear()
    after_local_write = store.search(keyword="gamma", limit=10)
    post_write_fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]

    assert after_local_write["search_strategy"]["index"] == "fts5_trigram"
    assert post_write_fts_count_checks == []

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            "DELETE FROM raw_index_search_fts WHERE rowid = ?",
            (beta_id,),
        )

    statements.clear()
    changed = store.search(keyword="beta", limit=10)
    post_change_fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]

    assert changed["total"] == 1
    assert changed["search_strategy"]["index"] == "materialized_like"
    assert changed["search_strategy"]["fast_candidate_gap"] == "stale_fts"
    assert post_change_fts_count_checks


def test_local_insert_preserves_verified_fts_freshness(tmp_path):
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
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    first = store.search(keyword="alpha", limit=10)
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    beta_id = store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="/c:",
        source_path="/c:/Tools/beta.exe",
        primary_path="/c:/Tools/beta.exe",
        description="File System Entry /c:/Tools/beta.exe",
        strings={"Name": "beta.exe", "Path": "/c:/Tools/beta.exe"},
        parser_run_id=run_id,
    )
    statements.clear()
    second = store.search(keyword="beta", limit=10)

    post_insert_fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]
    assert first["search_strategy"]["index"] == "fts5_trigram"
    assert second["total"] == 1
    assert second["search_strategy"]["index"] == "fts5_trigram"
    assert post_insert_fts_count_checks == []

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            "DELETE FROM raw_index_search_fts WHERE rowid = ?",
            (beta_id,),
        )

    statements.clear()
    changed = store.search(keyword="beta", limit=10)
    post_change_fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]

    assert changed["total"] == 1
    assert changed["search_strategy"]["index"] == "materialized_like"
    assert changed["search_strategy"]["fast_candidate_gap"] == "stale_fts"
    assert post_change_fts_count_checks


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


def test_hydrate_hit_details_reuses_connection_per_page(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    artifact_ids = []
    for name in ("alpha.exe", "beta.exe"):
        artifact_id = store.insert_artifact(
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
        artifact_ids.append(artifact_id)
    placeholders = ",".join("?" * len(artifact_ids))
    artifact_rows = store._conn().execute(
        f"""
        SELECT artifact_id, artifact_type, source_path, primary_path,
               description
        FROM raw_index_artifacts
        WHERE artifact_id IN ({placeholders})
        ORDER BY artifact_id
        """,
        artifact_ids,
    ).fetchall()
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    details = store._hydrate_hit_details(artifact_ids, artifact_rows)

    assert conn_calls == 1
    assert [detail["fields"]["Name"] for detail in details] == [
        "alpha.exe",
        "beta.exe",
    ]
    assert details[0]["timestamps"]["Modified"] == "2026-10-04T00:00:00Z"


def test_get_hit_detail_reuses_connection_for_single_detail(tmp_path):
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
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
        times={"Modified": (_ms("2026-10-04T00:00:00Z"), "2026-10-04T00:00:00Z")},
        parser_run_id=run_id,
    )
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    detail = store.get_hit_detail(artifact_id)

    assert detail["fields"]["Path"] == "/c:/Tools/alpha.exe"
    assert detail["timestamps"]["Modified"] == "2026-10-04T00:00:00Z"
    assert conn_calls == 1


def test_artifact_type_counts_cache_miss_reuses_connection(tmp_path):
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
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    counts = store.get_artifact_type_counts()

    assert counts == [
        {
            "artifact_name": "File System Entry",
            "hit_count": 1,
            "count_accuracy": "exact",
        }
    ]
    assert conn_calls <= 2


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


def test_search_limit_zero_skips_page_hydration_queries(tmp_path):
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
        limit=0,
    )

    page_selects = [
        sql
        for sql in statements
        if "SELECT DISTINCT" in sql
        and "FROM raw_index_artifacts a" in sql
    ]
    detail_selects = [
        sql
        for sql in statements
        if "FROM raw_index_artifact_strings" in sql
        or "FROM raw_index_artifact_times" in sql
    ]
    assert result["total"] == 3
    assert result["returned"] == 0
    assert result["total_is_estimated"] is False
    assert result["truncated"] is True
    assert page_selects == []
    assert detail_selects == []


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


def test_rebuilt_search_text_marks_fts_fresh_without_recount(tmp_path):
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
        source_path="/c:/Tools/alpha.exe",
        primary_path="/c:/Tools/alpha.exe",
        description="File System Entry /c:/Tools/alpha.exe",
        strings={"Name": "alpha.exe", "Path": "/c:/Tools/alpha.exe"},
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
    statements: list[str] = []
    store._conn().set_trace_callback(statements.append)

    result = store.search(keyword="alpha", limit=10)

    fts_count_checks = [
        sql
        for sql in statements
        if "SELECT COUNT(*) FROM raw_index_search_fts" in sql
    ]
    assert result["total"] == 1
    assert result["search_strategy"]["index"] == "fts5_trigram"
    assert result["search_strategy"]["rebuilt_search_text"] is True
    assert fts_count_checks == []


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


def test_repeated_date_filtered_searches_cache_untimed_candidate_probe(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run(
        "file_indexer",
        "/c:",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in ("alpha.exe", "beta.exe"):
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

    first = store.search(
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )
    second = store.search(
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    untimed_probes = [
        sql
        for sql in statements
        if "NOT EXISTS" in sql
        and "FROM raw_index_artifact_times t" in sql
    ]
    assert first["total"] == 2
    assert second["total"] == 2
    assert len(untimed_probes) == 1

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            """
            INSERT INTO raw_index_artifacts(
                artifact_type, source_ref, source_path, primary_path,
                description, parser_run_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "File System Entry",
                "/c:",
                "/c:/Tools/notimed.exe",
                "/c:/Tools/notimed.exe",
                "File System Entry /c:/Tools/notimed.exe",
                run_id,
            ),
        )

    statements.clear()
    changed = store.search(
        artifact_type="File System Entry",
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )
    post_change_probes = [
        sql
        for sql in statements
        if "NOT EXISTS" in sql
        and "FROM raw_index_artifact_times t" in sql
    ]

    assert changed["status"] == "not_evaluable"
    assert post_change_probes
