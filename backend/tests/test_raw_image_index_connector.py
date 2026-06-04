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


def _seed_untimed(db_path):
    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    store.insert_artifact(
        artifact_type="File System Entry",
        source_ref="unit",
        source_path="/c:/Temp/untimed.exe",
        primary_path="/c:/Temp/untimed.exe",
        description="File System Entry /c:/Temp/untimed.exe",
        strings={"Path": "/c:/Temp/untimed.exe", "Name": "untimed.exe"},
        times={},
        parser_run_id=run_id,
    )
    store.finish_parser_run(
        run_id,
        status="completed",
        coverage_status="searched",
        finished_at="2026-06-04T00:00:01Z",
    )
    store.close()


def _seed_failed(db_path):
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
    store.close()


def _seed_timed_types(db_path, artifact_types):
    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    for index, artifact_type in enumerate(artifact_types):
        name = f"timed-{index}.exe"
        store.insert_artifact(
            artifact_type=artifact_type,
            source_ref="unit",
            source_path=f"/c:/Temp/{name}",
            primary_path=f"/c:/Temp/{name}",
            description=f"{artifact_type} /c:/Temp/{name}",
            strings={"Path": f"/c:/Temp/{name}", "Name": name},
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


def _seed_timed_names(db_path, names):
    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run(
        "seed",
        "unit",
        started_at="2026-06-04T00:00:00Z",
    )
    for name in names:
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="unit",
            source_path=f"/c:/Tools/{name}",
            primary_path=f"/c:/Tools/{name}",
            description=f"File System Entry /c:/Tools/{name}",
            strings={"Path": f"/c:/Tools/{name}", "Name": name},
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


def test_raw_image_index_connector_missing_hit_detail_reports_not_evaluable_coverage(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_failed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    detail = conn.get_hit_detail(999)

    assert detail["ok"] is False
    assert detail["status"] == "not_evaluable"
    assert detail["coverage"]["status"] == "not_evaluable"
    assert detail["coverage"]["gaps"][0]["error"] == "simulated parser failure"
    assert "not found" in detail["error"]


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


def test_raw_image_index_connector_search_strips_artifact_type_filter(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    result = conn.search(
        keyword="a.tmp",
        filters={"artifact_type": " File System Entry "},
        limit=10,
    )

    assert result["total"] == 1
    assert result["hits"][0]["fields"]["Path"] == "/c:/Temp/a.tmp"


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


def test_raw_image_index_connector_timeline_matching_untimed_artifact_is_not_evaluable(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_untimed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        keywords=["untimed.exe"],
        limit=10,
    )

    assert timeline["ok"] is False
    assert timeline["status"] == "not_evaluable"
    assert timeline["total_events"] == 0
    assert timeline["coverage"]["status"] == "not_evaluable"
    assert timeline["coverage"]["gaps"][0]["reason"] == (
        "raw_timeline_date_filter_without_indexed_times"
    )


def test_raw_image_index_connector_timeline_reports_parser_failure_as_not_evaluable(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_failed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    assert timeline["ok"] is False
    assert timeline["status"] == "not_evaluable"
    assert timeline["total_events"] == 0
    assert timeline["total_is_estimated"] is False
    assert timeline["coverage"]["status"] == "not_evaluable"
    assert timeline["coverage"]["gaps"][0]["error"] == "simulated parser failure"


def test_raw_image_index_connector_timeline_checks_multi_type_untimed_candidates_once(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_timed_types(db_path, ["File System Entry", "Registry Entry"])
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry", "Registry Entry"],
        limit=10,
    )

    untimed_probes = [
        sql
        for sql in statements
        if "NOT EXISTS" in sql
        and "FROM raw_index_artifacts a" in sql
    ]
    assert timeline["total_events"] == 2
    assert len(untimed_probes) == 1


def test_raw_image_index_connector_timeline_reuses_required_store(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    original_require_store = conn._require_store
    require_store_calls = 0

    def counted_require_store():
        nonlocal require_store_calls
        require_store_calls += 1
        return original_require_store()

    conn._require_store = counted_require_store

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
    )

    assert timeline["total_events"] == 1
    assert require_store_calls == 1


def test_raw_image_index_connector_timeline_limit_zero_skips_page_query(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=0,
    )

    page_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT T.ARTIFACT_ID")
        and "FROM raw_index_artifact_times t" in sql
    ]
    assert timeline["total_events"] == 1
    assert timeline["total_is_estimated"] is False
    assert timeline["returned"] == 0
    assert timeline["truncated"] is True
    assert timeline["entries"] == []
    assert page_selects == []


def test_raw_image_index_connector_timeline_offset_past_total_skips_page_query(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        limit=10,
        offset=10,
    )

    page_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT T.ARTIFACT_ID")
        and "FROM raw_index_artifact_times t" in sql
    ]
    assert timeline["total_events"] == 1
    assert timeline["total_is_estimated"] is False
    assert timeline["returned"] == 0
    assert timeline["truncated"] is False
    assert timeline["entries"] == []
    assert page_selects == []


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


def test_raw_image_index_connector_timeline_uses_fts_join_for_hot_keywords(tmp_path):
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
    with store.batch():
        for index in range(905):
            name = f"agent-{index:04d}.exe"
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
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry"],
        keywords=["agent", "tools"],
        limit=5,
    )

    assert timeline["total_events"] == 905
    assert timeline["returned"] == 5
    assert timeline["total_is_estimated"] is False
    assert timeline["timeline_strategy"]["keyword_filter"] == "search_text"
    assert timeline["timeline_strategy"]["index"] == "fts5_trigram_join_or"
    assert (
        timeline["timeline_strategy"]["fast_candidate_gap"]
        == "fast_candidate_too_large"
    )
    assert timeline["timeline_strategy"]["revalidated"] is True
    joined_queries = [
        sql
        for sql in statements
        if "JOIN raw_index_search_fts fts" in sql
        and "st.search_text LIKE" in sql
    ]
    assert joined_queries


def test_raw_image_index_connector_hot_keyword_timeline_reuses_store_connection(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        keywords=["a.tmp"],
        limit=10,
    )
    store = conn._require_store()
    original_conn = store._conn
    conn_calls = 0

    def counted_conn():
        nonlocal conn_calls
        conn_calls += 1
        return original_conn()

    store._conn = counted_conn

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        keywords=["a.tmp"],
        limit=10,
    )

    assert timeline["total_events"] == 1
    assert timeline["entries"][0]["time_field"] == "Modified"
    assert conn_calls <= 2


def test_raw_image_index_connector_timeline_deduplicates_keyword_terms(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        keywords=["a.tmp", "a.tmp", " "],
        limit=10,
    )

    timeline_like_queries = [
        sql
        for sql in statements
        if "st.search_text LIKE" in sql
    ]
    assert timeline["total_events"] == 1
    assert timeline_like_queries
    assert all(
        sql.count("st.search_text LIKE") == 1
        for sql in timeline_like_queries
    )


def test_raw_image_index_connector_timeline_deduplicates_artifact_types(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types=["File System Entry", "File System Entry", " "],
        limit=10,
    )

    timeline_type_queries = [
        sql
        for sql in statements
        if "a.artifact_type IN" in sql
    ]
    assert timeline["total_events"] == 1
    assert timeline_type_queries
    assert all(
        sql.count("'File System Entry'") == 1
        for sql in timeline_type_queries
    )


def test_raw_image_index_connector_timeline_accepts_artifact_type_string(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry",
        limit=10,
    )

    assert timeline["total_events"] == 1
    assert timeline["entries"][0]["artifact_type"] == "File System Entry"


def test_raw_image_index_connector_timeline_splits_artifact_type_string_list(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_timed_types(db_path, ["File System Entry", "Registry Entry"])
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        artifact_types="File System Entry,Registry Entry",
        limit=10,
    )

    assert timeline["total_events"] == 2
    assert {entry["artifact_type"] for entry in timeline["entries"]} == {
        "File System Entry",
        "Registry Entry",
    }


def test_raw_image_index_connector_timeline_accepts_keyword_string(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        keywords="a.tmp",
        limit=10,
    )

    timeline_like_queries = [
        sql
        for sql in statements
        if "st.search_text LIKE" in sql
    ]
    assert timeline["total_events"] == 1
    assert timeline_like_queries
    assert all(
        sql.count("st.search_text LIKE") == 1
        for sql in timeline_like_queries
    )


def test_raw_image_index_connector_timeline_splits_keyword_string_list(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed_timed_names(db_path, ["alpha-one.exe", "beta-one.exe"])
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(
        start_date="2026-10-01",
        end_date="2026-10-31",
        keywords="alpha,beta",
        limit=10,
    )

    assert timeline["total_events"] == 2
    assert timeline["timeline_strategy"]["keyword_filter"] == "search_text"
    assert {entry["hit_id"] for entry in timeline["entries"]} == {1, 2}


def test_raw_image_index_connector_caches_artifact_type_counts_until_external_change(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))
    statements: list[str] = []
    conn._require_store()._conn().set_trace_callback(statements.append)

    first = conn.get_artifact_type_counts()
    second = conn.get_artifact_type_counts()

    count_selects = [
        sql
        for sql in statements
        if "SELECT artifact_type, COUNT(*) AS hit_count" in sql
    ]
    assert first == second
    assert first[0]["artifact_name"] == "File System Entry"
    assert first[0]["count_accuracy"] == "exact"
    assert len(count_selects) == 1

    with sqlite3.connect(db_path) as other_conn:
        other_conn.execute(
            """
            INSERT INTO raw_index_artifacts(
                artifact_type, source_ref, source_path, primary_path,
                description
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "Registry Entry",
                "external",
                "/c:/Windows/System32/config/SOFTWARE",
                "HKLM/Software/Example",
                "Registry Entry HKLM/Software/Example",
            ),
        )

    statements.clear()
    changed = conn.get_artifact_type_counts()
    post_change_selects = [
        sql
        for sql in statements
        if "SELECT artifact_type, COUNT(*) AS hit_count" in sql
    ]

    assert [row["artifact_name"] for row in changed] == [
        "File System Entry",
        "Registry Entry",
    ]
    assert post_change_selects


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


def test_raw_image_index_connector_rejects_index_roots_mismatch(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
            ("index_roots", "/d:"),
        )

    connector = RawImageIndexConnector()

    with pytest.raises(RuntimeError, match="index roots mismatch"):
        connector.connect(str(db_path), expected_index_roots=["/c:"])


def test_raw_image_index_connector_accepts_reordered_expected_index_roots(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
            ("index_roots", "/c:,/d:"),
        )

    connector = RawImageIndexConnector()

    meta = connector.connect(str(db_path), expected_index_roots=["/d:", "/c:"])

    assert meta["index_roots"] == "/c:,/d:"


def test_raw_image_index_connector_accepts_equivalent_drive_root_forms(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
            ("index_roots", r"C:\,/D:/,/c:"),
        )

    connector = RawImageIndexConnector()

    meta = connector.connect(str(db_path), expected_index_roots=["/d:", "/c:"])

    assert meta["index_roots"] == "/c:,/d:"
