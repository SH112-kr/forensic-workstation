from __future__ import annotations

import sqlite3

from core.raw_index.schema import RAW_INDEX_SCHEMA_VERSION, initialize_schema


def test_initialize_schema_creates_required_tables(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)

    initialize_schema(conn)

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {
        "raw_index_metadata",
        "raw_index_parser_runs",
        "raw_index_artifacts",
        "raw_index_artifact_strings",
        "raw_index_artifact_times",
        "raw_index_locations",
        "raw_index_search_text",
    } <= tables

    version = conn.execute(
        "SELECT value FROM raw_index_metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == str(RAW_INDEX_SCHEMA_VERSION)


def test_initialize_schema_does_not_overwrite_existing_version(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE raw_index_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("schema_version", "999"),
    )
    conn.commit()

    initialize_schema(conn)

    version = conn.execute(
        "SELECT value FROM raw_index_metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "999"
