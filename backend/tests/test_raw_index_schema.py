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


def test_initialize_schema_indexes_artifact_id_lookup_tables(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)

    initialize_schema(conn)

    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }
    assert {
        "idx_raw_strings_artifact_field",
        "idx_raw_times_artifact_field",
        "idx_raw_locations_artifact_value",
    } <= indexes


def test_initialize_schema_indexes_timeline_range_order(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)

    initialize_schema(conn)

    index_columns = [
        row[2]
        for row in conn.execute(
            "PRAGMA index_info(idx_raw_times_ms_artifact_field)"
        ).fetchall()
    ]
    assert index_columns == [
        "unix_timestamp_ms",
        "artifact_id",
        "field_name",
    ]


def test_initialize_schema_indexes_hot_search_order_paths(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)

    initialize_schema(conn)

    artifact_type_columns = [
        row[2]
        for row in conn.execute(
            "PRAGMA index_info(idx_raw_artifact_type_id)"
        ).fetchall()
    ]
    location_columns = [
        row[2]
        for row in conn.execute(
            "PRAGMA index_info(idx_raw_locations_artifact_value)"
        ).fetchall()
    ]
    assert artifact_type_columns == ["artifact_type", "artifact_id"]
    assert location_columns == ["artifact_id", "location_value"]


def test_initialize_schema_avoids_redundant_prefix_indexes_on_hot_paths(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    conn = sqlite3.connect(db_path)

    initialize_schema(conn)

    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }
    assert {
        "idx_raw_artifact_type",
        "idx_raw_times_ms",
        "idx_raw_locations_artifact",
        "idx_raw_search_text_artifact",
    }.isdisjoint(indexes)
