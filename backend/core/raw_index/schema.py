from __future__ import annotations

import sqlite3


RAW_INDEX_SCHEMA_VERSION = 1


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_index_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_index_parser_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    parser_name TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    coverage_status TEXT NOT NULL DEFAULT 'not_evaluable',
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS raw_index_artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    source_path TEXT NOT NULL DEFAULT '',
    primary_path TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    parser_run_id INTEGER,
    FOREIGN KEY(parser_run_id) REFERENCES raw_index_parser_runs(run_id)
);

CREATE TABLE IF NOT EXISTS raw_index_artifact_strings (
    artifact_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY(artifact_id) REFERENCES raw_index_artifacts(artifact_id)
);

CREATE TABLE IF NOT EXISTS raw_index_artifact_times (
    artifact_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    unix_timestamp_ms INTEGER NOT NULL,
    formatted_value TEXT NOT NULL,
    FOREIGN KEY(artifact_id) REFERENCES raw_index_artifacts(artifact_id)
);

CREATE TABLE IF NOT EXISTS raw_index_locations (
    artifact_id INTEGER NOT NULL,
    location_value TEXT NOT NULL,
    source_path TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(artifact_id) REFERENCES raw_index_artifacts(artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_raw_artifact_type
    ON raw_index_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_raw_strings_value
    ON raw_index_artifact_strings(value);
CREATE INDEX IF NOT EXISTS idx_raw_times_ms
    ON raw_index_artifact_times(unix_timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_raw_locations_value
    ON raw_index_locations(location_value);
"""


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.execute(
        "INSERT OR REPLACE INTO raw_index_metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(RAW_INDEX_SCHEMA_VERSION)),
    )
    conn.commit()
