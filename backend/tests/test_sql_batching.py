"""Regression test for Bug #4 — SQLite "too many SQL variables".

Before the batching fix, any query that hydrated more than ~999 hit_ids
(trivially reachable on EVTX-heavy cases — 188k rows in production
testing) crashed with ``sqlite3.OperationalError: too many SQL
variables``. The fix splits the IN-clause fan-out into chunks of
``_SQLITE_PARAM_BATCH`` (default 900). This test exercises the chunk
helper and confirms a >999-id hydrate call no longer raises.
"""

from __future__ import annotations

import sqlite3

import pytest

from connectors.axiom_mfdb import AxiomMfdbConnector, _SQLITE_PARAM_BATCH, _chunk


def test_chunk_splits_on_batch_boundary():
    ids = list(range(2500))
    batches = list(_chunk(ids))
    # 2500 / 900 = 3 batches (900, 900, 700)
    assert len(batches) == 3
    assert len(batches[0]) == 900
    assert len(batches[1]) == 900
    assert len(batches[2]) == 700
    # Round-trip preserves order and membership.
    rebuilt = [x for batch in batches for x in batch]
    assert rebuilt == ids


def test_chunk_handles_small_lists_without_splitting():
    assert list(_chunk([])) == []
    assert list(_chunk([1, 2, 3])) == [[1, 2, 3]]


def test_chunk_respects_custom_size():
    batches = list(_chunk([1, 2, 3, 4, 5], size=2))
    assert batches == [[1, 2], [3, 4], [5]]


def _build_minimal_mfdb_schema(conn: sqlite3.Connection) -> None:
    """Build only the tables ``_hydrate_hits`` touches plus the metadata
    rows ``_cache_lookups`` reads on connect."""
    conn.executescript(
        """
        CREATE TABLE fragment_definition (
            fragment_definition_id TEXT PRIMARY KEY,
            artifact_version_id TEXT,
            name TEXT,
            data_type TEXT
        );
        CREATE TABLE artifact_version (
            artifact_version_id TEXT PRIMARY KEY,
            artifact_name TEXT
        );
        CREATE TABLE scan_artifact_hit (
            hit_id INTEGER,
            artifact_version_id TEXT
        );
        CREATE TABLE hit_fragment_string (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value TEXT
        );
        CREATE TABLE hit_fragment_int (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value INTEGER
        );
        CREATE TABLE hit_fragment_date (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            unix_timestamp_ms INTEGER,
            formatted_value TEXT
        );
        CREATE TABLE hit_fragment_float (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value REAL
        );
        CREATE TABLE hit_location (
            hit_id INTEGER,
            location_value TEXT,
            source_id TEXT,
            sort_order INTEGER
        );
        CREATE TABLE source (
            source_id TEXT PRIMARY KEY,
            source_friendly_value TEXT
        );
        CREATE TABLE source_path (
            source_id TEXT,
            source_path TEXT
        );
        CREATE TABLE hit_hash (
            hit_id INTEGER,
            hash TEXT
        );
        """
    )
    # One artifact_version + one fragment so _cache_lookups has something
    # to index.
    conn.execute(
        "INSERT INTO artifact_version (artifact_version_id, artifact_name) VALUES (?, ?)",
        ("av-1", "Test Artifact"),
    )
    conn.execute(
        "INSERT INTO fragment_definition (fragment_definition_id, artifact_version_id, name, data_type) VALUES (?, ?, ?, ?)",
        ("frag-1", "av-1", "TestField", "string"),
    )
    conn.commit()


def test_hydrate_hits_batches_above_sqlite_variable_limit(monkeypatch, tmp_path):
    """Forces a _hydrate_hits call with 2000 hit_ids — which is safely above
    the 999-variable ceiling — and asserts it does not raise."""
    # Build a real SQLite file so sqlite3.connect(uri=..., mode=ro) works.
    db_path = tmp_path / "test.mfdb"
    raw = sqlite3.connect(str(db_path))
    _build_minimal_mfdb_schema(raw)
    # Populate 2000 string-fragment rows so we can see them come back.
    raw.executemany(
        "INSERT INTO hit_fragment_string (hit_id, fragment_definition_id, value) VALUES (?, ?, ?)",
        [(i, "frag-1", f"value-{i}") for i in range(2000)],
    )
    raw.commit()
    raw.close()

    conn = AxiomMfdbConnector()
    # Skip full connect (needs case_info tables) — wire up just enough
    # state for _hydrate_hits to run.
    conn._conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    conn._conn.row_factory = sqlite3.Row
    conn._frag_defs = {"frag-1": "TestField"}

    # 2000 > _SQLITE_PARAM_BATCH (900) and > SQLite's default 999 ceiling.
    hit_ids = list(range(2000))
    assert len(hit_ids) > _SQLITE_PARAM_BATCH

    hits = conn._hydrate_hits(hit_ids)

    # All 2000 should hydrate and preserve their TestField values.
    assert len(hits) == 2000
    # Spot-check boundary hits that sit across batch edges.
    for boundary in (0, 899, 900, 1799, 1800, 1999):
        assert hits[boundary]["fields"]["TestField"] == f"value-{boundary}"
