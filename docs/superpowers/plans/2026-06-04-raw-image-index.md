# Raw Image Index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first raw-image-first sidecar SQLite artifact index and connector without weakening no-miss investigation semantics.

**Architecture:** Raw disk images remain the source of truth. A case-local SQLite sidecar stores parsed artifacts for fast repeated search and timeline operations, and the connector exposes the same practical shape as existing forensic connectors. AXIOM/KAPE stay in place as reference/fallback sources until raw artifact family parity is proven.

**Tech Stack:** Python 3.10, sqlite3, pytest, existing `BaseConnector`, existing `E01ImageConnector`, existing MCP bridge patterns.

---

## File Structure

- Create `backend/core/raw_index/schema.py`: sidecar schema DDL and schema version constants.
- Create `backend/core/raw_index/store.py`: small SQLite writer/reader helpers for records, parser runs, and metadata.
- Create `backend/core/raw_index/file_indexer.py`: indexes file listing records from an `E01ImageConnector`-compatible object.
- Create `backend/core/connectors/raw_image_index.py`: connector that reads the sidecar and implements `BaseConnector` methods plus `get_timeline` and `get_hit_detail`.
- Create `backend/core/analysis/raw_parity.py`: compares raw index connector output with another connector for parity reporting.
- Modify `backend/mcp_bridge.py`: add narrow MCP wrappers only after the connector is tested.
- Create tests:
  - `backend/tests/test_raw_index_schema.py`
  - `backend/tests/test_raw_index_store.py`
  - `backend/tests/test_raw_image_index_connector.py`
  - `backend/tests/test_raw_file_indexer.py`
  - `backend/tests/test_raw_parity.py`
  - `backend/tests/test_raw_index_mcp.py`

## Non-Negotiable Semantics

- Do not use estimated counts.
- Do not return zero for parser failure, timeout, missing sidecar, stale sidecar, or unsupported artifact family.
- If a source cannot be evaluated, return `not_evaluable` or `coverage_gap`.
- If sidecar schema version or fingerprint does not match, return a stale-index error and do not search stale rows.
- Sidecar files are local forensic data. Do not commit generated sidecar files.
- Do not delete AXIOM/KAPE code in this phase.

## Task 1: Sidecar Schema

**Files:**
- Create: `backend/core/raw_index/__init__.py`
- Create: `backend/core/raw_index/schema.py`
- Test: `backend/tests/test_raw_index_schema.py`

- [ ] **Step 1: Write the failing schema test**

Create `backend/tests/test_raw_index_schema.py`:

```python
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
    } <= tables

    version = conn.execute(
        "SELECT value FROM raw_index_metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == str(RAW_INDEX_SCHEMA_VERSION)
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_schema.py -q
```

Expected: fail because `core.raw_index.schema` does not exist.

- [ ] **Step 3: Implement the schema**

Create `backend/core/raw_index/__init__.py`:

```python
"""Raw image sidecar index package."""
```

Create `backend/core/raw_index/schema.py`:

```python
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
```

- [ ] **Step 4: Run the schema test**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_schema.py -q
```

Expected: `1 passed`.

- [ ] **Step 5: Commit Task 1**

```powershell
git add backend/core/raw_index/__init__.py backend/core/raw_index/schema.py backend/tests/test_raw_index_schema.py
git commit -m "Add raw image sidecar schema"
```

## Task 2: Store Helper With Exact Counts

**Files:**
- Create: `backend/core/raw_index/store.py`
- Test: `backend/tests/test_raw_index_store.py`

- [ ] **Step 1: Write the failing store test**

Create `backend/tests/test_raw_index_store.py`:

```python
from __future__ import annotations

from core.raw_index.store import RawIndexStore


def test_store_inserts_artifact_and_returns_exact_count(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    run_id = store.start_parser_run("file_indexer", "/c:", started_at="2026-06-04T00:00:00Z")
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
    store.finish_parser_run(run_id, status="completed", coverage_status="searched", finished_at="2026-06-04T00:00:01Z")

    result = store.search(keyword="notepad", artifact_type="File System Entry", limit=10, offset=0)

    assert artifact_id > 0
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert result["count_accuracy"] == "exact"
    assert result["returned"] == 1
    assert result["hits"][0]["fields"]["Path"] == "/c:/Windows/notepad.exe"
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_store.py -q
```

Expected: fail because `RawIndexStore` does not exist.

- [ ] **Step 3: Implement the store**

Create `backend/core/raw_index/store.py` with:

```python
from __future__ import annotations

import sqlite3
from typing import Any

from core.raw_index.schema import initialize_schema


class RawIndexStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        initialize_schema(self.conn)

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def _conn(self) -> sqlite3.Connection:
        if self.conn is None:
            raise RuntimeError("RawIndexStore is not open")
        return self.conn

    def start_parser_run(self, parser_name: str, source_ref: str, *, started_at: str) -> int:
        cur = self._conn().execute(
            "INSERT INTO raw_index_parser_runs(parser_name, source_ref, status, started_at) VALUES (?, ?, ?, ?)",
            (parser_name, source_ref, "running", started_at),
        )
        self._conn().commit()
        return int(cur.lastrowid)

    def finish_parser_run(self, run_id: int, *, status: str, coverage_status: str, finished_at: str, error: str = "") -> None:
        self._conn().execute(
            "UPDATE raw_index_parser_runs SET status = ?, coverage_status = ?, finished_at = ?, error = ? WHERE run_id = ?",
            (status, coverage_status, finished_at, error, run_id),
        )
        self._conn().commit()

    def insert_artifact(
        self,
        *,
        artifact_type: str,
        source_ref: str,
        source_path: str,
        primary_path: str,
        description: str,
        strings: dict[str, str] | None = None,
        times: dict[str, tuple[int, str]] | None = None,
        parser_run_id: int | None = None,
    ) -> int:
        cur = self._conn().execute(
            """
            INSERT INTO raw_index_artifacts(
                artifact_type, source_ref, source_path, primary_path, description, parser_run_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (artifact_type, source_ref, source_path, primary_path, description, parser_run_id),
        )
        artifact_id = int(cur.lastrowid)
        for field_name, value in (strings or {}).items():
            self._conn().execute(
                "INSERT INTO raw_index_artifact_strings(artifact_id, field_name, value) VALUES (?, ?, ?)",
                (artifact_id, field_name, str(value)),
            )
        for field_name, value in (times or {}).items():
            unix_ms, formatted = value
            self._conn().execute(
                "INSERT INTO raw_index_artifact_times(artifact_id, field_name, unix_timestamp_ms, formatted_value) VALUES (?, ?, ?, ?)",
                (artifact_id, field_name, int(unix_ms), formatted),
            )
        if primary_path:
            self._conn().execute(
                "INSERT INTO raw_index_locations(artifact_id, location_value, source_path) VALUES (?, ?, ?)",
                (artifact_id, primary_path, source_path),
            )
        self._conn().commit()
        return artifact_id

    def search(self, *, keyword: str = "", artifact_type: str = "", limit: int = 50, offset: int = 0) -> dict[str, Any]:
        params: list[Any] = []
        where: list[str] = []
        if artifact_type:
            where.append("a.artifact_type = ?")
            params.append(artifact_type)
        if keyword:
            where.append(
                """
                a.artifact_id IN (
                    SELECT artifact_id FROM raw_index_artifact_strings WHERE value LIKE ?
                    UNION
                    SELECT artifact_id FROM raw_index_locations WHERE location_value LIKE ?
                )
                """
            )
            like = f"%{keyword}%"
            params.extend([like, like])
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        total = self._conn().execute(
            f"SELECT COUNT(DISTINCT a.artifact_id) FROM raw_index_artifacts a {where_sql}",
            params,
        ).fetchone()[0]
        rows = self._conn().execute(
            f"""
            SELECT DISTINCT a.artifact_id, a.artifact_type, a.source_path, a.primary_path, a.description
            FROM raw_index_artifacts a
            {where_sql}
            ORDER BY a.artifact_id
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        hits = [self.get_hit_detail(int(row["artifact_id"])) for row in rows]
        return {
            "total": int(total),
            "total_estimated": int(total),
            "total_is_estimated": False,
            "count_accuracy": "exact",
            "returned": len(hits),
            "offset": offset,
            "limit": limit,
            "truncated": int(total) > offset + len(hits),
            "hits": hits,
        }

    def get_hit_detail(self, artifact_id: int) -> dict[str, Any]:
        row = self._conn().execute(
            "SELECT artifact_id, artifact_type, source_path, primary_path, description FROM raw_index_artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            return {"error": f"artifact_id {artifact_id} not found"}
        fields = {
            r["field_name"]: r["value"]
            for r in self._conn().execute(
                "SELECT field_name, value FROM raw_index_artifact_strings WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchall()
        }
        timestamps = {
            r["field_name"]: r["formatted_value"]
            for r in self._conn().execute(
                "SELECT field_name, formatted_value FROM raw_index_artifact_times WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchall()
        }
        return {
            "hit_id": int(row["artifact_id"]),
            "artifact_type": row["artifact_type"],
            "source_path": row["source_path"],
            "location": row["primary_path"],
            "description": row["description"],
            "fields": fields,
            "timestamps": timestamps,
        }
```

- [ ] **Step 4: Run the store test**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_store.py -q
```

Expected: `1 passed`.

- [ ] **Step 5: Commit Task 2**

```powershell
git add backend/core/raw_index/store.py backend/tests/test_raw_index_store.py
git commit -m "Add raw image sidecar store"
```

## Task 3: Raw Image Index Connector

**Files:**
- Create: `backend/core/connectors/raw_image_index.py`
- Test: `backend/tests/test_raw_image_index_connector.py`

- [ ] **Step 1: Write connector tests**

Create `backend/tests/test_raw_image_index_connector.py`:

```python
from __future__ import annotations

from core.connectors.raw_image_index import RawImageIndexConnector
from core.raw_index.store import RawIndexStore


def _seed(db_path):
    store = RawIndexStore(str(db_path))
    store.open()
    run_id = store.start_parser_run("seed", "unit", started_at="2026-06-04T00:00:00Z")
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
    store.finish_parser_run(run_id, status="completed", coverage_status="searched", finished_at="2026-06-04T00:00:01Z")
    store.close()


def test_raw_image_index_connector_search_and_detail(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()

    meta = conn.connect(str(db_path))
    result = conn.search(keyword="a.tmp", filters={"artifact_type": "File System Entry"}, limit=10)
    detail = conn.get_hit_detail(result["hits"][0]["hit_id"])

    assert meta["source_type"] == "raw_image_sidecar"
    assert result["total"] == 1
    assert result["total_is_estimated"] is False
    assert detail["fields"]["Path"] == "/c:/Temp/a.tmp"
    assert "search" in conn.get_capabilities()


def test_raw_image_index_connector_timeline_is_exact(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    _seed(db_path)
    conn = RawImageIndexConnector()
    conn.connect(str(db_path))

    timeline = conn.get_timeline(start_date="2026-10-01", end_date="2026-10-31", limit=10)

    assert timeline["total_events"] == 1
    assert timeline["returned"] == 1
    assert timeline["entries"][0]["artifact_type"] == "File System Entry"
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_image_index_connector.py -q
```

Expected: fail because `RawImageIndexConnector` does not exist.

- [ ] **Step 3: Implement the connector**

Create `backend/core/connectors/raw_image_index.py`:

```python
from __future__ import annotations

import os
import sqlite3
from typing import Any

from core.connectors.base import BaseConnector
from core.raw_index.schema import RAW_INDEX_SCHEMA_VERSION
from core.raw_index.store import RawIndexStore


class RawImageIndexConnector(BaseConnector):
    def __init__(self) -> None:
        self._store: RawIndexStore | None = None
        self._path = ""
        self._metadata: dict[str, Any] = {}

    def connect(self, path: str, **kwargs: Any) -> dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Raw index not found: {path}")
        self._path = path
        self._store = RawIndexStore(path)
        self._store.open()
        self._metadata = self._load_metadata()
        return self._metadata

    def disconnect(self) -> None:
        if self._store:
            self._store.close()
        self._store = None
        self._path = ""
        self._metadata = {}

    def is_connected(self) -> bool:
        return self._store is not None

    def get_metadata(self) -> dict:
        return dict(self._metadata)

    def get_capabilities(self) -> list[str]:
        return ["search", "timeline", "hit_detail", "artifact_type_counts"]

    def search(self, keyword: str = "", filters: dict | None = None, limit: int = 50, offset: int = 0) -> dict:
        store = self._require_store()
        filters = filters or {}
        return store.search(
            keyword=keyword,
            artifact_type=filters.get("artifact_type", ""),
            limit=limit,
            offset=offset,
        )

    def get_hit_detail(self, hit_id: int) -> dict:
        return self._require_store().get_hit_detail(hit_id)

    def get_timeline(
        self,
        start_date: str = "",
        end_date: str = "",
        artifact_types: list[str] | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> dict:
        conn = self._require_store()._conn()
        start_ms = _iso_date_to_ms(start_date, is_end=False) if start_date else 0
        end_ms = _iso_date_to_ms(end_date, is_end=True) if end_date else 9999999999999
        params: list[Any] = [start_ms, end_ms]
        type_sql = ""
        if artifact_types:
            placeholders = ",".join("?" * len(artifact_types))
            type_sql = f"AND a.artifact_type IN ({placeholders})"
            params.extend(artifact_types)
        total = conn.execute(
            f"""
            SELECT COUNT(DISTINCT t.artifact_id)
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            WHERE t.unix_timestamp_ms BETWEEN ? AND ? {type_sql}
            """,
            params,
        ).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT t.artifact_id, t.unix_timestamp_ms, t.formatted_value, t.field_name,
                   a.artifact_type, a.description
            FROM raw_index_artifact_times t
            JOIN raw_index_artifacts a ON t.artifact_id = a.artifact_id
            WHERE t.unix_timestamp_ms BETWEEN ? AND ? {type_sql}
            ORDER BY t.unix_timestamp_ms, t.artifact_id
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        entries = [
            {
                "hit_id": int(row["artifact_id"]),
                "timestamp_ms": int(row["unix_timestamp_ms"]),
                "timestamp": row["formatted_value"],
                "time_field": row["field_name"],
                "artifact_type": row["artifact_type"],
                "description": row["description"],
            }
            for row in rows
        ]
        return {
            "total_events": int(total),
            "returned": len(entries),
            "truncated": int(total) > offset + len(entries),
            "entries": entries,
        }

    def _load_metadata(self) -> dict[str, Any]:
        conn = self._require_store()._conn()
        rows = conn.execute("SELECT key, value FROM raw_index_metadata").fetchall()
        meta = {row["key"]: row["value"] for row in rows}
        version = meta.get("schema_version", "")
        if version != str(RAW_INDEX_SCHEMA_VERSION):
            raise RuntimeError(f"Raw index schema mismatch: {version}")
        return {
            "source_type": "raw_image_sidecar",
            "source_path": self._path,
            "schema_version": version,
        }

    def _require_store(self) -> RawIndexStore:
        if self._store is None:
            raise RuntimeError("RawImageIndexConnector is not connected")
        return self._store


def _iso_date_to_ms(value: str, *, is_end: bool) -> int:
    from datetime import datetime, timezone

    if "T" not in value:
        suffix = "T23:59:59.999+00:00" if is_end else "T00:00:00+00:00"
        value = value + suffix
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
```

- [ ] **Step 4: Run connector tests**

Run:

```powershell
python -m pytest backend/tests/test_raw_image_index_connector.py -q
```

Expected: `2 passed`.

- [ ] **Step 5: Commit Task 3**

```powershell
git add backend/core/connectors/raw_image_index.py backend/tests/test_raw_image_index_connector.py
git commit -m "Add raw image sidecar connector"
```

## Task 4: File Listing Indexer

**Files:**
- Create: `backend/core/raw_index/file_indexer.py`
- Test: `backend/tests/test_raw_file_indexer.py`

- [ ] **Step 1: Write file indexer tests**

Create `backend/tests/test_raw_file_indexer.py`:

```python
from __future__ import annotations

from core.raw_index.file_indexer import index_file_listing
from core.raw_index.store import RawIndexStore


class _StubImage:
    def list_directory(self, path="/"):
        if path == "/c:":
            return [
                {"name": "Windows", "path": "/c:/Windows", "is_dir": True},
                {"name": "Temp", "path": "/c:/Temp", "is_dir": True},
            ]
        if path == "/c:/Windows":
            return [{"name": "notepad.exe", "path": "/c:/Windows/notepad.exe", "is_dir": False, "size": 1024}]
        if path == "/c:/Temp":
            return [{"error": "simulated unreadable directory"}]
        return []


def test_index_file_listing_records_files_and_coverage_gaps(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    result = index_file_listing(_StubImage(), store, roots=["/c:"], started_at="2026-06-04T00:00:00Z")
    search = store.search(keyword="notepad", artifact_type="File System Entry", limit=10)

    assert result["status"] == "partial"
    assert result["indexed_files"] == 1
    assert result["coverage_gaps"][0]["path"] == "/c:/Temp"
    assert search["total"] == 1
    assert search["hits"][0]["fields"]["Path"] == "/c:/Windows/notepad.exe"
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_file_indexer.py -q
```

Expected: fail because `file_indexer` does not exist.

- [ ] **Step 3: Implement the file listing indexer**

Create `backend/core/raw_index/file_indexer.py`:

```python
from __future__ import annotations

from collections import deque
from typing import Any

from core.raw_index.store import RawIndexStore


def index_file_listing(
    image: Any,
    store: RawIndexStore,
    *,
    roots: list[str],
    started_at: str,
) -> dict[str, Any]:
    run_id = store.start_parser_run("file_indexer", ",".join(roots), started_at=started_at)
    queue = deque(roots)
    indexed_files = 0
    coverage_gaps: list[dict[str, str]] = []
    visited: set[str] = set()

    while queue:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        entries = image.list_directory(path)
        for entry in entries:
            if entry.get("error"):
                coverage_gaps.append({
                    "path": path,
                    "status": "coverage_gap",
                    "error": str(entry.get("error")),
                })
                continue
            entry_path = str(entry.get("path", ""))
            if not entry_path:
                continue
            if entry.get("is_dir"):
                queue.append(entry_path)
                continue
            name = str(entry.get("name") or entry_path.rsplit("/", 1)[-1])
            size = str(entry.get("size", ""))
            store.insert_artifact(
                artifact_type="File System Entry",
                source_ref=path,
                source_path=entry_path,
                primary_path=entry_path,
                description=f"File System Entry {entry_path}",
                strings={"Name": name, "Path": entry_path, "Size": size},
                times={},
                parser_run_id=run_id,
            )
            indexed_files += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "partial" if coverage_gaps else "searched"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(g["error"] for g in coverage_gaps),
    )
    return {
        "ok": True,
        "status": status,
        "indexed_files": indexed_files,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }
```

- [ ] **Step 4: Run file indexer tests**

Run:

```powershell
python -m pytest backend/tests/test_raw_file_indexer.py -q
```

Expected: `1 passed`.

- [ ] **Step 5: Commit Task 4**

```powershell
git add backend/core/raw_index/file_indexer.py backend/tests/test_raw_file_indexer.py
git commit -m "Add raw image file listing indexer"
```

## Task 5: Parity Report Helper

**Files:**
- Create: `backend/core/analysis/raw_parity.py`
- Test: `backend/tests/test_raw_parity.py`

- [ ] **Step 1: Write parity helper tests**

Create `backend/tests/test_raw_parity.py`:

```python
from __future__ import annotations

from core.analysis.raw_parity import compare_search_parity


class _Conn:
    def __init__(self, hits):
        self.hits = hits

    def search(self, keyword="", filters=None, limit=50, offset=0):
        return {"total": len(self.hits), "hits": self.hits, "returned": len(self.hits), "truncated": False}


def test_compare_search_parity_reports_missing_raw_hits():
    reference = _Conn([{"hit_id": 1, "fields": {"Path": "/c:/a"}}, {"hit_id": 2, "fields": {"Path": "/c:/b"}}])
    raw = _Conn([{"hit_id": 10, "fields": {"Path": "/c:/a"}}])

    result = compare_search_parity(reference, raw, keyword="", artifact_type="File System Entry")

    assert result["ok"] is True
    assert result["parity_status"] == "gap_detected"
    assert result["reference_total"] == 2
    assert result["raw_total"] == 1
    assert "/c:/b" in result["missing_in_raw"]
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_parity.py -q
```

Expected: fail because `raw_parity` does not exist.

- [ ] **Step 3: Implement parity helper**

Create `backend/core/analysis/raw_parity.py`:

```python
from __future__ import annotations

from typing import Any


def compare_search_parity(
    reference_connector: Any,
    raw_connector: Any,
    *,
    keyword: str,
    artifact_type: str = "",
    limit: int = 1000,
) -> dict[str, Any]:
    filters = {"artifact_type": artifact_type} if artifact_type else {}
    reference = reference_connector.search(keyword=keyword, filters=filters, limit=limit, offset=0)
    raw = raw_connector.search(keyword=keyword, filters=filters, limit=limit, offset=0)
    reference_keys = {_stable_hit_key(hit) for hit in reference.get("hits", [])}
    raw_keys = {_stable_hit_key(hit) for hit in raw.get("hits", [])}
    missing = sorted(reference_keys - raw_keys)
    extra = sorted(raw_keys - reference_keys)
    return {
        "ok": True,
        "parity_status": "matched" if not missing else "gap_detected",
        "keyword": keyword,
        "artifact_type": artifact_type,
        "reference_total": int(reference.get("total", len(reference.get("hits", []))) or 0),
        "raw_total": int(raw.get("total", len(raw.get("hits", []))) or 0),
        "missing_in_raw": missing,
        "extra_in_raw": extra,
        "strong_conclusion_allowed": not missing,
        "notes": [
            "A raw parity gap means the raw index is not yet a drop-in replacement for this query.",
            "Do not remove the reference connector for this artifact family until parity gaps are resolved.",
        ],
    }


def _stable_hit_key(hit: dict[str, Any]) -> str:
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    for key in ("Path", "Full Path", "File Path", "URL", "Name"):
        if fields.get(key):
            return str(fields[key]).lower()
    return str(hit.get("location") or hit.get("source_path") or hit.get("hit_id", "")).lower()
```

- [ ] **Step 4: Run parity tests**

Run:

```powershell
python -m pytest backend/tests/test_raw_parity.py -q
```

Expected: `1 passed`.

- [ ] **Step 5: Commit Task 5**

```powershell
git add backend/core/analysis/raw_parity.py backend/tests/test_raw_parity.py
git commit -m "Add raw index parity helper"
```

## Task 6: Minimal MCP Surface

**Files:**
- Modify: `backend/mcp_bridge.py`
- Test: `backend/tests/test_raw_index_mcp.py`

- [ ] **Step 1: Write MCP tests with monkeypatched state**

Create `backend/tests/test_raw_index_mcp.py`:

```python
from __future__ import annotations

import asyncio

import mcp_bridge


def _run(coro):
    return asyncio.run(coro)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


def test_open_raw_index_sets_raw_connector(monkeypatch, tmp_path):
    from core.raw_index.store import RawIndexStore

    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    store.close()

    captured = {}

    class _State:
        def set(self, name, connector):
            captured[name] = connector

    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "app_state", _State())

    result = _run(mcp_bridge.open_raw_index(str(db_path)))

    assert result["source_type"] == "raw_image_sidecar"
    assert "raw_index" in captured
```

- [ ] **Step 2: Run the MCP test and verify it fails**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_mcp.py -q
```

Expected: fail because `open_raw_index` does not exist.

- [ ] **Step 3: Add `open_raw_index` MCP wrapper**

Modify `backend/mcp_bridge.py` near other case/image opening tools:

```python
@mcp.tool()
async def open_raw_index(path: str) -> dict:
    """Open a raw image sidecar index as the active raw-index connector.

    Reading guide for AI consumers:
    - This opens an existing sidecar index, not the raw image itself.
    - Stale or mismatched sidecars must be treated as not_evaluable until rebuilt.
    - AXIOM/KAPE parity references should remain available during migration.
    """
    def fn():
        from core.connectors.raw_image_index import RawImageIndexConnector

        c = RawImageIndexConnector()
        meta = c.connect(path)
        app_state.set("raw_index", c)
        return meta

    return await _traced("open_raw_index", {"path": path}, fn, timeout_seconds=TIMEOUT_LIGHT)
```

- [ ] **Step 4: Run MCP tests**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_mcp.py -q
```

Expected: `1 passed`.

- [ ] **Step 5: Commit Task 6**

```powershell
git add backend/mcp_bridge.py backend/tests/test_raw_index_mcp.py
git commit -m "Add raw index MCP opener"
```

## Task 7: Full Verification

**Files:**
- No new files.

- [ ] **Step 1: Run targeted tests**

Run:

```powershell
python -m pytest backend/tests/test_raw_index_schema.py backend/tests/test_raw_index_store.py backend/tests/test_raw_image_index_connector.py backend/tests/test_raw_file_indexer.py backend/tests/test_raw_parity.py backend/tests/test_raw_index_mcp.py -q
```

Expected: all raw index tests pass.

- [ ] **Step 2: Run backend regression tests**

Run:

```powershell
python -m pytest backend/tests
```

Expected: all existing backend tests pass or only pre-existing documented skips appear.

- [ ] **Step 3: Check whitespace**

Run:

```powershell
git diff --check
```

Expected: no whitespace errors.

- [ ] **Step 4: Check generated files are not staged**

Run:

```powershell
git status --short
```

Expected: only source files and tests from this plan are modified or committed. No `export/cache/raw_index` files should appear.

## Self-Review Checklist

- Each task preserves exact count semantics.
- Each failure path reports a gap or error instead of silent zero.
- The first phase does not remove AXIOM/KAPE code.
- The sidecar schema is local and generated sidecar files are not committed.
- Tests seed synthetic paths only and do not include incident-specific values.

