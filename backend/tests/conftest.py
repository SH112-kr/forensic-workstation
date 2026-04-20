"""Shared pytest fixtures.

The backend package uses an implicit sys.path trick (``from state import
app_state``) rather than a proper ``forensic_workstation`` package, so we
add ``backend/`` to sys.path before any module is imported.
"""

from __future__ import annotations

import os
import sys

import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


class MockConnector:
    """Minimal connector that mimics the AxiomMfdbConnector / KapeCsvConnector
    surface used by aggregator / coverage / scoring / timeline modules.

    Tests pass explicit lists of rows + metadata so each assertion targets a
    well-known shape. No SQL, no filesystem.
    """

    def __init__(
        self,
        source_type: str = "mfdb",
        source_path: str = "C:/fixture.mfdb",
        case_name: str = "fixture",
        total_hits: int = 0,
        artifact_counts: list[dict] | None = None,
        search_hits: list[dict] | None = None,
        timeline_entries: list[dict] | None = None,
        hash_hits: list[dict] | None = None,
        raise_on: set[str] | None = None,
    ) -> None:
        self._source_type = source_type
        self._source_path = source_path
        self._case_name = case_name
        self._total_hits = total_hits
        self._artifact_counts = artifact_counts or []
        self._search_hits = search_hits or []
        self._timeline = timeline_entries or []
        self._hash_hits = hash_hits or []
        self._raise_on = raise_on or set()
        self._connected = True

    def is_connected(self) -> bool:
        return self._connected

    def disconnect(self) -> None:
        self._connected = False

    def get_metadata(self) -> dict:
        if "metadata" in self._raise_on:
            raise RuntimeError("simulated metadata failure")
        return {
            "source_type": self._source_type,
            "source_path": self._source_path,
            "case_name": self._case_name,
            "total_hits": self._total_hits,
            "date_range_start": "2026-03-01T00:00:00",
            "date_range_end": "2026-04-15T00:00:00",
        }

    def get_artifact_type_counts(self):
        if "counts" in self._raise_on:
            raise RuntimeError("simulated counts failure")
        return self._artifact_counts

    def search(self, keyword="", filters=None, limit=50, offset=0) -> dict:
        if "search" in self._raise_on:
            raise RuntimeError("simulated search failure")
        kw = (keyword or "").lower()
        matches = [
            h for h in self._search_hits
            if not kw or kw in " ".join(str(v) for v in h.values()).lower()
        ]
        return {"hits": matches[:limit], "total": len(matches), "returned": min(len(matches), limit)}

    def get_timeline(self, start_date="", end_date="", artifact_types=None, limit=200, offset=0) -> dict:
        if "timeline" in self._raise_on:
            raise RuntimeError("simulated timeline failure")
        return {"entries": self._timeline[:limit], "total_events": len(self._timeline)}

    def search_by_hash(self, hash_value, limit=50, offset=0) -> dict:
        if "hash" in self._raise_on:
            raise RuntimeError("simulated hash failure")
        matches = [h for h in self._hash_hits if h.get("hash") == hash_value]
        return {"hits": matches[:limit], "total": len(matches)}


@pytest.fixture
def mfdb_case() -> MockConnector:
    return MockConnector(
        source_type="mfdb",
        source_path="C:/cases/a.mfdb",
        case_name="Case-A",
        total_hits=200,
        artifact_counts=[
            {"artifact_name": "Prefetch", "hit_count": 50},
            {"artifact_name": "Chat Applications", "hit_count": 150},
        ],
        search_hits=[
            {"hit_id": 1, "timestamp": "2026-04-01T10:00:00", "artifact_type": "Prefetch",
             "fields": {"Application Name": "powershell.exe"}},
            {"hit_id": 2, "timestamp": "2026-04-02T11:00:00", "artifact_type": "Chat Applications",
             "fields": {"message": "admin"}},
        ],
        timeline_entries=[
            {"hit_id": 1, "timestamp": "2026-04-01T10:00:00", "artifact_type": "Prefetch",
             "description": "powershell.exe ran"},
        ],
        hash_hits=[
            {"hit_id": 5, "hash": "deadbeef", "timestamp": "2026-04-03"},
        ],
    )


@pytest.fixture
def kape_case() -> MockConnector:
    return MockConnector(
        source_type="kape",
        source_path="C:/cases/b",
        case_name="Case-B",
        total_hits=500,
        artifact_counts=[
            {"artifact_name": "Prefetch", "hit_count": 100},
            {"artifact_name": "Windows Event Logs", "hit_count": 400},
        ],
        search_hits=[
            {"hit_id": 11, "timestamp": "2026-04-05T09:00:00", "artifact_type": "Windows Event Logs",
             "fields": {"user": "Administrator"}},
        ],
        timeline_entries=[
            {"hit_id": 11, "timestamp": "2026-04-05T09:00:00", "artifact_type": "Windows Event Logs",
             "description": "Logon by Administrator"},
        ],
    )


@pytest.fixture
def broken_case() -> MockConnector:
    return MockConnector(
        source_type="kape",
        source_path="C:/cases/broken",
        case_name="Case-Broken",
        raise_on={"metadata", "counts", "search", "timeline", "hash"},
    )
