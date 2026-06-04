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
            return [
                {
                    "name": "notepad.exe",
                    "path": "/c:/Windows/notepad.exe",
                    "is_dir": False,
                    "size": 1024,
                }
            ]
        if path == "/c:/Temp":
            return [{"error": "simulated unreadable directory"}]
        return []


class _RaisingImage:
    def list_directory(self, path="/"):
        raise RuntimeError(f"cannot list {path}")


def test_index_file_listing_records_files_and_coverage_gaps(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    result = index_file_listing(
        _StubImage(),
        store,
        roots=["/c:"],
        started_at="2026-06-04T00:00:00Z",
    )
    search = store.search(
        keyword="notepad",
        artifact_type="File System Entry",
        limit=10,
    )

    assert result["status"] == "partial"
    assert result["indexed_files"] == 1
    assert result["coverage_gaps"][0]["path"] == "/c:/Temp"
    assert search["total"] == 1
    assert search["hits"][0]["fields"]["Path"] == "/c:/Windows/notepad.exe"


def test_index_file_listing_records_listing_exceptions_as_coverage_gaps(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    result = index_file_listing(
        _RaisingImage(),
        store,
        roots=["/c:"],
        started_at="2026-06-04T00:00:00Z",
    )

    assert result["status"] == "partial"
    assert result["indexed_files"] == 0
    assert result["coverage_gaps"][0]["path"] == "/c:"
    assert "cannot list /c:" in result["coverage_gaps"][0]["error"]
