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


class _TimestampImage:
    def list_directory(self, path="/"):
        if path == "/c:":
            return [
                {
                    "name": "dated.exe",
                    "path": "/c:/Tools/dated.exe",
                    "is_dir": False,
                    "size": 2048,
                    "created": "2026-10-03T00:00:00Z",
                    "modified": "2026-10-04T00:00:00Z",
                    "accessed": "2026-10-05T00:00:00Z",
                },
            ]
        return []


class _ManyFilesImage:
    def list_directory(self, path="/"):
        if path == "/c:":
            return [
                {
                    "name": f"tool-{idx}.exe",
                    "path": f"/c:/Tools/tool-{idx}.exe",
                    "is_dir": False,
                    "size": idx,
                }
                for idx in range(3)
            ]
        return []


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


def test_index_file_listing_records_entry_timestamps(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()

    result = index_file_listing(
        _TimestampImage(),
        store,
        roots=["/c:"],
        started_at="2026-06-04T00:00:00Z",
    )
    search = store.search(
        keyword="dated",
        artifact_type="File System Entry",
        start_date="2026-10-04",
        end_date="2026-10-04",
        limit=10,
    )
    detail = store.get_hit_detail(1)

    assert result["status"] == "completed"
    assert search["total"] == 1
    assert search["total_is_estimated"] is False
    assert search["search_strategy"]["date_filter"] == "artifact_times"
    assert detail["timestamps"]["Modified"] == "2026-10-04T00:00:00Z"


def test_index_file_listing_batches_database_commits(tmp_path):
    db_path = tmp_path / "raw-index.sqlite"
    store = RawIndexStore(str(db_path))
    store.open()
    traced_statements: list[str] = []
    store._conn().set_trace_callback(traced_statements.append)

    result = index_file_listing(
        _ManyFilesImage(),
        store,
        roots=["/c:"],
        started_at="2026-06-04T00:00:00Z",
    )
    commit_count = sum(
        1 for statement in traced_statements if statement.strip().upper() == "COMMIT"
    )

    assert result["indexed_files"] == 3
    assert commit_count == 1


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
