"""Tests for the $MFT-streaming file indexer (TB-safe, roadmap P5)."""

from __future__ import annotations

from core.raw_index.file_indexer import index_file_listing, index_mft_listing
from core.raw_index.store import RawIndexStore


_EPOCH_MS = 1779160440000  # 2026-05-19T03:14:00Z


class _MftImage:
    """Stub exposing iter_mft_records (the TB-safe MFT stream)."""

    def __init__(self, records=None, cap_after=0):
        self._records = records if records is not None else [
            {"segment": 40, "path": "/c:/Windows/notepad.exe", "name": "notepad.exe",
             "is_dir": False, "in_use": True, "size": 1024,
             "created": _EPOCH_MS, "modified": _EPOCH_MS + 1000,
             "accessed": _EPOCH_MS + 2000, "changed": _EPOCH_MS + 500},
            {"segment": 41, "path": "/c:/Windows", "name": "Windows",
             "is_dir": True, "in_use": True, "size": 0,
             "created": _EPOCH_MS, "modified": None, "accessed": None, "changed": None},
            {"segment": 99, "path": "/c:/Temp/deleted.exe", "name": "deleted.exe",
             "is_dir": False, "in_use": False, "size": 512,
             "created": _EPOCH_MS, "modified": _EPOCH_MS, "accessed": _EPOCH_MS,
             "changed": _EPOCH_MS},
        ]
        self._cap_after = cap_after

    def iter_mft_records(self, volume_ref="/c:", max_records=0):
        for i, rec in enumerate(self._records):
            if self._cap_after and i >= self._cap_after:
                yield {"error": "mft_record_cap_reached", "cap": self._cap_after,
                       "scanned": i}
                return
            yield dict(rec)


class _MftErrorImage:
    def iter_mft_records(self, volume_ref="/c:", max_records=0):
        yield {"segment": 40, "path": "/c:/ok.exe", "name": "ok.exe",
               "is_dir": False, "in_use": True, "size": 1,
               "created": _EPOCH_MS, "modified": None, "accessed": None, "changed": None}
        yield {"error": "bad record", "segment": 50}


class _NoMftVolumeImage:
    def iter_mft_records(self, volume_ref="/c:", max_records=0):
        yield {"error": "no_ntfs_mft_for_volume", "volume": volume_ref}


def _open(tmp_path):
    s = RawIndexStore(str(tmp_path / "mft.sqlite"))
    s.open()
    return s


def test_index_file_listing_prefers_mft_when_available(tmp_path):
    """index_file_listing must route to the MFT stream when the image
    exposes iter_mft_records (not the legacy directory walk)."""
    store = _open(tmp_path)
    try:
        result = index_file_listing(_MftImage(), store, roots=["/c:"],
                                    started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexer"] == "mft"
    assert result["ok"] is True
    assert result["indexed_files"] == 3  # file + dir + deleted file


def test_mft_indexing_records_paths_times_and_deleted(tmp_path):
    store = _open(tmp_path)
    try:
        result = index_mft_listing(_MftImage(), store, roots=["/c:"],
                                   started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexed_files"] == 3
    assert result["coverage_gaps"] == []

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "mft.sqlite"))
    # deleted record is indexed and flagged
    deleted = conn.search(keyword="deleted.exe", filters={}, limit=5)
    assert deleted["total"] == 1
    blob = " ".join(str(v) for h in deleted["hits"] for v in h.values())
    assert "True" in blob  # Deleted flag
    # timestamps stored on the file record
    hit = conn.search(keyword="notepad.exe", filters={}, limit=5)["hits"][0]
    detail = conn.get_hit_detail(hit["hit_id"])
    assert detail.get("timestamps")  # Created/Modified/Accessed present
    conn.disconnect()


def test_clean_mft_run_is_not_flagged_as_coverage_gap(tmp_path):
    """A clean MFT run (no per-record gaps) must persist parser status
    'completed'/'searched' so store._coverage_summary treats it as healthy —
    not 'indexed', which the summary would mis-read as a coverage gap."""
    store = _open(tmp_path)
    try:
        result = index_mft_listing(_MftImage(), store, roots=["/c:"],
                                   started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["coverage_gaps"] == []
    assert result["status"] == "completed"

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "mft.sqlite"))
    coverage = conn.get_coverage()
    conn.disconnect()
    assert coverage["status"] == "searched"  # not "coverage_gap"


def test_mft_per_record_error_becomes_gap_not_abort(tmp_path):
    store = _open(tmp_path)
    try:
        result = index_mft_listing(_MftErrorImage(), store, roots=["/c:"],
                                   started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexed_files"] == 1  # the good record still indexed
    assert any(g.get("error") == "bad record" for g in result["coverage_gaps"])
    assert result["status"] == "partial"


def test_mft_record_cap_reported_as_gap(tmp_path):
    store = _open(tmp_path)
    try:
        result = index_mft_listing(_MftImage(cap_after=2), store, roots=["/c:"],
                                   started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexed_files"] == 2
    assert result["record_cap_reached"] is True
    assert any(g.get("reason") == "mft_record_cap_reached"
               for g in result["coverage_gaps"])


def test_mft_volume_without_ntfs_is_gap(tmp_path):
    store = _open(tmp_path)
    try:
        result = index_mft_listing(_NoMftVolumeImage(), store, roots=["/c:"],
                                   started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexed_files"] == 0
    assert result["status"] == "not_evaluable"
    assert any(g.get("reason") == "no_ntfs_mft_for_volume"
               for g in result["coverage_gaps"])


def test_legacy_walk_still_used_without_iter_mft(tmp_path):
    """Images without iter_mft_records keep the directory-walk path."""
    class _WalkOnly:
        def list_directory(self, path="/"):
            if path == "/c:":
                return [{"name": "a.exe", "path": "/c:/a.exe", "is_dir": False, "size": 1}]
            return []

    store = _open(tmp_path)
    try:
        result = index_file_listing(_WalkOnly(), store, roots=["/c:"],
                                    started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result.get("indexer") != "mft"
    assert result["indexed_files"] == 1
