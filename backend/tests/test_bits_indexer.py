"""Tests for the BITS qmgr.db transfer-job parser."""

from __future__ import annotations

from core.raw_index.artifact_indexer import index_bits_jobs, parse_bits_blob
from core.raw_index.store import RawIndexStore


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def test_parse_bits_blob_extracts_url_and_path():
    blob = _u16("\x00C:\\Users\\v\\AppData\\Local\\Temp\\x.exe\x00"
                "http://evil.example.com/payload.dll\x00")
    urls, paths = parse_bits_blob(blob)
    assert "http://evil.example.com/payload.dll" in urls
    assert any(p.startswith("C:\\Users\\v\\AppData") for p in paths)
    # the path must be cut where it would run into the URL field
    assert all("http://" not in p for p in paths)


def test_parse_bits_blob_recovers_odd_aligned_string():
    # a binary field of odd byte length pushes the UTF-16 string to an odd
    # offset; decoding only from offset 0 would garble it
    blob = b"\x07" + _u16("http://host.example.com/a.dll\x00")
    urls, _paths = parse_bits_blob(blob)
    assert any("host.example.com/a.dll" in u for u in urls)


def test_parse_bits_blob_caps_overlong_string():
    from core.raw_index.artifact_indexer import _BITS_MAX_STR
    huge = "http://h.example.com/" + ("a" * (_BITS_MAX_STR * 2))
    urls, _paths = parse_bits_blob(_u16(huge + "\x00"))
    assert urls
    assert all(len(u) <= _BITS_MAX_STR for u in urls)


def test_parse_bits_blob_non_bytes_is_empty():
    assert parse_bits_blob(None) == ([], [])
    assert parse_bits_blob(123) == ([], [])


def test_parse_bits_blob_no_url_or_path():
    urls, paths = parse_bits_blob(_u16("just some job name text"))
    assert urls == []
    assert paths == []


def test_index_bits_missing_db_is_not_evaluable(tmp_path):
    class _NoDbImage:
        def extract_file(self, internal, local):
            return {"error": f"File not found in image: {internal}"}

    store = RawIndexStore(str(tmp_path / "bits.sqlite"))
    store.open()
    try:
        result = index_bits_jobs(_NoDbImage(), store,
                                 started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert result["status"] == "not_evaluable"
    assert result["indexed_records"] == 0
    assert any(g.get("reason") == "bits_db_unavailable"
               for g in result["coverage_gaps"])
