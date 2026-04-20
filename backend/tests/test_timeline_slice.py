"""Unit tests for core.analysis.timeline_slice."""

from __future__ import annotations

from core.analysis.timeline_slice import slice_entries


ENTRIES = [
    {"description": "User login Administrator from 10.0.1.5", "artifact_type": "Event Logs"},
    {"description": "Process powershell.exe started", "artifact_type": "Prefetch",
     "fields": {"User": "Bob"}},
    {"description": "Process cmd.exe started by User Bob", "artifact_type": "Prefetch"},
    {"description": "Registry autorun modified", "artifact_type": "Registry"},
]


def test_user_filter_matches_description():
    rows, meta = slice_entries(ENTRIES, user="Administrator")
    assert len(rows) == 1
    assert meta["stages"][0]["dimension"] == "user"
    assert meta["stages"][0]["matched"] == 1
    assert meta["stages"][0]["removed"] == 3


def test_user_filter_matches_fields():
    rows, _ = slice_entries(ENTRIES, user="Bob")
    # Bob appears in description (entry 2) and fields (entry 1)
    assert len(rows) == 2


def test_process_and_user_filters_are_ANDed():
    rows, meta = slice_entries(ENTRIES, user="Bob", process="cmd")
    assert len(rows) == 1
    assert rows[0]["description"].startswith("Process cmd.exe")
    # Two stages run in order
    dims = [s["dimension"] for s in meta["stages"]]
    assert dims == ["user", "process"]


def test_empty_filters_return_all():
    rows, meta = slice_entries(ENTRIES)
    assert len(rows) == len(ENTRIES)
    assert meta["stages"] == []
    assert meta["active_filters"] == {}


def test_path_filter():
    rows, _ = slice_entries(ENTRIES, path="autorun")
    assert len(rows) == 1
    assert "autorun" in rows[0]["description"].lower()
