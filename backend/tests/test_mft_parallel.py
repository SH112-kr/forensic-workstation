"""Tests for the parallel $MFT shard scanner (TB-safe speed lever)."""

from __future__ import annotations

from core.raw_index.mft_parallel import (
    default_worker_count,
    parallel_mft_record_stream,
    segment_ranges,
)


def test_segment_ranges_are_inclusive_and_cover_all():
    ranges = segment_ranges(25, 10)
    assert ranges == [(0, 9), (10, 19), (20, 25)]
    # contiguous, no overlap, no gap
    assert ranges[0][0] == 0
    assert ranges[-1][1] == 25
    for (a_start, a_end), (b_start, _) in zip(ranges, ranges[1:]):
        assert b_start == a_end + 1


def test_segment_ranges_single_chunk():
    assert segment_ranges(5, 100) == [(0, 5)]


def test_segment_ranges_empty_when_nothing_to_scan():
    assert segment_ranges(0, 100) == []
    assert segment_ranges(-1, 100) == []
    assert segment_ranges(100, 0) == []


def test_default_worker_count_at_least_one():
    assert default_worker_count() >= 1


def test_parallel_stream_empty_for_no_segments():
    # last_segment<=0 must yield nothing without spawning any worker process.
    assert list(parallel_mft_record_stream("nope.e01", "/c:", 0, 4)) == []
