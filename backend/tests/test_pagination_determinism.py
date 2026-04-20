"""Cross-case pagination determinism — verify merged-sort-then-slice is
stable under tied timestamps, identical primary fields, and partial
failure.

Codex's Round-3 blind spot: naive merges can produce unstable ordering
when timestamps tie and the secondary sort falls through to connector
iteration order. These tests drive the code down to the final stable
unique key (case_id + hit_id).
"""

from __future__ import annotations

from core.analysis.case_aggregator import search_across_cases


class _TiedConnector:
    """Minimal connector with controllable search hits."""

    def __init__(self, source_path: str, hits: list[dict], source_type: str = "mfdb"):
        self._source_path = source_path
        self._hits = hits
        self._source_type = source_type

    def is_connected(self):
        return True

    def get_metadata(self):
        return {"source_type": self._source_type, "source_path": self._source_path}

    def search(self, keyword="", filters=None, limit=50, offset=0):
        return {"hits": list(self._hits)[:limit], "total": len(self._hits), "returned": len(self._hits)}


def _make_tied_hits():
    """Two cases with hits that share timestamps (and even artifact_type)
    so tie-breaking must reach case_id + hit_id."""
    ts = "2026-04-01T10:00:00"
    case_a = _TiedConnector("C:/a.mfdb", [
        {"hit_id": 1, "timestamp": ts, "artifact_type": "Prefetch",
         "fields": {"Application Name": "powershell.exe"}},
        {"hit_id": 2, "timestamp": ts, "artifact_type": "Prefetch",
         "fields": {"Application Name": "powershell.exe"}},
    ])
    case_b = _TiedConnector("C:/b", [
        {"hit_id": 1, "timestamp": ts, "artifact_type": "Prefetch",
         "fields": {"Application Name": "powershell.exe"}},
    ], source_type="kape")
    return {"axiom:a": case_a, "axiom:b": case_b}


def _hit_key(h):
    return (h["timestamp"], h["case_id"], h["hit_id"])


def test_same_query_run_three_times_is_identical():
    conns = _make_tied_hits()
    r1 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    r2 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    r3 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    k1 = [_hit_key(h) for h in r1["hits"]]
    k2 = [_hit_key(h) for h in r2["hits"]]
    k3 = [_hit_key(h) for h in r3["hits"]]
    assert k1 == k2 == k3, "Same query produced different orderings across runs"


def test_tied_timestamps_break_to_case_id_then_hit_id():
    """All 3 hits share a timestamp. Expect order: (a,1) (a,2) (b,1)
    — case_id ascending, then hit_id ascending."""
    conns = _make_tied_hits()
    r = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    keys = [(h["case_id"], h["hit_id"]) for h in r["hits"]]
    assert keys == [("a", 1), ("a", 2), ("b", 1)]


def test_paginated_pages_union_matches_single_page():
    """Page 1 + page 2 together must equal the first 2*limit of the merged list
    with no duplicates and no gaps."""
    conns = _make_tied_hits()

    big = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=4)
    big_keys = [_hit_key(h) for h in big["hits"]]

    page1 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=2, global_offset=0)
    page2 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=2, global_offset=2)
    merged = [_hit_key(h) for h in page1["hits"]] + [_hit_key(h) for h in page2["hits"]]

    # No duplicates across pages
    assert len(merged) == len(set(merged))
    # Pages together match the slice of the single-call result
    assert merged == big_keys[:len(merged)]


def test_partial_failure_preserves_determinism():
    """A broken connector must not change the ordering of the surviving
    case's hits or introduce duplicates."""
    class _Broken:
        def is_connected(self): return True
        def get_metadata(self): return {"source_type": "kape", "source_path": "C:/broken"}
        def search(self, **kwargs): raise RuntimeError("simulated")

    healthy = _make_tied_hits()["axiom:a"]
    conns = {"axiom:a": healthy, "axiom:x": _Broken()}

    r1 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    r2 = search_across_cases(conns, keyword="powershell", limit_per_case=10, global_limit=10)
    assert [_hit_key(h) for h in r1["hits"]] == [_hit_key(h) for h in r2["hits"]]
    # Warnings must surface the failure
    assert any("x:" in w or "x " in w for w in r1["warnings"])
    # Only healthy case's hits
    assert {h["case_id"] for h in r1["hits"]} == {"a"}
