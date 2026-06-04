from __future__ import annotations

from core.analysis.raw_parity import compare_search_parity


class _Conn:
    def __init__(self, hits, *, truncated=False, total=None):
        self.hits = hits
        self.truncated = truncated
        self.total = len(hits) if total is None else total

    def search(self, keyword="", filters=None, limit=50, offset=0):
        return {
            "total": self.total,
            "hits": self.hits,
            "returned": len(self.hits),
            "truncated": self.truncated,
        }


class _PagedConn:
    def __init__(self, hits):
        self.hits = hits
        self.calls = []

    def search(self, keyword="", filters=None, limit=50, offset=0):
        self.calls.append({"limit": limit, "offset": offset})
        page = self.hits[offset:offset + limit]
        return {
            "total": len(self.hits),
            "hits": page,
            "returned": len(page),
            "truncated": offset + len(page) < len(self.hits),
            "total_is_estimated": False,
        }


def test_compare_search_parity_reports_missing_raw_hits():
    reference = _Conn([
        {"hit_id": 1, "fields": {"Path": "/c:/a"}},
        {"hit_id": 2, "fields": {"Path": "/c:/b"}},
    ])
    raw = _Conn([{"hit_id": 10, "fields": {"Path": "/c:/a"}}])

    result = compare_search_parity(
        reference,
        raw,
        keyword="",
        artifact_type="File System Entry",
    )

    assert result["ok"] is True
    assert result["parity_status"] == "gap_detected"
    assert result["reference_total"] == 2
    assert result["raw_total"] == 1
    assert "/c:/b" in result["missing_in_raw"]
    assert result["strong_conclusion_allowed"] is False


def test_compare_search_parity_paginates_truncated_exact_inputs():
    reference = _PagedConn([
        {"hit_id": 1, "fields": {"Path": "/c:/a"}},
        {"hit_id": 2, "fields": {"Path": "/c:/b"}},
        {"hit_id": 3, "fields": {"Path": "/c:/c"}},
    ])
    raw = _PagedConn([
        {"hit_id": 10, "fields": {"Path": "/c:/a"}},
        {"hit_id": 11, "fields": {"Path": "/c:/c"}},
    ])

    result = compare_search_parity(
        reference,
        raw,
        keyword="",
        artifact_type="File System Entry",
        limit=2,
    )

    assert result["ok"] is True
    assert result["parity_status"] == "gap_detected"
    assert result["reference_total"] == 3
    assert result["raw_total"] == 2
    assert result["missing_in_raw"] == ["/c:/b"]
    assert reference.calls == [
        {"limit": 2, "offset": 0},
        {"limit": 2, "offset": 2},
    ]
    assert raw.calls == [{"limit": 2, "offset": 0}]


def test_compare_search_parity_refuses_truncated_inputs():
    reference = _Conn(
        [{"hit_id": 1, "fields": {"Path": "/c:/a"}}],
        truncated=True,
        total=2,
    )
    raw = _Conn([{"hit_id": 10, "fields": {"Path": "/c:/a"}}])

    result = compare_search_parity(
        reference,
        raw,
        keyword="",
        artifact_type="File System Entry",
    )

    assert result["ok"] is False
    assert result["parity_status"] == "not_evaluable"
    assert result["strong_conclusion_allowed"] is False
    assert result["coverage_gap"]["reason"] == "truncated_input"
