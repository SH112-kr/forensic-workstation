"""Unit tests for core.analysis.case_aggregator."""

from __future__ import annotations

from core.analysis.case_aggregator import (
    aggregate_artifact_counts,
    aggregate_metadata,
    compare_cases,
    hash_across_cases,
    iter_cases,
    pivot_across_cases,
    safe_collect,
    search_across_cases,
    timeline_across_cases,
)


def test_iter_cases_filters_axiom_prefix(mfdb_case, kape_case):
    conns = {"axiom:a": mfdb_case, "axiom:b": kape_case, "volatility": mfdb_case, "e01": mfdb_case}
    cases = iter_cases(conns)
    assert [cid for cid, _ in cases] == ["a", "b"]


def test_iter_cases_includes_active_raw_index(mfdb_case):
    conns = {"raw_index": mfdb_case, "e01": mfdb_case}
    cases = iter_cases(conns)
    assert [cid for cid, _ in cases] == ["raw_index"]


def test_safe_collect_survives_partial_failure(mfdb_case, broken_case):
    cases = iter_cases({"axiom:a": mfdb_case, "axiom:x": broken_case})
    results, warnings = safe_collect(cases, lambda cid, c: c.get_artifact_type_counts())
    by_case = {r["case_id"]: r for r in results}
    assert by_case["a"]["ok"] is True
    assert by_case["x"]["ok"] is False
    assert "simulated counts failure" in by_case["x"]["error"]
    assert any("x:" in w for w in warnings)


def test_aggregate_artifact_counts_matrix(mfdb_case, kape_case):
    r = aggregate_artifact_counts({"axiom:a": mfdb_case, "axiom:b": kape_case})
    # Prefetch is present in both cases
    assert r["matrix"]["Prefetch"] == {"a": 50, "b": 100}
    # Chat Applications only in mfdb_case
    assert r["matrix"]["Chat Applications"] == {"a": 150}
    assert r["totals"]["Prefetch"] == 150
    # Families ordered by total descending
    assert r["families"][0] == "Windows Event Logs"  # 400 hits


def test_aggregate_artifact_counts_surfaces_raw_not_evaluable_coverage():
    class _RawNotEvaluableCounts:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def get_artifact_type_counts(self):
            return []

        def get_coverage(self):
            return {
                "status": "not_evaluable",
                "gaps": [{"error": "simulated parser failure"}],
            }

    r = aggregate_artifact_counts({"raw_index": _RawNotEvaluableCounts()})

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["matrix"] == {}
    assert r["results"][0]["ok"] is False
    assert r["results"][0]["status"] == "not_evaluable"
    assert r["results"][0]["coverage"]["gaps"][0]["error"] == (
        "simulated parser failure"
    )


def test_compare_cases_envelope(mfdb_case, kape_case, broken_case):
    r = compare_cases({"axiom:a": mfdb_case, "axiom:b": kape_case, "axiom:x": broken_case})
    assert r["case_count"] == 3
    statuses = [m["ok"] for m in r["metadata"]]
    assert True in statuses and False in statuses
    assert len(r["warnings"]) >= 1


def test_compare_cases_surfaces_raw_not_evaluable_artifact_counts():
    class _RawNotEvaluableCounts:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def get_artifact_type_counts(self):
            return []

        def get_coverage(self):
            return {
                "status": "not_evaluable",
                "gaps": [{"error": "simulated parser failure"}],
            }

    r = compare_cases({"raw_index": _RawNotEvaluableCounts()})

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["artifact_counts"]["results"][0]["ok"] is False
    assert r["artifact_counts"]["results"][0]["coverage"]["status"] == (
        "not_evaluable"
    )


def test_search_across_cases_provenance(mfdb_case, kape_case):
    r = search_across_cases(
        {"axiom:a": mfdb_case, "axiom:b": kape_case},
        keyword="admin", limit_per_case=10, global_limit=10,
    )
    # Every hit must carry provenance fields.
    assert all("case_id" in h and "source_type" in h and "source_path" in h for h in r["hits"])
    # Sorted by timestamp ascending — first hit is earlier.
    ts = [h.get("timestamp", "") for h in r["hits"]]
    assert ts == sorted(ts)


def test_search_across_cases_preserves_exact_per_case_totals():
    class _SearchWithMoreRows:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def search(self, keyword="", filters=None, limit=50, offset=0):
            hits = [
                {
                    "hit_id": idx + 1,
                    "timestamp": f"2026-10-04T00:00:0{idx}Z",
                    "fields": {"Path": f"/c:/Tools/event-{idx}.exe"},
                }
                for idx in range(3)
            ]
            return {
                "total": 3,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": min(limit, len(hits)),
                "hits": hits[:limit],
            }

    r = search_across_cases(
        {"raw_index": _SearchWithMoreRows()},
        keyword="event",
        artifact_type="File System Entry",
        limit_per_case=1,
        global_limit=1,
    )

    assert r["per_case_totals"] == {"raw_index": 3}
    assert r["merged_total"] == 3
    assert r["returned"] == 1
    assert r["hits"][0]["case_id"] == "raw_index"


def test_search_across_cases_surfaces_connector_not_evaluable():
    class _RawNotEvaluable:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def search(self, **kwargs):
            return {
                "ok": False,
                "status": "not_evaluable",
                "total": 0,
                "returned": 0,
                "hits": [],
                "coverage": {
                    "status": "not_evaluable",
                    "gaps": [{"error": "simulated parser failure"}],
                },
            }

    r = search_across_cases(
        {"raw_index": _RawNotEvaluable()},
        keyword="agent.exe",
        global_limit=10,
    )

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["merged_total"] == 0
    assert r["per_case"][0]["ok"] is False
    assert r["per_case"][0]["status"] == "not_evaluable"
    assert r["per_case"][0]["coverage"]["status"] == "not_evaluable"
    assert "raw_index:" in r["warnings"][0]


def test_timeline_across_cases_provenance(mfdb_case, kape_case):
    r = timeline_across_cases({"axiom:a": mfdb_case, "axiom:b": kape_case})
    assert all("case_id" in e for e in r["entries"])
    assert r["merged_total"] >= 2


def test_timeline_across_cases_preserves_exact_per_case_totals():
    class _TimelineWithMoreRows:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

        def get_timeline(
            self,
            start_date="",
            end_date="",
            artifact_types=None,
            limit=200,
            offset=0,
        ):
            entries = [
                {
                    "hit_id": idx + 1,
                    "timestamp": f"2026-10-04T00:00:0{idx}Z",
                    "description": f"event {idx}",
                }
                for idx in range(3)
            ]
            return {
                "total_events": 3,
                "total_is_estimated": False,
                "count_accuracy": "exact",
                "returned": min(limit, len(entries)),
                "entries": entries[:limit],
            }

    r = timeline_across_cases(
        {"raw_index": _TimelineWithMoreRows()},
        limit_per_case=1,
        global_limit=1,
    )

    assert r["per_case_totals"] == {"raw_index": 3}
    assert r["merged_total"] == 3
    assert r["returned"] == 1
    assert r["entries"][0]["case_id"] == "raw_index"


def test_timeline_across_cases_refuses_unsupported_keyword_filter():
    class _TimelineWithoutKeywords:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "legacy_case",
                "source_path": "legacy",
            }

        def get_timeline(
            self,
            start_date="",
            end_date="",
            artifact_types=None,
            limit=200,
            offset=0,
        ):
            return {
                "total_events": 1,
                "entries": [{"description": "unfiltered timeline row"}],
            }

    r = timeline_across_cases(
        {"axiom:legacy": _TimelineWithoutKeywords()},
        keywords=["agent.exe"],
    )

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["merged_total"] == 0
    assert r["per_case"][0]["coverage"]["gaps"][0]["reason"] == (
        "timeline_keyword_filter_not_supported"
    )


def test_hash_across_cases_finds_only_matching(mfdb_case, kape_case):
    r = hash_across_cases({"axiom:a": mfdb_case, "axiom:b": kape_case}, "deadbeef")
    assert r["total"] == 1
    assert r["hits"][0]["case_id"] == "a"


def test_hash_across_cases_surfaces_raw_unsupported_as_not_evaluable():
    class _RawWithoutHash:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

    r = hash_across_cases({"raw_index": _RawWithoutHash()}, "deadbeef")

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["total"] == 0
    assert r["per_case"][0]["ok"] is False
    assert r["per_case"][0]["status"] == "not_evaluable"
    assert "raw_index:" in r["warnings"][0]


def test_hash_pivot_surfaces_raw_unsupported_as_not_evaluable():
    class _RawWithoutHash:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {
                "source_type": "raw_image_sidecar",
                "source_path": "raw-index.sqlite",
            }

    r = pivot_across_cases(
        {"raw_index": _RawWithoutHash()},
        entity_type="hash",
        entity_value="deadbeef",
    )

    assert r["ok"] is False
    assert r["status"] == "not_evaluable"
    assert r["total"] == 0
    assert r["case_count"] == 1
    assert r["per_case"][0]["ok"] is False


def test_pivot_first_last_seen(mfdb_case, kape_case):
    r = pivot_across_cases(
        {"axiom:a": mfdb_case, "axiom:b": kape_case},
        entity_type="keyword", entity_value="admin",
    )
    assert r["ok"] is True
    assert r["total"] >= 2
    # first_seen should be the earliest timestamp
    assert r["first_seen"]["timestamp"] < r["last_seen"]["timestamp"]
    # per-case counts must include every case that matched
    assert set(r["per_case_counts"].keys()) == {"a", "b"}


def test_pivot_rejects_unknown_entity(mfdb_case):
    r = pivot_across_cases({"axiom:a": mfdb_case}, entity_type="xxx", entity_value="v")
    assert r["ok"] is False
    assert "Unsupported" in r["error"]


def test_pivot_default_match_key_raw_is_legacy_equivalent(mfdb_case, kape_case):
    """Codex Round-5c: omitting match_key must not change any hit field
    compared to explicit match_key='raw'. Guards against accidental future
    default-flip regressions."""
    conns = {"axiom:a": mfdb_case, "axiom:b": kape_case}
    a = pivot_across_cases(conns, entity_type="keyword", entity_value="admin")
    b = pivot_across_cases(conns, entity_type="keyword", entity_value="admin", match_key="raw")
    # Same hit keys, same counts, no normalized_* fields in default mode
    assert [(h["case_id"], h["hit_id"]) for h in a["hits"]] == \
           [(h["case_id"], h["hit_id"]) for h in b["hits"]]
    assert a["total"] == b["total"]
    for h in a["hits"] + b["hits"]:
        assert "normalized_value" not in h
        assert "normalized_warning" not in h


def test_pivot_match_key_loose_attaches_warning_on_envelope_and_hits(mfdb_case):
    """Codex Round-5b: Tier-2 warnings must surface BOTH on the envelope
    AND on each affected hit."""
    # mfdb_case has a hit with fields = {"user": "admin"} and another with Application Name
    r = pivot_across_cases(
        {"axiom:a": mfdb_case}, entity_type="username", entity_value="CONTOSO\\Alice",
        match_key="loose",
    )
    assert r["ok"] is True
    assert r["match_key"]["mode"] == "loose"
    # Warning should be mirrored on envelope when Tier-2 actually collapsed
    if r["hits"]:
        any_warned = any("normalized_warning" in h for h in r["hits"])
        envelope_warned = bool(r["match_key"]["warnings"])
        assert any_warned == envelope_warned
