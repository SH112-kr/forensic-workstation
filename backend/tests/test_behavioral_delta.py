"""Tests for ``core.analysis.behavioral_delta`` (T1 composition tool).

Codex pre-review blocker was "do not reimplement co-occurrence inside
behavioral_delta — reuse the shared helper or MCP and core will silently
drift". These tests pin the contract between the two:
  - The fixture simulates ``axiom.search`` at the real shape consumed by
    ``correlate_keywords`` (``hits[*].timestamps`` dict, ``total`` field,
    ``artifact_type``).
  - Every Codex-requested edge case has a dedicated test: absent entity,
    net-new, went-silent, volume ratio with zero baseline, multi-timestamp
    fan-out, seed-keyword normalization, claim / top_windows caps,
    deterministic sort, truncation warning propagation.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.analysis.behavioral_delta import behavioral_delta


class _CorrelatableStub:
    """Simulates the connector surface consumed by ``correlate_keywords``.

    Real ``axiom.search`` returns ``{"hits": [...], "total": N}`` where
    each hit carries a ``timestamps`` *dict* (not a scalar) — one entry
    per timestamp field. The ``MockConnector`` in conftest uses a flat
    ``timestamp`` so it doesn't match this code path. Codex pre-review #3
    flagged that test divergence; this stub closes the gap.
    """

    def __init__(self, hits_per_keyword: dict[str, list[dict[str, Any]]]):
        self._hits = hits_per_keyword
        self.search_calls: list[dict[str, Any]] = []

    def search(
        self, keyword: str = "", filters: dict[str, Any] | None = None,
        limit: int = 50, offset: int = 0,
    ) -> dict[str, Any]:
        self.search_calls.append({
            "keyword": keyword, "filters": filters or {},
            "limit": limit, "offset": offset,
        })
        filters = filters or {}
        start = filters.get("start_date", "")
        end = filters.get("end_date", "")
        hits = self._hits.get(keyword, [])
        # Filter by the period — use the FIRST timestamp on each hit.
        filtered: list[dict[str, Any]] = []
        for h in hits:
            ts_values = list((h.get("timestamps") or {}).values())
            if not ts_values:
                continue
            first_ts = ts_values[0]
            if start and first_ts < start:
                continue
            if end and first_ts > end + "Z":
                continue
            filtered.append(h)
        total = len(filtered)
        # Apply limit/offset like the real connector.
        returned = filtered[offset:offset + limit]
        return {"hits": returned, "total": total, "returned": len(returned)}

    @staticmethod
    def _iso_to_ms(iso: str) -> int:
        from datetime import datetime, timezone
        s = iso.replace(" ", "T", 1)
        if "T" in s:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s + "T00:00:00+00:00")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)


class _BroadMatchStub(_CorrelatableStub):
    def search(
        self, keyword: str = "", filters: dict[str, Any] | None = None,
        limit: int = 50, offset: int = 0,
    ) -> dict[str, Any]:
        self.search_calls.append({
            "keyword": keyword, "filters": filters or {},
            "limit": limit, "offset": offset,
        })
        filters = filters or {}
        start = filters.get("start_date", "")
        end = filters.get("end_date", "")
        matched: list[dict[str, Any]] = []
        needle = keyword.lower()
        for hits in self._hits.values():
            for h in hits:
                blob = " ".join(str(v) for v in (h.get("fields") or {}).values()).lower()
                if needle not in blob:
                    continue
                ts_values = list((h.get("timestamps") or {}).values())
                if not ts_values:
                    continue
                first_ts = ts_values[0]
                if start and first_ts < start:
                    continue
                if end and first_ts > end + "Z":
                    continue
                matched.append(h)
        returned = matched[offset:offset + limit]
        return {"hits": returned, "total": len(matched), "returned": len(returned)}


class _ArtifactQueryStub:
    def __init__(self, event_rows: dict[int, list[dict[str, Any]]]):
        self._event_rows = event_rows

    def query_event_logs(self, event_ids: list[int] | None = None, provider: str = "", keyword_in_data: str = "", limit: int = 100) -> list[dict]:
        rows: list[dict[str, Any]] = []
        for eid in event_ids or []:
            rows.extend(self._event_rows.get(eid, []))
        return rows if limit == 0 else rows[:limit]


def _hit(hit_id: int, timestamps: dict[str, str], artifact_type: str = "Windows Event Logs") -> dict[str, Any]:
    return {"hit_id": hit_id, "timestamps": timestamps, "artifact_type": artifact_type}


def _baro_like_stub() -> _CorrelatableStub:
    """Reduced replica of the real baro case signal:

    - bomgar-pec: one Jan 8 event (baseline), one Apr 12 + one Apr 15 (incident)
    - 4648: several Jan events (baseline), cluster on Apr 12 + Apr 14 (incident)
    - 7045: none in baseline, cluster on Apr 12 + Apr 14 (incident net-new)
    """
    return _CorrelatableStub({
        "bomgar-pec": [
            _hit(1001, {"File Created": "2026-01-08T06:36:59"}),
            _hit(1002, {"Last Run":     "2026-04-11T17:50:02"}),
            _hit(1003, {"Last Run":     "2026-04-15T00:35:18"}),
        ],
        "4648": [
            _hit(2001, {"Created": "2026-01-08T05:27:59"}),
            _hit(2002, {"Created": "2026-03-07T06:56:07"}),
            _hit(2003, {"Created": "2026-04-11T17:50:03"}),
            _hit(2004, {"Created": "2026-04-12T08:03:28"}),
            _hit(2005, {"Created": "2026-04-14T04:21:52"}),
        ],
        "7045": [
            _hit(3001, {"Created": "2026-04-11T17:50:04"}),
            _hit(3002, {"Created": "2026-04-12T08:59:25"}),
            _hit(3003, {"Created": "2026-04-14T04:21:54"}),
        ],
    })


# ── Happy path ────────────────────────────────────────────────────────────


def test_baro_like_produces_dormant_then_active_and_new_cooccurrence():
    """End-to-end check that mirrors the real baro signal."""
    stub = _baro_like_stub()
    result = behavioral_delta(
        stub,
        entity_value="bomgar-pec",
        baseline_start="2026-01-01",
        baseline_end="2026-04-10",
        incident_start="2026-04-11",
        incident_end="2026-04-16",
        seed_keywords=["4648", "7045"],
        window_minutes=60,
    )

    assert result["ok"] is True
    assert result["entity"]["value"] == "bomgar-pec"
    assert result["entity"]["seed_keywords"] == ["bomgar-pec", "4648", "7045"]

    # Dormant gap: Jan 8 (last baseline bomgar-pec) → Apr 11 17:50 (first incident) ≈ 94 days.
    gap = result["delta"]["dormant_gap_seconds"]
    assert result["delta"]["dormant_gap_reason"] == "computed"
    assert gap is not None
    assert 90 * 86400 < gap < 100 * 86400

    # 7045 is net-new in incident — must appear in new_cooccurring_keywords.
    assert "7045" in result["delta"]["new_cooccurring_keywords"]

    # A claim of kind entity_dormant_then_active must exist.
    kinds = {c["kind"] for c in result["claims"]}
    assert "entity_dormant_then_active" in kinds
    assert "observed_cooccurrence_change" in kinds


# ── Empty/edge periods ───────────────────────────────────────────────────


def test_no_activity_in_either_period_yields_single_claim():
    stub = _CorrelatableStub({})
    r = behavioral_delta(
        stub, entity_value="nonexistent",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    assert r["ok"] is True
    assert r["delta"]["dormant_gap_reason"] == "both_empty"
    assert r["delta"]["dormant_gap_seconds"] is None
    kinds = [c["kind"] for c in r["claims"]]
    assert kinds == ["no_activity_in_either_period"]


def test_entity_only_in_incident_is_net_new():
    stub = _CorrelatableStub({
        "new-tool": [_hit(1, {"ts": "2026-04-12T10:00:00"})],
    })
    r = behavioral_delta(
        stub, entity_value="new-tool",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    assert r["delta"]["dormant_gap_reason"] == "baseline_empty"
    assert r["delta"]["dormant_gap_seconds"] is None
    kinds = {c["kind"] for c in r["claims"]}
    assert "entity_net_new_in_incident" in kinds
    # Volume ratio for a keyword that appears in incident-only should be marked.
    assert r["delta"]["volume_ratio_per_keyword"]["new-tool"]["ratio_note"] \
        == "baseline_zero_entity_net_new"


def test_entity_only_in_baseline_went_silent():
    stub = _CorrelatableStub({
        "old-tool": [_hit(1, {"ts": "2026-02-01T10:00:00"})],
    })
    r = behavioral_delta(
        stub, entity_value="old-tool",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    assert r["delta"]["dormant_gap_reason"] == "incident_empty"
    assert r["delta"]["dormant_gap_seconds"] is None
    kinds = {c["kind"] for c in r["claims"]}
    assert "entity_went_silent_in_incident" in kinds
    assert r["delta"]["volume_ratio_per_keyword"]["old-tool"]["ratio"] == 0.0
    assert r["delta"]["volume_ratio_per_keyword"]["old-tool"]["ratio_note"] \
        == "incident_zero_entity_went_silent"


# ── Volume ratio semantics ───────────────────────────────────────────────


def test_volume_ratio_uses_true_total_not_returned():
    """Codex pre-review #4 — ratios must not quietly drift when search
    results are truncated."""
    # Same keyword: baseline has 10 hits total, incident has 30. All within
    # periods. Set the limit so incident gets truncated to 5 returned.
    many_hits = [_hit(100 + i, {"ts": f"2026-04-12T10:{i:02d}:00"}) for i in range(30)]
    baseline_hits = [_hit(i, {"ts": f"2026-01-{i + 1:02d}T10:00:00"}) for i in range(10)]
    stub = _CorrelatableStub({"x": baseline_hits + many_hits})
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        limit_per_keyword=5,  # forces truncation
    )
    ratios = r["delta"]["volume_ratio_per_keyword"]["x"]
    # True totals: baseline=10, incident=30 → ratio 3.0 regardless of returned cap.
    assert ratios["baseline"] == 10
    assert ratios["incident"] == 30
    assert ratios["ratio"] == pytest.approx(3.0)
    assert ratios["ratio_note"] == "computed"
    # Truncation warning must be emitted for both periods.
    warnings_text = " ".join(r["truncation_warnings"])
    assert "baseline" in warnings_text or "incident" in warnings_text
    assert "returned" in warnings_text


def test_identical_volumes_do_not_emit_volume_change_claim():
    stub = _CorrelatableStub({
        "x": [_hit(1, {"ts": "2026-01-05T00:00:00"}),
              _hit(2, {"ts": "2026-04-05T00:00:00"})],
    })
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    volume_claims = [c for c in r["claims"] if c["kind"] == "observed_volume_change"]
    assert volume_claims == []


# ── Multi-timestamp fan-out ──────────────────────────────────────────────


def test_single_hit_with_multiple_timestamps_does_not_double_count_totals():
    """Codex pre-review #4 — one hit with 3 timestamp fields should
    contribute 3 events (consistent with correlate_keywords), but the
    ``per_keyword_totals`` (which feed the volume ratio) come from
    ``axiom.search``'s ``total`` field, not event count. Total must
    remain at 1."""
    stub = _CorrelatableStub({
        "x": [_hit(1, {"Created": "2026-04-12T10:00:00",
                        "Modified": "2026-04-12T10:00:01",
                        "Accessed": "2026-04-12T10:00:02"})],
    })
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    # 3 events from fan-out but total_hits still = 1.
    assert r["incident"]["total_events"] == 3
    assert r["incident"]["per_keyword_totals"]["x"] == 1
    ratios = r["delta"]["volume_ratio_per_keyword"]["x"]
    assert ratios["incident"] == 1  # NOT 3


def test_out_of_range_timestamp_fields_do_not_leak_back_into_period_metrics():
    """Returned hits may carry stale timestamp fields; compositions must
    re-filter event fan-out to the requested period."""
    stub = _CorrelatableStub({
        "bomgar-pec": [
            _hit(1, {"Last Run": "2026-01-08T06:36:59"}),
            _hit(2, {
                "Last Run": "2026-04-11T17:50:02",
                "Volume Created": "2019-12-16T03:17:55.321",
            }, artifact_type="Prefetch Files - Windows 8/10/11"),
            _hit(3, {"Last Run": "2026-04-15T00:35:18.454"}),
        ],
        "4648": [
            _hit(10, {"Created": "2026-04-11T17:50:03"}),
        ],
        "7045": [
            _hit(20, {
                "Created": "2026-04-11T17:50:04",
                "Link Date": "1980-11-24T00:00:00",
            }, artifact_type="AmCache File Entries"),
        ],
    })

    r = behavioral_delta(
        stub,
        entity_value="bomgar-pec",
        baseline_start="2026-01-01",
        baseline_end="2026-04-10",
        incident_start="2026-04-11",
        incident_end="2026-04-16",
        seed_keywords=["4648", "7045"],
        window_minutes=60,
    )

    assert r["baseline"]["last_event_ts"] == "2026-01-08T06:36:59"
    assert r["incident"]["first_event_ts"] == "2026-04-11T17:50:02"
    assert r["delta"]["dormant_gap_reason"] == "computed"
    assert r["delta"]["dormant_gap_seconds"] is not None
    assert r["delta"]["dormant_gap_seconds"] > 90 * 86400


# ── Seed keyword normalization ───────────────────────────────────────────


def test_seed_keywords_deduplicate_and_trim_preserving_order():
    stub = _CorrelatableStub({"x": [], "y": [], "z": []})
    r = behavioral_delta(
        stub, entity_value=" x ",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords=["y", "", "y", " z ", "x"],
    )
    # entity comes first; seen duplicates / blanks drop.
    assert r["entity"]["seed_keywords"] == ["x", "y", "z"]


def test_seed_keywords_comma_string_accepted():
    stub = _CorrelatableStub({"x": [], "a": [], "b": []})
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords="a, b , a",
    )
    assert r["entity"]["seed_keywords"] == ["x", "a", "b"]


def test_entity_value_whitespace_does_not_break_entity_classification():
    stub = _CorrelatableStub({
        "x": [_hit(1, {"ts": "2026-04-12T10:00:00"})],
    })
    r = behavioral_delta(
        stub, entity_value=" x ",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    kinds = {c["kind"] for c in r["claims"]}
    assert "entity_net_new_in_incident" in kinds
    assert "no_activity_in_either_period" not in kinds


def test_exact_match_mode_filters_broad_substring_matches():
    stub = _BroadMatchStub({
        "bundle": [
            {
                "hit_id": 1,
                "timestamps": {"ts": "2026-04-12T10:00:00"},
                "artifact_type": "Prefetch",
                "fields": {"Application Name": "bomgar-pec.exe"},
            },
            {
                "hit_id": 2,
                "timestamps": {"ts": "2026-04-12T10:10:00"},
                "artifact_type": "Prefetch",
                "fields": {"Application Name": "bomgar-pec-helper.dll"},
            },
        ],
    })

    substring_r = behavioral_delta(
        stub,
        entity_value="bomgar-pec",
        baseline_start="2026-01-01",
        baseline_end="2026-01-31",
        incident_start="2026-04-01",
        incident_end="2026-04-30",
    )
    exact_r = behavioral_delta(
        stub,
        entity_value="bomgar-pec",
        baseline_start="2026-01-01",
        baseline_end="2026-01-31",
        incident_start="2026-04-01",
        incident_end="2026-04-30",
        match_mode="exact",
    )

    assert substring_r["incident"]["per_keyword_totals"]["bomgar-pec"] == 2
    assert exact_r["incident"]["per_keyword_totals"]["bomgar-pec"] == 1
    assert exact_r["match_semantics"]["mode"] == "exact"


def test_event_id_seed_avoids_keyword_noise():
    stub = _BroadMatchStub({
        "bundle": [
            {
                "hit_id": 1,
                "timestamps": {"ts": "2026-04-12T10:00:00"},
                "artifact_type": "UsnJrnl",
                "fields": {"File Name": "etilqs_LJ4648ThtooQ8Ul"},
            },
            {
                "hit_id": 2,
                "timestamps": {"ts": "2026-04-12T10:05:00"},
                "artifact_type": "Windows Event Logs",
                "fields": {"Event ID": 4648, "Event Data": "Explicit credentials used"},
            },
        ],
    })
    stub.artifact_queries = _ArtifactQueryStub({
        4648: [
            {
                "hit_id": 2,
                "artifact_type": "Windows Event Logs",
                "Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-12T10:05:00",
                "timestamps": {"Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-12T10:05:00"},
            }
        ]
    })

    keyword_r = behavioral_delta(
        stub,
        entity_value="entity",
        baseline_start="2026-01-01",
        baseline_end="2026-01-31",
        incident_start="2026-04-01",
        incident_end="2026-04-30",
        seed_keywords=["4648"],
    )
    typed_r = behavioral_delta(
        stub,
        entity_value="entity",
        baseline_start="2026-01-01",
        baseline_end="2026-01-31",
        incident_start="2026-04-01",
        incident_end="2026-04-30",
        seed_keywords=["event_id:4648"],
    )

    assert keyword_r["incident"]["per_keyword_totals"]["4648"] == 2
    assert typed_r["incident"]["per_keyword_totals"]["event_id:4648"] == 1


def test_empty_entity_returns_error():
    stub = _CorrelatableStub({})
    r = behavioral_delta(
        stub, entity_value="   ",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    assert r["ok"] is False
    assert "entity_value" in r["error"]


# ── Caps ─────────────────────────────────────────────────────────────────


def test_top_windows_capped_at_20():
    # 25 distinct co-occurrence windows by producing 25 distinct minute-level
    # clusters of bomgar-pec + marker across the incident period.
    bom = [_hit(1000 + i, {"ts": f"2026-04-12T10:{i:02d}:00"}) for i in range(25)]
    mkr = [_hit(2000 + i, {"ts": f"2026-04-12T10:{i:02d}:30"}) for i in range(25)]
    stub = _CorrelatableStub({"bomgar-pec": bom, "marker": mkr})
    r = behavioral_delta(
        stub, entity_value="bomgar-pec",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords=["marker"],
        window_minutes=1,
    )
    assert len(r["incident"]["top_windows"]) <= 20


def test_claims_capped_per_kind():
    """50 per kind. Build more than 50 observed_cooccurrence_change claims
    by seeding many unique keywords that co-occur only in the incident."""
    hits: dict[str, list[dict[str, Any]]] = {"entity": [_hit(1, {"ts": "2026-04-12T10:00:00"})]}
    seeds: list[str] = ["entity"]
    # 55 marker keywords, each co-occurring in a distinct minute-level bucket.
    for i in range(55):
        kw = f"marker{i:02d}"
        seeds.append(kw)
        hits[kw] = [_hit(1000 + i, {"ts": f"2026-04-12T10:{i:02d}:30"}), ]
    # Shift the entity into the incident with matching minute buckets so
    # each marker + entity forms a new cooccurrence pair.
    hits["entity"] = [_hit(1, {"ts": f"2026-04-12T10:{i:02d}:00"}) for i in range(55)]
    stub = _CorrelatableStub(hits)
    r = behavioral_delta(
        stub, entity_value="entity",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords=seeds[1:],
        window_minutes=1,
    )
    cooc = [c for c in r["claims"] if c["kind"] == "observed_cooccurrence_change"]
    assert len(cooc) <= 50


def test_entity_classification_uses_true_totals_not_global_chronological_sample():
    """Large seed sets must not push the primary entity out of the global
    chronological sample and flip the result to no_activity."""
    hits: dict[str, list[dict[str, Any]]] = {
        "entity": [_hit(10000 + i, {"ts": f"2026-04-12T12:{i % 60:02d}:00"}) for i in range(10)]
    }
    seed_keywords: list[str] = []
    for i in range(600):
        kw = f"k{i:03d}"
        hits[kw] = [_hit(i, {"ts": f"2026-04-12T00:{i % 60:02d}:00"})]
        seed_keywords.append(kw)

    stub = _CorrelatableStub(hits)
    r = behavioral_delta(
        stub, entity_value="entity",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords=seed_keywords,
        limit_per_keyword=500,
    )
    kinds = {c["kind"] for c in r["claims"]}
    assert "entity_net_new_in_incident" in kinds
    assert "no_activity_in_either_period" not in kinds
    assert r["delta"]["volume_ratio_per_keyword"]["entity"]["incident"] == 10


def test_truncated_entity_suppresses_dormant_gap_and_entity_boundary_timestamps():
    hits = {
        "entity": [
            _hit(i, {"ts": f"2026-01-{(i % 28) + 1:02d}T00:00:00"}) for i in range(600)
        ] + [
            _hit(10000 + i, {"ts": f"2026-04-12T12:{i % 60:02d}:00"}) for i in range(10)
        ]
    }
    stub = _CorrelatableStub(hits)
    r = behavioral_delta(
        stub,
        entity_value="entity",
        baseline_start="2026-01-01",
        baseline_end="2026-01-31",
        incident_start="2026-04-01",
        incident_end="2026-04-30",
        limit_per_keyword=500,
    )

    assert r["delta"]["dormant_gap_seconds"] is None
    assert r["delta"]["dormant_gap_reason"] == "truncated_sample"
    assert r["baseline"]["last_event_ts"] is None
    assert r["incident"]["first_event_ts"] == "2026-04-12T12:00:00"


# ── Determinism ──────────────────────────────────────────────────────────


def test_output_is_deterministic_for_same_input():
    import json
    stub1 = _baro_like_stub()
    stub2 = _baro_like_stub()
    kwargs = dict(
        entity_value="bomgar-pec",
        baseline_start="2026-01-01", baseline_end="2026-04-10",
        incident_start="2026-04-11", incident_end="2026-04-16",
        seed_keywords=["4648", "7045"],
    )
    r1 = behavioral_delta(stub1, **kwargs)
    r2 = behavioral_delta(stub2, **kwargs)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


# ── derived_from pointers ────────────────────────────────────────────────


def test_every_non_noactivity_claim_carries_derived_from():
    stub = _baro_like_stub()
    r = behavioral_delta(
        stub, entity_value="bomgar-pec",
        baseline_start="2026-01-01", baseline_end="2026-04-10",
        incident_start="2026-04-11", incident_end="2026-04-16",
        seed_keywords=["4648", "7045"],
    )
    for c in r["claims"]:
        if c["kind"] == "no_activity_in_either_period":
            continue
        assert c["derived_from"], \
            f"claim {c['kind']} must carry derived_from pointers"
        for ptr in c["derived_from"]:
            assert "period" in ptr
            assert "timestamp" in ptr


# ── Integration test with real AxiomMfdbConnector ─────────────────────────
#
# Codex post-review #1 — stub-only tests let unit pass while prod breaks.
# Build a minimal .mfdb SQLite file with just the tables axiom.search +
# _hydrate_hits touch, then drive behavioral_delta end-to-end. If
# AxiomMfdbConnector ever changes its hydration shape, this breaks.


def _build_axiom_mfdb(path, rows):
    """Create a tiny .mfdb file exercising the full axiom.search pipeline.

    ``rows`` is a list of ``(hit_id, keyword_text, timestamp_iso,
    artifact_name)``. Each row produces:
      - one artifact_version entry (one per unique artifact_name)
      - one fragment_definition for the 'Value' string field + 'Date' date field
      - one scan_artifact_hit
      - one hit_fragment_string with the keyword text (so axiom.search finds it)
      - one hit_fragment_date with the timestamp (so correlate sees a ts)
    """
    import sqlite3

    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE fragment_definition (
            fragment_definition_id TEXT PRIMARY KEY,
            artifact_version_id TEXT,
            name TEXT,
            data_type TEXT
        );
        CREATE TABLE artifact_version (
            artifact_version_id TEXT PRIMARY KEY,
            artifact_name TEXT
        );
        CREATE TABLE scan_artifact_hit (
            hit_id INTEGER,
            artifact_version_id TEXT
        );
        CREATE TABLE hit_fragment_string (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value TEXT
        );
        CREATE TABLE hit_fragment_int (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value INTEGER
        );
        CREATE TABLE hit_fragment_date (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            unix_timestamp_ms INTEGER,
            formatted_value TEXT
        );
        CREATE TABLE hit_fragment_float (
            hit_id INTEGER,
            fragment_definition_id TEXT,
            value REAL
        );
        CREATE TABLE hit_location (
            hit_id INTEGER,
            location_value TEXT,
            source_id TEXT,
            sort_order INTEGER
        );
        CREATE TABLE source (
            source_id TEXT PRIMARY KEY,
            source_friendly_value TEXT
        );
        CREATE TABLE source_path (
            source_id TEXT,
            source_path TEXT
        );
        CREATE TABLE hit_hash (
            hit_id INTEGER,
            hash TEXT
        );
        -- Case metadata tables used by _load_case_info (skipped by tests
        -- since we never call connect() — we manually populate _frag_defs).
    """)
    # Single artifact version + single string/date fragment definition.
    conn.execute(
        "INSERT INTO artifact_version VALUES (?, ?)",
        ("av-1", "Test Event Log"),
    )
    conn.execute(
        "INSERT INTO fragment_definition VALUES (?, ?, ?, ?)",
        ("frag-str", "av-1", "Value", "string"),
    )
    conn.execute(
        "INSERT INTO fragment_definition VALUES (?, ?, ?, ?)",
        ("frag-date", "av-1", "Event Time", "date"),
    )
    # Insert each row's hit + fragments.
    import datetime
    for hit_id, kw, ts_iso, _artifact in rows:
        conn.execute(
            "INSERT INTO scan_artifact_hit VALUES (?, ?)",
            (hit_id, "av-1"),
        )
        conn.execute(
            "INSERT INTO hit_fragment_string VALUES (?, ?, ?)",
            (hit_id, "frag-str", kw),
        )
        ms = int(datetime.datetime.fromisoformat(
            ts_iso.replace("Z", "+00:00")
        ).replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
        conn.execute(
            "INSERT INTO hit_fragment_date VALUES (?, ?, ?, ?)",
            (hit_id, "frag-date", ms, ts_iso),
        )
    conn.commit()
    conn.close()


def test_behavioral_delta_with_real_axiom_mfdb_connector(tmp_path):
    """End-to-end — closes the Codex post-review #1 gap that stubs alone
    cannot. Exercises axiom.search → _hydrate_hits → correlate_keywords →
    behavioral_delta. If any of those contracts drifts, this breaks.
    """
    import sqlite3
    from connectors.axiom_mfdb import AxiomMfdbConnector

    db_path = tmp_path / "test.mfdb"
    _build_axiom_mfdb(db_path, rows=[
        # Baseline: bomgar-pec appears Jan 8 only.
        (1, "bomgar-pec user=S-1-5", "2026-01-08T06:36:59", "Test Event Log"),
        # Incident: bomgar-pec reappears Apr 11, plus a 4648 event same-ish time.
        (2, "bomgar-pec reconnect", "2026-04-11T17:50:03", "Test Event Log"),
        (3, "EID 4648 explicit credentials", "2026-04-11T17:50:04", "Test Event Log"),
    ])

    conn = AxiomMfdbConnector()
    conn._conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    conn._conn.row_factory = sqlite3.Row
    conn._frag_defs = {"frag-str": "Value", "frag-date": "Event Time"}
    conn._frag_types = {"frag-str": "string", "frag-date": "date"}
    conn._artifact_versions = {"av-1": "Test Event Log"}

    result = behavioral_delta(
        conn,
        entity_value="bomgar-pec",
        baseline_start="2026-01-01", baseline_end="2026-04-10",
        incident_start="2026-04-11", incident_end="2026-04-16",
        seed_keywords=["4648"],
        window_minutes=60,
    )

    assert result["ok"] is True
    # Dormant gap: Jan 8 → Apr 11 is about 93-94 days.
    gap = result["delta"]["dormant_gap_seconds"]
    assert gap is not None
    assert 90 * 86400 < gap < 100 * 86400
    assert result["delta"]["dormant_gap_reason"] == "computed"
    # bomgar-pec: baseline=1, incident=1 → no volume_change claim.
    # 4648: baseline=0, incident=1 → net-new co-occurrence.
    assert "4648" in result["delta"]["new_cooccurring_keywords"]
    kinds = {c["kind"] for c in result["claims"]}
    assert "entity_dormant_then_active" in kinds


def test_co_occurrence_growth_ratio_reason_is_always_populated():
    """Codex post-review — cooc ratio must carry a reason like dormant_gap."""
    # Case 1: both periods empty.
    stub = _CorrelatableStub({})
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-01-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
    )
    assert r["delta"]["co_occurrence_growth"]["ratio_reason"] == "no_windows_in_either_period"

    # Case 2: incident only (baseline has no co-occurrences).
    stub = _CorrelatableStub({
        "x": [_hit(1, {"ts": "2026-04-12T10:00:00"})],
        "y": [_hit(2, {"ts": "2026-04-12T10:00:30"})],
    })
    r = behavioral_delta(
        stub, entity_value="x",
        baseline_start="2026-01-01", baseline_end="2026-03-31",
        incident_start="2026-04-01", incident_end="2026-04-30",
        seed_keywords=["y"], window_minutes=1,
    )
    assert r["delta"]["co_occurrence_growth"]["ratio_reason"] == "baseline_zero_windows"
