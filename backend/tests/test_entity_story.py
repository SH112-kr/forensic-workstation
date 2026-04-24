"""Tests for ``core.analysis.entity_story`` composition."""

from __future__ import annotations

from typing import Any

from core.analysis.entity_story import entity_story


class _StoryStub:
    def __init__(self, hits_per_keyword: dict[str, list[dict[str, Any]]]):
        self._hits = hits_per_keyword
        self.artifact_queries = object()

    def search(
        self,
        keyword: str = "",
        filters: dict[str, Any] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        filters = filters or {}
        start = filters.get("start_date", "")
        end = filters.get("end_date", "")
        hits = self._hits.get(keyword, [])
        filtered = []
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
        returned = filtered[offset:offset + limit]
        return {"hits": returned, "total": len(filtered), "returned": len(returned)}

    @staticmethod
    def _iso_to_ms(iso: str) -> int:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)


class _BroadStoryStub(_StoryStub):
    def search(
        self,
        keyword: str = "",
        filters: dict[str, Any] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        filters = filters or {}
        start = filters.get("start_date", "")
        end = filters.get("end_date", "")
        needle = keyword.lower()
        matched = []
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


class _StoryArtifactQueryStub:
    def __init__(self, event_rows: dict[int, list[dict[str, Any]]]):
        self._event_rows = event_rows

    def query_event_logs(self, event_ids: list[int] | None = None, provider: str = "", keyword_in_data: str = "", limit: int = 100) -> list[dict]:
        rows: list[dict[str, Any]] = []
        for eid in event_ids or []:
            rows.extend(self._event_rows.get(eid, []))
        return rows if limit == 0 else rows[:limit]


def _hit(hit_id: int, timestamps: dict[str, str], artifact_type: str = "Windows Event Logs", **fields: Any) -> dict[str, Any]:
    return {
        "hit_id": hit_id,
        "timestamps": timestamps,
        "artifact_type": artifact_type,
        "fields": fields or {},
    }


def test_entity_story_builds_expected_phase_structure(monkeypatch):
    stub = _StoryStub({
        "bomgar-pec": [
            _hit(1, {"Created": "2026-01-08T06:36:59"}, Name="bomgar-pec"),
            _hit(2, {"Last Run": "2026-04-11T17:50:02"}, Name="bomgar-pec"),
            _hit(3, {"Last Run": "2026-04-15T00:35:18"}, Name="bomgar-pec"),
        ],
        "4648": [
            _hit(10, {"Created": "2026-04-11T17:50:03"}, EventID="4648"),
            _hit(11, {"Created": "2026-04-12T08:03:28"}, EventID="4648"),
        ],
        "7045": [
            _hit(20, {"Created": "2026-04-11T17:50:04"}, EventID="7045"),
        ],
    })

    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {
            "ok": True,
            "nodes": [
                {
                    "id": "process:raw:bomgar-pec.exe",
                    "type": "process",
                    "label": "bomgar-pec.exe",
                    "normalized_value": "bomgar-pec.exe",
                    "collapsed_from": [{"raw": "C:\\Temp\\bomgar-pec.exe"}],
                    "sample_hit_ids": [1, 2],
                },
                {
                    "id": "service:raw:bomgar",
                    "type": "service",
                    "label": "bomgar",
                    "normalized_value": "bomgar",
                    "collapsed_from": [{"raw": "bomgar"}],
                    "sample_hit_ids": [20],
                },
            ],
            "edges": [
                {"id": "e1", "source": "process:raw:bomgar-pec.exe", "target": "service:raw:bomgar", "type": "created_svc"},
            ],
            "warnings": [],
        },
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {
            "findings": [
                {
                    "rule_name": "evtx_eid_7045_service_installs",
                    "query_description": "bomgar-pec related service install",
                    "matching_count": 1,
                    "details": [{"hit_id": 20, "artifact_context": "bomgar service"}],
                },
                {
                    "rule_name": "openssh_artifacts",
                    "query_description": "unrelated ssh activity",
                    "matching_count": 1,
                    "details": [{"hit_id": 999, "artifact_context": "sshd"}],
                },
            ]
        },
    )

    r = entity_story(
        stub,
        entity_value="bomgar-pec",
        start_date="2026-01-01",
        end_date="2026-04-16",
        seed_keywords=["4648", "7045"],
        window_minutes=60,
    )

    assert r["ok"] is True
    kinds = [p["kind"] for p in r["phases"]]
    assert "first_seen" in kinds
    assert "dormant_period" in kinds
    assert "reactivation" in kinds
    assert "repeat_bursts" in kinds
    assert r["supporting_findings"][0]["rule_name"] == "evtx_eid_7045_service_installs"
    assert r["nearby_entities"][0]["type"] == "service"


def test_entity_story_handles_no_activity(monkeypatch):
    stub = _StoryStub({})
    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {"ok": True, "nodes": [], "edges": [], "warnings": []},
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {"findings": []},
    )

    r = entity_story(
        stub,
        entity_value="missing-tool",
        start_date="2026-01-01",
        end_date="2026-04-16",
    )

    assert r["ok"] is True
    assert r["phases"][0]["kind"] == "no_activity"
    assert r["summary"]["event_count"] == 0


def test_entity_story_whitespace_entity_value_normalizes(monkeypatch):
    stub = _StoryStub({
        "x": [_hit(1, {"ts": "2026-04-12T10:00:00"})],
    })
    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {"ok": True, "nodes": [], "edges": [], "warnings": []},
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {"findings": []},
    )

    r = entity_story(
        stub,
        entity_value=" x ",
        start_date="2026-04-01",
        end_date="2026-04-30",
    )

    assert r["entity"]["seed_keywords"] == ["x"]
    assert r["summary"]["entity_hit_count"] == 1
    assert r["phases"][0]["kind"] == "first_seen"


def test_entity_story_filters_out_of_range_timestamps_from_returned_hits(monkeypatch):
    stub = _StoryStub({
        "bomgar-pec": [
            _hit(
                1,
                {
                    "Last Run": "2026-04-11T17:50:02",
                    "Volume Created": "2019-12-16T03:17:55.321",
                    "File Created": "2026-01-08T06:36:59",
                },
                artifact_type="Prefetch Files - Windows 8/10/11",
            ),
            _hit(2, {"Last Run": "2026-04-15T00:35:18.454"}),
        ],
    })
    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {"ok": True, "nodes": [], "edges": [], "warnings": []},
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {"findings": []},
    )

    r = entity_story(
        stub,
        entity_value="bomgar-pec",
        start_date="2026-04-11",
        end_date="2026-04-16",
    )

    assert r["summary"]["event_count"] == 2
    timestamps = [item["timestamp"] for item in r["timeline_excerpt"]]
    assert timestamps == ["2026-04-11T17:50:02", "2026-04-15T00:35:18.454"]
    assert r["phases"][0]["timestamp"] == "2026-04-11T17:50:02"


def test_entity_story_exact_match_mode_filters_broad_substring_hits(monkeypatch):
    stub = _BroadStoryStub({
        "bundle": [
            _hit(1, {"ts": "2026-04-12T10:00:00"}, Application="bomgar-pec.exe"),
            _hit(2, {"ts": "2026-04-12T10:10:00"}, Application="bomgar-pec-helper.dll"),
        ],
    })
    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {"ok": True, "nodes": [], "edges": [], "warnings": []},
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {"findings": []},
    )

    r = entity_story(
        stub,
        entity_value="bomgar-pec",
        start_date="2026-04-01",
        end_date="2026-04-30",
        match_mode="exact",
    )

    assert r["summary"]["entity_hit_count"] == 1
    assert r["match_semantics"]["mode"] == "exact"


def test_entity_story_supports_event_id_seed(monkeypatch):
    stub = _StoryStub({
        "bomgar-pec": [_hit(1, {"ts": "2026-04-12T10:00:00"}, Application="bomgar-pec.exe")],
    })
    stub.artifact_queries = _StoryArtifactQueryStub({
        4648: [
            {
                "hit_id": 2,
                "artifact_type": "Windows Event Logs",
                "timestamps": {"Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-12T10:00:30"},
                "fields": {"Event ID": 4648, "Event Data": "Explicit credentials used"},
            }
        ]
    })
    monkeypatch.setattr(
        "core.analysis.entity_graph.build_entity_graph",
        lambda *args, **kwargs: {"ok": True, "nodes": [], "edges": [], "warnings": []},
    )
    monkeypatch.setattr(
        "core.analysis.suspicious.find_suspicious",
        lambda aq, rules="": {"findings": []},
    )

    r = entity_story(
        stub,
        entity_value="bomgar-pec",
        start_date="2026-04-01",
        end_date="2026-04-30",
        seed_keywords=["event_id:4648"],
        window_minutes=1,
    )

    assert r["summary"]["co_occurrence_windows"] >= 1
