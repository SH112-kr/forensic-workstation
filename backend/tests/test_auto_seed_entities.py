"""Tests for core.analysis.auto_seed_entities."""

from __future__ import annotations

from typing import Any

from core.analysis.auto_seed_entities import _context_bucket_seed, auto_seed_entities


class _AQStub:
    def __init__(self, event_rows=None, services=None, startup=None):
        self._event_rows = event_rows or {}
        self._services = services or []
        self._startup = startup or []

    def query_event_logs(self, event_ids=None, provider="", keyword_in_data="", limit=100):
        rows = []
        for eid in event_ids or []:
            rows.extend(self._event_rows.get(eid, []))
        return rows if limit == 0 else rows[:limit]

    def query_services(self, limit=0):
        return [{"Service Name": s} for s in self._services]

    def query_scheduled_tasks(self, limit=0):
        return []

    def _query_artifact(self, name, limit=0):
        if name == "Startup Items":
            return [{"Path": s} for s in self._startup]
        if name == "User Accounts":
            return []
        return []


class _ConnectorStub:
    def __init__(self, keyword_hits: dict[str, list[dict[str, Any]]], event_rows=None, services=None, startup=None):
        self._keyword_hits = keyword_hits
        self.artifact_queries = _AQStub(event_rows=event_rows, services=services, startup=startup)

    def search(self, keyword="", filters=None, limit=50, offset=0):
        filters = filters or {}
        start = filters.get("start_date", "")
        end = filters.get("end_date", "")
        matched: list[dict[str, Any]] = []
        needle = keyword.lower()
        for hits in self._keyword_hits.values():
            for hit in hits:
                blob = " ".join(str(v) for v in (hit.get("fields") or {}).values()).lower()
                if needle not in blob:
                    continue
                ts_values = list((hit.get("timestamps") or {}).values())
                if not ts_values:
                    continue
                first_ts = ts_values[0]
                if start and first_ts < start:
                    continue
                if end and first_ts > end + "Z":
                    continue
                matched.append(hit)
        returned = matched[offset:offset + limit]
        return {"hits": returned, "total": len(matched), "returned": len(returned)}

    def _hydrate_hits(self, hit_ids):
        by_id = {}
        for hits in self._keyword_hits.values():
            for hit in hits:
                by_id[hit["hit_id"]] = hit
        return [by_id[hid] for hid in hit_ids if hid in by_id]

    @staticmethod
    def _iso_to_ms(iso: str) -> int:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)


def _hit(hit_id: int, ts: str, **fields: Any) -> dict[str, Any]:
    return {
        "hit_id": hit_id,
        "artifact_type": fields.pop("artifact_type", "Windows Event Logs"),
        "timestamps": {"ts": ts},
        "fields": fields,
    }


def test_auto_seed_entities_extracts_event_ids_and_basenames():
    connector = _ConnectorStub(
        {
            "bundle": [
                _hit(1, "2026-04-12T10:00:00", **{"Application Name": "bomgar-pec.exe"}),
                _hit(2, "2026-04-12T10:00:30", **{"Event ID": 4648, "Event Data": "Explicit credentials used"}),
            ]
        },
        event_rows={4648: [{"hit_id": 2}]},
        services=["bomgar-pec.exe", "disk.sys"],
        startup=['"C:\\ProgramData\\bomgar-pec.exe"'],
    )
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_4648_explicit_credential_logons",
                "details": [
                    {
                        "hit_id": 2,
                        "artifact_type": "Windows Event Logs (EID 4648)",
                        "timestamp": "2026-04-12T10:00:30",
                        "ProcessName": "C:\\Windows\\System32\\svchost.exe",
                    }
                ],
            },
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "details": [
                    {
                        "hit_id": 1,
                        "artifact_type": "Windows Event Logs (EID 7045)",
                        "timestamp": "2026-04-12T10:00:00",
                        "ImagePath": "C:\\ProgramData\\bomgar-pec.exe",
                    }
                ],
            },
        ]
    }

    r = auto_seed_entities(
        connector,
        start_date="2026-04-01",
        end_date="2026-04-30",
        findings_payload=findings,
        window_minutes=1,
    )

    tokens = [x["token"] for x in r["seed_catalog"]]
    assert "event_id:4648" in tokens
    assert "event_id:7045" in tokens
    assert "bomgar-pec.exe" in tokens
    assert "disk.sys" not in tokens
    assert any(x["token"] == "event_id:4648" and x["bucket"] == "priority" for x in r["seed_catalog"])
    assert any(x["token"] == "bomgar-pec.exe" and x["bucket"] == "priority" for x in r["priority_seed_catalog"])
    assert r["recommended"]["entity_value"] == "bomgar-pec.exe"
    assert "event_id:4648" in r["recommended"]["priority_seed_keywords"]


def test_auto_seed_entities_clusters_selected_seeds():
    connector = _ConnectorStub(
        {
            "bundle": [
                _hit(1, "2026-04-12T10:00:00", **{"Application Name": "bomgar-pec.exe"}),
                _hit(2, "2026-04-12T10:00:30", **{"Event ID": 4648, "Event Data": "Explicit credentials used"}),
            ]
        },
        event_rows={4648: [{"hit_id": 2}]},
    )
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_4648_explicit_credential_logons",
                "details": [{"hit_id": 2, "artifact_type": "Windows Event Logs (EID 4648)", "timestamp": "2026-04-12T10:00:30"}],
            },
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "details": [{"hit_id": 1, "artifact_type": "Windows Event Logs (EID 7045)", "timestamp": "2026-04-12T10:00:00", "ImagePath": "C:\\ProgramData\\bomgar-pec.exe"}],
            },
        ]
    }
    baseline = {"categories": {"services": {"net_new": ["bomgar-pec.exe"]}, "startup_items": {"net_new": []}}}

    r = auto_seed_entities(
        connector,
        start_date="2026-04-01",
        end_date="2026-04-30",
        findings_payload=findings,
        baseline_payload=baseline,
        window_minutes=1,
        max_seeds=5,
    )

    assert r["summary"]["selected_seed_count"] >= 2
    assert r["co_occurrence_clusters"]
    assert r["summary"]["priority_seed_count"] >= 1
    assert (
        r["summary"]["priority_seed_count"] + r["summary"]["context_seed_count"]
        == r["summary"]["selected_seed_count"]
    )


def test_auto_seed_entities_splits_context_into_adjacent_and_common():
    connector = _ConnectorStub(
        {"bundle": [_hit(1, "2026-04-12T10:00:00", **{"Application Name": "bomgar-pec.exe"})]},
        services=["bomgar-pec.exe", "googleupdate.exe"],
        startup=[],
    )
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_4648_explicit_credential_logons",
                "matched_patterns": {"Event ID 4648 (Explicit Credential Use)": 1},
                "details": [],
            }
        ]
    }
    baseline = {"categories": {"services": {"net_new": ["bomgar-pec.exe", "googleupdate.exe"]}, "startup_items": {"net_new": []}}}

    r = auto_seed_entities(
        connector,
        start_date="2026-04-01",
        end_date="2026-04-30",
        findings_payload=findings,
        baseline_payload=baseline,
        max_seeds=5,
    )

    assert r["entity_adjacent_context"] == []
    assert [x["token"] for x in r["baseline_common_context"]] == ["bomgar-pec.exe", "googleupdate.exe"]


def test_context_bucket_seed_allows_entity_adjacent_when_non_baseline_source_exists():
    bucket, reason = _context_bucket_seed(
        {
            "token": "tool.exe",
            "sources": ["baseline_diff", "evtx_eid_7045_service_installs"],
            "source_kinds": ["baseline_services_basename"],
        },
        "tool.exe",
    )

    assert bucket == "entity_adjacent"
    assert "non-baseline source" in reason


def test_auto_seed_entities_recommended_entities_keep_alternatives():
    connector = _ConnectorStub(
        {
            "bundle": [
                _hit(1, "2026-04-12T10:00:00", **{"Application Name": "bomgar-pec.exe"}),
                _hit(2, "2026-04-12T10:00:30", **{"Application Name": "netscan.exe"}),
            ]
        },
    )
    findings = {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "details": [
                    {
                        "hit_id": 1,
                        "artifact_type": "Windows Event Logs (EID 7045)",
                        "timestamp": "2026-04-12T10:00:00",
                        "ImagePath": "C:\\ProgramData\\bomgar-pec.exe",
                    }
                ],
            },
            {
                "rule_name": "evtx_eid_4688_process_creation_events",
                "details": [
                    {
                        "hit_id": 2,
                        "artifact_type": "Windows Event Logs (EID 4688)",
                        "timestamp": "2026-04-12T10:00:30",
                        "ImagePath": "C:\\Users\\S\\AppData\\Local\\Temp\\netscan.exe",
                    }
                ],
            },
        ]
    }

    r = auto_seed_entities(
        connector,
        start_date="2026-04-01",
        end_date="2026-04-30",
        findings_payload=findings,
        max_seeds=6,
    )

    assert r["recommended"]["entity_value"] == "bomgar-pec.exe"
    assert "bomgar-pec.exe" in r["recommended"]["recommended_entities"]
    assert "netscan.exe" in r["recommended"]["recommended_entities"]
