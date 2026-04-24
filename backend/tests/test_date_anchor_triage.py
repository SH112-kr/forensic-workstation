from __future__ import annotations

from core.analysis.date_anchor_triage import date_anchor_triage


class _StubConnector:
    def search(self, keyword="", filters=None, limit=50, offset=0):
        filters = filters or {}
        artifact_type = filters.get("artifact_type", "")

        if artifact_type == "System Services":
            return {
                "total": 1,
                "hits": [
                    {
                        "hit_id": 1,
                        "artifact_type": artifact_type,
                        "timestamp": "2026-02-20T14:50:18Z",
                        "fields": {
                            "Service Name": "uploadmgr",
                            "Hosted Service": r"%SYSTEMROOT%\system32\enamgr.dll",
                        },
                    }
                ],
            }
        if artifact_type == "Shim Cache":
            return {
                "total": 2,
                "hits": [
                    {
                        "hit_id": 2,
                        "artifact_type": artifact_type,
                        "timestamp": "2026-02-20T14:50:18Z",
                        "fields": {"Path": r"C:\Windows\System32\enamgr.dll"},
                    },
                    {
                        "hit_id": 3,
                        "artifact_type": artifact_type,
                        "timestamp": "2026-02-20T14:55:00Z",
                        "fields": {"Path": r"C:\Users\user\Desktop\notes.txt"},
                    },
                ],
            }
        if artifact_type == "Prefetch Files - Windows 8/10/11":
            return {
                "total": 1,
                "hits": [
                    {
                        "hit_id": 4,
                        "artifact_type": artifact_type,
                        "timestamp": "2026-02-20T14:51:00Z",
                        "fields": {
                            "Application Name": "rundll32.exe",
                            "Full Path": r"C:\Windows\System32\rundll32.exe",
                        },
                    }
                ],
            }
        if artifact_type == "Edge Downloads":
            return {
                "total": 1,
                "hits": [
                    {
                        "hit_id": 5,
                        "artifact_type": artifact_type,
                        "timestamp": "2026-02-20T14:45:00Z",
                        "fields": {
                            "URL": "https://metroerp.a1capital.co.kr/payload",
                            "Download Location": r"C:\Users\user\Downloads\payload.exe",
                        },
                    }
                ],
            }
        return {"total": 0, "hits": []}


def test_date_anchor_triage_surfaces_raw_high_value_sections():
    result = date_anchor_triage(
        _StubConnector(),
        start_date="2026-02-20",
        end_date="2026-02-20",
        limit_per_query=5,
    )

    assert result["ok"] is True
    assert result["period"]["start"] == "2026-02-20"
    sections = {section["section_id"]: section for section in result["sections"]}

    assert sections["service_and_autorun"]["total_hits"] >= 1
    assert sections["execution_and_scripts"]["total_hits"] >= 1
    assert sections["browser_and_downloads"]["total_hits"] >= 1

    suspicious_hits = sections["suspicious_file_drops"]["queries"][3]["hits"]
    assert len(suspicious_hits) == 1
    assert suspicious_hits[0]["snippet"].endswith(r"Path=C:\Windows\System32\enamgr.dll")
    assert "does not assign intent" in result["notes"][0]
