"""F2 — Benign remote work that could be misread as lurking compromise.

Purpose: regression against the user's past false positive. A legitimate
PRA / Bomgar rollout that fills net-new baselines but has no impact.
A naive LLM that treats net-new remote tools as "lurking access" will
flag this incorrectly.

Evidence shape:
  - Bomgar service net-new (recent install)
  - Bomgar sessions only during business hours, weekdays
  - No encryption / note files / abnormal process spawns
  - Normal logon-logoff patterns
"""

from __future__ import annotations

from regression.fixtures.base import FixtureConnector, FixtureHit


def build() -> FixtureConnector:
    hits: list[FixtureHit] = []
    hit_id = 1

    def add(artifact_type: str, ts: str, fields: dict, source_path: str = "", tags=None):
        nonlocal hit_id
        hits.append(FixtureHit(
            hit_id=hit_id,
            artifact_type=artifact_type,
            timestamp=ts,
            source_path=source_path,
            fields=fields,
            tags=tags or [],
        ))
        hit_id += 1

    # Weekdays in mid-April 2026
    business_days = [
        ("2026-04-06", "Mon"),
        ("2026-04-07", "Tue"),
        ("2026-04-08", "Wed"),
        ("2026-04-09", "Thu"),
        ("2026-04-10", "Fri"),
        ("2026-04-13", "Mon"),
        ("2026-04-14", "Tue"),
    ]
    for day, _ in business_days:
        for hour in (10, 13, 15):
            add(
                "Prefetch Files - Windows 8/10/11",
                f"{day}T{hour:02d}:05:00Z",
                {"Application Name": "Bomgar.exe",
                 "Full Path": "\\Program Files\\Bomgar\\Bomgar.exe",
                 "Run Count": hour},
            )
            add(
                "SRUM",
                f"{day}T{hour:02d}:10:00Z",
                {"Application Name": "Bomgar.exe",
                 "Bytes Sent": 3_000_000,
                 "Bytes Received": 2_500_000,
                 "User": "alice"},
            )
            add(
                "Windows Event Logs - Security",
                f"{day}T{hour:02d}:00:00Z",
                {"Event ID": 4624,
                 "Account Name": "alice",
                 "Logon Type": 10,
                 "Source Network Address": "10.20.30.44"},
            )
            add(
                "Windows Event Logs - Security",
                f"{day}T{hour + 1:02d}:45:00Z",
                {"Event ID": 4634,
                 "Account Name": "alice",
                 "Logon Type": 10},
            )

    # Bomgar service, legitimately net-new on 2026-04-05
    add(
        "System Services",
        "2026-04-05T09:00:00Z",
        {"Service Name": "BomgarPRA",
         "Display Name": "Bomgar Privileged Remote Access",
         "ImagePath": "\\Program Files\\Bomgar\\BomgarPRA.exe",
         "Start Type": "Auto",
         "Account": "LocalSystem"},
    )
    add(
        "Windows Event Logs - System",
        "2026-04-05T09:00:12Z",
        {"Event ID": 7045,
         "Service Name": "BomgarPRA",
         "Image Path": "\\Program Files\\Bomgar\\BomgarPRA.exe",
         "Start Type": "Auto"},
    )

    # A handful of typical admin-style prefetch entries (no suspicious drops)
    for t in ("2026-04-08T09:30:00Z", "2026-04-10T14:10:00Z"):
        add(
            "Prefetch Files - Windows 8/10/11",
            t,
            {"Application Name": "powershell.exe",
             "Full Path": "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "Run Count": 4},
        )

    # Deliberately absent: encrypted files, ransom notes, signature mismatches,
    # log-clear events, SRUM network spikes above 10 MB, unusual scheduled tasks.

    metadata = {
        "case_name": "fixture_benign_remote_work",
        "source_type": "fixture",
        "source_path": "fixture://case_benign_remote_work",
        "total_hits": len(hits),
        "artifact_type_count": 0,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-15",
    }
    # Coverage: EVTX / prefetch / SRUM present but no filesystem impact
    # family hits — investigation_impact lane will lack corroboration.
    coverage = {
        "evtx": "present",
        "prefetch": "present",
        "mft_logfile_usn": "missing",
        "srum": "present",
        "browser": "missing",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
