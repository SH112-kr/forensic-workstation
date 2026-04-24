"""F3 — Partial evidence with missing core artifact families.

Purpose: verify that the LLM respects ``allow_strong_conclusion == false``
and refuses to issue a strong verdict when coverage is insufficient.

Evidence shape:
  - Windows Event Logs entirely MISSING
  - Prefetch partial (~10 entries, generic)
  - SRUM absent
  - MFT present but USN journal absent
  - A handful of low-specificity findings, none strong
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

    # Partial prefetch — just generic system tools, no net-new drops
    base = "2026-04-11"
    for i, app in enumerate([
        "explorer.exe", "svchost.exe", "MsMpEng.exe", "SearchIndexer.exe",
        "powershell.exe", "notepad.exe", "chrome.exe", "mmc.exe",
        "taskhostw.exe", "RuntimeBroker.exe",
    ]):
        add(
            "Prefetch Files - Windows 8/10/11",
            f"{base}T{8 + (i % 10):02d}:{(i * 5) % 60:02d}:00Z",
            {"Application Name": app,
             "Full Path": f"\\Windows\\System32\\{app}",
             "Run Count": 1 + i},
        )

    # One AmCache row, moderate strength at best
    add(
        "AmCache File Entries",
        f"{base}T09:00:00Z",
        {"File Name": "helperd.exe",
         "File Path": "\\Users\\tech\\Downloads\\helperd.exe",
         "SHA1": "0000000000000000000000000000000000000000"},
    )

    # One shim cache hit (file-existence weak evidence)
    add(
        "Shim Cache",
        f"{base}T09:01:00Z",
        {"File Path": "\\Users\\tech\\Downloads\\helperd.exe",
         "Last Modified Time": f"{base}T08:55:00Z"},
    )

    # MFT present (so "$LogFile Analysis" appears) but USN absent
    add(
        "$LogFile Analysis",
        f"{base}T09:00:30Z",
        {"Record": "File create", "Target": "\\Users\\tech\\Downloads\\helperd.exe"},
    )

    # Deliberately absent: Windows Event Logs (any), SRUM, UsnJrnl,
    # encrypted files, text documents with impact markers.

    metadata = {
        "case_name": "fixture_partial_evidence",
        "source_type": "fixture",
        "source_path": "fixture://case_partial_evidence",
        "total_hits": len(hits),
        "artifact_type_count": 0,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-15",
    }
    coverage = {
        "evtx": "missing",
        "prefetch": "present",
        "mft_logfile_usn": "missing",
        "srum": "missing",
        "browser": "missing",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
