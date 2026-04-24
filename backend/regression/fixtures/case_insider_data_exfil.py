"""F4 — Insider data exfil without extortion.

Purpose: test taxonomy overflow. The ``candidate_axes`` taxonomy covers
ransomware / credential access / persistence / remote access / tool
execution / anti-forensics. It does NOT include insider data
exfiltration *without* extortion. A correctly behaving LLM should notice
the axis is not in the taxonomy yet still surface it (per CLAUDE.md
"fourth angle" rule).

Evidence shape:
  - Trusted admin account accesses unusual volume of documents over
    several business-hour sessions.
  - Large outbound cloud-sync traffic (Google Drive, Dropbox) from the
    same account.
  - USB storage device connected, LNK files for sensitive shares.
  - NO encryption, NO ransom note, NO remote-access exploit, NO
    persistence artefact, NO anti-forensics.
  - NO fired findings from rules that target ransomware / remote admin.

Expected behaviour: verdict ``insider`` (or hedged equivalent), not
``benign`` and not ``unknown``. LLM must reach beyond taxonomy and cite
the exfil-pattern evidence directly.
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

    # Business-day activity by trusted account "carol"
    for day in ("2026-04-13", "2026-04-14", "2026-04-15"):
        for hour in (10, 12, 14, 16):
            # Logon
            add(
                "Windows Event Logs - Security",
                f"{day}T{hour:02d}:00:00Z",
                {"Event ID": 4624,
                 "Account Name": "carol",
                 "Logon Type": 2,
                 "Source Network Address": "-"},
            )
            # SRUM — very large outbound to cloud services
            add(
                "SRUM",
                f"{day}T{hour:02d}:20:00Z",
                {"Application Name": "Chrome.exe",
                 "Bytes Sent": 180_000_000 + (hour * 1_500_000),
                 "Bytes Received": 4_000_000,
                 "User": "carol"},
            )
            add(
                "SRUM",
                f"{day}T{hour:02d}:35:00Z",
                {"Application Name": "GoogleDriveFS.exe",
                 "Bytes Sent": 420_000_000,
                 "Bytes Received": 2_000_000,
                 "User": "carol"},
            )

    # Browser history — repeated visits to cloud file shares
    for day in ("2026-04-13", "2026-04-14", "2026-04-15"):
        for host in ("drive.google.com", "dropbox.com", "mega.nz"):
            add(
                "Edge/Internet Explorer 10-11 Main History",
                f"{day}T10:10:00Z",
                {"URL": f"https://{host}/folders/confidential-2026",
                 "Title": "Confidential client data folder",
                 "User": "carol"},
            )

    # LNK files pointing at sensitive shares
    for idx, share in enumerate([
        "\\\\fileserver01\\Legal\\clients",
        "\\\\fileserver01\\HR\\compensation",
        "\\\\fileserver01\\R&D\\product-roadmap-2026",
    ]):
        add(
            "LNK Files",
            f"2026-04-13T09:{idx * 5:02d}:00Z",
            {"Target Path": share,
             "Target Full Path": share,
             "Drive Letter": "UNC"},
        )

    # USB storage device connected + jump list
    add(
        "Windows Event Logs - System",
        "2026-04-15T16:45:00Z",
        {"Event ID": 20001,
         "Provider": "Microsoft-Windows-UserPnp",
         "Device Description": "Kingston DataTraveler USB 3.0",
         "Event Data": "Device installed"},
    )
    add(
        "Jump List",
        "2026-04-15T16:50:00Z",
        {"Application": "explorer.exe",
         "Target Path": "E:\\Confidential"},
    )

    # Shellbags showing navigation through sensitive directories
    for folder in ("Legal\\Clients", "HR\\Salaries", "R&D\\Roadmap"):
        add(
            "Shellbags",
            "2026-04-15T16:52:00Z",
            {"Full Path": f"E:\\Confidential\\{folder}"},
        )

    # A handful of normal-looking prefetch entries — no malware drops,
    # no LOLBin abuse
    for i, app in enumerate(["chrome.exe", "explorer.exe", "outlook.exe", "excel.exe"]):
        add(
            "Prefetch Files - Windows 8/10/11",
            f"2026-04-14T{9 + i:02d}:00:00Z",
            {"Application Name": app,
             "Full Path": f"\\Program Files\\{app}",
             "Run Count": 10 + i},
        )

    # Crucially absent: encrypted files, ransom notes, log clearing,
    # signature mismatches, net-new services, suspicious scheduled tasks,
    # VSS deletion, Sysmon EID 10 (LSASS access), explicit credential use.

    metadata = {
        "case_name": "fixture_insider_data_exfil",
        "source_type": "fixture",
        "source_path": "fixture://case_insider_data_exfil",
        "total_hits": len(hits),
        "artifact_type_count": 0,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-16",
    }
    coverage = {
        "evtx": "present",
        "prefetch": "present",
        "mft_logfile_usn": "missing",
        "srum": "present",
        "browser": "present",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
