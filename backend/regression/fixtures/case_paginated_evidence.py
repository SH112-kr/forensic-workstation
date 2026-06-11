"""F7 — Distributed evidence buried beyond the first result page.

Purpose: verify pagination discipline (roadmap P0 / truncation hard gate).
A busy host produces thousands of benign rows; the actual ransomware
evidence sits deep in the timeline so that any page-1-only analysis sees
nothing but noise. The correct behaviour is to notice ``truncated`` /
``total > returned`` markers, paginate (or fetch_all), and only then
conclude.

Evidence shape (interleaved with ~5,000 benign rows over ~3.5 days):
  - Cluster I (~timeline position 1,600): remote-tool session (AnyDesk
    SRUM volume + prefetch) and a browser download of the dropper.
  - Cluster A (~position 1,630): EID 7045 service install with a
    ProgramData binary, plus matching Prefetch + AmCache rows.
  - Cluster B (~position 2,230): ~160 Encrypted Files (.lkd), signature
    mismatches, USN rename records, and a ransom note text document.
  - Cluster C (~position 2,810): EID 1102 security log cleared.

Noise families are realistic for a workstation: 4624 logons, 4688 process
creations, Edge web visits, Prefetch for standard binaries. All values are
index-derived — no randomness, no wall-clock reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from regression.fixtures.base import FixtureConnector, FixtureHit


_BASE = datetime(2026, 5, 18, 0, 0, 0, tzinfo=timezone.utc)

# Minute offsets (from _BASE) of the evidence clusters. One benign row is
# emitted per minute, so these are also approximate timeline positions —
# all far beyond a 200-row search page or 500-row timeline page.
_CLUSTER_I_MINUTE = 1602   # 2026-05-19T02:42Z — ingress (remote tool + download)
_CLUSTER_A_MINUTE = 1634   # 2026-05-19T03:14Z — service persistence
_CLUSTER_B_MINUTE = 2225   # 2026-05-19T13:05Z — encryption impact
_CLUSTER_C_MINUTE = 2807   # 2026-05-19T22:47Z — log cleared

_NOISE_MINUTES = 5000      # ~3.5 days of one-row-per-minute noise

_BENIGN_PROCESSES = [
    "svchost.exe", "explorer.exe", "RuntimeBroker.exe", "SearchIndexer.exe",
    "taskhostw.exe", "dllhost.exe", "conhost.exe", "MsMpEng.exe",
    "OneDrive.exe", "msedge.exe", "teams.exe", "outlook.exe",
]

_BENIGN_SITES = [
    "intranet.corp.local/portal", "mail.corp.local/owa",
    "docs.corp.local/wiki", "www.msftconnecttest.com/connecttest.txt",
    "edge.microsoft.com/start", "sharepoint.corp.local/sites/team",
]

_ENCRYPTED_DIRS = [
    "\\Users\\jhlee\\Documents\\contracts",
    "\\Users\\jhlee\\Documents\\finance",
    "\\Users\\jhlee\\Desktop\\projects",
    "\\Shares\\team\\reports",
]


def _ts(minute: int, second: int = 0) -> str:
    moment = _BASE + timedelta(minutes=minute, seconds=second)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


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

    # ── Benign noise: one row per minute, family rotated by index ─────
    for minute in range(_NOISE_MINUTES):
        family = minute % 10
        if family < 4:  # 40% — interactive / service logons
            add(
                "Windows Event Logs",
                _ts(minute),
                {"Event ID": "4624",
                 "Provider Name": "Microsoft-Windows-Security-Auditing",
                 "Logon Type": "5" if minute % 3 else "2",
                 "Account Name": f"CORP\\user{minute % 17:02d}",
                 "Workstation Name": f"WS-{minute % 23:03d}"},
            )
        elif family < 7:  # 30% — routine process creations
            proc = _BENIGN_PROCESSES[minute % len(_BENIGN_PROCESSES)]
            add(
                "Windows Event Logs",
                _ts(minute),
                {"Event ID": "4688",
                 "Provider Name": "Microsoft-Windows-Security-Auditing",
                 "New Process Name": f"\\Windows\\System32\\{proc}",
                 "Creator Process Name": "\\Windows\\System32\\services.exe"},
            )
        elif family < 9:  # 20% — corporate browsing
            site = _BENIGN_SITES[minute % len(_BENIGN_SITES)]
            add(
                "Edge Web Visits",
                _ts(minute),
                {"URL": f"https://{site}",
                 "Title": "Corporate page",
                 "Visit Count": 1 + minute % 5},
            )
        else:  # 10% — standard prefetch
            proc = _BENIGN_PROCESSES[minute % len(_BENIGN_PROCESSES)]
            add(
                "Prefetch Files - Windows 8/10/11",
                _ts(minute),
                {"Application Name": proc,
                 "Full Path": f"\\Windows\\System32\\{proc}",
                 "Run Count": 1 + minute % 40},
            )

    # ── Cluster I — ingress: remote-tool session + dropper download ───
    for i in range(6):
        add(
            "SRUM Network Usage",
            _ts(_CLUSTER_I_MINUTE + i * 2, 30),
            {"Application Name": "AnyDesk.exe",
             "Exe Info": "\\Users\\jhlee\\AppData\\Local\\AnyDesk\\AnyDesk.exe",
             "Bytes Sent": 4_500_000 + i * 750_000,
             "Bytes Received": 12_000_000 + i * 2_000_000},
        )
    add(
        "Prefetch Files - Windows 8/10/11",
        _ts(_CLUSTER_I_MINUTE, 50),
        {"Application Name": "ANYDESK.EXE",
         "Full Path": "\\Users\\jhlee\\AppData\\Local\\AnyDesk\\AnyDesk.exe",
         "Run Count": 4},
    )
    add(
        "Edge Web Visits",
        _ts(_CLUSTER_I_MINUTE + 14, 5),
        {"URL": "http://cdn.lkd-delivery.example/pkg/updsvc.exe",
         "Title": "", "Visit Count": 1},
    )
    add(
        "Edge Downloads",
        _ts(_CLUSTER_I_MINUTE + 14, 35),
        {"URL": "http://cdn.lkd-delivery.example/pkg/updsvc.exe",
         "Target Path": "\\Users\\jhlee\\Downloads\\updsvc.exe",
         "Received Bytes": 824_320},
    )
    add(
        "Windows Event Logs",
        _ts(_CLUSTER_I_MINUTE + 20, 0),
        {"Event ID": "4648",
         "Provider Name": "Microsoft-Windows-Security-Auditing",
         "Account Name": "CORP\\user03",
         "Target Account Name": "CORP\\admin-jh",
         "description": "Windows Event Logs | Event ID=4648 explicit "
                        "credential use CORP\\user03 -> CORP\\admin-jh"},
    )

    # ── Cluster A — service persistence (deep page) ────────────────────
    add(
        "Windows Event Logs",
        _ts(_CLUSTER_A_MINUTE, 5),
        {"Event ID": "7045",
         "Provider Name": "Service Control Manager",
         "Service Name": "UpdaterSvc",
         "Image Path": "\\ProgramData\\updsvc.exe",
         "Service Start Type": "auto start",
         "description": "Windows Event Logs | Event ID=7045 service install "
                        "UpdaterSvc ImagePath=\\ProgramData\\updsvc.exe"},
    )
    add(
        "Prefetch Files - Windows 8/10/11",
        _ts(_CLUSTER_A_MINUTE, 40),
        {"Application Name": "UPDSVC.EXE",
         "Full Path": "\\ProgramData\\updsvc.exe",
         "Run Count": 2},
    )
    add(
        "AmCache File Entries",
        _ts(_CLUSTER_A_MINUTE + 1, 10),
        {"File Name": "updsvc.exe",
         "File Path": "\\ProgramData\\updsvc.exe",
         "SHA1": "7045704570457045704570457045704570457045"},
    )

    # ── Cluster B — encryption impact (deeper page) ───────────────────
    for i in range(160):
        directory = _ENCRYPTED_DIRS[i % len(_ENCRYPTED_DIRS)]
        add(
            "Encrypted Files",
            _ts(_CLUSTER_B_MINUTE + i // 8, (i * 7) % 60),
            {"File Path": f"{directory}\\doc_{i:03d}.docx.lkd",
             "Extension": ".lkd"},
        )
    for i in range(2):
        add(
            "File Signature Mismatch (Document)",
            _ts(_CLUSTER_B_MINUTE + 1, 30 + i),
            {"File Path": f"{_ENCRYPTED_DIRS[i]}\\doc_{i:03d}.docx.lkd",
             "Expected": "docx", "Actual": "unknown/high-entropy"},
        )
    for i in range(3):
        add(
            "UsnJrnl",
            _ts(_CLUSTER_B_MINUTE + 2 + i, 15),
            {"Name": f"doc_{i:03d}.docx.lkd",
             "Full Path": f"{_ENCRYPTED_DIRS[i % len(_ENCRYPTED_DIRS)]}\\doc_{i:03d}.docx.lkd",
             "Update Reasons": "RenameNewName|DataExtend|Close"},
        )
    add(
        "Text Documents",
        _ts(_CLUSTER_B_MINUTE + 21, 0),
        {"File Path": "\\Users\\jhlee\\Desktop\\HOW_TO_RECOVER.txt",
         "Content": "All your files are encrypted. To decrypt and restore "
                    "your data, contact recover@lkd-support.example with "
                    "your personal ID."},
    )

    # ── Cluster C — audit log cleared (deepest page) ──────────────────
    add(
        "Windows Event Logs",
        _ts(_CLUSTER_C_MINUTE, 12),
        {"Event ID": "1102",
         "Provider Name": "Microsoft-Windows-Eventlog",
         "Account Name": "CORP\\user03",
         "Channel": "Security",
         "description": "Windows Event Logs | Event ID=1102 security audit "
                        "log cleared by CORP\\user03"},
    )

    metadata = {
        "case_name": "fixture_paginated_evidence",
        "source_type": "fixture",
        "source_path": "fixture://case_paginated_evidence",
        "total_hits": len(hits),
        "artifact_type_count": 0,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-05-18",
        "date_range_end": "2026-05-22",
    }
    coverage = {
        "evtx": "present",
        "prefetch": "present",
        "mft_logfile_usn": "present",
        "srum": "present",
        "browser": "present",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
