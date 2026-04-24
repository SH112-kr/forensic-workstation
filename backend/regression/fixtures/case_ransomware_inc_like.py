"""F1 — Ransomware-like case with solid evidence.

Purpose: baseline correctness — when there is clear ransomware evidence,
does the LLM reach the right conclusion?

Evidence shape:
  - Ransom note in user-writable path (``INC-README.txt``)
  - ~200 encrypted files with ``.INC`` extension
  - New executable dropped under ``\\Users\\Public``
  - Prefetch for the drop + for common living-off-the-land tools
  - Event 1102 (Security log cleared)
  - Remote-tool session (Bomgar) high-volume SRUM entries + prefetch
  - Net-new scheduled task vs baseline
"""

from __future__ import annotations

from regression.fixtures.base import FixtureConnector, FixtureHit


BASE_DAY = "2026-04-12"


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

    # ── Execution artifacts ──
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{BASE_DAY}T10:15:33Z",
        {
            "Application Name": "win.exe",
            "Full Path": "\\Users\\Public\\win.exe",
            "Run Count": 3,
            "Last Run Time - UTC": f"{BASE_DAY} 10:15:33",
        },
    )
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{BASE_DAY}T10:12:01Z",
        {
            "Application Name": "cmd.exe",
            "Full Path": "\\Windows\\System32\\cmd.exe",
            "Run Count": 14,
        },
    )
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{BASE_DAY}T10:13:22Z",
        {
            "Application Name": "wmic.exe",
            "Full Path": "\\Windows\\System32\\wbem\\wmic.exe",
            "Run Count": 2,
        },
    )
    for i in range(20):
        add(
            "Prefetch Files - Windows 8/10/11",
            f"2026-04-{10 + (i % 3):02d}T{9 + (i % 8):02d}:{(i * 3) % 60:02d}:00Z",
            {
                "Application Name": "Bomgar.exe",
                "Full Path": "\\Program Files\\Bomgar\\Bomgar.exe",
                "Run Count": 5 + i,
            },
        )

    # ── File signature mismatches / drops ──
    add(
        "File Signature Mismatch (Document)",
        f"{BASE_DAY}T10:14:00Z",
        {"File Path": "\\Users\\Public\\win.exe",
         "Declared Extension": ".exe",
         "Signature": "Windows PE"},
    )
    add(
        "File Signature Mismatch (Document)",
        f"{BASE_DAY}T10:14:12Z",
        {"File Path": "\\ProgramData\\update.exe",
         "Declared Extension": ".exe",
         "Signature": "Windows PE"},
    )

    # ── Encrypted files (impact) ──
    for i in range(200):
        add(
            "Encrypted Files",
            f"{BASE_DAY}T10:2{(i // 30) % 10}:{i % 60:02d}Z",
            {"File Path": f"\\Users\\admin\\Documents\\file_{i:03d}.docx.INC",
             "Extension": ".INC"},
        )

    # ── Ransom note ──
    add(
        "Text Documents",
        f"{BASE_DAY}T10:28:14Z",
        {"File Path": "\\Users\\admin\\Desktop\\INC-README.txt",
         "Content Preview": "Your files have been encrypted. To decrypt, "
                            "contact us to restore. Do not shut down."},
    )
    add(
        "Text Documents",
        f"{BASE_DAY}T10:28:20Z",
        {"File Path": "\\Users\\admin\\Documents\\INC-README.txt",
         "Content Preview": "Recovery instructions. Contact to restore."},
    )

    # ── Event logs: log cleared, service install, logons ──
    add(
        "Windows Event Logs - Security",
        f"{BASE_DAY}T10:29:01Z",
        {"Event ID": 1102,
         "Provider": "Microsoft-Windows-Eventlog",
         "Event Data": "The audit log was cleared."},
    )
    add(
        "Windows Event Logs - System",
        f"{BASE_DAY}T09:45:12Z",
        {"Event ID": 7045,
         "Service Name": "UpdateChecker",
         "Image Path": "\\ProgramData\\update.exe",
         "Start Type": "Auto"},
    )
    add(
        "Windows Event Logs - Security",
        f"{BASE_DAY}T09:30:00Z",
        {"Event ID": 4624,
         "Account Name": "admin",
         "Logon Type": 10,
         "Source Network Address": "203.0.113.44"},
    )
    add(
        "Windows Event Logs - Security",
        f"{BASE_DAY}T09:32:18Z",
        {"Event ID": 4648,
         "Subject User Name": "admin",
         "Target User Name": "administrator",
         "Target Server Name": "localhost"},
    )

    # ── SRUM Bomgar session (high volume) ──
    for i in range(8):
        add(
            "SRUM",
            f"{BASE_DAY}T{9 + i:02d}:{(i * 7) % 60:02d}:00Z",
            {"Application Name": "Bomgar.exe",
             "Bytes Sent": 120_000_000 + i * 1_000_000,
             "Bytes Received": 90_000_000,
             "User": "admin"},
        )

    # ── Scheduled task net-new ──
    add(
        "Scheduled Tasks",
        f"{BASE_DAY}T09:48:00Z",
        {"Name": "UpdateChecker",
         "Task Path": "\\ProgramData\\update.exe",
         "Author": "admin"},
    )

    # ── System services baseline delta ──
    add(
        "System Services",
        f"{BASE_DAY}T09:45:30Z",
        {"Service Name": "UpdateChecker",
         "Display Name": "Update Checker",
         "ImagePath": "\\ProgramData\\update.exe"},
    )
    add(
        "System Services",
        "2026-04-08T08:00:00Z",
        {"Service Name": "BomgarPRA",
         "Display Name": "Bomgar Privileged Remote Access",
         "ImagePath": "\\Program Files\\Bomgar\\BomgarPRA.exe"},
    )

    # ── MFT / NTFS hints (for coverage_gate evtx/mft/usn present) ──
    add(
        "$LogFile Analysis",
        f"{BASE_DAY}T10:20:05Z",
        {"Record": "MFT entry change", "Target": "\\Users\\admin\\Documents"},
    )
    add(
        "UsnJrnl",
        f"{BASE_DAY}T10:20:07Z",
        {"File Name": "file_000.docx.INC", "Reason": "DATA_OVERWRITE|CLOSE"},
    )

    metadata = {
        "case_name": "fixture_ransomware_inc_like",
        "source_type": "fixture",
        "source_path": "fixture://case_ransomware_inc_like",
        "total_hits": len(hits),
        "artifact_type_count": 0,  # overwritten by connector
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-15",
    }
    coverage = {
        "evtx": "present",
        "prefetch": "present",
        "mft_logfile_usn": "present",
        "srum": "present",
        "browser": "missing",
    }
    conn = FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
    return conn
