"""F5 — Anti-forensics heavy, impact ambiguous.

Purpose: guard against over-attributing log tampering + shadow-copy
deletion as "confirmed compromise." Many legitimate admin / backup
workflows also trigger these patterns (maintenance windows, storage
housekeeping). The LLM must recognise anti-forensic signals are strong
*priority* hints but not on their own sufficient for a strong verdict
when lane corroboration is weak.

Evidence shape:
  - Security log cleared (EID 1102) + System log cleared (EID 104)
  - VSS shadow deletion (vssadmin delete shadows / wmic shadowcopy)
  - USN journal deletion trace
  - PowerShell ScriptBlockLogging disabled registry touch
  - No encrypted files, no ransom note, minimal filesystem change
  - Admin account performed all actions (could be malicious actor OR
    legitimate maintenance — caller must say so)
  - No SRUM spikes, no remote-tool execution

Expected behaviour: verdict ``unknown`` or hedged ``anti_forensics
observed / impact unverified``; allow_strong_conclusion should be
``false`` because execution / impact lane is unverified.
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

    base_day = "2026-04-11"

    # Log clearing events
    add(
        "Windows Event Logs - Security",
        f"{base_day}T02:15:00Z",
        {"Event ID": 1102,
         "Provider": "Microsoft-Windows-Eventlog",
         "Account Name": "admin",
         "Event Data": "The audit log was cleared."},
    )
    add(
        "Windows Event Logs - System",
        f"{base_day}T02:16:00Z",
        {"Event ID": 104,
         "Provider": "Microsoft-Windows-Eventlog",
         "Account Name": "admin",
         "Event Data": "The System log file was cleared."},
    )

    # VSS shadow copy deletion — Prefetch for vssadmin and wmic
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{base_day}T02:10:00Z",
        {"Application Name": "vssadmin.exe",
         "Full Path": "\\Windows\\System32\\vssadmin.exe",
         "Run Count": 1},
    )
    add(
        "PowerShell History",
        f"{base_day}T02:11:00Z",
        {"User": "admin",
         "Command": "vssadmin delete shadows /all /quiet"},
    )
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{base_day}T02:12:00Z",
        {"Application Name": "wmic.exe",
         "Full Path": "\\Windows\\System32\\wbem\\wmic.exe",
         "Run Count": 1},
    )

    # USN journal deletion
    add(
        "Prefetch Files - Windows 8/10/11",
        f"{base_day}T02:14:00Z",
        {"Application Name": "fsutil.exe",
         "Full Path": "\\Windows\\System32\\fsutil.exe",
         "Run Count": 1},
    )

    # Registry touch disabling PowerShell logging
    add(
        "AmCache File Entries",
        f"{base_day}T02:13:00Z",
        {"File Name": "reg.exe",
         "File Path": "\\Windows\\System32\\reg.exe"},
    )
    add(
        "Registry Value",
        f"{base_day}T02:13:30Z",
        {"Key Path": "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
         "Value Name": "EnableScriptBlockLogging",
         "Value Data": 0},
    )

    # Admin logon just before the tampering burst
    add(
        "Windows Event Logs - Security",
        f"{base_day}T02:05:00Z",
        {"Event ID": 4624,
         "Account Name": "admin",
         "Logon Type": 3,
         "Source Network Address": "10.10.0.5"},
    )

    # A small amount of filesystem activity in admin paths — not clearly
    # impactful
    add(
        "$LogFile Analysis",
        f"{base_day}T02:20:00Z",
        {"Record": "File deleted", "Target": "\\Windows\\Temp\\audit_tmp.log"},
    )

    # Deliberately absent: encrypted files, ransom notes, signature
    # mismatches, mass file change evidence, SRUM exfil, remote-tool
    # prefetch, new services, new scheduled tasks.

    metadata = {
        "case_name": "fixture_anti_forensics_heavy",
        "source_type": "fixture",
        "source_path": "fixture://case_anti_forensics_heavy",
        "total_hits": len(hits),
        "artifact_type_count": 0,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-15",
    }
    coverage = {
        # evtx present but content thin after tampering
        "evtx": "thin",
        "prefetch": "present",
        "mft_logfile_usn": "thin",
        "srum": "missing",
        "browser": "missing",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
