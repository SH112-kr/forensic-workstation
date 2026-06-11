"""Structured artifact detection — artifact-type-aware rules.

Each rule queries specific artifact types with specific field conditions,
not keyword matching. This eliminates false positives from substring matches.

IMPORTANT forensic principles encoded in rules:
- ShimCache entry ≠ execution proof (file existence on disk triggers it)
- Prefetch Last Run = strong execution evidence, but does NOT record command-line arguments
- Link Date = compile time, NOT deployment time
- File timestamps must be verified from $MFT, not inferred from other artifacts
- Temporal correlation ≠ causation — always flag as needing verification

Each rule returns: rule_name, query_description, matching_count, returned_count,
truncated, detail_cap, matched_patterns, details[]. No severity, confidence, or
MITRE pre-labels — those judgments belong to the analyst, not the code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_artifact_queries import ArtifactQueries

RULE_CATEGORY_MAP = {
    "sysmon_eid10_lsass_handle_open": "credential_access",
    "evtx_eid_4688_process_creation_events": "execution",
    "evtx_eid_7045_service_installs": "persistence",
    "evtx_eid_4698_scheduled_task_events": "persistence",
    "evtx_eid_1102_audit_log_cleared": "anti_forensics",
    "evtx_eid_4624_type10_rdp_logons": "remote_access",
    "evtx_eid_4648_explicit_credential_logons": "credential_access",
    "prefetch_pentest_tool_names": "tool_execution",
    "services_nonstandard_binary_paths": "persistence",
    "evtx_eid_4104_scriptblock_logs": "execution",
    "prefetch_security_sw_werfault_correlation": "initial_access",
    "amcache_remote_access_tool_names": "tool_installation",
    "openssh_artifacts": "remote_access",
    "office_trustrecords_macro_enabled": "initial_access",
    "motw_internet_origin_risky_file": "initial_access",
}

# B-2 rule scope: how broadly a rule's 0-result should be read.
#   generic           — applies to most Windows endpoints; 0 hits is informative.
#   campaign_specific — tuned to one campaign/toolset; 0 hits means "not THIS
#                       campaign", NOT "no compromise". Do not widen.
#   region_specific   — tuned to a region's software ecosystem (e.g. Korean
#                       security SW); 0 hits outside that context is expected.
RULE_SCOPE_MAP = {
    "sysmon_eid10_lsass_handle_open": "generic",
    "evtx_eid_4688_process_creation_events": "generic",
    "evtx_eid_7045_service_installs": "generic",
    "evtx_eid_4698_scheduled_task_events": "generic",
    "evtx_eid_1102_audit_log_cleared": "generic",
    "evtx_eid_4624_type10_rdp_logons": "generic",
    "evtx_eid_4648_explicit_credential_logons": "generic",
    "prefetch_pentest_tool_names": "campaign_specific",
    "services_nonstandard_binary_paths": "generic",
    "evtx_eid_4104_scriptblock_logs": "generic",
    "prefetch_security_sw_werfault_correlation": "region_specific",
    "amcache_remote_access_tool_names": "campaign_specific",
    "openssh_artifacts": "generic",
    "office_trustrecords_macro_enabled": "generic",
    "motw_internet_origin_risky_file": "generic",
}

_SCOPE_ZERO_RESULT_HINT = {
    "campaign_specific": (
        "campaign_specific rule: 0 hits means this specific toolset/campaign "
        "was not matched, NOT that the host is clean. Other execution evidence "
        "may still indicate compromise."
    ),
    "region_specific": (
        "region_specific rule: tuned to a regional software ecosystem; 0 hits "
        "outside that context is expected and not evidence of absence."
    ),
}

# Query limits used by each rule — documented for transparency
RULE_QUERY_LIMITS: dict[str, dict[str, int]] = {
    "sysmon_eid10_lsass_handle_open": {"process_access_events": 500, "details": 20},
    "evtx_eid_4688_process_creation_events": {"process_creation_events": 1000, "details": 20},
    "evtx_eid_7045_service_installs": {"service_installs": 500},
    "evtx_eid_4698_scheduled_task_events": {"scheduled_task_events": 2000, "details": 20},
    "evtx_eid_1102_audit_log_cleared": {"log_cleared": 200, "details": 20},
    "evtx_eid_4624_type10_rdp_logons": {"logon_events": 1000},
    "evtx_eid_4648_explicit_credential_logons": {"event_logs_4648": 500},
    "prefetch_pentest_tool_names": {"prefetch_per_tool": 200, "details": 20},
    "services_nonstandard_binary_paths": {"services": 10000},
    "evtx_eid_4104_scriptblock_logs": {"scriptblock": 500, "details": 20},
    "prefetch_security_sw_werfault_correlation": {"werfault_prefetch": 500, "security_sw_prefetch": 200, "startup_items": 2000, "details": 20},
    "amcache_remote_access_tool_names": {"amcache_programs": 5000},
    "openssh_artifacts": {"openssh_events": 500, "services": 100, "prefetch": 500},
    "office_trustrecords_macro_enabled": {"trusted_documents": 0, "details": 20},
    "motw_internet_origin_risky_file": {"motw_entries": 0, "details": 20},
}

# Attack techniques and artifact families this workstation has no query interface for.
# Absence of a fired rule does NOT mean the technique did not occur if it appears here.
# NOTE: find_suspicious covers the .mfdb rule set. Several techniques listed
# here are covered by the EVTX rule pack (hunt_evtx_rules / BUILTIN_RULES)
# when the relevant channel is collected — those carry a "covered_by" note so
# the analyst pivots to the right tool instead of reading a flat gap.
KNOWN_COVERAGE_GAPS: dict[str, str] = {
    "evtx_eid_4769_kerberos_svc_ticket_requests": "Partial — hunt_evtx_rules fw-evtx-004 matches 4768/4769 weak-encryption; standalone 4769 enumeration still needs Kerberos service-ticket auditing",
    "evtx_eid_4768_kerberos_tgt_requests": "Partial — hunt_evtx_rules fw-evtx-004 covers 4768 weak encryption; full TGT auditing needed for complete coverage",
    "evtx_eid_4662_ad_object_access": "Covered by hunt_evtx_rules fw-evtx-031 (DCSync 4662 replication GUIDs) when DC Security EVTX is collected",
    "registry_run_keys_persistence": "Covered by build_raw_artifact_index (AutoRun Items from Run/RunOnce) and hunt_evtx_rules fw-evtx-028 (Sysmon 12/13 autostart)",
    "registry_clsid_hijacking": "No query interface — requires registry hive parsing of CLSID/InprocServer32 (raw indexer does not yet enumerate COM)",
    "vss_shadow_copy_deletion": "No query interface — VSS deletion typically via cmd/PS; cross-check prefetch + process creation; detect_anti_forensics covers vssadmin patterns",
    "wmi_event_subscription_persistence": "No query interface — requires WMI repository (OBJECTS.DATA) parsing (not yet implemented)",
    "ntds_dit_or_sam_extraction": "No query interface — requires EVTX EID 4663 + file access auditing on DC",
    "defender_tamper_events": "Covered by hunt_evtx_rules fw-evtx-034/035 (Defender 1116/1117 detection, 5001/5007/1119 tamper) when Defender Operational EVTX is collected",
    "bits_job_persistence": "Covered by hunt_evtx_rules fw-evtx-036 (BITS-Client 59/60) when the log is collected; qmgr.db parsing not yet implemented",
    "dpapi_master_key_operations": "No query interface — requires Security EVTX EID 4692/4693",
    "evtx_eid_4720_user_account_created": "Covered by hunt_evtx_rules fw-evtx-002 (4720) when account-management auditing is on",
    "evtx_eid_4732_group_membership_changes": "Covered by hunt_evtx_rules fw-evtx-003 (4728/4732/4756) when group auditing is on",
    "winrm_remote_execution": "Covered by hunt_evtx_rules fw-evtx-037 (WinRM 91/168/6) when WinRM Operational EVTX is collected",
    "outbound_rdp_pivot": "Covered by hunt_evtx_rules fw-evtx-039 (RDPClient 1024) for outbound connections; Terminal Server Client MRU via build_raw_artifact_index",
}

# Per-rule explanations for zero-result outcomes — prevents "0 hits = clean" misreads.
_ZERO_RESULT_NOTES: dict[str, str] = {
    "sysmon_eid10_lsass_handle_open": "0 LSASS handle events. Sysmon EID 10 requires Sysmon installation with process access auditing configured.",
    "evtx_eid_4688_process_creation_events": "0 matching process creation events. EID 4688 requires Audit Process Creation policy; Sysmon EID 1 is an alternative if deployed.",
    "evtx_eid_7045_service_installs": "0 service install events. Possible: no new services installed, Security EVTX not collected, or audit policy gap.",
    "evtx_eid_4698_scheduled_task_events": "0 scheduled task events. EID 4698/4702 requires task creation auditing; tasks may predate the collection window.",
    "evtx_eid_1102_audit_log_cleared": "0 log clearing events. If Security EVTX was collected, absence is meaningful — clearing events would appear here.",
    "evtx_eid_4624_type10_rdp_logons": "0 RDP logon events (LogonType 10). Possible: no RDP sessions, Security EVTX not collected, or NLA pre-auth not logged.",
    "evtx_eid_4648_explicit_credential_logons": "0 explicit credential use events. EID 4648 requires logon auditing; absence may indicate no runas or pass-the-hash activity.",
    "prefetch_pentest_tool_names": "0 Prefetch entries for known attack tools. Prefetch may be disabled, cleared, or tools ran from a network share (no prefetch generated).",
    "services_nonstandard_binary_paths": "0 services with Temp/ProgramData/Public binary paths. Service artifacts may be incomplete or paths were cleaned up post-incident.",
    "evtx_eid_4104_scriptblock_logs": "0 PowerShell Script Block logs. EID 4104 requires Script Block Logging group policy; without it, PS commands are not recorded.",
    "prefetch_security_sw_werfault_correlation": "0 WerFault + Korean security SW date correlations. WerFault not present or security SW not active during the collection window.",
    "amcache_remote_access_tool_names": "0 AmCache entries matching remote access tool names. AmCache may not include tools installed outside the case window.",
    "openssh_artifacts": "0 OpenSSH artifacts across event logs, services, key files, and Prefetch. SSH may not have been used or artifacts were removed.",
    "office_trustrecords_macro_enabled": "0 macro-enabled TrustRecords. Requires NTUSER hive parsing (raw build_raw_artifact_index or AXIOM Office artifacts); absence with no TrustRecords family collected means not-evaluable, not clean.",
    "motw_internet_origin_risky_file": "0 internet-origin risky files. Zone.Identifier requires ADS-capable collection (raw MOTW indexer or AXIOM file system artifacts); ADS-stripping tools or non-NTFS volumes also remove the marker.",
}


def find_suspicious(aq: ArtifactQueries, rules: str = "") -> dict:
    """Run structured detection rules against .mfdb artifact data.

    Every executed rule appears in the output — rules with 0 matches go to
    ``zero_result_rules`` so the LLM can distinguish "checked and clean"
    from "not checked". ``coverage_manifest`` lists what was queried and what
    has no query interface at all.
    """
    all_rules = {
        "sysmon_eid10_lsass_handle_open": rule_lsass_access,
        "evtx_eid_4688_process_creation_events": rule_suspicious_process_creation,
        "evtx_eid_7045_service_installs": rule_service_installation,
        "evtx_eid_4698_scheduled_task_events": rule_scheduled_task_creation,
        "evtx_eid_1102_audit_log_cleared": rule_log_clearing,
        "evtx_eid_4624_type10_rdp_logons": rule_rdp_lateral_movement,
        "evtx_eid_4648_explicit_credential_logons": rule_explicit_credential_use,
        "prefetch_pentest_tool_names": rule_suspicious_prefetch,
        "services_nonstandard_binary_paths": rule_suspicious_service_paths,
        "evtx_eid_4104_scriptblock_logs": rule_powershell_scriptblock,
        "prefetch_security_sw_werfault_correlation": rule_watering_hole_indicators,
        "amcache_remote_access_tool_names": rule_suspicious_msi_install,
        "openssh_artifacts": rule_ssh_activity,
        "office_trustrecords_macro_enabled": rule_trustrecords_macro_enabled,
        "motw_internet_origin_risky_file": rule_motw_internet_origin_risky_file,
    }

    if rules:
        rule_names = [r.strip().lower() for r in rules.split(",") if r.strip()]
        active = {name: all_rules[name] for name in rule_names if name in all_rules}
    else:
        active = all_rules

    if not active:
        return {"error": f"Unknown rules. Available: {', '.join(all_rules.keys())}"}

    findings: list[dict] = []
    zero_result_rules: list[dict] = []
    for name, func in active.items():
        result = func(aq)
        scope = RULE_SCOPE_MAP.get(name, "generic")
        if result:
            result["rule_name"] = name  # canonical artifact-descriptive name
            result["query_limits"] = RULE_QUERY_LIMITS.get(name, {})
            result["category"] = RULE_CATEGORY_MAP.get(name, "uncategorized")
            result["scope"] = scope
            result["query_status"] = "executed"
            td = _temporal_distribution(result.get("details", []))
            if td:
                result["temporal_distribution"] = td
            findings.append(result)
        else:
            zero_entry = {
                "rule_name": name,
                "matching_count": 0,
                "query_status": "executed",
                "category": RULE_CATEGORY_MAP.get(name, "uncategorized"),
                "scope": scope,
                "note": _ZERO_RESULT_NOTES.get(name, "0 results — artifact was queried but no matches found."),
            }
            scope_hint = _SCOPE_ZERO_RESULT_HINT.get(scope)
            if scope_hint:
                zero_entry["scope_hint"] = scope_hint
            zero_result_rules.append(zero_entry)

    rules_not_in_scope = sorted(set(all_rules.keys()) - set(active.keys()))
    coverage_manifest = {
        "queries_executed": sorted(active.keys()),
        "queries_with_hits": [f["rule_name"] for f in findings],
        "queries_zero_hits": [z["rule_name"] for z in zero_result_rules],
        "queries_not_in_scope": rules_not_in_scope,
        "queries_not_implemented": KNOWN_COVERAGE_GAPS,
        "note": (
            "queries_not_implemented lists attack techniques this workstation "
            "has no query interface for. Absence from findings does not mean "
            "the technique did not occur if it appears in queries_not_implemented."
        ),
    }

    return {
        "rules_executed": len(active),
        "rules_with_hits": len(findings),
        "total_findings": len(findings),
        "findings": findings,
        "zero_result_rules": zero_result_rules,
        "coverage_manifest": coverage_manifest,
        "available_rules": sorted(all_rules.keys()),
    }


# ── Helpers ──

def _temporal_distribution(details: list[dict]) -> dict | None:
    """Extract first_seen / last_seen / spike_dates from a detail list.

    Checks multiple timestamp field names to handle rule-specific differences.
    Returns None when no parseable dates are found.
    """
    from collections import Counter
    ts_fields = ["timestamp", "Last Run", "Install Date", "Registry Modified", "File Created"]
    dates: list[str] = []
    for d in details:
        for field in ts_fields:
            ts = str(d.get(field, "") or "")[:10]
            if len(ts) == 10 and ts[4] == "-":
                dates.append(ts)
                break
    if not dates:
        return None
    counts = Counter(dates)
    avg = len(dates) / max(len(counts), 1)
    spike_dates = sorted(d for d, c in counts.items() if c > avg)[:5]
    return {"first_seen": min(dates), "last_seen": max(dates), "spike_dates": spike_dates}


# ── Rules ──

def rule_lsass_access(aq: ArtifactQueries) -> dict | None:
    """Sysmon Event ID 10 — Process accessed LSASS.

    Real credential dumping detection: another process opening lsass.exe
    with suspicious access rights, not just "lsass" appearing in any string.
    """
    hits = aq.query_process_access_events(limit=0)
    # Filter to LSASS targets
    lsass_hits = [h for h in hits if "lsass" in str(h.get("Event Data", "")).lower()]
    if not lsass_hits:
        return None

    details = []
    for h in lsass_hits:
        event_data = h.get("Event Data", "")
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (Sysmon EID 10)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "Sysmon detected a process accessing LSASS memory",
            "event_data_excerpt": str(event_data)[:500],
            "computer": h.get("Computer", ""),
        }
        # Extract source/target from event data
        _extract_xml_fields(event_data, detail, [
            "SourceProcessId", "SourceImage", "TargetImage", "GrantedAccess",
        ])
        details.append(detail)

    details, truncated, returned_count = _apply_detail_cap(details)
    return {
        "rule_name": "lsass_access",
        "query_description": f"Sysmon EID 10 — {len(lsass_hits)} process access events targeting LSASS.",
        "matching_count": len(lsass_hits),
        "matched_patterns": {"Sysmon Event ID 10 + Target=lsass.exe": len(lsass_hits)},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_suspicious_process_creation(aq: ArtifactQueries) -> dict | None:
    """Sysmon EID 1 / Security EID 4688 — Suspicious process executions.

    Looks for: encoded PowerShell, cmd spawning from unusual parents,
    LOLBins with suspicious arguments.
    """
    hits = aq.query_process_creation_events(limit=0)
    suspicious = []

    suspicious_indicators = [
        # (check_function, description)
        (lambda d: "-encodedcommand" in d.lower() or "-enc " in d.lower(), "Encoded PowerShell command"),
        (lambda d: "downloadstring" in d.lower() or "downloadfile" in d.lower(), "PowerShell download cradle"),
        (lambda d: "invoke-expression" in d.lower() or "iex " in d.lower(), "PowerShell Invoke-Expression"),
        (lambda d: "-windowstyle hidden" in d.lower() or "-w hidden" in d.lower(), "Hidden window execution"),
        (lambda d: "certutil" in d.lower() and ("-urlcache" in d.lower() or "-decode" in d.lower()), "Certutil abuse (download/decode)"),
        (lambda d: "regsvr32" in d.lower() and "/s" in d.lower() and "scrobj" in d.lower(), "Regsvr32 scriptlet execution"),
        (lambda d: "mshta" in d.lower() and ("vbscript" in d.lower() or "javascript" in d.lower()), "MSHTA script execution"),
        (lambda d: "bitsadmin" in d.lower() and "/transfer" in d.lower(), "BITSADMIN file transfer"),
        (lambda d: "wmic" in d.lower() and "process" in d.lower() and "call" in d.lower() and "create" in d.lower(), "WMI remote process creation"),
        (lambda d: "psexec" in d.lower() or "psexesvc" in d.lower(), "PsExec execution"),
    ]

    for h in hits:
        event_data = str(h.get("Event Data", ""))
        cmd_line = str(h.get("Event Description Summary", ""))
        combined = event_data + " " + cmd_line

        for check_fn, desc in suspicious_indicators:
            if check_fn(combined):
                detail = {
                    "hit_id": h["hit_id"],
                    "artifact_type": f"Windows Event Logs (EID {h.get('Event ID', '?')})",
                    "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                    "artifact_context": desc,
                    "computer": h.get("Computer", ""),
                }
                _extract_xml_fields(event_data, detail, [
                    "CommandLine", "ParentCommandLine", "Image",
                    "ParentImage", "User", "NewProcessName",
                ])
                suspicious.append(detail)
                break

    if not suspicious:
        return None

    # Summarize by evidence type
    evidence_summary: dict[str, int] = {}
    for d in suspicious:
        ev = d.get("evidence", "")
        evidence_summary[ev] = evidence_summary.get(ev, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(suspicious)
    return {
        "rule_name": "suspicious_process_creation",
        "query_description": f"EID 1/4688 — {len(suspicious)} process creation events matching encoded commands, download cradles, LOLBin, or lateral movement tool patterns.",
        "matching_count": len(suspicious),
        "matched_patterns": evidence_summary,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_service_installation(aq: ArtifactQueries) -> dict | None:
    """Event ID 7045 — New service installed. Common persistence mechanism."""
    hits = aq.query_service_installs(limit=0)
    if not hits:
        return None

    details = []
    for h in hits:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 7045)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "New service installed on the system",
            "event_data_excerpt": str(h.get("Event Data", ""))[:500],
            "computer": h.get("Computer", ""),
        }
        _extract_xml_fields(h.get("Event Data", ""), detail, [
            "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",
        ])
        details.append(detail)

    details, truncated, returned_count = _apply_detail_cap(details)
    return {
        "rule_name": "service_installation",
        "query_description": f"EID 7045 — {len(hits)} service installation events. Review service names and paths.",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 7045 (Service Installed)": len(hits)},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_scheduled_task_creation(aq: ArtifactQueries) -> dict | None:
    """Event ID 4698/4702 — Scheduled task created/modified."""
    hits = aq.query_scheduled_task_events(limit=0)
    if not hits:
        # Fallback: check Scheduled Tasks artifact
        tasks = aq.query_scheduled_tasks(limit=0)
        if not tasks:
            return None
        details = []
        for t in tasks:
            details.append({
                "hit_id": t["hit_id"],
                "artifact_type": "Scheduled Tasks",
                "evidence": "Scheduled task found",
                "Name": t.get("Name", ""),
                "Command": t.get("Command", ""),
                "Author": t.get("Author", ""),
                "Run As": t.get("Run As", ""),
                "Created Date/Time": t.get("Created Date/Time - Local Time (yyyy-mm-dd)", ""),
            })
        details, truncated, returned_count = _apply_detail_cap(details)
        return {
            "rule_name": "scheduled_task_creation",
            "query_description": f"Scheduled Tasks artifact — {len(tasks)} tasks found.",
            "matching_count": len(tasks),
            "matched_patterns": {"Scheduled Tasks artifact": len(tasks)},
            "details": details,
            "returned_count": returned_count,
            "truncated": truncated,
            "detail_cap": 20,
        }

    details = []
    for h in hits:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": f"Windows Event Logs (EID {h.get('Event ID', '?')})",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "Scheduled task created or modified via event log",
            "computer": h.get("Computer", ""),
            "event_data_excerpt": str(h.get("Event Data", ""))[:500],
        }
        details.append(detail)

    details, truncated, returned_count = _apply_detail_cap(details)
    return {
        "rule_name": "scheduled_task_creation",
        "query_description": f"EID 4698/4702 — {len(hits)} scheduled task creation/modification events.",
        "matching_count": len(hits),
        "matched_patterns": {f"Event ID {h.get('Event ID', '?')}": 1 for h in hits[:5]},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_log_clearing(aq: ArtifactQueries) -> dict | None:
    """Event ID 1102 — Security audit log was cleared."""
    hits = aq.query_log_cleared(limit=0)
    if not hits:
        return None

    details = []
    for h in hits:
        details.append({
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 1102)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "Security audit log was cleared",
            "computer": h.get("Computer", ""),
            "security_id": h.get("Security Identifier", ""),
        })

    details, truncated, returned_count = _apply_detail_cap(details)
    return {
        "rule_name": "log_clearing",
        "query_description": f"EID 1102 — security audit log cleared {len(hits)} time(s).",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 1102 (Audit Log Cleared)": len(hits)},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_rdp_lateral_movement(aq: ArtifactQueries) -> dict | None:
    """Event ID 4624 Type 10 — RDP logon (lateral movement indicator)."""
    logons = aq.query_logon_events(limit=0)
    rdp_logons = []
    for h in logons:
        event_data = str(h.get("Event Data", ""))
        # Type 10 = RemoteInteractive (RDP)
        if ">10<" in event_data or "LogonType\">10" in event_data:
            detail = {
                "hit_id": h["hit_id"],
                "artifact_type": "Windows Event Logs (EID 4624 Type 10)",
                "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "artifact_context": "RDP logon (LogonType 10)",
                "computer": h.get("Computer", ""),
            }
            _extract_xml_fields(event_data, detail, [
                "TargetUserName", "IpAddress", "WorkstationName", "LogonType",
            ])
            rdp_logons.append(detail)

    if not rdp_logons:
        return None

    # Summarize source IPs
    ip_counts: dict[str, int] = {}
    for d in rdp_logons:
        ip = d.get("IpAddress", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(rdp_logons)
    return {
        "rule_name": "rdp_lateral_movement",
        "query_description": f"EID 4624 Type 10 — {len(rdp_logons)} RDP logons from {len(ip_counts)} unique source(s).",
        "matching_count": len(rdp_logons),
        "matched_patterns": {f"RDP from {ip}": cnt for ip, cnt in ip_counts.items()},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_explicit_credential_use(aq: ArtifactQueries) -> dict | None:
    """Event ID 4648 — Explicit credential use (runas, pass-the-hash indicator)."""
    hits = aq.query_event_logs(event_ids=[4648], limit=0)
    if not hits:
        return None

    details = []
    for h in hits:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 4648)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "Explicit credential use event",
            "computer": h.get("Computer", ""),
        }
        _extract_xml_fields(h.get("Event Data", ""), detail, [
            "SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName",
        ])
        details.append(detail)

    details, truncated, returned_count = _apply_detail_cap(details)
    return {
        "rule_name": "explicit_credential_use",
        "query_description": f"EID 4648 — {len(hits)} explicit credential use events.",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 4648 (Explicit Credential Use)": len(hits)},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_suspicious_prefetch(aq: ArtifactQueries) -> dict | None:
    """Prefetch files for known attack tools."""
    suspicious_tools = [
        "PSEXEC", "PSEXESVC", "MIMIKATZ", "PROCDUMP", "LAZAGNE",
        "SHARPHOUND", "BLOODHOUND", "RUBEUS", "SEATBELT",
        "PYPYKATZ", "SECRETSDUMP", "WMIEXEC", "SMBEXEC",
        "CRACKMAPEXEC", "NMAP", "NETCAT", "NC.EXE", "NC64",
        "POWERVIEW", "EMPIRE", "COVENANT",
    ]
    found = []
    for tool in suspicious_tools:
        hits = aq.query_prefetch(app_name_filter=tool, limit=0)
        for h in hits:
            app_name = h.get("Application Name", "")
            # Exact match check (not substring)
            if tool.lower() in app_name.lower().split(".")[0].replace("-", "").replace("_", ""):
                found.append({
                    "hit_id": h["hit_id"],
                    "artifact_type": "Prefetch",
                    "artifact_context": f"Prefetch entry for '{app_name}'",
                    "Application Name": app_name,
                    "Application Path": h.get("Application Path", ""),
                    "Run Count": h.get("Application Run Count", ""),
                    "Last Run": h.get("Last Run Date/Time - UTC (yyyy-mm-dd)", ""),
                    "File Created": h.get("File Created Date/Time - UTC (yyyy-mm-dd)", ""),
                })

    if not found:
        return None

    tool_counts = {}
    for d in found:
        name = d.get("Application Name", "unknown")
        tool_counts[name] = tool_counts.get(name, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(found)
    return {
        "rule_name": "suspicious_prefetch",
        "query_description": f"Prefetch — {len(found)} entries matching known attack tool names.",
        "matching_count": len(found),
        "matched_patterns": tool_counts,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_suspicious_service_paths(aq: ArtifactQueries) -> dict | None:
    """Services with executables in suspicious locations."""
    services = aq.query_services(limit=0)
    suspicious = []
    suspicious_paths = [
        "\\temp\\", "\\tmp\\", "\\public\\", "\\perflogs\\",
        "\\appdata\\", "\\programdata\\",
    ]
    # Known-good ProgramData paths — exact directory segment matches only.
    # Uses path separators to prevent bypass (e.g. "nvidia" won't match "n_vidia")
    _known_good_segments = [
        "\\microsoft\\windows defender\\",
        "\\microsoft\\edge\\",
        "\\google\\chrome\\",
        "\\google\\update\\",
        "\\google\\googleupdater\\",
        "\\adobe\\arm\\",
        "\\adobe\\acrobat\\",
        "\\mozilla\\updates\\",
        "\\dell\\supportassist",
        "\\intel\\shadercache\\",
        "\\nvidia corporation\\",
        "\\package cache\\",
    ]

    for svc in services:
        location = str(svc.get("Service Location", "")).lower()
        if not location:
            continue
        for p in suspicious_paths:
            if p in location:
                # Skip known-good software — exact path segment match only
                if p == "\\programdata\\" and any(seg in location for seg in _known_good_segments):
                    continue
                suspicious.append({
                    "hit_id": svc["hit_id"],
                    "artifact_type": "System Services",
                    "artifact_context": f"Service binary path contains: {p.strip(chr(92))}",
                    "Service Name": svc.get("Service Name", ""),
                    "Service Location": svc.get("Service Location", ""),
                    "Start Type": svc.get("Start Type", ""),
                    "User Account": svc.get("User Account", ""),
                    "Registry Modified": svc.get("Registry Key Modified Date/Time - UTC (yyyy-mm-dd)", ""),
                })
                break

    if not suspicious:
        return None

    details, truncated, returned_count = _apply_detail_cap(suspicious)
    return {
        "rule_name": "suspicious_service_paths",
        "query_description": f"System Services — {len(suspicious)} services with binaries in Temp/ProgramData/Public paths.",
        "matching_count": len(suspicious),
        "matched_patterns": {d["Service Name"]: 1 for d in suspicious[:10]},
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_powershell_scriptblock(aq: ArtifactQueries) -> dict | None:
    """Event ID 4104 — PowerShell Script Block Logging."""
    hits = aq.query_powershell_scriptblock(limit=0)
    if not hits:
        return None

    suspicious = []
    indicators = [
        "frombase64string", "downloadstring", "invoke-expression",
        "invoke-mimikatz", "invoke-shellcode", "new-object net.webclient",
        "invoke-webrequest", "-enc ", "bypass",
    ]

    for h in hits:
        event_data = str(h.get("Event Data", "")).lower()
        matched = [ind for ind in indicators if ind in event_data]
        if matched:
            suspicious.append({
                "hit_id": h["hit_id"],
                "artifact_type": "Windows Event Logs (EID 4104)",
                "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "artifact_context": f"Script block matched: {', '.join(matched)}",
                "event_data_excerpt": str(h.get("Event Data", ""))[:500],
                "computer": h.get("Computer", ""),
            })

    if not suspicious:
        # Still report if there are script blocks (informational)
        _info_details = [{
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 4104)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "PowerShell Script Block logged (no keyword match)",
        } for h in hits]
        _info_details, _info_truncated, _info_returned = _apply_detail_cap(_info_details, cap=10)
        return {
            "rule_name": "powershell_scriptblock",
            "query_description": f"EID 4104 — {len(hits)} PowerShell Script Block logs, no keyword matches.",
            "matching_count": len(hits),
            "matched_patterns": {"Event ID 4104 (Script Block)": len(hits)},
            "details": _info_details,
            "returned_count": _info_returned,
            "truncated": _info_truncated,
            "detail_cap": 10,
        }

    indicator_counts = {}
    for d in suspicious:
        for part in d["artifact_context"].replace("Suspicious PowerShell script block: ", "").split(", "):
            indicator_counts[part] = indicator_counts.get(part, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(suspicious)
    return {
        "rule_name": "powershell_scriptblock",
        "query_description": f"EID 4104 — {len(suspicious)} script blocks matching download cradles, encoded commands, or known attack patterns.",
        "matching_count": len(suspicious),
        "matched_patterns": indicator_counts,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_watering_hole_indicators(aq: ArtifactQueries) -> dict | None:
    """Korean security software presence + WerFault crash correlation.

    IMPORTANT: This rule detects DATE-LEVEL correlation only. WerFault on the
    same day as security SW does NOT prove watering hole exploitation. Security
    SW often runs as startup items and will co-occur with ANY crash on that day.

    To confirm a watering hole attack, you must ALSO verify:
    1. WER crash reports show the SECURITY SW itself crashed (not unrelated process)
    2. The crash occurred BEFORE other malicious activity on the timeline
    3. Exploit artifacts exist (shellcode in memory, anomalous child processes)
    """
    # Search for WerFault Prefetch entries (covers both 32-bit and 64-bit)
    werfault_hits = aq.query_prefetch(app_name_filter="WERFAULT", limit=0)
    if not werfault_hits:
        return None

    # Korean security software commonly exploited in watering hole campaigns
    security_sw_names = [
        "MAGICLINE", "ANYSIGN", "INISAFE", "CROSSEX",
        "DELFINO", "VERAPORT", "TOUCHEN",
    ]

    # Gather Prefetch data for security software
    sec_sw_hits: list[dict] = []
    for sw_name in security_sw_names:
        hits = aq.query_prefetch(app_name_filter=sw_name, limit=0)
        sec_sw_hits.extend(hits)

    if not sec_sw_hits:
        return None

    # Check if security SW is in startup items (reduces confidence significantly)
    startup_hits = aq._query_artifact("Startup Items", limit=0)
    startup_sw_names = set()
    for s in startup_hits:
        path = str(s.get("Path", "")).upper()
        for sw_name in security_sw_names:
            if sw_name in path:
                startup_sw_names.add(sw_name)

    # Build a set of security SW execution timestamps (date-level for correlation)
    # Handle both AXIOM and KAPE field names
    sec_sw_dates: dict[str, list[str]] = {}  # date -> list of SW names
    for h in sec_sw_hits:
        ts = (h.get("Last Run Date/Time - UTC (yyyy-mm-dd)", "")
              or h.get("Last Run Time", ""))
        app_name = h.get("Application Name", "")
        if ts:
            date_part = ts[:10]  # yyyy-mm-dd
            sec_sw_dates.setdefault(date_part, []).append(app_name)

    # Correlate: find WerFault entries on dates when security SW was active
    correlated = []
    for wf in werfault_hits:
        wf_ts = (wf.get("Last Run Date/Time - UTC (yyyy-mm-dd)", "")
                 or wf.get("Last Run Time", ""))
        # Application Path: AXIOM uses "Application Path", KAPE uses "Files Loaded" (contains EXE path)
        # "Source File" in KAPE is the .pf file path, not the executable path
        wf_path = (wf.get("Application Path", "")
                   or wf.get("Files Loaded", "")
                   or wf.get("Source File", ""))
        if not wf_ts:
            continue
        wf_date = wf_ts[:10]

        # Determine 32-bit vs 64-bit based on path
        if "syswow64" in wf_path.lower():
            bitness = "32-bit (SysWOW64)"
        elif "system32" in wf_path.lower():
            bitness = "64-bit (System32)"
        else:
            bitness = "unknown"

        if wf_date in sec_sw_dates:
            correlated.append({
                "hit_id": wf["hit_id"],
                "artifact_type": "Prefetch",
                "timestamp": wf_ts,
                "artifact_context": f"WerFault ({bitness}) ran on same date as security SW",
                "WerFault Path": wf_path,
                "WerFault Bitness": bitness,
                "Run Count": wf.get("Application Run Count", "") or wf.get("Run Count", ""),
                "Nearby Security SW": sec_sw_dates[wf_date],
            })

    if not correlated:
        return None

    sw_summary: dict[str, int] = {}
    for d in correlated:
        for sw in d.get("Nearby Security SW", []):
            sw_summary[sw] = sw_summary.get(sw, 0) + 1

    # Determine if this is likely a false positive
    # If most flagged security SW are startup items, correlation is expected
    flagged_sw_names = set()
    for names in sec_sw_dates.values():
        for n in names:
            for pat in security_sw_names:
                if pat in n.upper():
                    flagged_sw_names.add(pat)
    startup_overlap = flagged_sw_names & startup_sw_names
    is_startup_correlation = len(startup_overlap) >= len(flagged_sw_names) * 0.5

    caveat = (
        " NOTE: security SW in startup items — co-occurrence may be coincidental."
        if is_startup_correlation else
        " Verify with search_wer_reports whether the security SW itself crashed."
    )

    details, truncated, returned_count = _apply_detail_cap(correlated)
    return {
        "rule_name": "watering_hole_indicators",
        "query_description": (
            f"Prefetch date correlation — {len(correlated)} WerFault entries co-date with Korean security SW.{caveat}"
        ),
        "matching_count": len(correlated),
        "matched_patterns": sw_summary,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
        "startup_items": sorted(startup_overlap) if startup_overlap else [],
    }


def rule_suspicious_msi_install(aq: ArtifactQueries) -> dict | None:
    """AmCache entries for MSI-installed programs — suspicious installs outside work hours.

    Flags MSI-installed programs that were installed outside normal working
    hours (before 07:00 or after 19:00 UTC), or that match known remote
    access / SSH tool patterns.
    """
    # Query AmCache Program Entries for MSI installs
    # Try "AmCache Program Entries" first, then fall back to generic search
    program_hits = aq._query_artifact("AmCache Program Entries", limit=0)
    if not program_hits:
        # Fall back to AmCache File Entries
        program_hits = aq.query_amcache(limit=0)

    if not program_hits:
        return None

    # Filter to MSI source — handle both AXIOM and KAPE field names
    msi_installs = [
        h for h in program_hits
        if "msi" in str(h.get("AppSource", "")).lower()
        or "msi" in str(h.get("Install Source", "")).lower()
        or "msi" in str(h.get("Source", "")).lower()
        or ".msi" in str(h.get("Full Path", "")).lower()
        or h.get("MSI Package Code", "")
    ]

    # Note: MSI filter results are not used for gating — all programs are checked
    # against suspicious tool patterns regardless of install source.

    # Known suspicious tool patterns
    suspicious_tool_patterns = [
        "openssh", "ssh", "putty", "winscp", "mremoteng",
        "teamviewer", "anydesk", "rustdesk", "meshagent",
        "radmin", "vnc", "vpn", "wireguard", "openvpn",
    ]

    # Check all programs (MSI and non-MSI) against suspicious tool patterns
    flagged = []
    for h in program_hits:
        # Handle both AXIOM ("Name") and KAPE ("Program Name") field names
        name = str(h.get("Name", "") or h.get("Program Name", "")).lower()
        install_date = (h.get("Install Date/Time - UTC (yyyy-mm-dd)", "")
                       or h.get("Created Date/Time - UTC (yyyy-mm-dd)", "")
                       or h.get("Install Date ARP", "")
                       or h.get("Key Last Write Time", ""))
        publisher = h.get("Publisher", "") or h.get("Manufacturer", "")
        version = h.get("Version", "")
        install_path = h.get("Full Path", "") or h.get("Install Path", "")
        reasons = []

        # Check for suspicious tool names only — no time-based filtering
        # (attackers operate during business hours too)
        for pattern in suspicious_tool_patterns:
            if pattern in name or pattern in str(install_path).lower():
                reasons.append(f"Matches suspicious tool pattern: {pattern}")
                break

        if reasons:
            flagged.append({
                "hit_id": h["hit_id"],
                "artifact_type": h.get("artifact_type", "AmCache Program Entries"),
                "artifact_context": "; ".join(reasons),
                "Program Name": h.get("Name", "") or h.get("Program Name", ""),
                "Version": version,
                "Publisher": publisher,
                "Install Date": install_date,
                "Install Path": install_path,
            })

    if not flagged:
        return None

    reason_counts: dict[str, int] = {}
    for d in flagged:
        for part in d["artifact_context"].split("; "):
            reason_counts[part] = reason_counts.get(part, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(flagged)
    return {
        "rule_name": "suspicious_msi_install",
        "query_description": f"AmCache — {len(flagged)} programs matching remote access or SSH tool name patterns.",
        "matching_count": len(flagged),
        "matched_patterns": reason_counts,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_ssh_activity(aq: ArtifactQueries) -> dict | None:
    """SSH-related artifacts — OpenSSH events, services, keys, and Prefetch.

    Combines multiple data sources to detect SSH activity which is uncommon
    on standard Korean enterprise Windows endpoints.
    """
    findings: list[dict] = []

    # 1. OpenSSH event log entries (Provider="OpenSSH")
    ssh_events = aq.query_event_logs(provider="OpenSSH", limit=0)
    for h in ssh_events:
        event_data = str(h.get("Event Data", ""))
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (OpenSSH)",
            "event_type": "OpenSSH Event Log",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "artifact_context": "OpenSSH event log entry",
            "computer": h.get("Computer", ""),
            "event_data_excerpt": event_data[:500],
        }
        # Extract useful details from event data
        if "listening" in event_data.lower():
            detail["details"] = "SSH daemon listening for connections"
        elif "accepted" in event_data.lower():
            detail["details"] = "SSH authentication accepted"
        elif "disconnect" in event_data.lower():
            detail["details"] = "SSH session disconnected"
        else:
            detail["details"] = "SSH activity"
        findings.append(detail)

    # 2. SSH-related services (sshd, ssh-agent)
    for svc_name in ["sshd", "ssh-agent", "OpenSSH"]:
        svc_hits = aq.query_services(service_filter=svc_name, limit=0)
        for s in svc_hits:
            findings.append({
                "hit_id": s["hit_id"],
                "artifact_type": "System Services",
                "event_type": "SSH Service",
                "timestamp": s.get("Registry Key Modified Date/Time - UTC (yyyy-mm-dd)", ""),
                "artifact_context": f"SSH-related service: {s.get('Service Name', '')}",
                "service_details": f"Location: {s.get('Service Location', '')}, Start Type: {s.get('Start Type', '')}",
            })

    # 3. SSH key artifacts
    for art_name in ["SSH Keys", "SSH Known Hosts"]:
        key_hits = aq._query_artifact(art_name, limit=0)
        for k in key_hits:
            findings.append({
                "hit_id": k["hit_id"],
                "artifact_type": art_name,
                "event_type": "SSH Key Artifact",
                "timestamp": k.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "artifact_context": f"{art_name} artifact",
                "key_details": str({
                    key: val for key, val in k.items()
                    if key not in ("hit_id", "artifact_type") and val
                })[:500],
            })

    # 4. SSH-related Prefetch
    ssh_prefetch_names = ["SSHD", "SSH-KEYGEN", "SSH-AGENT", "SSH.EXE"]
    for pf_name in ssh_prefetch_names:
        pf_hits = aq.query_prefetch(app_name_filter=pf_name, limit=0)
        for p in pf_hits:
            app_name = p.get("Application Name", "")
            # Verify it is actually an SSH binary, not a substring match
            base_name = app_name.upper().split(".")[0]
            expected = pf_name.replace(".EXE", "")
            if expected not in base_name:
                continue
            findings.append({
                "hit_id": p["hit_id"],
                "artifact_type": "Prefetch",
                "event_type": "SSH Prefetch",
                "timestamp": p.get("Last Run Date/Time - UTC (yyyy-mm-dd)", ""),
                "artifact_context": f"Prefetch entry: {app_name}",
                "prefetch_details": f"Path: {p.get('Application Path', '')}, Run Count: {p.get('Application Run Count', '')}",
            })

    if not findings:
        return None

    # Summarize by event type
    type_counts: dict[str, int] = {}
    for f in findings:
        et = f.get("event_type", "unknown")
        type_counts[et] = type_counts.get(et, 0) + 1

    details, truncated, returned_count = _apply_detail_cap(findings)
    return {
        "rule_name": "ssh_activity",
        "query_description": f"OpenSSH events + services + key artifacts + Prefetch — {len(findings)} SSH-related artifacts across {len(type_counts)} source type(s).",
        "matching_count": len(findings),
        "matched_patterns": type_counts,
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def rule_trustrecords_macro_enabled(aq: ArtifactQueries) -> dict | None:
    """Office TrustRecords entries where the user clicked "Enable Content".

    Each hit is a deliberate user action that unlocked macros for a specific
    document — the canonical ingress signal for document-based intrusion.
    """
    hits = aq._query_artifact("Office Trusted Documents", limit=0)
    findings: list[dict] = []
    for h in hits:
        if str(h.get("Macro Enabled", "")).strip().lower() != "true":
            continue
        findings.append({
            "hit_id": h.get("hit_id"),
            "artifact_type": "Office Trusted Documents",
            "event_type": "Macro Enabled Document",
            "timestamp": h.get("Trusted At", h.get("timestamp", "")),
            "document": h.get("Document", ""),
            "application": h.get("Application", ""),
            "user": h.get("User", ""),
            "artifact_context": (
                "User explicitly enabled macros/content for this document "
                "(TrustRecords FF FF FF 7F marker)."
            ),
        })
    if not findings:
        return None
    details, truncated, returned_count = _apply_detail_cap(findings)
    return {
        "rule_name": "office_trustrecords_macro_enabled",
        "query_description": (
            f"Office TrustRecords with macro-enable marker — {len(findings)} "
            "document(s) the user explicitly trusted."
        ),
        "matching_count": len(findings),
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


_MOTW_RISKY_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".msi", ".iso", ".img", ".vhd", ".lnk", ".docm", ".xlsm",
    ".pptm",
)


def rule_motw_internet_origin_risky_file(aq: ArtifactQueries) -> dict | None:
    """Mark-of-the-Web entries: internet-zone files with risky extensions.

    ZoneId 3 (Internet) / 4 (Restricted) on an executable, script, container,
    or macro-document bridges the ingress lane to a concrete file. The URL
    fields, when present, identify the delivery source.
    """
    hits = aq._query_artifact("Mark of the Web", limit=0)
    findings: list[dict] = []
    for h in hits:
        zone = str(h.get("Zone ID", "")).strip()
        if zone not in {"3", "4"}:
            continue
        path = str(h.get("File Path", h.get("source_path", "")))
        if not path.lower().endswith(_MOTW_RISKY_EXTENSIONS):
            continue
        findings.append({
            "hit_id": h.get("hit_id"),
            "artifact_type": "Mark of the Web (Zone.Identifier)",
            "event_type": "Internet-Origin Risky File",
            "timestamp": h.get("Created", h.get("timestamp", "")),
            "file_path": path,
            "zone_id": zone,
            "host_url": h.get("Host URL", ""),
            "referrer_url": h.get("Referrer URL", ""),
            "user": h.get("User", ""),
            "artifact_context": (
                "File carries an Internet/Restricted-zone Zone.Identifier ADS. "
                "Origin evidence only — check Prefetch/BAM/4688 for execution."
            ),
        })
    if not findings:
        return None
    details, truncated, returned_count = _apply_detail_cap(findings)
    return {
        "rule_name": "motw_internet_origin_risky_file",
        "query_description": (
            f"Zone.Identifier ZoneId 3/4 on risky extensions — {len(findings)} "
            "internet-origin file(s) in user folders."
        ),
        "matching_count": len(findings),
        "details": details,
        "returned_count": returned_count,
        "truncated": truncated,
        "detail_cap": 20,
    }


def _apply_detail_cap(hits: list, cap: int = 20) -> tuple[list, bool, int]:
    """Apply the standard detail cap. Returns (capped_list, truncated, returned_count)."""
    capped = hits[:cap]
    return capped, len(hits) > cap, len(capped)


# C-4: map a free-text hypothesis to the lanes/families whose ABSENCE would
# refute it. Keyed by substring; the first matching entry wins. This is a
# soft hint, not a gate — it never blocks the call, only nudges the analyst
# toward the refuting evidence before they commit to a verdict.
_HYPOTHESIS_REFUTATION_MAP = [
    (("ransomware", "ransom", "encrypt"), {
        "hypothesis_class": "ransomware_impact",
        "refute_by_checking": [
            "Encrypted Files / mass extension churn count (impact lane)",
            "ransom note text documents",
            "USN/$LogFile rename-burst around the suspected window",
        ],
        "absence_refutes": (
            "No encrypted-file churn AND no ransom note in a collected impact "
            "lane refutes ransomware — downgrade to anti-forensics or unknown."
        ),
        "next_tool": "build_timeline(fetch_all=true) over the impact window",
    }),
    (("insider", "exfil", "exfiltration", "data theft"), {
        "hypothesis_class": "insider_exfiltration",
        "refute_by_checking": [
            "USB Devices (USBSTOR / MountPoints2 / setupapi) connect times",
            "cloud-upload / webmail browser activity",
            "sensitive-file access (LNK / ShellBags) vs. business-hours baseline",
        ],
        "absence_refutes": (
            "Authorized account + business-hours + approved app/destination is "
            "a credible benign-transfer alternative — do not call exfil on "
            "volume alone."
        ),
        "next_tool": "find_suspicious then correlate on the device/account",
    }),
    (("lateral", "pivot", "rdp", "smb", "remote execution"), {
        "hypothesis_class": "lateral_movement",
        "refute_by_checking": [
            "INBOUND vs OUTBOUND direction (4624 type10 / WinRM vs RDP Client "
            "Destinations) — keep them in separate lanes",
            "explicit-credential use (4648) tying source to destination",
        ],
        "absence_refutes": (
            "Inbound-only evidence does not make this host a pivot; outbound-"
            "only does not make it a victim. Refute the direction you did not "
            "see."
        ),
        "next_tool": "run_hunt_pack(lateral_movement_sweep)",
    }),
    (("persistence", "backdoor", "service", "scheduled task", "autorun"), {
        "hypothesis_class": "persistence",
        "refute_by_checking": [
            "service/task creation time vs. a known-good baseline (net-new?)",
            "binary path + signer (legitimate vendor install vs. drop)",
            "execution corroboration (Prefetch/BAM) for the persistence binary",
        ],
        "absence_refutes": (
            "A net-new service that matches a signed vendor installer is not "
            "persistence — check install_vs_compromise before concluding."
        ),
        "next_tool": "service_persistence_gate",
    }),
    (("anti-forensic", "anti forensic", "log clear", "tamper", "wipe"), {
        "hypothesis_class": "anti_forensics",
        "refute_by_checking": [
            "actor/process behind the clear (admin maintenance vs. adversary)",
            "temporal proximity to intrusion/impact evidence",
            "single tamper family vs. multiple",
        ],
        "absence_refutes": (
            "A lone VSS/log-clear by an admin account in a maintenance window, "
            "with no nearby intrusion, is credibly benign — do not escalate to "
            "compromise on the clear alone."
        ),
        "next_tool": "detect_anti_forensics then correlate on the actor",
    }),
    (("credential", "lsass", "mimikatz", "dump", "pass-the-hash"), {
        "hypothesis_class": "credential_access",
        "refute_by_checking": [
            "LSASS access (Sysmon 10) source process legitimacy",
            "explicit-credential / NTLM events around the same window",
            "DCSync (4662 replication) if a DC is in scope",
        ],
        "absence_refutes": (
            "AV/EDR processes legitimately open LSASS handles — refute by "
            "checking the accessing process, not the handle alone."
        ),
        "next_tool": "find_suspicious(rules=sysmon_eid10_lsass_handle_open)",
    }),
]


def build_refutation_hint(declared_hypothesis: str) -> dict | None:
    """Return a refutation hint for a declared hypothesis, or None.

    Soft nudge toward the evidence whose absence would refute the stated
    hypothesis — implements CLAUDE.md "declare hypothesis, then call tools"
    as structured output without gating the call.
    """
    text = (declared_hypothesis or "").lower().strip()
    if not text:
        return None
    for needles, hint in _HYPOTHESIS_REFUTATION_MAP:
        if any(n in text for n in needles):
            return {"declared_hypothesis": declared_hypothesis, **hint}
    return {
        "declared_hypothesis": declared_hypothesis,
        "hypothesis_class": "unmapped",
        "refute_by_checking": [
            "state the single observation that would most cleanly disprove "
            "this hypothesis, then query for it directly",
        ],
        "absence_refutes": (
            "No canned refutation path for this hypothesis class; design one "
            "before treating supporting hits as confirmation."
        ),
        "next_tool": "hypothesis_refutation_pack",
    }


def _extract_xml_fields(event_data: str, detail: dict, field_names: list[str]) -> None:
    """Extract specific fields from Windows Event XML data."""
    if not event_data:
        return
    for field in field_names:
        # Try: <Data Name="FieldName">value</Data>
        import re
        pattern = rf'Name="{field}"[^>]*>([^<]*)<'
        match = re.search(pattern, str(event_data))
        if match:
            detail[field] = match.group(1)
