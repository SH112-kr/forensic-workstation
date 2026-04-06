"""Structured suspicious pattern detection — artifact-type-aware rules.

Each rule queries specific artifact types with specific field conditions,
not keyword matching. This eliminates false positives from substring matches.

Evidence confidence levels:
- confirmed: Multiple independent artifacts corroborate (e.g., Prefetch + SRUM + Event Log)
- high: Strong single-source evidence (e.g., Event Log with specific EID)
- moderate: Artifact exists but interpretation has caveats (e.g., ShimCache = existence, not execution)
- low: Heuristic correlation only (e.g., time-based co-occurrence without causal link)

IMPORTANT forensic principles encoded in rules:
- ShimCache entry ≠ execution proof (file existence on disk triggers it)
- Prefetch Last Run = strong execution evidence, but does NOT record command-line arguments
- Link Date = compile time, NOT deployment time
- File timestamps must be verified from $MFT, not inferred from other artifacts
- Temporal correlation ≠ causation — always flag as needing verification
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_artifact_queries import ArtifactQueries

MITRE_MAP = {
    "lsass_access": ["T1003.001"],
    "suspicious_process_creation": ["T1059", "T1059.001", "T1059.003"],
    "service_installation": ["T1543.003"],
    "scheduled_task_creation": ["T1053.005"],
    "log_clearing": ["T1070.001"],
    "rdp_lateral_movement": ["T1021.001"],
    "explicit_credential_use": ["T1078"],
    "suspicious_prefetch": ["T1204"],
    "suspicious_service_paths": ["T1543.003"],
    "powershell_scriptblock": ["T1059.001"],
    "watering_hole_indicators": ["T1189"],
    "suspicious_msi_install": ["T1218.007"],
    "ssh_activity": ["T1021.004"],
}

# Confidence level for each rule — indicates evidence strength
CONFIDENCE_MAP = {
    "lsass_access": "high",           # Event log with specific EID
    "suspicious_process_creation": "high",  # Event log with specific EID
    "service_installation": "confirmed",    # EID 7045 = definitive
    "scheduled_task_creation": "moderate",  # Task exists, but creation time may be missing
    "log_clearing": "confirmed",       # EID 1102 = definitive
    "rdp_lateral_movement": "high",    # Event log with specific EID
    "explicit_credential_use": "high", # EID 4648 = definitive
    "suspicious_prefetch": "moderate", # Prefetch = execution, but no cmdline context
    "suspicious_service_paths": "moderate",  # Service exists in suspicious path
    "powershell_scriptblock": "high",  # Script content captured
    "watering_hole_indicators": "low", # Date-level correlation only — NOT causation
    "suspicious_msi_install": "moderate",   # Install record exists
    "ssh_activity": "high",            # Multiple artifact types combined
}


# Query limits used by each rule — documented for transparency
RULE_QUERY_LIMITS: dict[str, dict[str, int]] = {
    "lsass_access": {"process_access_events": 200, "details": 20},
    "suspicious_process_creation": {"process_creation_events": 500, "details": 20},
    "service_installation": {"service_installs": 100},
    "scheduled_task_creation": {"scheduled_task_events": 100, "details": 20},
    "log_clearing": {"log_cleared": 50, "details": 20},
    "rdp_lateral_movement": {"logon_events": 500},
    "explicit_credential_use": {"event_logs_4648": 100},
    "suspicious_prefetch": {"prefetch_per_tool": 50, "details": 20},
    "suspicious_service_paths": {"services": 500},
    "powershell_scriptblock": {"scriptblock": 100, "details": 20},
    "watering_hole_indicators": {"werfault_prefetch": 200, "security_sw_prefetch": 50, "startup_items": 200, "details": 20},
    "suspicious_msi_install": {"amcache_programs": 500},
    "ssh_activity": {"openssh_events": 100, "services": 20, "prefetch": 20},
}


def find_suspicious(aq: ArtifactQueries, rules: str = "") -> dict:
    """Run structured detection rules against .mfdb artifact data."""
    all_rules = {
        "lsass_access": rule_lsass_access,
        "suspicious_process_creation": rule_suspicious_process_creation,
        "service_installation": rule_service_installation,
        "scheduled_task_creation": rule_scheduled_task_creation,
        "log_clearing": rule_log_clearing,
        "rdp_lateral_movement": rule_rdp_lateral_movement,
        "explicit_credential_use": rule_explicit_credential_use,
        "suspicious_prefetch": rule_suspicious_prefetch,
        "suspicious_service_paths": rule_suspicious_service_paths,
        "powershell_scriptblock": rule_powershell_scriptblock,
        "watering_hole_indicators": rule_watering_hole_indicators,
        "suspicious_msi_install": rule_suspicious_msi_install,
        "ssh_activity": rule_ssh_activity,
    }

    if rules:
        rule_names = [r.strip().lower() for r in rules.split(",") if r.strip()]
        active = {name: all_rules[name] for name in rule_names if name in all_rules}
    else:
        active = all_rules

    if not active:
        return {"error": f"Unknown rules. Available: {', '.join(all_rules.keys())}"}

    findings = []
    for name, func in active.items():
        result = func(aq)
        if result:
            result["mitre_techniques"] = MITRE_MAP.get(name, [])
            result["confidence"] = CONFIDENCE_MAP.get(name, "moderate")
            result["query_limits"] = RULE_QUERY_LIMITS.get(name, {})
            findings.append(result)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", ""), 99))

    return {
        "rules_executed": len(active),
        "total_findings": len(findings),
        "findings": findings,
        "available_rules": sorted(all_rules.keys()),
    }


# ── Rules ──

def rule_lsass_access(aq: ArtifactQueries) -> dict | None:
    """Sysmon Event ID 10 — Process accessed LSASS.

    Real credential dumping detection: another process opening lsass.exe
    with suspicious access rights, not just "lsass" appearing in any string.
    """
    hits = aq.query_process_access_events(limit=200)
    # Filter to LSASS targets
    lsass_hits = [h for h in hits if "lsass" in str(h.get("Event Data", "")).lower()]
    if not lsass_hits:
        return None

    details = []
    for h in lsass_hits[:20]:
        event_data = h.get("Event Data", "")
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (Sysmon EID 10)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "Sysmon detected a process accessing LSASS memory",
            "event_data_excerpt": str(event_data)[:500],
            "computer": h.get("Computer", ""),
        }
        # Extract source/target from event data
        _extract_xml_fields(event_data, detail, [
            "SourceProcessId", "SourceImage", "TargetImage", "GrantedAccess",
        ])
        details.append(detail)

    return {
        "rule_name": "lsass_access",
        "severity": "critical",
        "description": f"Sysmon detected {len(lsass_hits)} process access events targeting LSASS. "
                       "This indicates potential credential dumping (Mimikatz, procdump, etc.).",
        "matching_count": len(lsass_hits),
        "matched_patterns": {"Sysmon Event ID 10 + Target=lsass.exe": len(lsass_hits)},
        "details": details,
    }


def rule_suspicious_process_creation(aq: ArtifactQueries) -> dict | None:
    """Sysmon EID 1 / Security EID 4688 — Suspicious process executions.

    Looks for: encoded PowerShell, cmd spawning from unusual parents,
    LOLBins with suspicious arguments.
    """
    hits = aq.query_process_creation_events(limit=500)
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
                    "evidence": desc,
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

    return {
        "rule_name": "suspicious_process_creation",
        "severity": "high",
        "description": f"{len(suspicious)} suspicious process creation events detected. "
                       "Includes encoded commands, download cradles, LOLBin abuse, or lateral movement tools.",
        "matching_count": len(suspicious),
        "matched_patterns": evidence_summary,
        "details": suspicious[:20],
    }


def rule_service_installation(aq: ArtifactQueries) -> dict | None:
    """Event ID 7045 — New service installed. Common persistence mechanism."""
    hits = aq.query_service_installs(limit=100)
    if not hits:
        return None

    details = []
    for h in hits[:20]:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 7045)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "New service installed on the system",
            "event_data_excerpt": str(h.get("Event Data", ""))[:500],
            "computer": h.get("Computer", ""),
        }
        _extract_xml_fields(h.get("Event Data", ""), detail, [
            "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",
        ])
        details.append(detail)

    return {
        "rule_name": "service_installation",
        "severity": "high",
        "description": f"{len(hits)} service installation events (EID 7045) detected. "
                       "Review service names and paths for unauthorized persistence.",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 7045 (Service Installed)": len(hits)},
        "details": details,
    }


def rule_scheduled_task_creation(aq: ArtifactQueries) -> dict | None:
    """Event ID 4698/4702 — Scheduled task created/modified."""
    hits = aq.query_scheduled_task_events(limit=100)
    if not hits:
        # Fallback: check Scheduled Tasks artifact
        tasks = aq.query_scheduled_tasks(limit=100)
        if not tasks:
            return None
        details = []
        for t in tasks[:20]:
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
        return {
            "rule_name": "scheduled_task_creation",
            "severity": "medium",
            "description": f"{len(tasks)} scheduled tasks found. Review for unauthorized persistence.",
            "matching_count": len(tasks),
            "matched_patterns": {"Scheduled Tasks artifact": len(tasks)},
            "details": details,
        }

    details = []
    for h in hits[:20]:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": f"Windows Event Logs (EID {h.get('Event ID', '?')})",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "Scheduled task created or modified via event log",
            "computer": h.get("Computer", ""),
            "event_data_excerpt": str(h.get("Event Data", ""))[:500],
        }
        details.append(detail)

    return {
        "rule_name": "scheduled_task_creation",
        "severity": "high",
        "description": f"{len(hits)} scheduled task creation/modification events detected.",
        "matching_count": len(hits),
        "matched_patterns": {f"Event ID {h.get('Event ID', '?')}": 1 for h in hits[:5]},
        "details": details,
    }


def rule_log_clearing(aq: ArtifactQueries) -> dict | None:
    """Event ID 1102 — Security audit log was cleared."""
    hits = aq.query_log_cleared(limit=50)
    if not hits:
        return None

    details = []
    for h in hits[:20]:
        details.append({
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 1102)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "Security audit log was cleared — anti-forensic activity",
            "computer": h.get("Computer", ""),
            "security_id": h.get("Security Identifier", ""),
        })

    return {
        "rule_name": "log_clearing",
        "severity": "critical",
        "description": f"Security audit log was cleared {len(hits)} time(s). "
                       "This is a strong indicator of anti-forensic activity.",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 1102 (Audit Log Cleared)": len(hits)},
        "details": details,
    }


def rule_rdp_lateral_movement(aq: ArtifactQueries) -> dict | None:
    """Event ID 4624 Type 10 — RDP logon (lateral movement indicator)."""
    logons = aq.query_logon_events(limit=500)
    rdp_logons = []
    for h in logons:
        event_data = str(h.get("Event Data", ""))
        # Type 10 = RemoteInteractive (RDP)
        if ">10<" in event_data or "LogonType\">10" in event_data:
            detail = {
                "hit_id": h["hit_id"],
                "artifact_type": "Windows Event Logs (EID 4624 Type 10)",
                "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "evidence": "RDP logon detected — potential lateral movement",
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

    return {
        "rule_name": "rdp_lateral_movement",
        "severity": "high",
        "description": f"{len(rdp_logons)} RDP logon events (Type 10) detected from "
                       f"{len(ip_counts)} unique source(s). Potential lateral movement.",
        "matching_count": len(rdp_logons),
        "matched_patterns": {f"RDP from {ip}": cnt for ip, cnt in ip_counts.items()},
        "details": rdp_logons[:20],
    }


def rule_explicit_credential_use(aq: ArtifactQueries) -> dict | None:
    """Event ID 4648 — Explicit credential use (runas, pass-the-hash indicator)."""
    hits = aq.query_event_logs(event_ids=[4648], limit=100)
    if not hits:
        return None

    details = []
    for h in hits[:20]:
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (EID 4648)",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "Explicit credentials used (runas, mapped drive, or pass-the-hash)",
            "computer": h.get("Computer", ""),
        }
        _extract_xml_fields(h.get("Event Data", ""), detail, [
            "SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName",
        ])
        details.append(detail)

    return {
        "rule_name": "explicit_credential_use",
        "severity": "medium",
        "description": f"{len(hits)} explicit credential use events (EID 4648). "
                       "May indicate runas, pass-the-hash, or mapped drive authentication.",
        "matching_count": len(hits),
        "matched_patterns": {"Event ID 4648 (Explicit Credential Use)": len(hits)},
        "details": details,
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
        hits = aq.query_prefetch(app_name_filter=tool, limit=50)
        for h in hits:
            app_name = h.get("Application Name", "")
            # Exact match check (not substring)
            if tool.lower() in app_name.lower().split(".")[0].replace("-", "").replace("_", ""):
                found.append({
                    "hit_id": h["hit_id"],
                    "artifact_type": "Prefetch",
                    "evidence": f"Attack tool '{app_name}' was executed on this system",
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

    return {
        "rule_name": "suspicious_prefetch",
        "severity": "critical",
        "description": f"{len(found)} Prefetch entries for known attack tools. "
                       "These tools were executed on this system.",
        "matching_count": len(found),
        "matched_patterns": tool_counts,
        "details": found[:20],
    }


def rule_suspicious_service_paths(aq: ArtifactQueries) -> dict | None:
    """Services with executables in suspicious locations."""
    services = aq.query_services(limit=500)
    suspicious = []
    suspicious_paths = [
        "\\temp\\", "\\tmp\\", "\\public\\", "\\perflogs\\",
        "\\appdata\\", "\\programdata\\",
    ]

    for svc in services:
        location = str(svc.get("Service Location", "")).lower()
        if not location:
            continue
        for p in suspicious_paths:
            if p in location:
                suspicious.append({
                    "hit_id": svc["hit_id"],
                    "artifact_type": "System Services",
                    "evidence": f"Service binary in suspicious path: {p.strip(chr(92))}",
                    "Service Name": svc.get("Service Name", ""),
                    "Service Location": svc.get("Service Location", ""),
                    "Start Type": svc.get("Start Type", ""),
                    "User Account": svc.get("User Account", ""),
                    "Registry Modified": svc.get("Registry Key Modified Date/Time - UTC (yyyy-mm-dd)", ""),
                })
                break

    if not suspicious:
        return None

    return {
        "rule_name": "suspicious_service_paths",
        "severity": "high",
        "description": f"{len(suspicious)} services with binaries in suspicious locations. "
                       "May indicate malware persistence via service installation.",
        "matching_count": len(suspicious),
        "matched_patterns": {d["Service Name"]: 1 for d in suspicious[:10]},
        "details": suspicious[:20],
    }


def rule_powershell_scriptblock(aq: ArtifactQueries) -> dict | None:
    """Event ID 4104 — PowerShell Script Block Logging."""
    hits = aq.query_powershell_scriptblock(limit=100)
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
                "evidence": f"Suspicious PowerShell script block: {', '.join(matched)}",
                "event_data_excerpt": str(h.get("Event Data", ""))[:500],
                "computer": h.get("Computer", ""),
            })

    if not suspicious:
        # Still report if there are script blocks (informational)
        return {
            "rule_name": "powershell_scriptblock",
            "severity": "info",
            "description": f"{len(hits)} PowerShell Script Block logs found (EID 4104). "
                           "No obviously suspicious content, but review recommended.",
            "matching_count": len(hits),
            "matched_patterns": {"Event ID 4104 (Script Block)": len(hits)},
            "details": [{
                "hit_id": h["hit_id"],
                "artifact_type": "Windows Event Logs (EID 4104)",
                "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "evidence": "PowerShell Script Block logged",
            } for h in hits[:10]],
        }

    indicator_counts = {}
    for d in suspicious:
        for part in d["evidence"].replace("Suspicious PowerShell script block: ", "").split(", "):
            indicator_counts[part] = indicator_counts.get(part, 0) + 1

    return {
        "rule_name": "powershell_scriptblock",
        "severity": "high",
        "description": f"{len(suspicious)} suspicious PowerShell script blocks detected in EID 4104 logs. "
                       "Contains download cradles, encoded commands, or known attack patterns.",
        "matching_count": len(suspicious),
        "matched_patterns": indicator_counts,
        "details": suspicious[:20],
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
    werfault_hits = aq.query_prefetch(app_name_filter="WERFAULT", limit=200)
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
        hits = aq.query_prefetch(app_name_filter=sw_name, limit=50)
        sec_sw_hits.extend(hits)

    if not sec_sw_hits:
        return None

    # Check if security SW is in startup items (reduces confidence significantly)
    startup_hits = aq._query_artifact("Startup Items", limit=200)
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
                "evidence": f"WerFault crash ({bitness}) on same date as security SW execution",
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

    if is_startup_correlation:
        severity = "medium"
        caveat = (
            " NOTE: The flagged security software runs as startup items, so "
            "co-occurrence with WerFault on the same day may be coincidental. "
            "Verify with search_wer_reports whether the security SW itself crashed, "
            "and use get_file_timestamps to check if malicious files existed before the crash."
        )
    else:
        severity = "high"
        caveat = (
            " Verify with search_wer_reports to confirm the security SW actually crashed, "
            "and check the timeline to establish causation."
        )

    return {
        "rule_name": "watering_hole_indicators",
        "severity": severity,
        "description": (
            f"{len(correlated)} WerFault crash(es) correlated with Korean security software "
            f"execution.{caveat}"
        ),
        "matching_count": len(correlated),
        "matched_patterns": sw_summary,
        "details": correlated[:20],
        "startup_items": sorted(startup_overlap) if startup_overlap else [],
        "verification_needed": [
            "Run search_wer_reports with security SW names to check if THEY crashed",
            "Use get_file_timestamps on suspicious files to verify creation time",
            "Build timeline around crash time to check for causal sequence",
        ],
    }


def rule_suspicious_msi_install(aq: ArtifactQueries) -> dict | None:
    """AmCache entries for MSI-installed programs — suspicious installs outside work hours.

    Flags MSI-installed programs that were installed outside normal working
    hours (before 07:00 or after 19:00 UTC), or that match known remote
    access / SSH tool patterns.
    """
    # Query AmCache Program Entries for MSI installs
    # Try "AmCache Program Entries" first, then fall back to generic search
    program_hits = aq._query_artifact("AmCache Program Entries", limit=500)
    if not program_hits:
        # Fall back to AmCache File Entries
        program_hits = aq.query_amcache(limit=500)

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

    # If no MSI filter matches, only check against suspicious tool patterns
    # (skip time-based check to avoid false positives on non-MSI installs)
    check_all = msi_installs
    check_all_tools_only = not msi_installs  # only match tool patterns, not install time

    # Known suspicious tool patterns
    suspicious_tool_patterns = [
        "openssh", "ssh", "putty", "winscp", "mremoteng",
        "teamviewer", "anydesk", "rustdesk", "meshagent",
        "radmin", "vnc", "vpn", "wireguard", "openvpn",
    ]

    # If no MSI matches, fall back to checking ALL programs but only for tool patterns
    if check_all_tools_only:
        check_all = program_hits

    flagged = []
    for h in check_all:
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

        # Check install time — only for confirmed MSI installs (not fallback)
        # Apply local timezone offset (default KST=UTC+9) for work hours check
        if not check_all_tools_only and install_date and len(install_date) >= 16:
            try:
                utc_hour = int(install_date[11:13])
                tz_offset = 9  # KST default
                try:
                    import mcp_bridge
                    if hasattr(mcp_bridge, '_tz_config'):
                        tz_offset = int(mcp_bridge._tz_config.get("local_tz_offset_hours", 9))
                except Exception:
                    pass
                local_hour = (utc_hour + tz_offset) % 24
                if local_hour < 7 or local_hour >= 22:
                    reasons.append(f"Installed outside work hours (local {local_hour:02d}:xx)")
            except (ValueError, IndexError):
                pass

        # Check for suspicious tool names
        for pattern in suspicious_tool_patterns:
            if pattern in name or pattern in str(install_path).lower():
                reasons.append(f"Matches suspicious tool pattern: {pattern}")
                break

        if reasons:
            flagged.append({
                "hit_id": h["hit_id"],
                "artifact_type": h.get("artifact_type", "AmCache Program Entries"),
                "evidence": "; ".join(reasons),
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
        for part in d["evidence"].split("; "):
            reason_counts[part] = reason_counts.get(part, 0) + 1

    return {
        "rule_name": "suspicious_msi_install",
        "severity": "high",
        "description": (
            f"{len(flagged)} suspicious MSI-installed program(s) detected. "
            "Includes off-hours installs or known remote access / SSH tools."
        ),
        "matching_count": len(flagged),
        "matched_patterns": reason_counts,
        "details": flagged[:20],
    }


def rule_ssh_activity(aq: ArtifactQueries) -> dict | None:
    """SSH-related artifacts — OpenSSH events, services, keys, and Prefetch.

    Combines multiple data sources to detect SSH activity which is uncommon
    on standard Korean enterprise Windows endpoints.
    """
    findings: list[dict] = []

    # 1. OpenSSH event log entries (Provider="OpenSSH")
    ssh_events = aq.query_event_logs(provider="OpenSSH", limit=100)
    for h in ssh_events:
        event_data = str(h.get("Event Data", ""))
        detail = {
            "hit_id": h["hit_id"],
            "artifact_type": "Windows Event Logs (OpenSSH)",
            "event_type": "OpenSSH Event Log",
            "timestamp": h.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
            "evidence": "OpenSSH event log entry detected",
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
        svc_hits = aq.query_services(service_filter=svc_name, limit=20)
        for s in svc_hits:
            findings.append({
                "hit_id": s["hit_id"],
                "artifact_type": "System Services",
                "event_type": "SSH Service",
                "timestamp": s.get("Registry Key Modified Date/Time - UTC (yyyy-mm-dd)", ""),
                "evidence": f"SSH-related service found: {s.get('Service Name', '')}",
                "details": f"Location: {s.get('Service Location', '')}, "
                           f"Start Type: {s.get('Start Type', '')}",
            })

    # 3. SSH key artifacts
    for art_name in ["SSH Keys", "SSH Known Hosts"]:
        key_hits = aq._query_artifact(art_name, limit=50)
        for k in key_hits:
            findings.append({
                "hit_id": k["hit_id"],
                "artifact_type": art_name,
                "event_type": "SSH Key Artifact",
                "timestamp": k.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "evidence": f"{art_name} artifact found",
                "details": str({
                    key: val for key, val in k.items()
                    if key not in ("hit_id", "artifact_type") and val
                })[:500],
            })

    # 4. SSH-related Prefetch
    ssh_prefetch_names = ["SSHD", "SSH-KEYGEN", "SSH-AGENT", "SSH.EXE"]
    for pf_name in ssh_prefetch_names:
        pf_hits = aq.query_prefetch(app_name_filter=pf_name, limit=20)
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
                "evidence": f"SSH executable was run: {app_name}",
                "details": f"Path: {p.get('Application Path', '')}, "
                           f"Run Count: {p.get('Application Run Count', '')}",
            })

    if not findings:
        return None

    # Summarize by event type
    type_counts: dict[str, int] = {}
    for f in findings:
        et = f.get("event_type", "unknown")
        type_counts[et] = type_counts.get(et, 0) + 1

    return {
        "rule_name": "ssh_activity",
        "severity": "high",
        "description": (
            f"{len(findings)} SSH-related artifact(s) detected across event logs, "
            "services, key files, and Prefetch. SSH activity is uncommon on standard "
            "Windows enterprise endpoints and may indicate unauthorized remote access."
        ),
        "matching_count": len(findings),
        "matched_patterns": type_counts,
        "details": findings[:20],
    }


# ── Helpers ──

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
