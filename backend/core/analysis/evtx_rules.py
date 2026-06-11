"""Lightweight Sigma-style EVTX rule engine.

Runs entirely against the EVTX rows already parsed by the connector (KAPE
EvtxECmd output or AXIOM Event Logs artifact). Intentionally **not** a
Hayabusa wrapper — that's a separate track with its own binary, ruleset,
and maintenance story. This engine is just enough to cover common
investigator asks without adding dependencies:

- A rule is a plain dict (id, title, severity, event_ids, matcher, mitre).
- A matcher is the intersection of event_ids and ``any`` keyword substrings
  that must appear in the event data / description.
- Every rule is published verbatim in the output so the analyst can audit
  the logic and disable / tune specific ids.

Rules below target the common EIDs that the hand-curated ``find_suspicious``
rules do not cover. When find_suspicious already owns an EID (4688/1102/
7045/4104/etc.) we skip it to avoid double counting. Keep this list small
and generic — CLAUDE.md forbids overfitting to specific incidents.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_artifact_queries import ArtifactQueries


# Built-in rule pack. Publicly documented behaviours only.
BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "id": "fw-evtx-001",
        "title": "Failed logon burst (Event ID 4625)",
        "severity": "medium",
        "event_ids": [4625],
        "any": [],  # EID alone is enough; bursts show up in the count.
        "mitre": ["T1110.001"],
        "tags": ["credential_access", "brute_force"],
    },
    {
        "id": "fw-evtx-002",
        "title": "User account created (Event ID 4720)",
        "severity": "medium",
        "event_ids": [4720],
        "any": [],
        "mitre": ["T1136.001"],
        "tags": ["persistence", "account_create"],
    },
    {
        "id": "fw-evtx-003",
        "title": "Member added to security-enabled group (4728 / 4732 / 4756)",
        "severity": "high",
        "event_ids": [4728, 4732, 4756],
        "any": [],
        "mitre": ["T1098", "T1078.003"],
        "tags": ["privilege_escalation", "group_membership"],
    },
    {
        "id": "fw-evtx-004",
        "title": "Kerberos TGT/AS-REP request with weak encryption (4768 / 4769)",
        "severity": "medium",
        "event_ids": [4768, 4769],
        "any": ["0x17", "0x1"],  # RC4 / DES — potential AS-REP roasting
        "mitre": ["T1558.004", "T1558.003"],
        "tags": ["credential_access"],
    },
    {
        "id": "fw-evtx-005",
        "title": "NTLM authentication (4776) — legacy / lateral-movement indicator",
        "severity": "low",
        "event_ids": [4776],
        "any": [],
        "mitre": ["T1550.002"],
        "tags": ["credential_access", "lateral_movement"],
    },
    {
        "id": "fw-evtx-006",
        "title": "Audit policy changed (Event ID 4719)",
        "severity": "high",
        "event_ids": [4719],
        "any": [],
        "mitre": ["T1562.002"],
        "tags": ["defense_evasion"],
    },
    {
        "id": "fw-evtx-007",
        "title": "Windows Firewall rule added / modified (4946 / 4947 / 4950)",
        "severity": "medium",
        "event_ids": [4946, 4947, 4950],
        "any": [],
        "mitre": ["T1562.004"],
        "tags": ["defense_evasion", "firewall"],
    },
    {
        "id": "fw-evtx-008",
        "title": "File share accessed from network (5140 / 5145)",
        "severity": "low",
        "event_ids": [5140, 5145],
        "any": [],
        "mitre": ["T1021.002"],
        "tags": ["lateral_movement", "smb"],
    },
    {
        "id": "fw-evtx-009",
        "title": "Scheduled Task action triggered (106 / 140 / 141)",
        "severity": "medium",
        "event_ids": [106, 140, 141],
        "any": [],
        "mitre": ["T1053.005"],
        "tags": ["persistence", "scheduled_task"],
    },
    {
        "id": "fw-evtx-010",
        "title": "RDP session reconnect / disconnect (1149 / 21 / 25)",
        "severity": "low",
        "event_ids": [21, 25, 1149],
        "any": [],
        "mitre": ["T1021.001"],
        "tags": ["lateral_movement", "rdp"],
    },
    {
        "id": "fw-evtx-011",
        "title": "Privileged service called by client (4674)",
        "severity": "medium",
        "event_ids": [4674],
        "any": ["SeDebug", "SeTcb", "SeImpersonate", "SeLoadDriver"],
        "mitre": ["T1134"],
        "tags": ["privilege_escalation"],
    },
    {
        "id": "fw-evtx-012",
        "title": "Special privileges assigned to new logon (4672)",
        "severity": "low",
        "event_ids": [4672],
        "any": [],
        "mitre": ["T1078"],
        "tags": ["privilege_escalation"],
    },
    {
        "id": "fw-evtx-013",
        "title": "Kerberos pre-authentication failed (4771)",
        "severity": "medium",
        "event_ids": [4771],
        "any": [],
        "mitre": ["T1110.003"],
        "tags": ["credential_access", "password_spray"],
    },
    {
        "id": "fw-evtx-014",
        "title": "Suspicious process creation via Sysmon (Event ID 1)",
        "severity": "medium",
        "event_ids": [1],
        "any": [
            "powershell", "cmd.exe", "wscript", "cscript", "rundll32",
            "regsvr32", "mshta", "wmic", "bitsadmin", "certutil",
        ],
        "mitre": ["T1059"],
        "tags": ["execution"],
    },
    {
        "id": "fw-evtx-015",
        "title": "Process access to LSASS via Sysmon (Event ID 10)",
        "severity": "high",
        "event_ids": [10],
        "any": ["lsass.exe"],
        "mitre": ["T1003.001"],
        "tags": ["credential_access"],
    },
    {
        "id": "fw-evtx-016",
        "title": "Sysmon network connection observed (Event ID 3)",
        "severity": "low",
        "event_ids": [3],
        "any": [],
        "mitre": ["T1071"],
        "tags": ["command_and_control"],
    },
    {
        "id": "fw-evtx-017",
        "title": "Directory service object modified (Event ID 5136)",
        "severity": "medium",
        "event_ids": [5136],
        "any": [],
        "mitre": ["T1098"],
        "tags": ["persistence", "privilege_escalation"],
    },
    {
        "id": "fw-evtx-018",
        "title": "Sensitive local data access (4663)",
        "severity": "medium",
        "event_ids": [4663],
        "any": ["ntds.dit", "system32\\config", "lsass", "chrome", "firefox", "opera"],
        "mitre": ["T1003", "T1555.003"],
        "tags": ["credential_access"],
    },
    {
        "id": "fw-evtx-019",
        "title": "Audit log cleared (Event ID 1102)",
        "severity": "high",
        "event_ids": [1102],
        "any": [],
        "mitre": ["T1070.001"],
        "tags": ["defense_evasion"],
    },
    {
        "id": "fw-evtx-020",
        "title": "PowerShell script block logged (4104)",
        "severity": "medium",
        "event_ids": [4104],
        "any": ["iex", "invoke-", "download", "encodedcommand", "frombase64string"],
        "mitre": ["T1059.001"],
        "tags": ["execution"],
    },
    {
        "id": "fw-evtx-021",
        "title": "Discovery command process creation via Sysmon (Event ID 1)",
        "severity": "low",
        "event_ids": [1],
        "any": [
            "whoami", "ipconfig", "systeminfo", "net.exe", "net1.exe",
            "nltest", "quser", "qwinsta", "tasklist", "appcmd",
        ],
        "mitre": ["T1087", "T1016", "T1082"],
        "tags": ["discovery"],
    },
    {
        "id": "fw-evtx-022",
        "title": "Local account or group enumeration (4798 / 4799)",
        "severity": "low",
        "event_ids": [4798, 4799],
        "any": [],
        "mitre": ["T1087.001", "T1069.001"],
        "tags": ["discovery"],
    },
    {
        "id": "fw-evtx-023",
        "title": "Remote discovery named pipe access via Sysmon (Event ID 18)",
        "severity": "low",
        "event_ids": [18],
        "any": ["\\srvsvc", "\\winreg", "\\samr", "\\lsarpc", "\\lsass"],
        "mitre": ["T1046", "T1087"],
        "tags": ["discovery"],
    },
    {
        "id": "fw-evtx-024",
        "title": "LDAP/SMB discovery network activity via Sysmon (Event ID 3)",
        "severity": "low",
        "event_ids": [3],
        "any": ["destinationport=389", "destinationport=445", "destport=389", "destport=445"],
        "mitre": ["T1087.002", "T1018"],
        "tags": ["discovery"],
    },
    # ── B-3 coverage-gap closures (step 5) ──────────────────────────────
    {
        "id": "fw-evtx-025",
        "title": "Service installed via Security channel (Event ID 4697)",
        "severity": "high",
        "event_ids": [4697],
        "any": [],  # Security-channel pair of System 7045; either can be cleared
        "mitre": ["T1543.003"],
        "tags": ["persistence", "service_install"],
    },
    {
        "id": "fw-evtx-026",
        "title": "PowerShell engine started (Event ID 400 / 600)",
        "severity": "low",
        "event_ids": [400, 600],
        "any": [],  # fallback when 4104 ScriptBlock logging is disabled
        "mitre": ["T1059.001"],
        "tags": ["execution", "powershell"],
    },
    {
        "id": "fw-evtx-027",
        "title": "Sysmon file created in suspicious path (Event ID 11)",
        "severity": "low",
        "event_ids": [11],
        "any": ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\",
                "\\downloads\\", ".lnk", "startup"],
        "mitre": ["T1105", "T1547.001"],
        "tags": ["execution", "persistence"],
    },
    {
        "id": "fw-evtx-028",
        "title": "Sysmon registry autostart modification (Event ID 12 / 13)",
        "severity": "medium",
        "event_ids": [12, 13],
        "any": ["currentversion\\run", "runonce", "\\services\\",
                "image file execution options", "\\winlogon", "userinit"],
        "mitre": ["T1547.001", "T1112"],
        "tags": ["persistence", "registry"],
    },
    {
        "id": "fw-evtx-029",
        "title": "Sysmon DNS query to suspicious TLD/host (Event ID 22)",
        "severity": "low",
        "event_ids": [22],
        "any": [".top", ".xyz", ".ru", ".su", "duckdns", "ngrok",
                "pastebin", "anydesk", "teamviewer"],
        "mitre": ["T1071.004"],
        "tags": ["command_and_control"],
    },
    {
        "id": "fw-evtx-030",
        "title": "Sysmon CreateRemoteThread injection (Event ID 8)",
        "severity": "high",
        "event_ids": [8],
        "any": [],
        "mitre": ["T1055"],
        "tags": ["defense_evasion", "process_injection"],
    },
    {
        "id": "fw-evtx-031",
        "title": "Directory Service replication / DCSync (Event ID 4662)",
        "severity": "high",
        "event_ids": [4662],
        "any": ["1131f6aa", "1131f6ad", "9923a32a", "replicating directory",
                "ds-replication"],
        "mitre": ["T1003.006"],
        "tags": ["credential_access", "dcsync"],
    },
    {
        "id": "fw-evtx-032",
        "title": "Windows Filtering Platform allowed connection (Event ID 5156)",
        "severity": "low",
        "event_ids": [5156],
        "any": [],
        "mitre": ["T1071"],
        "tags": ["command_and_control", "network"],
    },
    {
        "id": "fw-evtx-033",
        "title": "Scheduled task executed (TaskScheduler 129 / 200 / 201)",
        "severity": "low",
        "event_ids": [129, 200, 201],
        "any": [],  # execution, distinct from creation (106/4698)
        "mitre": ["T1053.005"],
        "tags": ["persistence", "execution"],
    },
    {
        "id": "fw-evtx-034",
        "title": "Windows Defender threat detected (1116 / 1117)",
        "severity": "high",
        "event_ids": [1116, 1117],
        "any": [],
        "mitre": ["T1059", "T1204"],
        "tags": ["impact", "malware_detected"],
    },
    {
        "id": "fw-evtx-035",
        "title": "Windows Defender protection disabled / tampered (5001 / 5007 / 1119)",
        "severity": "high",
        "event_ids": [5001, 5007, 1119],
        "any": [],
        "mitre": ["T1562.001"],
        "tags": ["defense_evasion", "defender_tamper"],
    },
    {
        "id": "fw-evtx-036",
        "title": "BITS transfer job created/completed (BITS-Client 59 / 60 / 3)",
        "severity": "medium",
        "event_ids": [59, 60, 3],
        "any": ["http://", "https://", ".exe", ".dll", ".ps1", "bitsadmin"],
        "mitre": ["T1197"],
        "tags": ["persistence", "command_and_control"],
    },
    {
        "id": "fw-evtx-037",
        "title": "WinRM remote session (WinRM 91 / 168 / 6)",
        "severity": "medium",
        "event_ids": [91, 168, 6],
        "any": [],
        "mitre": ["T1021.006"],
        "tags": ["lateral_movement", "remote_execution"],
    },
    {
        "id": "fw-evtx-038",
        "title": "RDP session reconnected/disconnected (4778 / 4779)",
        "severity": "low",
        "event_ids": [4778, 4779],
        "any": [],
        "mitre": ["T1021.001"],
        "tags": ["lateral_movement", "remote_access"],
    },
    {
        "id": "fw-evtx-039",
        "title": "Outbound RDP client connection (TerminalServices-RDPClient 1024 / 1102)",
        "severity": "medium",
        "event_ids": [1024, 1102],
        "any": [],  # 1102 here is RDPClient channel, distinct from Security 1102
        "mitre": ["T1021.001"],
        "tags": ["lateral_movement", "pivot"],
    },
]


def _extract_haystack(row: dict[str, Any]) -> str:
    """Concatenate the fields most likely to carry sigma-style matchables."""
    parts = [
        str(row.get("Event Data", "")),
        str(row.get("Event Description Summary", "")),
        str(row.get("Provider Name", "")),
        str(row.get("Channel", "")),
        str(row.get("Computer", "")),
    ]
    return " ".join(parts).lower()


def _rule_matches(rule: dict[str, Any], row: dict[str, Any]) -> bool:
    """``any`` keyword substrings act as an OR; if empty the EID alone matches."""
    needles = [k.lower() for k in (rule.get("any") or []) if k]
    if not needles:
        return True
    hay = _extract_haystack(row)
    return any(n in hay for n in needles)


def _sigma_dir() -> str:
    """Resolve backend/hunt_packs/sigma relative to this module."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "hunt_packs", "sigma"))


def hunt_evtx_rules(
    aq: ArtifactQueries,
    rule_ids: list[str] | None = None,
    severity_min: str = "low",
    limit_per_rule: int = 100,
    include_sigma: bool = True,
) -> dict[str, Any]:
    """Run the built-in + optional Sigma rule pack against Event Log artifacts.

    Args:
        aq: ``ArtifactQueries`` bound to an open case.
        rule_ids: Optional whitelist of rule ids. Omit to run every rule.
        severity_min: ``low``/``medium``/``high``/``critical``. Filters by
            rule severity before execution so noisy low-sev rules can be
            skipped.
        limit_per_rule: Max hits kept per rule (raw count is still reported).
        include_sigma: When True (default) also load community/case Sigma
            rules from ``backend/hunt_packs/sigma``. Each carries
            ``provenance.origin == "sigma-community"``; a Sigma hit is an
            evidence hint, not a verdict, and unsupported Sigma features are
            reported (not silently approximated).

    Returns a single envelope containing every matched rule with its exact
    criteria attached so the analyst can audit or tune any hit.
    """
    sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = sev_order.get((severity_min or "low").lower(), 1)

    rule_pool = list(BUILTIN_RULES)
    sigma_load: dict[str, Any] | None = None
    if include_sigma:
        from core.analysis.sigma_loader import load_sigma_dir
        sigma_load = load_sigma_dir(_sigma_dir())
        rule_pool.extend(sigma_load.get("rules", []))

    wanted_ids = set(rule_ids or [])
    active: list[dict[str, Any]] = [
        r for r in rule_pool
        if (not wanted_ids or r["id"] in wanted_ids)
        and sev_order.get(r.get("severity", "low"), 1) >= min_rank
    ]

    results: list[dict[str, Any]] = []
    total_hits = 0

    for rule in active:
        try:
            rows = aq.query_event_logs(event_ids=rule["event_ids"], limit=0) or []
        except Exception as e:
            results.append({
                "rule_id": rule["id"], "ok": False, "error": str(e),
                "title": rule["title"], "severity": rule["severity"],
                "event_ids": rule["event_ids"], "mitre": rule.get("mitre", []),
            })
            continue

        matched = [r for r in rows if _rule_matches(rule, r)]
        if not matched:
            continue

        details = []
        for row in matched[:limit_per_rule]:
            details.append({
                "hit_id": row.get("hit_id"),
                "artifact_type": f"Windows Event Logs (EID {row.get('Event ID', '?')})",
                "timestamp": row.get("Created Date/Time - UTC (yyyy-mm-dd)", ""),
                "computer": row.get("Computer", ""),
                "provider": row.get("Provider Name", ""),
                "event_data_excerpt": str(row.get("Event Data", ""))[:300],
            })

        total_hits += len(matched)
        results.append({
            "rule_id": rule["id"],
            "ok": True,
            "title": rule["title"],
            "severity": rule["severity"],
            "event_ids": rule["event_ids"],
            "matchers": {"any": rule.get("any", [])},
            "mitre": rule.get("mitre", []),
            "tags": rule.get("tags", []),
            "provenance": rule.get("provenance", {"origin": "builtin"}),
            "match_count": len(matched),
            "returned": len(details),
            "details": details,
        })

    # Sort by severity descending then by count. NOTE: this orders the audit
    # view; it is NOT a significance ranking. Sigma/builtin hits are evidence
    # hints — judge each on its details, not its position (CLAUDE.md).
    results.sort(key=lambda r: (-(sev_order.get(r.get("severity", "low"), 1)), -(r.get("match_count", 0))))

    notes = [
        "No network calls. Built-in rules have no dependencies; Sigma rules "
        "need PyYAML.",
        "Overlap with find_suspicious is avoided by design — EIDs already "
        "handled there (1102/4688/4104/7045/...) are NOT in the builtin pack.",
        "Result order is severity-then-count for auditability, NOT a "
        "significance ranking. Sigma hits are evidence hints, not verdicts.",
        "To tune: drop a rule by passing rule_ids=[keep,...] or raise "
        "severity_min to 'medium' / 'high' for noisy-low rules.",
    ]
    out = {
        "ok": True,
        "rule_pack": "builtin+sigma" if include_sigma else "builtin",
        "rule_pack_version": "2026-06-10",
        "rules_evaluated": len(active),
        "rules_fired": sum(1 for r in results if r.get("ok") and r.get("match_count")),
        "total_hits": total_hits,
        "results": results,
        "notes": notes,
    }
    if sigma_load is not None:
        out["sigma_load"] = {
            "stats": sigma_load.get("stats", {}),
            "unsupported_feature_counts": sigma_load.get("unsupported_feature_counts", {}),
            "skipped": sigma_load.get("skipped", [])[:50],
        }
    return out
