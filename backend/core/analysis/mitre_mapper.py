"""MITRE ATT&CK mapping for forensic findings."""

from __future__ import annotations

TECHNIQUE_DB = {
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Credential Access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    # Initial Access
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    # Execution
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1106": {"name": "Native API", "tactic": "Execution"},
    "T1129": {"name": "Shared Modules", "tactic": "Execution"},
    "T1569": {"name": "System Services", "tactic": "Execution"},
    # Persistence
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    # Privilege Escalation
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    # Defense Evasion
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1036.005": {"name": "Match Legitimate Name or Location", "tactic": "Defense Evasion"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1218.007": {"name": "Msiexec", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1622": {"name": "Debugger Evasion", "tactic": "Defense Evasion"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    # Collection
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
}


def map_findings_to_mitre(findings: list[dict]) -> dict:
    """Map suspicious findings to MITRE ATT&CK techniques.

    Args:
        findings: Output from find_suspicious()["findings"]
    """
    techniques_seen: dict[str, dict] = {}
    tactics_seen: dict[str, list[str]] = {}

    for finding in findings:
        rule_name = finding.get("rule_name", "")
        severity = finding.get("severity", "")
        count = finding.get("matching_count", 0)
        mitre_ids = finding.get("mitre_techniques", [])

        for tid in mitre_ids:
            tech = TECHNIQUE_DB.get(tid, {"name": tid, "tactic": "Unknown"})
            if tid not in techniques_seen:
                techniques_seen[tid] = {
                    "technique_id": tid,
                    "technique_name": tech["name"],
                    "tactic": tech["tactic"],
                    "rules_matched": [],
                    "total_hits": 0,
                    "max_severity": severity,
                }
            techniques_seen[tid]["rules_matched"].append(rule_name)
            techniques_seen[tid]["total_hits"] += count

            tactic = tech["tactic"]
            if tactic not in tactics_seen:
                tactics_seen[tactic] = []
            if tid not in tactics_seen[tactic]:
                tactics_seen[tactic].append(tid)

    return {
        "techniques": list(techniques_seen.values()),
        "tactics_summary": {k: len(v) for k, v in tactics_seen.items()},
        "total_techniques": len(techniques_seen),
        "total_tactics": len(tactics_seen),
    }


def get_attack_narrative(findings: list[dict]) -> dict:
    """Generate an ATT&CK-based attack narrative from findings."""
    mapping = map_findings_to_mitre(findings)
    techniques = mapping["techniques"]

    # Order by kill chain
    tactic_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    narrative_sections = []
    for tactic in tactic_order:
        techs = [t for t in techniques if t["tactic"] == tactic]
        if techs:
            section = {
                "tactic": tactic,
                "techniques": [
                    {
                        "id": t["technique_id"],
                        "name": t["technique_name"],
                        "evidence_count": t["total_hits"],
                        "detection_rules": t["rules_matched"],
                    }
                    for t in techs
                ],
            }
            narrative_sections.append(section)

    return {
        "attack_phases": len(narrative_sections),
        "narrative": narrative_sections,
        "summary": mapping["tactics_summary"],
    }
