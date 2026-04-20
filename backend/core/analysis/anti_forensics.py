"""Detect anti-forensic activity by looking for a small set of well-known
behavioural signals.

Every signal is tied to a publicly documented ATT&CK sub-technique (T1070.*).
The rule set is deliberately small and transparent — each rule carries its
exact match criteria in the response so the analyst can challenge or filter
any hit without reverse-engineering the tool.

Rules covered (intentionally conservative):

- T1070.001 Security log cleared        (Event ID 1102)
- T1070.001 System log cleared          (Event ID 104)
- T1490    Shadow-copy deletion         (vssadmin / wmic / powershell)
- T1070.002 USN journal deletion        (fsutil usn deletejournal)
- T1562.006 Sysmon / Windows Defender service stop
- T1562.002 PowerShell logging tamper   (ScriptBlockLogging / Transcription)
- T1070    Anti-forensic tool execution (sdelete, cipher /w, bcdedit disable)

Explicitly out of scope for this rule:

- Timestomp $SI/$FN divergence — data-heavy and noisy per case. Use
  ``get_file_timestamps`` manually on specific files instead.
- Heuristics derived from a single incident (ransomware families, APT
  toolmarks) — that would overfit the detector and violate the Claude
  rules the project agreed to.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from connectors.axiom_artifact_queries import ArtifactQueries


_VSS_PATTERNS = re.compile(
    r"(vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)"
    r"|wmic\s+shadowcopy\s+delete"
    r"|(powershell|pwsh)[^\n]*get-wmiobject[^\n]*win32_shadowcopy[^\n]*delete"
    r"|Get-WmiObject\s+Win32_Shadowcopy)",
    re.IGNORECASE,
)

_USN_PATTERNS = re.compile(
    r"fsutil(\.exe)?\s+usn\s+deletejournal", re.IGNORECASE,
)

_PS_LOGGING_PATTERNS = re.compile(
    r"Set-ItemProperty[^\n]*(EnableScriptBlockLogging|EnableTranscription|EnableModuleLogging)"
    r"|Remove-ItemProperty[^\n]*(EnableScriptBlockLogging|EnableTranscription|EnableModuleLogging)"
    r"|reg(\.exe)?\s+(add|delete)[^\n]*PowerShell[^\n]*(EnableScriptBlockLogging|EnableTranscription|EnableModuleLogging)",
    re.IGNORECASE,
)

_SERVICE_STOP_PATTERNS = re.compile(
    r"(net(\.exe)?|sc(\.exe)?)\s+stop\s+(sysmon|sysmon64|windefend|sense|wdnissvc|wuauserv|eventlog)"
    r"|Stop-Service\s+(-Name\s+)?(sysmon|sysmon64|windefend|sense|wdnissvc|wuauserv|eventlog)",
    re.IGNORECASE,
)

_CLEANUP_TOOLS = {
    "sdelete", "sdelete64", "cipher", "bcdedit", "wipefs",
}


def _collect_cmdlines(aq: ArtifactQueries) -> list[dict[str, Any]]:
    """Gather event-log hits likely to contain command lines.

    Sysmon EID 1, Security 4688, and PowerShell 4104 all carry command-line /
    script-block data. Returning the raw list lets rule functions apply their
    own regex without duplicating the query.
    """
    rows: list[dict[str, Any]] = []
    try:
        rows.extend(aq.query_process_creation_events(limit=0) or [])
    except Exception:
        pass
    try:
        rows.extend(aq.query_powershell_scriptblock(limit=0) or [])
    except Exception:
        pass
    return rows


def _cmdline_text(hit: dict[str, Any]) -> str:
    """Best-effort concatenation of fields that may contain command lines."""
    return " ".join(str(v) for v in (
        hit.get("Event Data", ""),
        hit.get("Event Description Summary", ""),
        hit.get("CommandLine", ""),
        hit.get("ProcessCommandLine", ""),
    ) if v)


def _hit_to_detail(
    hit: dict[str, Any],
    rule: str,
    evidence: str,
    matched_text: str,
    artifact_override: str | None = None,
) -> dict[str, Any]:
    return {
        "hit_id": hit.get("hit_id"),
        "rule": rule,
        "artifact_type": artifact_override or hit.get("artifact_type") or "Windows Event Logs",
        "timestamp": hit.get("Created Date/Time - UTC (yyyy-mm-dd)") or hit.get("Last Run Date/Time - UTC (yyyy-mm-dd)") or "",
        "computer": hit.get("Computer", ""),
        "evidence": evidence,
        "matched_text": matched_text[:400],
    }


def _rule_log_cleared(aq: ArtifactQueries) -> list[dict[str, Any]] | None:
    """Reuse the existing cleared-log query (EID 1102)."""
    try:
        hits = aq.query_log_cleared(limit=0)
    except Exception:
        return None
    return [
        _hit_to_detail(
            h, "log_cleared_security_1102",
            "Security audit log cleared (EID 1102)",
            str(h.get("Event Data", ""))[:400],
        )
        for h in hits
    ] or None


def _rule_system_log_cleared(aq: ArtifactQueries) -> list[dict[str, Any]] | None:
    try:
        hits = aq.query_event_logs(event_ids=[104], limit=0)
    except Exception:
        return None
    return [
        _hit_to_detail(
            h, "log_cleared_system_104",
            "System audit log cleared (EID 104)",
            str(h.get("Event Data", ""))[:400],
        )
        for h in hits
    ] or None


def _rule_shadow_copy_deletion(aq: ArtifactQueries, cmdlines: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    out = []
    for h in cmdlines:
        text = _cmdline_text(h)
        m = _VSS_PATTERNS.search(text)
        if m:
            out.append(_hit_to_detail(
                h, "vss_shadow_deletion",
                "Shadow-copy deletion command detected",
                m.group(0),
            ))
    return out or None


def _rule_usn_journal_deletion(aq: ArtifactQueries, cmdlines: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    out = []
    for h in cmdlines:
        text = _cmdline_text(h)
        m = _USN_PATTERNS.search(text)
        if m:
            out.append(_hit_to_detail(
                h, "usn_journal_deletion",
                "USN journal deletion command detected",
                m.group(0),
            ))
    return out or None


def _rule_ps_logging_tamper(aq: ArtifactQueries, cmdlines: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    out = []
    for h in cmdlines:
        text = _cmdline_text(h)
        m = _PS_LOGGING_PATTERNS.search(text)
        if m:
            out.append(_hit_to_detail(
                h, "ps_logging_tamper",
                "PowerShell logging / transcription registry key modification detected",
                m.group(0),
            ))
    return out or None


def _rule_defender_or_sysmon_stop(aq: ArtifactQueries, cmdlines: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    out = []
    for h in cmdlines:
        text = _cmdline_text(h)
        m = _SERVICE_STOP_PATTERNS.search(text)
        if m:
            out.append(_hit_to_detail(
                h, "security_service_stop",
                "Stop command targeting Sysmon / Defender / EventLog service",
                m.group(0),
            ))
    return out or None


def _rule_cleanup_tool_execution(aq: ArtifactQueries) -> list[dict[str, Any]] | None:
    """Prefetch entries for known anti-forensic cleanup utilities."""
    out: list[dict[str, Any]] = []
    for tool in _CLEANUP_TOOLS:
        try:
            hits = aq.query_prefetch(app_name_filter=tool, limit=0) or []
        except Exception:
            continue
        for h in hits:
            app = str(h.get("Application Name", "") or "")
            # Guard against substring matches (sdelete vs sdelete64 is fine; cipher vs ciphersec is not).
            base = app.upper().split(".")[0].replace("-", "")
            if not base.startswith(tool.upper()):
                continue
            out.append({
                "hit_id": h.get("hit_id"),
                "rule": "cleanup_tool_execution",
                "artifact_type": "Prefetch",
                "timestamp": h.get("Last Run Date/Time - UTC (yyyy-mm-dd)", "") or h.get("Last Run Time", ""),
                "evidence": f"Anti-forensic utility executed: {app}",
                "matched_text": app,
            })
    return out or None


def detect_anti_forensics(aq: ArtifactQueries) -> dict[str, Any]:
    """Run every rule and return a single consolidated envelope.

    Each rule carries its own ``details`` list plus a human-readable
    description of what it matched. Empty rules are dropped so the caller can
    render only what fired. MITRE technique IDs are attached per-rule.
    """
    cmdlines = _collect_cmdlines(aq)

    rule_descriptors = [
        (
            "log_cleared_security_1102", "T1070.001",
            "Security audit log cleared (EID 1102) — strong anti-forensic signal.",
            lambda: _rule_log_cleared(aq),
        ),
        (
            "log_cleared_system_104", "T1070.001",
            "System audit log cleared (EID 104).",
            lambda: _rule_system_log_cleared(aq),
        ),
        (
            "vss_shadow_deletion", "T1490",
            "Shadow-copy deletion command detected in process creation / scriptblock events.",
            lambda: _rule_shadow_copy_deletion(aq, cmdlines),
        ),
        (
            "usn_journal_deletion", "T1070.002",
            "USN journal deletion command detected.",
            lambda: _rule_usn_journal_deletion(aq, cmdlines),
        ),
        (
            "ps_logging_tamper", "T1562.002",
            "PowerShell logging / transcription keys modified to suppress recording.",
            lambda: _rule_ps_logging_tamper(aq, cmdlines),
        ),
        (
            "security_service_stop", "T1562.001",
            "Stop-Service / net stop / sc stop targeting Sysmon, Defender, or EventLog.",
            lambda: _rule_defender_or_sysmon_stop(aq, cmdlines),
        ),
        (
            "cleanup_tool_execution", "T1070",
            "Prefetch entries for known anti-forensic utilities (sdelete, cipher, bcdedit, wipefs).",
            lambda: _rule_cleanup_tool_execution(aq),
        ),
    ]

    rules_output = []
    total_hits = 0
    for name, technique, desc, fn in rule_descriptors:
        try:
            details = fn()
        except Exception as e:  # noqa: BLE001 — rule failures must not poison the others
            rules_output.append({
                "rule_name": name, "ok": False, "error": str(e),
                "mitre_technique": technique, "description": desc,
            })
            continue
        if not details:
            continue
        total_hits += len(details)
        rules_output.append({
            "rule_name": name, "ok": True,
            "mitre_technique": technique,
            "description": desc,
            "count": len(details),
            "details": details,
        })

    return {
        "ok": True,
        "rules_fired": len([r for r in rules_output if r.get("ok") and r.get("count")]),
        "total_hits": total_hits,
        "rules": rules_output,
        "notes": [
            "Timestomp ($SI vs $FN divergence) is intentionally out of scope — use get_file_timestamps "
            "on specific suspect files instead.",
            "Heuristics tied to any single incident are excluded by design. All matches above come from "
            "publicly documented ATT&CK sub-techniques (T1070.*/T1562.*/T1490).",
        ],
    }
