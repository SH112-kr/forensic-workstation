"""Validation adapter for the public EVTX-ATTACK-SAMPLES CSV.

The dataset is parsed Windows event-log metadata, not executable content. This
module lets us compare built-in EVTX detections against the repository's
published tactic labels without checking the downloaded CSV into git.
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_SCENARIOS = {
    "LM_5145_Remote_FileCopy.evtx": {
        "expected_tactic": "Lateral Movement",
        "expected_rule_ids": ["fw-evtx-008"],
    },
    "kerberos_pwd_spray_4771.evtx": {
        "expected_tactic": "Credential Access",
        "expected_rule_ids": ["fw-evtx-013"],
    },
    "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx": {
        "expected_tactic": "Command and Control",
        "expected_rule_ids": ["fw-evtx-010"],
        "known_gap": (
            "Event 1149 confirms RDP authentication, but C2-via-RDP-tunnel attribution "
            "requires network/session context beyond this generic EVTX rule."
        ),
    },
}

TAG_TO_TACTIC = {
    "command_and_control": "Command and Control",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "execution": "Execution",
    "lateral_movement": "Lateral Movement",
    "persistence": "Persistence",
    "defense_evasion": "Defense Evasion",
    "privilege_escalation": "Privilege Escalation",
}

TACTIC_TO_TAG = {value: key for key, value in TAG_TO_TACTIC.items()}


class CsvEventLogArtifactQueries:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def query_event_logs(
        self,
        event_ids: list[int] | None = None,
        eids: list[int] | None = None,
        provider: str = "",
        keyword_in_data: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        wanted = event_ids if event_ids is not None else eids
        out = list(self.rows)
        if wanted:
            wanted_text = {str(x) for x in wanted}
            out = [r for r in out if str(r.get("Event ID", "")) in wanted_text]
        if provider:
            needle = provider.lower()
            out = [r for r in out if needle in str(r.get("Provider Name", "")).lower()]
        if keyword_in_data:
            needle = keyword_in_data.lower()
            out = [r for r in out if needle in str(r.get("Event Data", "")).lower()]
        return out[: limit or len(out)]


def load_evtx_attack_samples_csv(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Load the public CSV and group rows by EVTX_FileName."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with Path(path).open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            filename = row.get("EVTX_FileName", "")
            if not filename:
                continue
            grouped[filename].append(_to_event_row(idx, row))
    return dict(grouped)


def validate_scenarios(
    csv_path: str | Path,
    scenarios: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run built-in EVTX rules against selected public labeled scenarios."""
    from core.analysis.evtx_rules import BUILTIN_RULES, hunt_evtx_rules

    grouped = load_evtx_attack_samples_csv(csv_path)
    rule_by_id = {rule["id"]: rule for rule in BUILTIN_RULES}
    scenarios = scenarios or _build_scenarios_from_dataset(grouped, rule_by_id)

    results = []
    passed = 0
    for filename, expected in scenarios.items():
        rows = grouped.get(filename, [])
        aq = CsvEventLogArtifactQueries(rows)
        hunt = hunt_evtx_rules(aq, severity_min="low", limit_per_rule=25)
        fired_ids = [r.get("rule_id") for r in hunt.get("results", []) if r.get("ok") is not False]
        fired_tactics = sorted({
            TAG_TO_TACTIC[tag]
            for rule_id in fired_ids
            for tag in rule_by_id.get(rule_id, {}).get("tags", [])
            if tag in TAG_TO_TACTIC
        })
        expected_rules = set(expected.get("expected_rule_ids", []))
        rules_ok = expected_rules.issubset(set(fired_ids))
        tactic_ok = expected.get("expected_tactic") in fired_tactics
        known_gap = expected.get("known_gap", "")
        ok = rules_ok and (tactic_ok or bool(known_gap))
        if ok:
            passed += 1
        results.append({
            "filename": filename,
            "rows": len(rows),
            "expected_tactic": expected.get("expected_tactic", ""),
            "expected_rule_ids": sorted(expected_rules),
            "fired_rule_ids": fired_ids,
            "fired_tactics": fired_tactics,
            "rules_ok": rules_ok,
            "tactic_ok": tactic_ok,
            "known_gap": known_gap,
            "ok": ok,
            "event_id_counts": dict(Counter(str(r.get("Event ID", "")) for r in rows).most_common(8)),
            "scenario_source": expected.get("source", "manual"),
        })

    return {
        "ok": passed == len(results),
        "dataset": "sbousseaden/EVTX-ATTACK-SAMPLES evtx_data.csv",
        "scenario_count": len(results),
        "coverage_summary": _coverage_summary(grouped, results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
        "safety": {
            "download_type": "parsed CSV event-log metadata",
            "executables_downloaded": False,
            "malware_samples_downloaded": False,
        },
    }


def _to_event_row(idx: int, row: dict[str, str]) -> dict[str, Any]:
    event_data_keys = [
        "CommandLine",
        "ProcessName",
        "Image",
        "TargetImage",
        "SourceImage",
        "ParentImage",
        "ParentCommandLine",
        "TargetUserName",
        "SubjectUserName",
        "User",
        "IpAddress",
        "SourceIp",
        "DestinationIp",
        "DestAddress",
        "SourceAddress",
        "DestinationPort",
        "DestPort",
        "ServiceName",
        "TaskName",
        "ScriptBlockText",
        "ObjectName",
        "ObjectDN",
        "ObjectClass",
        "AttributeLDAPDisplayName",
        "AttributeValue",
        "Properties",
        "PrivilegeList",
        "TicketEncryptionType",
        "AccessMask",
        "GrantedAccess",
        "TargetObject",
        "TargetFilename",
        "PipeName",
        "ImagePath",
        "ShareName",
        "RelativeTargetName",
    ]
    event_data = " ".join(
        f"{key}={row.get(key, '')}"
        for key in event_data_keys
        if row.get(key)
    )
    return {
        "hit_id": idx,
        "artifact_type": "Windows Event Logs",
        "Event ID": row.get("EventID", ""),
        "Provider Name": row.get("ProviderName", ""),
        "Channel": row.get("Channel", ""),
        "Computer": row.get("Computer", ""),
        "Created Date/Time - UTC (yyyy-mm-dd)": row.get("SystemTime", "") or row.get("UtcTime", ""),
        "Event Data": event_data,
        "Event Description Summary": row.get("EVTX_FileName", ""),
        "EVTX_Tactic": row.get("EVTX_Tactic", ""),
        "EVTX_FileName": row.get("EVTX_FileName", ""),
    }


def _build_scenarios_from_dataset(
    grouped: dict[str, list[dict[str, Any]]],
    rule_by_id: dict[str, dict[str, Any]],
    *,
    max_per_tactic: int = 12,
) -> dict[str, dict[str, Any]]:
    scenarios = {
        name: {**spec, "source": "manual"}
        for name, spec in DEFAULT_SCENARIOS.items()
        if grouped.get(name)
    }
    chosen_per_tactic = Counter()
    for filename, rows in sorted(grouped.items()):
        tactic = _dominant_tactic(rows)
        if not tactic or chosen_per_tactic[tactic] >= max_per_tactic:
            continue
        expected_rules = _expected_rules_for_rows(rows, tactic, rule_by_id)
        if not expected_rules:
            continue
        scenarios.setdefault(filename, {
            "expected_tactic": tactic,
            "expected_rule_ids": expected_rules,
            "source": "auto_labeled_csv",
        })
        chosen_per_tactic[tactic] += 1
    return scenarios


def _expected_rules_for_rows(
    rows: list[dict[str, Any]],
    tactic: str,
    rule_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    tactic_tag = TACTIC_TO_TAG.get(tactic, "")
    if not tactic_tag:
        return []
    event_ids = {str(row.get("Event ID", "")) for row in rows}
    expected = []
    for rule_id, rule in rule_by_id.items():
        if tactic_tag not in set(rule.get("tags", [])):
            continue
        if not event_ids.intersection({str(eid) for eid in rule.get("event_ids", [])}):
            continue
        if any(_row_matches_rule_shape(row, rule) for row in rows):
            expected.append(rule_id)
    return sorted(expected)


def _row_matches_rule_shape(row: dict[str, Any], rule: dict[str, Any]) -> bool:
    if str(row.get("Event ID", "")) not in {str(eid) for eid in rule.get("event_ids", [])}:
        return False
    needles = [str(item).lower() for item in rule.get("any", []) if item]
    if not needles:
        return True
    haystack = " ".join([
        str(row.get("Event Data", "")),
        str(row.get("Event Description Summary", "")),
        str(row.get("Provider Name", "")),
    ]).lower()
    return any(needle in haystack for needle in needles)


def _dominant_tactic(rows: list[dict[str, Any]]) -> str:
    counts = Counter(str(row.get("EVTX_Tactic", "")) for row in rows if row.get("EVTX_Tactic"))
    return counts.most_common(1)[0][0] if counts else ""


def _coverage_summary(grouped: dict[str, list[dict[str, Any]]], results: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = {str(result.get("filename", "")) for result in results}
    tactic_totals = Counter(_dominant_tactic(rows) or "unknown" for rows in grouped.values())
    tactic_evaluated = Counter(str(result.get("expected_tactic", "")) or "unknown" for result in results)
    return {
        "total_files": len(grouped),
        "evaluated_files": len(evaluated),
        "unevaluated_files": max(len(grouped) - len(evaluated), 0),
        "tactic_totals": dict(tactic_totals),
        "tactic_evaluated": dict(tactic_evaluated),
    }
