"""Artifact-first evidence bundles for LLM and analyst workflows.

The purpose of this module is to package raw artifact families and direct
artifact searches into methodology-oriented bundles. These bundles are meant
to be the *primary* analysis surface for LLM reasoning, while rule-based
findings remain an analyst-assist layer.
"""

from __future__ import annotations

from typing import Any


_BUNDLE_SPECS: list[dict[str, Any]] = [
    {
        "bundle_id": "execution_evidence",
        "label": "Execution Evidence Bundle",
        "why_it_matters": "Use execution artifacts to establish what actually ran, when it ran, and whether multiple sources corroborate execution.",
        "methodology": [
            "Start with Prefetch / UserAssist / AmCache / script logs rather than malware-family or rule names.",
            "Confirm whether multiple independent sources agree on execution timing and executable identity.",
        ],
        "artifacts": [
            {"artifact_type": "Prefetch Files - Windows 8/10/11", "signal_weight": 2.5, "count_cap": 25},
            {"artifact_type": "UserAssist", "signal_weight": 2.0, "count_cap": 12},
            {"artifact_type": "AmCache File Entries", "signal_weight": 1.5, "count_cap": 30},
            {"artifact_type": "PowerShell History", "signal_weight": 3.0, "count_cap": 6},
            {"artifact_type": "Windows Event Logs - Script Events", "signal_weight": 2.5, "count_cap": 12},
        ],
    },
    {
        "bundle_id": "persistence_evidence",
        "label": "Persistence Evidence Bundle",
        "why_it_matters": "Use service, task, autorun, and startup artifacts to determine whether access is transient or configured to survive reboot or user logon.",
        "methodology": [
            "Treat persistence as a file-system and configuration question first, not as a rule verdict.",
            "Check service/task/startup entries alongside their paths and surrounding execution evidence.",
        ],
        "artifacts": [
            {"artifact_type": "System Services", "signal_weight": 1.8, "count_cap": 20},
            {"artifact_type": "Scheduled Tasks", "signal_weight": 1.3, "count_cap": 20},
            {"artifact_type": "AutoRun Items", "signal_weight": 2.0, "count_cap": 12},
            {"artifact_type": "Startup Items", "signal_weight": 2.0, "count_cap": 8},
            {"artifact_type": "Windows Event Logs - Service Events", "signal_weight": 1.0, "count_cap": 15},
        ],
    },
    {
        "bundle_id": "credential_evidence",
        "label": "Credential Evidence Bundle",
        "why_it_matters": "Use credential and logon-oriented artifacts to separate hostile credential use from expected local session behavior.",
        "methodology": [
            "Start from the target account, target host, and process context for credential events.",
            "Look for supporting process, session, and remote-access context before calling it hostile credential activity.",
        ],
        "artifacts": [
            {"artifact_type": "Windows Stored Credentials", "signal_weight": 3.5, "count_cap": 4},
            {"artifact_type": "Passwords and Tokens", "signal_weight": 3.5, "count_cap": 4},
            {"artifact_type": "Windows Event Logs", "keyword": "4648", "signal_weight": 1.2, "count_cap": 12},
        ],
    },
    {
        "bundle_id": "impact_evidence",
        "label": "Impact Evidence Bundle",
        "why_it_matters": "Use file-system change artifacts and user-facing marker artifacts to assess whether the case includes destructive or extortion-style impact.",
        "methodology": [
            "Prefer file-system and document artifacts over family-name assumptions.",
            "Validate note-style markers against timeline placement and deletion / rename evidence.",
        ],
        "artifacts": [
            {"artifact_type": "Encrypted Files", "signal_weight": 4.5, "count_cap": 20},
            {"artifact_type": "Text Documents", "keyword": "README", "signal_weight": 1.2, "count_cap": 10},
            {"artifact_type": "Windows Event Logs", "keyword": "Ransom:", "signal_weight": 6.0, "count_cap": 4},
            {"artifact_type": "$LogFile Analysis", "signal_weight": 0.15, "count_cap": 8},
            {"artifact_type": "UsnJrnl", "signal_weight": 0.12, "count_cap": 10},
            {"artifact_type": "File Signature Mismatch (Document)", "signal_weight": 0.2, "count_cap": 8},
        ],
    },
    {
        "bundle_id": "remote_access_evidence",
        "label": "Remote Access Evidence Bundle",
        "why_it_matters": "Use network, browser, and session-facing artifacts to determine whether access was interactive, remote, or tied to administrative tooling.",
        "methodology": [
            "Correlate network/session artifacts with downloads, browser activity, and service/task installs.",
            "Do not assume a remote-access tool is malicious without deployment and session context.",
        ],
        "artifacts": [
            {"artifact_type": "Potential Browser Activity", "signal_weight": 0.8, "count_cap": 12},
            {"artifact_type": "Edge Downloads", "signal_weight": 3.0, "count_cap": 6},
            {"artifact_type": "SRUM Network Connections", "signal_weight": 1.3, "count_cap": 12},
            {"artifact_type": "SRUM Network Usage", "signal_weight": 0.8, "count_cap": 12},
            {"artifact_type": "Windows Event Logs - Firewall Events", "signal_weight": 1.0, "count_cap": 10},
        ],
    },
]


def _artifact_type_count(connector: Any, artifact_type: str) -> int:
    try:
        rows = connector.get_artifact_type_counts() or []
    except Exception:
        rows = []
    total = 0
    for row in rows:
        art = str(row.get("artifact_type") or row.get("artifact_name") or "")
        cnt = int(row.get("count") or row.get("hit_count") or 0)
        if art == artifact_type:
            total += cnt
    return total


def _sample_hit(hit: dict[str, Any]) -> dict[str, Any]:
    out = {
        "hit_id": hit.get("hit_id"),
        "artifact_type": hit.get("artifact_type", ""),
    }
    if hit.get("source_path"):
        out["source_path"] = hit.get("source_path")
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    if hit.get("timestamp"):
        out["timestamp"] = hit.get("timestamp")
    snippets: list[str] = []
    if fields:
        for key, value in fields.items():
            if value in (None, ""):
                continue
            snippets.append(f"{key}={value}")
            if len(snippets) >= 2:
                break
    else:
        for key in ("description", "evidence", "Name", "Filename", "Full Path", "Path"):
            value = hit.get(key)
            if value:
                snippets.append(f"{key}={value}")
            if len(snippets) >= 2:
                break
    if snippets:
        out["snippet"] = " | ".join(snippets)
    return out


def _artifact_entry(connector: Any, spec: dict[str, Any]) -> dict[str, Any]:
    artifact_type = spec["artifact_type"]
    keyword = str(spec.get("keyword", "") or "")
    count = _artifact_type_count(connector, artifact_type)
    search_total = None
    samples: list[dict[str, Any]] = []

    try:
        result = connector.search(
            keyword=keyword,
            filters={"artifact_type": artifact_type},
            limit=3,
            offset=0,
        )
        search_total = int(result.get("total", 0))
        samples = [_sample_hit(h) for h in (result.get("hits") or [])[:3]]
    except Exception:
        pass

    return {
        "artifact_type": artifact_type,
        "query_keyword": keyword,
        "artifact_count": count,
        "search_total": search_total if search_total is not None else count,
        "samples": samples,
        "signal_weight": float(spec.get("signal_weight", 1.0)),
        "count_cap": int(spec.get("count_cap", 10)),
    }


def _entry_signal_score(entry: dict[str, Any]) -> float:
    total = int(entry.get("search_total", 0) or 0)
    weight = float(entry.get("signal_weight", 1.0) or 1.0)
    cap = int(entry.get("count_cap", 10) or 10)
    capped_total = min(total, cap)
    return round(capped_total * weight, 2)


def _impact_bundle_bonus(entries: list[dict[str, Any]]) -> float:
    by_type = {str(e.get("artifact_type", "")): e for e in entries}
    encrypted = int(by_type.get("Encrypted Files", {}).get("search_total", 0) or 0)
    notes = int(by_type.get("Text Documents", {}).get("search_total", 0) or 0)
    av_ransom = int(by_type.get("Windows Event Logs", {}).get("search_total", 0) or 0)
    usn = int(by_type.get("UsnJrnl", {}).get("search_total", 0) or 0)
    logfile = int(by_type.get("$LogFile Analysis", {}).get("search_total", 0) or 0)
    bonus = 0.0

    # Strong impact should come from combined signals, not from raw journal volume.
    if encrypted > 0 and notes > 0:
        bonus += 12.0
    if encrypted > 0 and (usn > 0 or logfile > 0):
        bonus += 5.0
    if notes > 0 and (usn > 0 or logfile > 0):
        bonus += 1.5
    if av_ransom > 0 and (encrypted > 0 or notes > 0):
        bonus += 10.0
    return bonus


def _bundle_signal_score(bundle_id: str, entries: list[dict[str, Any]]) -> float:
    score = sum(_entry_signal_score(entry) for entry in entries)
    if bundle_id == "impact_evidence":
        score += _impact_bundle_bonus(entries)
    return round(score, 2)


def build_artifact_bundles(connector: Any) -> dict[str, Any]:
    bundles: list[dict[str, Any]] = []
    for spec in _BUNDLE_SPECS:
        entries = [_artifact_entry(connector, art) for art in spec["artifacts"]]
        evidence_total = sum(int(e.get("search_total", 0) or 0) for e in entries)
        signal_score = _bundle_signal_score(spec["bundle_id"], entries)
        bundles.append({
            "bundle_id": spec["bundle_id"],
            "label": spec["label"],
            "why_it_matters": spec["why_it_matters"],
            "methodology": list(spec["methodology"]),
            "artifacts": entries,
            "evidence_total": evidence_total,
            "signal_score": signal_score,
        })

    bundles.sort(key=lambda b: (-float(b.get("signal_score", 0)), -int(b.get("evidence_total", 0)), b.get("bundle_id", "")))
    return {
        "artifact_bundles": bundles,
        "notes": [
            "artifact_bundles are the primary analysis surface for LLM reasoning and method-driven review.",
            "bundle ordering uses signal_score rather than raw artifact volume so generic high-volume sources do not dominate by default.",
            "rule-based findings should be treated as analyst assists layered on top of these bundles, not as the main case narrative.",
        ],
    }
