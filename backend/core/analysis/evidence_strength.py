"""Tag forensic evidence with a CLAUDE.md-aligned strength tier.

CLAUDE.md defines four tiers that the tool output should surface explicitly:

- **confirmed** — Prefetch Last Run co-occurring with SRUM, MFT timestamps,
  Event Log EIDs that definitively record the action (7045 service install,
  1102 log clear, 4688 process creation, 4624 logon).
- **strong**    — Prefetch Run Count > 0 (execution is certain, but the
  command-line / arguments are not recorded).
- **moderate**  — AmCache File / Program Entries (proves the file existed on
  disk with metadata; does not prove execution).
- **weak**      — Shim Cache (file-existence only, not execution), Link Date
  (compile time, not deployment time), absence-based signals.

Everything is rule-based, transparent, and offline. Every tagged item carries
a ``strength_reason`` string so an analyst can see which criteria fired.
"""

from __future__ import annotations

import re
from typing import Any

# Rule ordering matters — the first rule that matches wins. Keep
# highest-confidence rules near the top.
_RULES: list[dict[str, Any]] = [
    # ── confirmed ──────────────────────────────────────────────────────────
    {
        "tier": "confirmed",
        "match_artifact": re.compile(r"event\s*logs?\s*\(?.*(4688|4624|4634|4648|4697|7045|1102|4698|4702)", re.I),
        "reason": "Windows Event Log with definitive EID (process creation / logon / service / log clear / task).",
    },
    {
        "tier": "confirmed",
        "match_artifact": re.compile(r"\bSRUM\b|\bsystem\s*resource\s*usage", re.I),
        "reason": "SRUM records process execution and network usage over time — authoritative execution evidence.",
    },
    {
        "tier": "confirmed",
        "match_artifact": re.compile(r"master\s*file\s*table|\$MFT|MFT\s*Created", re.I),
        "reason": "NTFS $MFT timestamps are the canonical file-system truth for a given volume.",
    },
    # ── strong ─────────────────────────────────────────────────────────────
    {
        "tier": "strong",
        "match_artifact": re.compile(r"prefetch", re.I),
        "reason": (
            "Prefetch Last Run proves the binary was executed. Note: Prefetch does NOT "
            "record command-line arguments — pair with Sysmon EID 1 or Security 4688 "
            "for cmdline context."
        ),
    },
    {
        "tier": "strong",
        "match_artifact": re.compile(r"sysmon|security.*scriptblock|event\s*logs?\s*\(?.*4104", re.I),
        "reason": "Sysmon / PowerShell ScriptBlock logs capture full activity context at the time it happened.",
    },
    # ── moderate ───────────────────────────────────────────────────────────
    {
        "tier": "moderate",
        "match_artifact": re.compile(r"amcache", re.I),
        "reason": (
            "AmCache records file existence and metadata. It does NOT prove execution — "
            "pair with Prefetch or SRUM for execution evidence."
        ),
    },
    {
        "tier": "moderate",
        "match_artifact": re.compile(r"user\s*assist", re.I),
        "reason": "UserAssist records GUI-initiated launches; misses command-line and service starts.",
    },
    {
        "tier": "moderate",
        "match_artifact": re.compile(r"scheduled\s*tasks?", re.I),
        "reason": "Scheduled task XML / registry proves a task exists but may lack creation-time context.",
    },
    # ── weak ───────────────────────────────────────────────────────────────
    {
        "tier": "weak",
        "match_artifact": re.compile(r"shim\s*cache|appcompat\s*cache|application\s*compatibility\s*cache", re.I),
        "reason": (
            "Shim Cache records file existence only. An entry is NOT execution proof — "
            "the OS populates Shim Cache when it inspects a file for compatibility."
        ),
    },
    {
        "tier": "weak",
        "match_artifact": re.compile(r"link\s*date|compile\s*time", re.I),
        "reason": (
            "Link Date / compile time is set by the build toolchain, not by deployment. "
            "Never use Link Date to infer when a binary was placed on the host."
        ),
    },
]


def classify_artifact(artifact_type: str, fields: dict[str, Any] | None = None) -> dict[str, str]:
    """Return ``{tier, reason}`` for a single evidence item.

    Unknown artifact types default to ``moderate`` with an explicit
    "unclassified" reason so the tool output never silently asserts confidence.
    """
    haystack = artifact_type or ""
    if fields:
        # Let a hit promote into higher tiers when it carries corroborating
        # fields (e.g. a SRUM "Last Run" hit inside an Event-Logs row).
        haystack = haystack + " " + " ".join(str(v) for v in fields.values() if v is not None)

    for rule in _RULES:
        if rule["match_artifact"].search(haystack):
            return {"tier": rule["tier"], "reason": rule["reason"]}

    return {
        "tier": "moderate",
        "reason": "Artifact type did not match a rule; default 'moderate'. Consider verifying with corroborating sources.",
    }


def _upgrade_with_corroboration(tier: str, same_path_tiers: set[str]) -> tuple[str, str | None]:
    """Upgrade to ``confirmed`` when Prefetch + SRUM (or + MFT) corroborate.

    Returns the final tier and an optional extra reason to append.
    """
    if tier == "strong" and ("confirmed" in same_path_tiers):
        return "confirmed", "Corroborating SRUM / MFT / Event Log hit for the same target — upgraded to confirmed."
    return tier, None


def _extract_path_key(entry: dict[str, Any]) -> str | None:
    """Grab a canonical path-ish identifier used for cross-artifact corroboration.

    We intentionally keep this light — just filename or service name — because
    richer matching quickly degrades into overfitting. If you want to tighten
    it later, prefer MFT FRN / full absolute path over filename.
    """
    fields = entry.get("fields") if isinstance(entry, dict) else None
    if not isinstance(fields, dict):
        fields = {}
    for key in ("Application Name", "Name", "ImageFileName", "Image", "Service Name", "CommandLine", "ExecutableName"):
        v = fields.get(key) or entry.get(key)
        if v:
            s = str(v).lower()
            return s.split("\\")[-1].split("/")[-1]
    return None


def score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Annotate a single find_suspicious finding in place and return it.

    Each detail gains ``strength`` and ``strength_reason``. The finding itself
    gets an ``overall_strength`` (highest tier any detail earned).
    """
    details = finding.get("details") or []

    # First pass: classify each detail individually.
    same_path_tiers: dict[str, set[str]] = {}
    for d in details:
        artifact_type = str(d.get("artifact_type", "") or "")
        fields = d.get("fields") if isinstance(d.get("fields"), dict) else None
        verdict = classify_artifact(artifact_type, fields)
        d["strength"] = verdict["tier"]
        d["strength_reason"] = verdict["reason"]
        key = _extract_path_key(d)
        if key:
            same_path_tiers.setdefault(key, set()).add(verdict["tier"])

    # Second pass: apply corroboration upgrades.
    for d in details:
        key = _extract_path_key(d)
        if not key:
            continue
        upgraded, note = _upgrade_with_corroboration(d["strength"], same_path_tiers[key])
        if note:
            d["strength"] = upgraded
            d["strength_reason"] = d["strength_reason"] + " " + note

    # Roll up the highest tier for the finding as a whole.
    tier_order = {"confirmed": 4, "strong": 3, "moderate": 2, "weak": 1}
    best = max(
        (tier_order.get(d.get("strength", "moderate"), 2) for d in details),
        default=2,
    )
    tier_name = next((k for k, v in tier_order.items() if v == best), "moderate")
    finding["overall_strength"] = tier_name
    return finding


def score_findings(payload: dict[str, Any]) -> dict[str, Any]:
    """Annotate an entire find_suspicious payload with strength tiers.

    Safe to run on a payload that already has ``overall_strength`` — the tags
    are deterministic and overwrite-stable.
    """
    findings = payload.get("findings") or []
    for f in findings:
        score_finding(f)

    # Summary counts for the UI.
    rollup = {"confirmed": 0, "strong": 0, "moderate": 0, "weak": 0}
    for f in findings:
        rollup[f.get("overall_strength", "moderate")] = rollup.get(f.get("overall_strength", "moderate"), 0) + 1

    payload["strength_rollup"] = rollup
    payload["strength_notes"] = [
        "Tiers follow CLAUDE.md: confirmed (Prefetch+SRUM, MFT, definitive EID), "
        "strong (Prefetch Last Run, Sysmon/ScriptBlock), moderate (AmCache, UserAssist), "
        "weak (Shim Cache, Link Date).",
        "Shim Cache entries and Link Date are NOT execution proof — treat them as weak unless corroborated.",
    ]
    return payload
