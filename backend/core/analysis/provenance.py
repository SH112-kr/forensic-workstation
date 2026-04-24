"""Attach per-finding provenance: what supports it, what is absent.

Sits between ``find_suspicious`` / ``detect_anti_forensics`` output and the
UI. For every finding we enumerate:

- ``supporting_artifacts`` — the artifact families actually present in the
  finding's details, with hit counts and sample hit_ids so the analyst can
  drill back.
- ``absent_corroboration`` — the families that would *normally* corroborate
  this rule but are NOT present in the current case. Pulled from a static
  per-rule map; each entry carries a ``reason`` string derived from
  ``coverage.classify_artifact`` so weak absence (no records) is clearly
  distinguished from structural unavailability (wrong case format).

Everything is deterministic and transparent: the mapping is plain Python
data, no LLM inference, and ``absent_corroboration`` can be audited by
reading this file.
"""

from __future__ import annotations

from typing import Any


# Per-rule corroborating artifact families. These are the families an analyst
# would normally check alongside the rule's own evidence to strengthen the
# finding. Pulled from the forensics literature and CLAUDE.md guidance (e.g.
# Prefetch Last Run + SRUM = confirmed execution).
#
# Format: rule_name -> list of family names (exact strings the connectors
# use in artifact_type_counts). Keep this list conservative — it only has
# to name families that meaningfully corroborate, not every possible
# adjacent artifact.
CORROBORATION_MAP: dict[str, list[str]] = {
    "sysmon_eid10_lsass_handle_open": [
        "Windows Event Logs (EID 4688)",
        "SRUM",
        "Prefetch",
    ],
    "evtx_eid_4688_process_creation_events": [
        "SRUM",
        "Prefetch",
        "Sysmon Event Logs",
    ],
    "evtx_eid_7045_service_installs": [
        "Prefetch",
        "Amcache",
        "System Services",
    ],
    "evtx_eid_4698_scheduled_task_events": [
        "Scheduled Tasks",
        "Prefetch",
    ],
    "evtx_eid_1102_audit_log_cleared": [
        "System Event Logs",
        "Security Event Logs",
    ],
    "evtx_eid_4624_type10_rdp_logons": [
        "Prefetch",
        "Amcache",
        "Windows Event Logs (EID 4624)",
    ],
    "evtx_eid_4648_explicit_credential_logons": [
        "Windows Event Logs (EID 4624)",
        "SRUM",
    ],
    "prefetch_pentest_tool_names": [
        "Windows Event Logs (EID 4688)",
        "SRUM",
        "Amcache",
    ],
    "services_nonstandard_binary_paths": [
        "Amcache",
        "Prefetch",
        "Windows Event Logs (EID 7045)",
    ],
    "evtx_eid_4104_scriptblock_logs": [
        "Windows Event Logs (EID 4688)",
        "SRUM",
    ],
    "prefetch_security_sw_werfault_correlation": [
        "WER Reports",
        "SRUM",
    ],
    "amcache_remote_access_tool_names": [
        "Amcache",
        "Prefetch",
        "Scheduled Tasks",
    ],
    "openssh_artifacts": [
        "Windows Event Logs (EID 4624)",
        "Prefetch",
        "Amcache",
    ],
}


def _present_families(loaded_type_counts: dict[str, int]) -> set[str]:
    """Loose set of family names that have records in the loaded cases."""
    return {name for name, count in loaded_type_counts.items() if count > 0}


def _loose_match(want: str, present: set[str]) -> bool:
    """Match 'Windows Event Logs (EID 4688)' against 'Windows Event Logs'.

    The rule map uses specific family names; the connector returns broader
    categories. A substring match in either direction is good enough to say
    "the family is present" — we'd rather over-count presence than falsely
    claim corroboration is missing.
    """
    w = want.lower()
    for p in present:
        pl = p.lower()
        if w in pl or pl in w:
            return True
    return False


def _classify_absence(family: str, case_format: str) -> tuple[str, str]:
    """Return (status, reason) for a family that is not present.

    status is one of:
      - 'structurally_unavailable'  (current case format cannot produce it)
      - 'zero_records'              (format supports it but none loaded)
    """
    # Minimal structural heuristic: AXIOM-only families on KAPE-only cases
    # are structurally unavailable. Everything else defaults to zero_records.
    axiom_only_hints = ("chat", "mobile", "webmail", "carved", "identifier", "ssh keys", "known_hosts", "pdf", "hwp")
    is_axiom_only = any(h in family.lower() for h in axiom_only_hints)
    if case_format == "kape" and is_axiom_only:
        return (
            "structurally_unavailable",
            f"{family} is an AXIOM-only family and cannot exist in a KAPE-only case.",
        )
    return (
        "zero_records",
        f"{family} is supported by the current case format but has no records. "
        "Verify whether the activity is genuinely absent or the parser missed it.",
    )


def _summarize_details(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group finding details by artifact_type with counts and sample hit_ids."""
    grouped: dict[str, dict[str, Any]] = {}
    for d in details or []:
        art = str(d.get("artifact_type", "") or "(unknown)")
        g = grouped.setdefault(art, {"artifact_type": art, "count": 0, "sample_hit_ids": []})
        g["count"] += 1
        hid = d.get("hit_id")
        if hid is not None and len(g["sample_hit_ids"]) < 5:
            g["sample_hit_ids"].append(hid)
    return sorted(grouped.values(), key=lambda x: -x["count"])


def attach_provenance(
    payload: dict[str, Any],
    connectors: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Enrich a ``find_suspicious`` payload with per-finding provenance.

    Mutates and returns ``payload``. Safe to run on an already-provenance-
    annotated payload (idempotent — supporting_artifacts / absent_corroboration
    blocks are overwritten).
    """
    # Aggregate loaded artifact type counts across every connected axiom case.
    loaded: dict[str, int] = {}
    case_format = "none"
    if connectors:
        kinds: list[str] = []
        for name, c in connectors.items():
            if not name.startswith("axiom:"):
                continue
            if not getattr(c, "is_connected", lambda: False)():
                continue
            try:
                meta = c.get_metadata() or {}
            except Exception:
                meta = {}
            k = str(meta.get("source_type") or "").lower()
            if k:
                kinds.append(k)
            try:
                rows = c.get_artifact_type_counts() or []
            except Exception:
                rows = []
            for row in rows:
                art = row.get("artifact_name") or row.get("artifact_type") or row.get("name")
                cnt = int(row.get("hit_count") or row.get("count") or 0)
                if art:
                    loaded[art] = loaded.get(art, 0) + cnt
        if "mfdb" in kinds and "kape" in kinds:
            case_format = "mixed"
        elif "mfdb" in kinds:
            case_format = "mfdb"
        elif "kape" in kinds:
            case_format = "kape"
        elif kinds:
            case_format = "unknown"
        else:
            case_format = "none"

    present = _present_families(loaded)

    for f in payload.get("findings", []):
        rule_name = f.get("rule_name", "")
        f["supporting_artifacts"] = _summarize_details(f.get("details") or [])

        # Absent corroboration: consult the static map, filter to families that
        # aren't already present in the case.
        expected = CORROBORATION_MAP.get(rule_name, [])
        absent: list[dict[str, Any]] = []
        for fam in expected:
            if _loose_match(fam, present):
                continue
            status, reason = _classify_absence(fam, case_format)
            absent.append({"family": fam, "status": status, "reason": reason})
        f["absent_corroboration"] = absent

    payload["provenance_case_format"] = case_format
    payload["provenance_notes"] = [
        "supporting_artifacts lists the families actually backing the finding, with hit_id samples.",
        "absent_corroboration lists families that would normally strengthen the finding but are "
        "structurally_unavailable or have zero_records in the loaded case(s).",
        "Corroboration map is transparent: see core/analysis/provenance.py::CORROBORATION_MAP.",
    ]
    return payload
