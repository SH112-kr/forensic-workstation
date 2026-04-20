"""Per-rule coverage introspection for find_suspicious.

Distinguishes three outcomes an analyst needs separately:

1. **Rule fired** — rule ran and produced hits.
2. **Rule evaluated, no hits** — rule's required artifact families had
   records; the rule simply did not match anything suspicious. Silent but
   meaningful: the substrate was there, the behaviour wasn't.
3. **Rule not evaluable** — the rule's required artifacts are not present
   in the loaded case(s) at all. The "no hits" outcome is meaningless here;
   absence is not evidence.

Design follows Codex Round-4 review:

- Requirements are declared as **groups**, not a flat family list.
  ``RULE_REQUIREMENTS[rule] = [group1, group2, ...]`` — all groups must be
  satisfied. Within a group, any listed family satisfies it. This lets a
  rule say "I need EventLogs AND (Prefetch OR AmCache)" explicitly.
- Family matching is **exact** with explicit aliases, not loose substring.
  A loaded family named ``Prefetch Files - Windows 8/10/11`` matches
  ``Prefetch`` because ``Prefetch`` is one of the declared aliases; a
  loaded family called ``Prefetching`` does NOT match.
- ``attach_rule_coverage`` never mutates a rule's own semantics; it only
  annotates the payload with additive metadata. Callers who want the old
  shape pass ``include_rule_coverage=False`` to ``find_suspicious``.
"""

from __future__ import annotations

from typing import Any


# Rule requirements as lists of groups. Rule is evaluable iff EVERY group is
# satisfied. Within a group, ANY alias suffices.
#
# Keep this map conservative: only list families a rule genuinely cannot run
# without. Rules that degrade gracefully (still fire from a single EID even
# if the richer context is missing) should have their single must-have
# family listed.
RULE_REQUIREMENTS: dict[str, list[list[str]]] = {
    "lsass_access":                 [["Windows Event Logs"]],
    "suspicious_process_creation":  [["Windows Event Logs"]],
    "service_installation":         [["Windows Event Logs"]],
    "scheduled_task_creation":      [["Windows Event Logs", "Scheduled Tasks"]],
    "log_clearing":                 [["Windows Event Logs"]],
    "rdp_lateral_movement":         [["Windows Event Logs"]],
    "explicit_credential_use":      [["Windows Event Logs"]],
    "suspicious_prefetch":          [["Prefetch"]],
    "suspicious_service_paths":     [["System Services"]],
    "powershell_scriptblock":       [["Windows Event Logs"]],
    "watering_hole_indicators":     [["Prefetch"], ["Startup Items"]],
    "suspicious_msi_install":       [["AmCache"]],
    "ssh_activity":                 [["Windows Event Logs", "System Services", "Prefetch", "SSH Keys"]],
}


# Family-name aliases the connectors actually emit. Keep this explicit —
# loose substring matching silently misclassifies families with similar
# words (e.g. "Prefetching" would match "Prefetch" under substring rules).
FAMILY_ALIASES: dict[str, list[str]] = {
    "Windows Event Logs": [
        "Windows Event Logs",
        "Event Logs",
    ],
    "Prefetch": [
        "Prefetch",
        "Prefetch Files",
        "Prefetch Files - Windows 8/10/11",
    ],
    "AmCache": [
        "AmCache",
        "Amcache",
        "AmCache File Entries",
        "AmCache Program Entries",
    ],
    "Scheduled Tasks": [
        "Scheduled Tasks",
    ],
    "System Services": [
        "System Services",
        "Services",
    ],
    "Startup Items": [
        "Startup Items",
        "Startup Folder",
    ],
    "SSH Keys": [
        "SSH Keys",
        "SSH Known Hosts",
    ],
}


def _present(family: str, loaded: set[str]) -> bool:
    """Exact-match with alias expansion + ``name (sub)`` prefix handling.

    A loaded family name matches when it equals a declared alias, OR when
    it starts with ``alias + " ("`` (captures variants like
    ``Windows Event Logs (EID 4688)``). Nothing else matches — substring
    collisions stay excluded.
    """
    aliases = FAMILY_ALIASES.get(family, [family])
    for alias in aliases:
        for name in loaded:
            if name == alias or name.startswith(alias + " ("):
                return True
    return False


def evaluate_rule_coverage(
    rule_name: str,
    loaded_type_counts: dict[str, int],
) -> dict[str, Any]:
    """Return the coverage verdict for a single rule.

    Args:
        rule_name: Rule identifier (find_suspicious ``rule_name``).
        loaded_type_counts: ``artifact_name -> hit_count`` summed across
            every loaded case. Families with zero counts are treated as
            absent — "format supports this but parsed zero rows" is
            evaluable=False for our purposes because the rule cannot run.

    Returns ``{coverage_status, required_families, present_families,
    missing_families, satisfied_groups, unsatisfied_groups,
    reason_not_evaluable}``.
    """
    groups = RULE_REQUIREMENTS.get(rule_name)
    if groups is None:
        # Unknown rule — we don't want to flip it to "not_evaluable" based on
        # a gap in our metadata. Evaluable by default; an explicit note says
        # coverage is unknown so readers don't overinterpret.
        return {
            "coverage_status": "evaluated",
            "required_families": [],
            "present_families": [],
            "missing_families": [],
            "satisfied_groups": 0,
            "unsatisfied_groups": [],
            "reason_not_evaluable": None,
            "note": "No coverage metadata declared for this rule.",
        }

    loaded_with_records = {n for n, c in loaded_type_counts.items() if c > 0}

    satisfied: list[list[str]] = []
    unsatisfied: list[dict[str, Any]] = []
    for group in groups:
        if any(_present(fam, loaded_with_records) for fam in group):
            satisfied.append(group)
        else:
            unsatisfied.append({
                "alternatives": list(group),
                "reason": "No alternative in this group has records in the loaded case(s).",
            })

    required_flat = sorted({fam for g in groups for fam in g})
    present_flat = sorted([fam for fam in required_flat if _present(fam, loaded_with_records)])
    all_satisfied = not unsatisfied

    reason: str | None = None
    if not all_satisfied:
        missing_groups_desc = "; ".join(
            "(" + " | ".join(g["alternatives"]) + ")" for g in unsatisfied
        )
        reason = (
            f"Rule requires {len(groups)} evidence group(s); "
            f"{len(unsatisfied)} group(s) have no records in the loaded case(s): "
            f"{missing_groups_desc}"
        )

    return {
        "coverage_status": "evaluated" if all_satisfied else "not_evaluable",
        "required_families": required_flat,
        "present_families": present_flat,
        "missing_families": sorted(set(required_flat) - set(present_flat)),
        "satisfied_groups": len(satisfied),
        "unsatisfied_groups": unsatisfied,
        "reason_not_evaluable": reason,
    }


def _loaded_type_counts(connectors: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, c in (connectors or {}).items():
        if not name.startswith("axiom:"):
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        try:
            rows = c.get_artifact_type_counts() or []
        except Exception:
            rows = []
        for row in rows:
            art = row.get("artifact_name") or row.get("artifact_type") or row.get("name")
            cnt = int(row.get("hit_count") or row.get("count") or 0)
            if art:
                counts[art] = counts.get(art, 0) + cnt
    return counts


def attach_rule_coverage(payload: dict[str, Any], connectors: dict[str, Any]) -> dict[str, Any]:
    """Annotate a ``find_suspicious`` payload with per-rule coverage metadata.

    Additive — never removes or renames existing keys. A caller who wants
    the old shape passes ``include_rule_coverage=False`` upstream.

    - Every fired finding gains a ``coverage`` block (status='evaluated',
      including the required/present family lists so transparency works
      for *all* rules, not just the missing ones).
    - Top-level ``unevaluable_rules`` lists rules that did NOT fire AND
      are marked not_evaluable — distinguishes "didn't run" from "ran
      and found nothing".
    """
    counts = _loaded_type_counts(connectors)

    fired: set[str] = set()
    for f in payload.get("findings", []):
        rule_name = f.get("rule_name", "")
        if not rule_name:
            continue
        fired.add(rule_name)
        f["coverage"] = evaluate_rule_coverage(rule_name, counts)

    unevaluable: list[dict[str, Any]] = []
    for rule_name in RULE_REQUIREMENTS.keys():
        if rule_name in fired:
            continue
        verdict = evaluate_rule_coverage(rule_name, counts)
        if verdict["coverage_status"] == "not_evaluable":
            unevaluable.append({
                "rule_name": rule_name,
                "reason_not_evaluable": verdict["reason_not_evaluable"],
                "missing_families": verdict["missing_families"],
            })

    payload["unevaluable_rules"] = unevaluable
    payload["coverage_notes"] = [
        "'unevaluable_rules' lists rules that did NOT fire AND could not be "
        "evaluated because their required artifact families have no records.",
        "A rule that ran and found nothing is 'evaluated' — different from "
        "'could not run'. Do not conflate the two.",
        "Family matching uses exact names with explicit aliases. See "
        "core/analysis/rule_coverage.py::FAMILY_ALIASES.",
    ]
    return payload
