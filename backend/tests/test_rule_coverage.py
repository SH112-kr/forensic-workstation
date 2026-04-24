"""Unit tests for core.analysis.rule_coverage.

Covers Codex Round-4's required edge cases:
  - Rule with alternative evidence sources (ssh_activity).
  - Rule with multiple required groups (watering_hole_indicators).
  - Family present but zero rows -> not_evaluable.
  - Naming variant match + near-collision non-match.
  - Fired rule still marked 'evaluated' when one of several alternatives
    is present.
  - Unknown rule stays 'evaluated' with a note (no shadow rulesetting).
"""

from __future__ import annotations

from core.analysis.rule_coverage import (
    FAMILY_ALIASES,
    RULE_REQUIREMENTS,
    _present,
    attach_rule_coverage,
    evaluate_rule_coverage,
)


def test_exact_family_match():
    assert _present("Prefetch", {"Prefetch"})
    assert _present("Windows Event Logs", {"Windows Event Logs"})


def test_alias_match():
    assert _present("Prefetch", {"Prefetch Files - Windows 8/10/11"})
    assert _present("AmCache", {"AmCache File Entries"})


def test_parenthetical_subvariant_matches():
    assert _present("Windows Event Logs", {"Windows Event Logs (EID 4688)"})


def test_near_collision_does_not_match():
    # 'Prefetching' must NOT count as 'Prefetch'.
    assert not _present("Prefetch", {"Prefetching"})
    # Hypothetical near-collision: 'Event Logs (Legacy Archive)' is NOT an
    # alias; only 'Event Logs' is. The rule must stay explicit.
    assert _present("Windows Event Logs", {"Event Logs"})
    assert not _present("Windows Event Logs", {"Eventlog"})  # missing space


def test_any_alternative_satisfies_group():
    """openssh_artifacts: requires [Windows Event Logs | System Services | Prefetch | SSH Keys]."""
    counts = {"Prefetch Files - Windows 8/10/11": 100}
    v = evaluate_rule_coverage("openssh_artifacts", counts)
    assert v["coverage_status"] == "evaluated"
    assert "Prefetch" in v["present_families"]


def test_all_groups_required():
    """prefetch_security_sw_werfault_correlation: needs Prefetch AND Startup Items."""
    # Only Prefetch present -> one group unsatisfied -> not_evaluable
    v = evaluate_rule_coverage("prefetch_security_sw_werfault_correlation", {"Prefetch": 500})
    assert v["coverage_status"] == "not_evaluable"
    assert len(v["unsatisfied_groups"]) == 1

    # Both required -> evaluated
    v2 = evaluate_rule_coverage("prefetch_security_sw_werfault_correlation", {"Prefetch": 500, "Startup Items": 10})
    assert v2["coverage_status"] == "evaluated"


def test_family_present_with_zero_records_is_not_evaluable():
    counts = {"Windows Event Logs": 0}  # parsed zero rows
    v = evaluate_rule_coverage("sysmon_eid10_lsass_handle_open", counts)
    assert v["coverage_status"] == "not_evaluable"
    assert v["missing_families"] == ["Windows Event Logs"]


def test_unknown_rule_stays_evaluated_with_note():
    v = evaluate_rule_coverage("not_a_real_rule", {"Prefetch": 100})
    assert v["coverage_status"] == "evaluated"
    assert "note" in v


def test_attach_rule_coverage_marks_fired_and_unevaluable(mfdb_case):
    """End-to-end: fired finding gets coverage block + unknown-gap rules
    land in unevaluable_rules."""
    # mfdb_case artifact_counts: Prefetch=50, Chat Applications=150
    # No Windows Event Logs -> many rules become unevaluable.
    connectors = {"axiom:a": mfdb_case}
    payload = {
        "findings": [
            {"rule_name": "prefetch_pentest_tool_names", "details": [{"artifact_type": "Prefetch", "hit_id": 1}]},
        ],
    }
    attach_rule_coverage(payload, connectors)

    # Fired finding has a coverage block marked evaluated.
    fired = payload["findings"][0]
    assert fired["coverage"]["coverage_status"] == "evaluated"
    assert "Prefetch" in fired["coverage"]["present_families"]

    # Event-log-dependent rules (not fired here) must be listed as unevaluable.
    unevaluable_ids = {u["rule_name"] for u in payload["unevaluable_rules"]}
    assert "sysmon_eid10_lsass_handle_open" in unevaluable_ids
    assert "evtx_eid_1102_audit_log_cleared" in unevaluable_ids
    # prefetch_pentest_tool_names already fired -> NOT in unevaluable list
    assert "prefetch_pentest_tool_names" not in unevaluable_ids


def test_every_shipped_rule_has_requirements():
    """Guardrail: find_suspicious ships 13 rules. All must appear in
    RULE_REQUIREMENTS so adding a new rule forces an update here."""
    shipped = {
        "sysmon_eid10_lsass_handle_open",
        "evtx_eid_4688_process_creation_events",
        "evtx_eid_7045_service_installs",
        "evtx_eid_4698_scheduled_task_events",
        "evtx_eid_1102_audit_log_cleared",
        "evtx_eid_4624_type10_rdp_logons",
        "evtx_eid_4648_explicit_credential_logons",
        "prefetch_pentest_tool_names",
        "services_nonstandard_binary_paths",
        "evtx_eid_4104_scriptblock_logs",
        "prefetch_security_sw_werfault_correlation",
        "amcache_remote_access_tool_names",
        "openssh_artifacts",
    }
    missing = shipped - set(RULE_REQUIREMENTS.keys())
    assert not missing, f"Missing RULE_REQUIREMENTS entries: {missing}"


def test_aliases_cover_expected_connector_names():
    """Sanity: make sure our aliases cover the names connectors actually emit."""
    # Known KAPE/AXIOM names we've seen in shipped data
    known_names = {
        "Windows Event Logs",
        "Prefetch Files - Windows 8/10/11",
        "AmCache File Entries",
        "System Services",
    }
    for n in known_names:
        hit = False
        for family in FAMILY_ALIASES.keys():
            if _present(family, {n}):
                hit = True
                break
        assert hit, f"No FAMILY_ALIASES entry matches '{n}'"
