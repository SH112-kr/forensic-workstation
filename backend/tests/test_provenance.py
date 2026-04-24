"""Unit tests for core.analysis.provenance."""

from __future__ import annotations

from core.analysis.provenance import (
    CORROBORATION_MAP,
    _loose_match,
    _summarize_details,
    attach_provenance,
)


def test_corroboration_map_covers_shipped_rules():
    """Every shipped rule in find_suspicious should have a provenance entry."""
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
    assert shipped <= set(CORROBORATION_MAP.keys()), \
        f"Missing provenance entries for: {shipped - set(CORROBORATION_MAP.keys())}"


def test_loose_match_handles_subset():
    present = {"Windows Event Logs", "Prefetch"}
    assert _loose_match("Windows Event Logs (EID 4688)", present)
    assert _loose_match("Prefetch", present)
    assert not _loose_match("SRUM", present)


def test_summarize_details_groups_by_type():
    details = [
        {"artifact_type": "Prefetch", "hit_id": 1},
        {"artifact_type": "Prefetch", "hit_id": 2},
        {"artifact_type": "Windows Event Logs", "hit_id": 10},
    ]
    summary = _summarize_details(details)
    by_type = {s["artifact_type"]: s for s in summary}
    assert by_type["Prefetch"]["count"] == 2
    assert by_type["Prefetch"]["sample_hit_ids"] == [1, 2]
    assert by_type["Windows Event Logs"]["count"] == 1


def test_attach_provenance_fills_supporting_and_absent(kape_case):
    payload = {
        "findings": [
            {
                "rule_name": "prefetch_pentest_tool_names",
                "details": [{"artifact_type": "Prefetch", "hit_id": 1}],
            },
        ],
    }
    attach_provenance(payload, {"axiom:b": kape_case})
    f = payload["findings"][0]
    # Supporting: Prefetch with hit_id 1
    assert f["supporting_artifacts"][0]["artifact_type"] == "Prefetch"
    assert 1 in f["supporting_artifacts"][0]["sample_hit_ids"]
    # Absent: 4688 and SRUM not present in kape_case artifact counts
    absent_families = {a["family"] for a in f["absent_corroboration"]}
    assert "SRUM" in absent_families


def test_attach_provenance_empty_case():
    payload = {"findings": [{"rule_name": "sysmon_eid10_lsass_handle_open", "details": []}]}
    attach_provenance(payload, {})
    assert payload["provenance_case_format"] == "none"
    f = payload["findings"][0]
    # With no cases loaded, every corroborator is absent.
    assert len(f["absent_corroboration"]) == len(CORROBORATION_MAP["sysmon_eid10_lsass_handle_open"])
