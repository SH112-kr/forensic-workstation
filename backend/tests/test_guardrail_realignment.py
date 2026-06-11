"""Step-6 guardrail realignment: B-2 rule scope, C-4 refutation hint,
C-6 stable gap ids."""

from __future__ import annotations


# ── B-2: rule scope tagging ────────────────────────────────────────────────

def test_every_rule_has_a_scope():
    from core.analysis.suspicious import RULE_CATEGORY_MAP, RULE_SCOPE_MAP

    assert set(RULE_SCOPE_MAP) == set(RULE_CATEGORY_MAP)
    assert set(RULE_SCOPE_MAP.values()) <= {
        "generic", "campaign_specific", "region_specific"}


def test_campaign_and_region_rules_tagged():
    from core.analysis.suspicious import RULE_SCOPE_MAP

    assert RULE_SCOPE_MAP["prefetch_pentest_tool_names"] == "campaign_specific"
    assert RULE_SCOPE_MAP["amcache_remote_access_tool_names"] == "campaign_specific"
    assert (RULE_SCOPE_MAP["prefetch_security_sw_werfault_correlation"]
            == "region_specific")


def test_zero_result_campaign_rule_carries_scope_hint():
    from core.analysis.suspicious import find_suspicious
    from regression.fixtures import load

    conn = load("case_empty_or_malformed")
    result = find_suspicious(conn.artifact_queries,
                             rules="prefetch_pentest_tool_names")
    zero = result["zero_result_rules"]
    assert len(zero) == 1
    assert zero[0]["scope"] == "campaign_specific"
    assert "not THIS" in zero[0]["scope_hint"] or "not match" in zero[0]["scope_hint"].lower()


def test_generic_rule_has_no_scope_hint():
    from core.analysis.suspicious import find_suspicious
    from regression.fixtures import load

    conn = load("case_empty_or_malformed")
    result = find_suspicious(conn.artifact_queries,
                             rules="evtx_eid_1102_audit_log_cleared")
    zero = result["zero_result_rules"][0]
    assert zero["scope"] == "generic"
    assert "scope_hint" not in zero


# ── C-4: refutation hint ───────────────────────────────────────────────────

def test_refutation_hint_maps_known_hypotheses():
    from core.analysis.suspicious import build_refutation_hint

    ransom = build_refutation_hint("I suspect ransomware via RDP")
    assert ransom["hypothesis_class"] == "ransomware_impact"
    assert any("encrypt" in s.lower() or "ransom" in s.lower()
               for s in ransom["refute_by_checking"])

    insider = build_refutation_hint("insider USB data exfiltration")
    assert insider["hypothesis_class"] == "insider_exfiltration"

    lateral = build_refutation_hint("lateral movement / pivot to DC")
    assert lateral["hypothesis_class"] == "lateral_movement"


def test_refutation_hint_unmapped_and_empty():
    from core.analysis.suspicious import build_refutation_hint

    assert build_refutation_hint("") is None
    unmapped = build_refutation_hint("something totally novel")
    assert unmapped["hypothesis_class"] == "unmapped"
    assert unmapped["next_tool"] == "hypothesis_refutation_pack"


# ── C-6: stable gap ids ────────────────────────────────────────────────────

def test_make_gap_id_is_deterministic_and_order_insensitive_by_design():
    from core.analysis.investigation_gap import make_gap_id

    a = make_gap_id("lane", "ingress_access", "unverified")
    b = make_gap_id("lane", "ingress_access", "unverified")
    assert a == b
    assert a.startswith("gap_")
    # Different inputs -> different id
    assert a != make_gap_id("lane", "execution_impact", "unverified")
    # Case/whitespace normalized
    assert make_gap_id("LANE", " ingress_access ", "Unverified") == a


def test_lane_board_and_investigation_gap_share_id_shape():
    from core.analysis.investigation_gap import make_gap_id
    from core.analysis.initial_triage import initial_triage
    from regression.fixtures import load

    conn = load("case_partial_evidence")
    triage = initial_triage(conn)
    board = triage["lane_state_board"]
    blocked = board["blocked_lanes"]
    assert blocked  # partial evidence blocks at least one lane
    for lane in blocked:
        expected = make_gap_id("lane", lane, board[lane]["state"])
        assert board[lane]["gap_id"] == expected


# ── C-5: ingress artifacts actually feed the ingress lane ──────────────────

def test_ingress_artifacts_classified_to_ingress_axes():
    from core.analysis.initial_triage import _classify_entry

    for atype in ("Mark of the Web (Zone.Identifier)",
                  "Office Trusted Documents",
                  "USB Devices"):
        axes = _classify_entry({"artifact_type": atype, "description": ""})["axes"]
        assert "user_interaction" in axes, f"{atype} not on an ingress axis"

    bam_axes = _classify_entry(
        {"artifact_type": "BAM Execution Entries", "description": ""})["axes"]
    assert "execution" in bam_axes

    rdp_axes = _classify_entry(
        {"artifact_type": "RDP Client Destinations", "description": ""})["axes"]
    assert "network_session" in rdp_axes


def test_ingress_lane_fills_from_motw_and_trustrecords():
    """C-5: a case whose only ingress evidence is MOTW + TrustRecords must
    move the ingress lane off 'unverified' — otherwise the lane gate is stuck
    regardless of the new artifacts."""
    from core.analysis.initial_triage import initial_triage
    from regression.fixtures.base import FixtureConnector, FixtureHit

    hits = [
        FixtureHit(hit_id=1, artifact_type="Mark of the Web (Zone.Identifier)",
                   timestamp="2026-05-19T02:56:00Z",
                   source_path="/c:/Users/jh/Downloads/x.exe",
                   fields={"Zone ID": "3", "Host URL": "http://evil.example/x.exe",
                           "description": "Mark of the Web | x.exe ZoneId=3"}),
        FixtureHit(hit_id=2, artifact_type="Office Trusted Documents",
                   timestamp="2026-05-19T02:58:00Z",
                   source_path="/c:/Users/jh/NTUSER.DAT",
                   fields={"Macro Enabled": "True",
                           "description": "Office Trusted Documents | invoice.docm"}),
        FixtureHit(hit_id=3, artifact_type="Prefetch Files - Windows 8/10/11",
                   timestamp="2026-05-19T03:00:00Z",
                   source_path="/c:/Windows/Prefetch/X.EXE.pf",
                   fields={"Application Name": "X.EXE",
                           "description": "Prefetch | X.EXE"}),
    ]
    meta = {"case_name": "ingress_lane_test", "source_type": "fixture",
            "source_path": "fixture://il", "total_hits": 3,
            "artifact_type_count": 0, "evidence_sources": ["FIXTURE"],
            "evidence_locations": [], "date_range_start": "2026-05-18",
            "date_range_end": "2026-05-20"}
    coverage = {"evtx": "present", "prefetch": "present",
                "mft_logfile_usn": "missing", "srum": "missing", "browser": "present"}
    conn = FixtureConnector(metadata=meta, hits=hits, coverage_statuses=coverage)
    triage = initial_triage(conn)
    ingress = triage["lane_state_board"]["ingress_access"]["state"]
    assert ingress != "not_seen", "ingress lane saw no evidence from MOTW/TrustRecords"
