from __future__ import annotations

from core.analysis.hypothesis_refutation import hypothesis_refutation_pack


def test_anchor_proximity_creates_refutation_worklist_not_verdict():
    anchor = {
        "anchor": {
            "timestamp_utc": "2025-09-26T05:11:32Z",
            "label": "Naver Whale Cache IOC hxxps://www.winsystem.kr/share/inc/module.js",
            "entities": ["winsystem.kr", "module.js", "whale"],
        },
        "summary": {
            "event_count": 1,
            "token_linked_count": 0,
            "proximity_only_count": 1,
        },
        "token_linked": [],
        "proximity_only": [
            {
                "source_artifact": "Prefetch",
                "object": "WERFAULT.EXE",
                "delta_seconds": 23,
                "correlation_strength": "strong_temporal",
                "causality": "unproven",
                "relationship_hints": ["browser_or_url_anchor_near_werfault"],
            }
        ],
        "missing_sources": [
            {"source": "wer", "reason": "Report.wer not retained"},
        ],
        "dominance_warning": "Most correlated artifacts share no secondary token with the anchor.",
    }

    result = hypothesis_refutation_pack(anchor_correlation_payload=anchor)

    assert result["policy"] == "refutation_first_composition_v1"
    assert result["contract"]["forced_checks"] is True
    assert result["contract"]["forced_conclusions"] is False
    assert result["contract"]["strong_case_conclusion_allowed"] is False

    hypotheses = {h["id"]: h for h in result["hypotheses"]}
    exploit = hypotheses["browser_delivered_exploit_or_payload_chain"]
    benign = hypotheses["benign_browser_crash_or_site_error"]
    unrelated = hypotheses["unrelated_high_base_rate_artifact"]
    gap = hypotheses["collection_or_parser_gap"]

    assert exploit["status"] == "lead_needs_refutation"
    assert exploit["strong_conclusion_allowed"] is False
    assert exploit["claim_gate"]["blocked_claim"] == "exploit or compromise confirmed"
    assert any(t["task_id"] == "verify_payload_lifecycle" for t in exploit["refutation_tasks"])
    assert any("No downstream payload" in m for m in exploit["missing_evidence"])
    assert benign["role"] == "benign_alternative"
    assert unrelated["role"] == "unrelated_alternative"
    assert gap["status"] == "gap_blocks_conclusion"
    assert result["coverage_gaps"][0]["interpretation"].endswith("not negative evidence.")


def test_token_linked_wer_still_does_not_allow_strong_conclusion():
    anchor = {
        "anchor": {
            "timestamp_utc": "2025-09-26T05:11:32Z",
            "label": "Whale browser cache IOC",
            "entities": ["whale"],
        },
        "summary": {"event_count": 1, "token_linked_count": 1, "proximity_only_count": 0},
        "token_linked": [
            {
                "source_artifact": "WER Report",
                "object": "whale.exe",
                "shared_anchor_tokens": ["whale"],
                "correlation_strength": "confirmed_candidate",
                "causality": "unproven",
            }
        ],
        "proximity_only": [],
        "missing_sources": [],
    }
    findings = {
        "findings": [
            {
                "rule_name": "evtx_4688_process_creation",
                "details": ["process creation payload.exe", "SRUM network usage"],
            }
        ]
    }

    result = hypothesis_refutation_pack(
        anchor_correlation_payload=anchor,
        findings_payload=findings,
    )

    hypotheses = {h["id"]: h for h in result["hypotheses"]}
    exploit = hypotheses["browser_delivered_exploit_or_payload_chain"]
    benign = hypotheses["benign_browser_crash_or_site_error"]

    assert "WER report shares an anchor token" in exploit["supporting_observations"]
    assert exploit["strong_conclusion_allowed"] is False
    assert result["summary"]["strong_conclusions_blocked"] is True
    assert benign["role"] == "benign_alternative"
    assert "Downstream payload/process signal supplied" in benign["contradicting_observations"]


def test_existing_competing_hypotheses_are_carried_forward_for_refutation():
    hypotheses_payload = {
        "competing_hypotheses": [
            {
                "id": "benign_remote_administration",
                "label": "Benign remote administration or maintenance",
                "supporting_signals": ["remote_admin"],
                "missing_signals": ["impact_checked"],
                "falsifiers": ["Remote session spawned suspicious child processes."],
                "next_queries": ["Baseline remote-tool session times."],
            }
        ]
    }

    result = hypothesis_refutation_pack(hypotheses_payload=hypotheses_payload)

    carried = result["hypotheses"][0]
    assert carried["id"] == "benign_remote_administration"
    assert carried["status"] == "carried_forward_for_refutation"
    assert carried["strong_conclusion_allowed"] is False
    assert carried["refutation_tasks"][0]["task_id"] == "falsify_1"
