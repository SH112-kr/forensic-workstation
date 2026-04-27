from __future__ import annotations

import pytest

import mcp_bridge


@pytest.mark.parametrize(
    ("tool_name", "tool_fn"),
    [
        ("auto_triage", mcp_bridge.auto_triage),
        ("initial_triage_pack", mcp_bridge.initial_triage_pack),
        ("find_suspicious", mcp_bridge.find_suspicious),
        ("baseline_diff", mcp_bridge.baseline_diff),
        ("correlate", mcp_bridge.correlate),
        ("behavioral_delta_pack", mcp_bridge.behavioral_delta_pack),
        ("investigation_gap_report", mcp_bridge.investigation_gap_report),
        ("hypothesis_refutation_pack", mcp_bridge.hypothesis_refutation_pack),
        ("detect_anti_forensics", mcp_bridge.detect_anti_forensics),
    ],
)
def test_targeted_mcp_tools_include_ai_reading_guides(tool_name, tool_fn):
    doc = tool_fn.__doc__ or ""
    assert "Reading guide for AI consumers" in doc, tool_name
