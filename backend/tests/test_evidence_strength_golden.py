"""C-3 golden-table test for evidence_strength tier assignment.

evidence_strength._RULES is a first-match-wins list, so adding or reordering
a rule can silently change an unrelated family's tier. This locks the
(artifact family -> tier) mapping for every family the connectors emit. When
a tier here changes, it must be a *reviewed* change to this table — never an
accidental side effect of inserting a new rule above an existing one.
"""

from __future__ import annotations

import pytest

from core.analysis.evidence_strength import classify_artifact


# Canonical artifact-type strings as the connectors actually emit them,
# mapped to their expected strength tier. Keep this exhaustive for every
# family with a dedicated rule plus a few representative EID variants.
GOLDEN_TIERS = {
    # confirmed
    "Windows Event Logs (EID 4688)": "confirmed",
    "Windows Event Logs (EID 4624)": "confirmed",
    "Windows Event Logs (EID 7045)": "confirmed",
    "Windows Event Logs (EID 1102)": "confirmed",
    "Windows Event Logs (EID 4698)": "confirmed",
    "SRUM Network Usage": "confirmed",
    "SRUM Application Resource Usage": "confirmed",
    "Master File Table": "confirmed",
    # strong
    "Prefetch Files - Windows 8/10/11": "strong",
    "BAM Execution Entries": "strong",
    "Mark of the Web (Zone.Identifier)": "strong",
    "Office Trusted Documents": "strong",
    "Windows Event Logs (EID 4104)": "strong",
    # moderate
    "AmCache File Entries": "moderate",
    "UserAssist": "moderate",
    "Scheduled Tasks": "moderate",
    "RDP Client Destinations": "moderate",
    "Office Recent Documents": "moderate",
    "USB Devices": "moderate",
    # weak
    "Shim Cache": "weak",
    "AppCompatCache": "weak",
    "Link Date": "weak",
}


@pytest.mark.parametrize("artifact_type,expected_tier", sorted(GOLDEN_TIERS.items()))
def test_golden_tier_assignment(artifact_type, expected_tier):
    result = classify_artifact(artifact_type)
    assert result["tier"] == expected_tier, (
        f"{artifact_type!r} classified as {result['tier']!r}, "
        f"expected {expected_tier!r}. If this change is intentional, update "
        "GOLDEN_TIERS deliberately — do not let a new _RULES entry silently "
        "reclassify an existing family."
    )
    assert result.get("reason")


def test_unknown_artifact_defaults_to_moderate():
    result = classify_artifact("Some Future Artifact Type We Have Not Seen")
    assert result["tier"] == "moderate"
    assert "did not match" in result["reason"].lower()


def test_event_log_4104_not_swallowed_by_confirmed_rule():
    """4104 (ScriptBlock) must stay strong, not get promoted to confirmed by
    the confirmed Event-Logs rule which only lists definitive EIDs."""
    assert classify_artifact("Windows Event Logs (EID 4104)")["tier"] == "strong"
    # A confirmed EID in the same family must still be confirmed.
    assert classify_artifact("Windows Event Logs (EID 4688)")["tier"] == "confirmed"
