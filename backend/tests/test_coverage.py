"""Unit tests for core.analysis.coverage."""

from __future__ import annotations

from core.analysis.coverage import build_coverage_report, AXIOM_ONLY_FAMILIES


def test_empty_connectors():
    r = build_coverage_report({})
    assert r["case_context"]["case_format"] == "none"
    # Empty case skips families entirely so we don't mislead with phantom structural gaps.
    assert r["summary"]["total_reported"] == 0
    assert any("No cases are currently loaded" in n for n in r["notes"])


def test_kape_only_flags_axiom_families(kape_case):
    r = build_coverage_report({"axiom:b": kape_case})
    assert r["case_context"]["case_format"] == "kape"
    assert r["case_context"]["has_kape"] is True
    assert r["case_context"]["has_mfdb"] is False
    # Every AXIOM-only family should be structurally_unavailable on a KAPE-only case.
    struct = [c for c in r["coverage"] if c["status"] == "structurally_unavailable"]
    assert len(struct) == len(AXIOM_ONLY_FAMILIES)
    # Each should carry an explicit reason string.
    assert all(c["reason"] for c in struct)


def test_mixed_case_unblocks_axiom_families(mfdb_case, kape_case):
    r = build_coverage_report({"axiom:a": mfdb_case, "axiom:b": kape_case})
    assert r["case_context"]["case_format"] == "mixed"
    # Chat Applications is AXIOM-only but mfdb_case has 150 records, so it must be "searched".
    chat = next((c for c in r["coverage"] if c["artifact_type"] == "Chat Applications"), None)
    assert chat is not None
    assert chat["status"] == "searched"
    assert chat["record_count"] == 150
    # With MFDB loaded, nothing is structurally_unavailable.
    assert r["summary"]["structurally_unavailable"] == 0


def test_explicit_artifact_types_narrows_report(kape_case):
    r = build_coverage_report({"axiom:b": kape_case}, artifact_types=["Mobile Backups", "Prefetch"])
    assert r["summary"]["total_reported"] == 2
    by_type = {c["artifact_type"]: c for c in r["coverage"]}
    assert by_type["Mobile Backups"]["status"] == "structurally_unavailable"
    assert by_type["Prefetch"]["status"] == "searched"
