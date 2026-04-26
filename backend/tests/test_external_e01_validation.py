from __future__ import annotations

from pathlib import Path

import pytest


def test_external_safe_e01_pair_if_present():
    required = [
        Path("external/dfir_validation/nps-2010-emails.E01"),
        Path("external/dfir_validation/charlie-work-usb-2009-12-11.E01"),
    ]
    if not all(p.exists() for p in required):
        pytest.skip("External safe E01 pair not downloaded")

    from regression.external_e01_validation import validate_safe_e01_pair

    result = validate_safe_e01_pair(download=False)

    assert result["safety"]["executables_executed"] is False
    assert result["ok"] is True
    incident = next(r for r in result["results"] if r["case_id"] == "incident_m57_charlie_usb")
    assert not incident["missing_expected_paths"]
    assert incident["scenario_evidence"] >= 3
    benign = next(r for r in result["results"] if r["case_id"] == "normal_nps_2010_emails")
    assert benign["impact_candidates"] == 0
    assert result["bias_evaluation"]["ok"] is True

    jean = next((r for r in result["results"] if r["case_id"] == "incident_m57_jean_laptop"), None)
    if Path("external/dfir_validation/nps-2008-jean.E01").exists():
        assert jean is not None
        assert jean["label"] == "spear_phishing_data_leakage"
        assert not jean["missing_expected_paths"]
