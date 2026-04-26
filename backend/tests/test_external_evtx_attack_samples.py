from __future__ import annotations

from pathlib import Path

import pytest


def test_external_evtx_attack_samples_if_dataset_is_present():
    csv_path = Path("external/dfir_validation/evtx_attack_samples_evtx_data.csv")
    if not csv_path.exists():
        pytest.skip("External EVTX-ATTACK-SAMPLES CSV not downloaded")

    from regression.external_evtx_attack_samples import validate_scenarios

    result = validate_scenarios(csv_path)

    assert result["safety"]["executables_downloaded"] is False
    assert result["safety"]["malware_samples_downloaded"] is False
    assert result["ok"] is True
    assert result["passed"] == result["scenario_count"]


def test_external_evtx_validation_adapter_with_minimal_rows(tmp_path):
    from regression.external_evtx_attack_samples import validate_scenarios

    csv_path = tmp_path / "evtx_data.csv"
    csv_path.write_text(
        "EVTX_FileName,EVTX_Tactic,EventID,ProviderName,Channel,SystemTime,Computer\n"
        "kerberos_pwd_spray_4771.evtx,Credential Access,4771,Microsoft-Windows-Security-Auditing,Security,2020-01-01 00:00:00,dc01\n",
        encoding="utf-8",
    )

    result = validate_scenarios(
        csv_path,
        scenarios={
            "kerberos_pwd_spray_4771.evtx": {
                "expected_tactic": "Credential Access",
                "expected_rule_ids": ["fw-evtx-013"],
            }
        },
    )

    assert result["ok"] is True
    assert result["results"][0]["fired_rule_ids"] == ["fw-evtx-013"]
