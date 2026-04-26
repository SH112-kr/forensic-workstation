from __future__ import annotations

from pathlib import Path

import pytest


def test_external_otrf_eventlog_service_scenario_if_present():
    zip_path = Path("external/dfir_validation/otrf_psh_disable_eventlog_service.zip")
    if not zip_path.exists():
        pytest.skip("External OTRF JSON dataset not downloaded")

    from regression.external_otrf_security_datasets import validate_otrf_scenario

    result = validate_otrf_scenario(zip_path)

    assert result["safety"]["executables_extracted"] is False
    assert result["safety"]["malware_samples_downloaded"] is False
    assert result["ok"] is True
    assert "eventlog_service_registry_tamper" in result["fired_rules"]


def test_otrf_adapter_minimal_eventlog_service_row(tmp_path):
    from regression.external_otrf_security_datasets import (
        OtrfJsonArtifactQueries,
    )
    from core.analysis.anti_forensics import detect_anti_forensics

    row = {
        "hit_id": 1,
        "artifact_type": "Windows Event Logs",
        "Event ID": 4663,
        "Provider Name": "Microsoft-Windows-Security-Auditing",
        "Created Date/Time - UTC (yyyy-mm-dd)": "2022-01-01T00:00:00Z",
        "Event Data": r"ObjectName=\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\EventLog ProcessName=C:\\Temp\\payload.exe",
    }

    result = detect_anti_forensics(OtrfJsonArtifactQueries([row]))
    fired = [r["rule_name"] for r in result["rules"] if r.get("ok") and r.get("count")]

    assert "eventlog_service_registry_tamper" in fired
