from __future__ import annotations

from core.analysis.service_persistence import (
    build_service_persistence_gate,
    services_from_artifact_rows,
    windows_path_to_internal_path,
)


def test_svchost_servicedll_non_baseline_is_promoted():
    rows = [{
        "hit_id": 101,
        "Service Name": "uploadmgr",
        "Service Location": r"%SystemRoot%\system32\svchost.exe -k netsvcs -p",
        "ServiceDll": r"%SYSTEMROOT%\system32\sdhsvc.dll",
        "Start Type": "Auto",
        "User Account": "LocalSystem",
        "Registry Modified": "2026-02-11 08:00:07",
    }]

    services = services_from_artifact_rows(rows)
    result = build_service_persistence_gate(services)

    assert result["summary"]["candidate_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["service_name"] == "uploadmgr"
    assert candidate["service_dll"] == r"%SYSTEMROOT%\system32\sdhsvc.dll"
    assert candidate["payload_path_internal"] == "/c:/Windows/system32/sdhsvc.dll"
    evidence = {flag["name"]: flag["weight"] for flag in candidate["evidence_flags"]}
    gaps = {gap["name"] for gap in candidate["coverage_gaps"]}
    assert evidence["svchost_servicedll_chain_present"] == "moderate"
    assert evidence["non_baseline_service_dll"] == "weak"
    assert "system32_dll_signature_not_verified" in gaps
    assert "risk_score" not in candidate
    assert "risk_tier" not in candidate


def test_servicedll_is_extracted_from_kroll_style_text_blob():
    rows = [{
        "hit_id": 202,
        "Service Name": "uploadmgr",
        "Service Location": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
        "User Account": (
            r"Image path: C:\Windows\system32\svchost.exe -k netsvcs -p "
            r"ServiceDLL: %SYSTEMROOT%\system32\sdhsvc.dll"
        ),
        "Start Type": "Automatic",
    }]

    services = services_from_artifact_rows(rows)

    assert services[0]["service_dll"] == r"%SYSTEMROOT%\system32\sdhsvc.dll"


def test_payload_file_lookup_marks_missing_payloads():
    rows = [{
        "Service Name": "DemoSvc",
        "Service Location": r"C:\ProgramData\demo.exe",
        "Start Type": "Auto",
        "User Account": "LocalSystem",
    }]

    services = services_from_artifact_rows(rows)
    result = build_service_persistence_gate(
        services,
        file_info_lookup=lambda _path: {"error": "File not found"},
    )

    candidate = result["candidates"][0]
    assert candidate["payload_file"]["checked"] is True
    assert candidate["payload_file"]["present"] is False
    evidence = {flag["name"] for flag in candidate["evidence_flags"]}
    gaps = {gap["name"] for gap in candidate["coverage_gaps"]}
    assert "payload_missing_on_mounted_image" in evidence
    assert "missing_payload_event_context_not_verified" in gaps
    assert result["gates"][2]["status"] == "partial"


def test_source_conflicts_are_not_silently_merged():
    services = [
        {
            "source": "parsed_case",
            "service_name": "uploadmgr",
            "image_path": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
            "service_dll": r"%SYSTEMROOT%\system32\old.dll",
        },
        {
            "source": "system_hive",
            "service_name": "uploadmgr",
            "image_path": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
            "service_dll": r"%SYSTEMROOT%\system32\sdhsvc.dll",
        },
    ]

    result = build_service_persistence_gate(services)

    assert result["source_conflicts"][0]["service_name"] == "uploadmgr"
    assert "service_dll" in result["source_conflicts"][0]["field_differences"]


def test_windows_path_to_internal_path_handles_service_env_paths():
    assert (
        windows_path_to_internal_path(r"%SystemRoot%\system32\svchost.exe -k netsvcs -p")
        == "/c:/Windows/system32/svchost.exe"
    )
    assert (
        windows_path_to_internal_path(r"%SYSTEMROOT%\system32\sdhsvc.dll")
        == "/c:/Windows/system32/sdhsvc.dll"
    )
