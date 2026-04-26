from __future__ import annotations


def test_cfreds_bias_evaluation_requires_tools_attribution_and_sniffing_output():
    from regression.external_cfreds_hacking_case import _evaluate_bias

    path_results = [
        {"name": "cain_password_tool", "ok": True},
        {"name": "ethereal_packet_sniffer", "ok": True},
        {"name": "stored_password_tool", "ok": True},
        {"name": "anonymizer", "ok": True},
        {"name": "cuteftp", "ok": True},
        {"name": "look_at_lan", "ok": True},
    ]
    marker_results = [
        {"name": "look_at_lan_identity_file", "ok": True},
        {"name": "ethereal_interception_output", "ok": True},
    ]

    result = _evaluate_bias(path_results, marker_results)

    assert result["ok"] is True
    assert result["detected_hacking_tool_count"] == 6


def test_cfreds_bias_evaluation_flags_undercall_when_sniffing_output_missing():
    from regression.external_cfreds_hacking_case import _evaluate_bias

    result = _evaluate_bias(
        [{"name": "cain_password_tool", "ok": True}],
        [{"name": "look_at_lan_identity_file", "ok": True}],
    )

    assert result["ok"] is False
    assert any("undercall_risk" in note for note in result["bias_notes"])


def test_external_cfreds_hacking_case_if_present():
    from pathlib import Path

    import pytest

    project_root = Path(__file__).resolve().parents[2]
    required = [
        project_root / "external/dfir_validation/4Dell Latitude CPi.E01",
        project_root / "external/dfir_validation/4Dell Latitude CPi.E02",
        project_root / "external/dfir_validation/cfreds_hacking_case_answers.pdf",
    ]
    if not all(p.exists() for p in required):
        pytest.skip("CFReDS Hacking Case E01 not downloaded")

    from regression.external_cfreds_hacking_case import validate_cfreds_hacking_case

    result = validate_cfreds_hacking_case(download=False)

    assert result["ok"] is True
    assert result["metadata"]["hostname"] == "N-1A9ODN6ZXK4LQ"
    assert result["bias_evaluation"]["ok"] is True
    assert result["bias_evaluation"]["detected_hacking_tool_count"] >= 6
    assert result["safety"]["executables_executed"] is False
