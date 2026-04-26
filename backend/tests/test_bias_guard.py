from __future__ import annotations


def test_synthetic_bias_guard_reruns_prior_cases():
    from regression.bias_guard import run_synthetic_fixture_bias_guard

    result = run_synthetic_fixture_bias_guard()

    assert result["ok"] is True
    assert result["case_count"] >= 6
    names = {check["name"] for check in result["checks"]}
    assert "synthetic:case_benign_remote_work" in names
    assert "synthetic:case_ransomware_inc_like" in names


def test_external_bias_guard_fails_on_e01_overcall(monkeypatch):
    import regression.external_validation as external_validation
    from regression.bias_guard import run_external_bias_guard

    monkeypatch.setattr(
        external_validation,
        "run_external_validation",
        lambda download=False: {
            "ok": False,
            "result_count": 1,
            "passed": 0,
            "failed": 1,
            "results": [
                {
                    "ok": False,
                    "dataset": "Digital Corpora safe E01 pair and M57 data-leakage images",
                    "bias_evaluation": {
                        "ok": False,
                        "overcall_count": 1,
                        "undercall_count": 0,
                    },
                }
            ],
        },
    )

    result = run_external_bias_guard()

    assert result["ok"] is False
    assert any(check["bias_type"] == "overcall" for check in result["checks"])


def test_external_bias_guard_fails_on_apt_stage_undercall(monkeypatch):
    import regression.external_validation as external_validation
    from regression.bias_guard import run_external_bias_guard

    monkeypatch.setattr(
        external_validation,
        "run_external_validation",
        lambda download=False: {
            "ok": False,
            "result_count": 1,
            "passed": 0,
            "failed": 1,
            "results": [
                {
                    "ok": False,
                    "dataset": "skrghosh/apt-dataset APT29",
                    "bias_evaluation": {
                        "ok": False,
                        "missed_stage_count": 1,
                        "missed_stages": ["exfiltration"],
                        "bias_notes": [],
                    },
                }
            ],
        },
    )

    result = run_external_bias_guard()

    assert result["ok"] is False
    assert any(check["bias_type"] == "undercall" for check in result["checks"])


def test_bias_guard_cli_returns_failure_exit(monkeypatch, capsys):
    import regression.cli as cli

    monkeypatch.setattr(
        "regression.bias_guard.run_bias_guard",
        lambda include_external=True, download_external=False: {
            "ok": False,
            "policy": "feature_bias_guard_v1",
            "check_count": 1,
            "failed_count": 1,
            "failures": [
                {
                    "name": "synthetic:case_benign_remote_work",
                    "bias_type": "overcall",
                    "issues": ["overcall_risk:benign_or_unknown_case_escalated"],
                }
            ],
            "residual_risks": [],
        },
    )

    exit_code = cli.main(["bias-guard"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "ok=False" in output
    assert "case_benign_remote_work" in output
