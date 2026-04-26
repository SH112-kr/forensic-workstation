from __future__ import annotations


def test_claude_review_dry_run_builds_review_prompt():
    from regression.claude_review import run_claude_review

    result = run_claude_review(
        {"ok": True, "policy": "feature_bias_guard_v1"},
        dry_run=True,
    )

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert "feature_bias_guard_v1" in result["prompt"]
    assert "accuracy regressions" in result["prompt"]


def test_result_count_falls_back_to_dataset_specific_counts():
    from regression.claude_review import _result_count

    assert _result_count({"rows": 6563}) == 6563
    assert _result_count({"records_scanned": 1100}) == 1100
    assert _result_count({"content_marker_results": [{}, {}]}) == 2


def test_bias_guard_cli_can_prepare_claude_review_without_invoking_claude(monkeypatch):
    import regression.cli as cli

    monkeypatch.setattr(
        "regression.bias_guard.run_bias_guard",
        lambda include_external=True, download_external=False: {
            "ok": True,
            "policy": "feature_bias_guard_v1",
            "check_count": 1,
            "failed_count": 0,
            "failures": [],
            "residual_risks": [],
        },
    )

    exit_code = cli.main(["bias-guard", "--claude-review", "--claude-review-dry-run"])

    assert exit_code == 0
