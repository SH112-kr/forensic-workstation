from __future__ import annotations


def test_volume_coverage_quantifies_unparsed_partitions():
    from regression.autonomous_validation_runner import _volume_coverage

    result = _volume_coverage({
        "volumes": [
            "<Volume name='small' size=100 fs='ntfs'>",
            "<Volume name='large' size=900 fs=None>",
        ]
    })

    assert result["parsed_bytes"] == 100
    assert result["unparsed_bytes"] == 900
    assert result["unparsed_percent"] == 90.0


def test_data_volume_without_windows_os_is_not_penalized():
    from regression.autonomous_validation_runner import _probe_issues

    issues = _probe_issues(
        {"os_type": "default"},
        {"record_count": 2, "artifact_type_counts": {"Data File Candidate": 2}},
        expected_scope="data_volume",
        coverage={"unparsed_bytes": 0, "unparsed_percent": 0},
    )

    assert "os_not_detected_or_non_system_volume" not in issues


def test_windows_system_without_registry_is_penalized():
    from regression.autonomous_validation_runner import _probe_issues

    issues = _probe_issues(
        {"os_type": "default"},
        {"record_count": 2, "artifact_type_counts": {"NTFS Metadata Candidate": 2}},
        expected_scope="windows_system",
        coverage={"unparsed_bytes": 0, "unparsed_percent": 0},
    )

    assert "os_not_detected_or_non_system_volume" in issues


def test_missing_multipart_segments_are_reported():
    from pathlib import Path

    from regression.autonomous_validation_runner import _probe_issues

    issues = _probe_issues(
        {"os_type": "windows"},
        {"record_count": 3, "artifact_type_counts": {"Registry Hive Candidate": 1}},
        expected_scope="windows_system",
        coverage={"unparsed_bytes": 0, "unparsed_percent": 0},
        missing_companions=[Path("missing.E02")],
    )

    assert "missing_e01_companion_segments" in issues


def test_missing_expected_markers_are_reported():
    from regression.autonomous_validation_runner import _probe_issues

    issues = _probe_issues(
        {"os_type": "windows"},
        {"record_count": 3, "artifact_type_counts": {"Expected Scenario Path": 2}},
        expected_scope="windows_system",
        coverage={"unparsed_bytes": 0, "unparsed_percent": 0},
        missing_expected_markers=["/c:/Users/example/missing.docx"],
    )

    assert "missing_expected_markers" in issues


def test_missing_expected_markers_compares_normalized_paths():
    from regression.autonomous_validation_runner import _missing_expected_markers

    missing = _missing_expected_markers(
        {"records": [{"value": {"internal_path": "/c:/Users/Alice/Desktop/Plan.docx"}}]},
        [r"C:\Users\Alice\Desktop\Plan.docx", "/c:/Users/Alice/Desktop/Missing.docx"],
    )

    assert missing == ["/c:/Users/Alice/Desktop/Missing.docx"]


def test_claude_fail_review_blocks_autonomy():
    from regression.autonomous_validation_runner import _claude_blocks_autonomy

    assert _claude_blocks_autonomy({"ok": True, "review": "조건부 불합격: 자율 배포 승인할 수 없다"})
    assert _claude_blocks_autonomy({"ok": True, "review": "조건부 통과: 완전 자율 배포 불가"})
    assert _claude_blocks_autonomy({"ok": True, "review": "조건부 PASS: 완전 자율화 승인 불가, 감독하 운용 권고"})
    assert not _claude_blocks_autonomy({"ok": True, "review": "합격 권고"})


def test_autonomous_validation_summary_includes_safety_checks(monkeypatch, tmp_path):
    import regression.autonomous_validation_runner as runner

    monkeypatch.setattr(runner, "run_external_validation", lambda download=False: {"ok": True, "results": []})
    monkeypatch.setattr(runner, "download_registered_cases", lambda: [])
    monkeypatch.setattr(runner, "DEFAULT_E01_PROBES", [])
    monkeypatch.setattr(runner, "run_bias_guard", lambda include_external=True, download_external=False: {
        "ok": True,
        "policy": "feature_bias_guard_v1",
        "check_count": 1,
        "failed_count": 0,
        "failures": [],
        "residual_risks": [],
        "synthetic": {"ok": True, "case_count": 1, "checks": []},
        "external": {"checks": []},
    })

    result = runner.run_autonomous_validation(run_tests=False, output_dir=tmp_path)

    names = {item["name"] for item in result["safety_checks"]}
    assert "privacy_gateway_secret_redaction" in names
    assert "e01_extract_static_only" in names


def test_clean_baseline_extracts_benign_false_positive_check():
    from regression.autonomous_validation_runner import _clean_baseline_checks

    checks, gaps = _clean_baseline_checks({
        "results": [{
            "dataset": "safe E01 pair",
            "results": [{
                "case_id": "normal",
                "label": "benign",
                "ok": True,
                "impact_candidates": 0,
                "record_count": 12,
            }],
        }]
    })

    assert gaps == []
    assert checks == [{
        "case_id": "normal",
        "dataset": "safe E01 pair",
        "ok": True,
        "expected_malicious_findings": 0,
        "impact_candidates": 0,
        "record_count": 12,
        "coverage_note": "Benign E01 false-positive baseline; low artifact coverage must not be used as proof of absence.",
    }]


def test_zero_artifact_clean_baseline_is_gap_not_fp_baseline():
    from regression.autonomous_validation_runner import _clean_baseline_checks

    checks, gaps = _clean_baseline_checks({
        "results": [{
            "dataset": "safe E01 pair",
            "results": [{
                "case_id": "empty",
                "label": "benign",
                "ok": True,
                "impact_candidates": 0,
                "record_count": 0,
            }],
        }]
    })

    assert checks == []
    assert gaps[0]["case_id"] == "empty"
    assert gaps[0]["gap"] == "zero_indexed_artifacts"


def test_probe_clean_baseline_extracts_registry_benign_probe():
    from regression.autonomous_validation_runner import _probe_clean_baseline_checks

    checks = _probe_clean_baseline_checks([{
        "case_id": "domex",
        "label": "benign",
        "path": "domex.E01",
        "ok": True,
        "expected_malicious_findings": 0,
        "record_count": 20,
        "artifact_type_counts": {"Prefetch Candidate": 10},
    }])

    assert checks[0]["ok"] is True
    assert checks[0]["record_count"] == 20
    assert checks[0]["impact_candidates"] == 0


def test_autonomy_blockers_require_scored_complex_e01_and_nonempty_baseline():
    from regression.autonomous_validation_runner import _autonomy_blockers

    blockers = _autonomy_blockers({
        "e01_probes": [{
            "case_id": "lonewolf",
            "status": "ok",
            "expected_scope": "windows_system",
            "scoring_included": False,
        }],
        "clean_baseline": [{
            "case_id": "normal",
            "record_count": 0,
        }],
    })

    topics = {item["topic"] for item in blockers}
    assert "lonewolf scoring" in topics
    assert "clean baseline coverage" in topics


def test_autonomy_blockers_accept_one_nonempty_clean_baseline():
    from regression.autonomous_validation_runner import _autonomy_blockers

    blockers = _autonomy_blockers({
        "e01_probes": [],
        "clean_baseline": [{"case_id": "nonempty", "record_count": 44}],
        "clean_baseline_gaps": [],
    })

    assert blockers == []


def test_autonomy_blockers_report_clean_baseline_gaps():
    from regression.autonomous_validation_runner import _autonomy_blockers

    blockers = _autonomy_blockers({
        "e01_probes": [],
        "clean_baseline": [{"case_id": "nonempty", "record_count": 44}],
        "clean_baseline_gaps": [{"case_id": "empty"}],
    })

    assert blockers[0]["topic"] == "empty clean baseline gap"
