from __future__ import annotations


def test_blind_validation_writes_result_without_answer_key(tmp_path):
    from regression.blind_validation import write_blind_result

    path = tmp_path / "blind.json"
    result = write_blind_result(
        path,
        dataset_id="advanced_case_001",
        evidence_paths=["case.E01"],
        analysis_result={"findings": ["initial_access", "persistence"]},
    )

    assert result["answer_key_loaded"] is False
    assert result["phase"] == "blind_analysis"
    assert path.exists()


def test_blind_validation_reveal_compares_after_blind(tmp_path):
    from regression.blind_validation import reveal_against_answer_key, write_blind_result

    blind_path = tmp_path / "blind.json"
    reveal_path = tmp_path / "reveal.json"
    write_blind_result(
        blind_path,
        dataset_id="advanced_case_001",
        evidence_paths=["case.E01"],
        analysis_result={"findings": ["initial_access", "persistence"]},
    )

    result = reveal_against_answer_key(
        blind_path,
        {"expected_findings": ["initial_access", "persistence", "exfiltration"], "source": "writeup"},
        reveal_path,
    )

    assert result["answer_key_loaded_after_blind"] is True
    assert result["comparison"]["ok"] is False
    assert result["comparison"]["missed"] == ["exfiltration"]
