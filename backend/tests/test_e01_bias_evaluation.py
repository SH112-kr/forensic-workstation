from __future__ import annotations


class _PairFakeE01:
    def __init__(self, files):
        self.files = files

    def get_metadata(self):
        return {"image_path": "pair.E01"}

    def find_files(self, pattern: str, limit: int = 100):
        return self.files.get(pattern, [])


def test_e01_bias_evaluation_requires_benign_and_incident_pair():
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias

    benign = _PairFakeE01({
        "**/Windows/System32/winevt/Logs/*.evtx": [{"path": "/c:/Windows/System32/winevt/Logs/Security.evtx"}],
        "**/Windows/Prefetch/*.pf": [{"path": "/c:/Windows/Prefetch/NOTEPAD.EXE-111.pf"}],
        "**/Windows/System32/config/SYSTEM": [{"path": "/c:/Windows/System32/config/SYSTEM"}],
    })
    incident = _PairFakeE01({
        "**/Windows/System32/winevt/Logs/*.evtx": [{"path": "/c:/Windows/System32/winevt/Logs/Security.evtx"}],
        "**/Windows/Prefetch/*.pf": [{"path": "/c:/Windows/Prefetch/WIN.EXE-222.pf"}],
        "**/Windows/System32/config/SYSTEM": [{"path": "/c:/Windows/System32/config/SYSTEM"}],
        "**/*README*.txt": [{"path": "/c:/Users/admin/Desktop/INC-README.txt"}],
        "**/*.INC": [{"path": "/c:/Users/admin/Documents/file.docx.INC"}],
    })

    result = evaluate_e01_cache_bias([
        {
            "case_id": "normal_e01",
            "label": "benign",
            "cache": build_e01_artifact_cache(
                benign,
                include_lazy_targets=False,
                include_high_value_patterns=True,
            ),
        },
        {
            "case_id": "incident_e01",
            "label": "incident",
            "cache": build_e01_artifact_cache(
                incident,
                include_lazy_targets=False,
                include_high_value_patterns=True,
            ),
        },
    ])

    assert result["policy"] == "e01_labelled_pair_bias_v2"
    assert result["ok"] is True
    assert result["overcall_count"] == 0
    assert result["undercall_count"] == 0


def test_e01_bias_evaluation_flags_overcall_and_undercall():
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias

    result = evaluate_e01_cache_bias([
        {
            "case_id": "benign_with_readme",
            "label": "benign",
            "cache": {"artifact_type_counts": {"Ransom Note Candidate": 1, "EVTX Candidate": 1}, "parser_failures": []},
        },
        {
            "case_id": "incident_missing_impact",
            "label": "incident",
            "cache": {"artifact_type_counts": {"EVTX Candidate": 1, "Prefetch Candidate": 1}, "parser_failures": []},
        },
    ])

    assert result["ok"] is False
    assert result["overcalled_cases"] == ["benign_with_readme"]
    assert result["undercalled_cases"] == ["incident_missing_impact"]


def test_e01_bias_evaluation_accepts_data_leakage_scenario_evidence():
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias

    leakage = _PairFakeE01({
        "**/*.odt": [{"path": "/Nitroba work.odt"}],
        "**/*.zip": [{"path": "/01.zip"}],
        "**/Nitroba work.odt": [{"path": "/Nitroba work.odt"}],
        "**/01.zip": [{"path": "/01.zip"}],
    })

    cache = build_e01_artifact_cache(
        leakage,
        include_lazy_targets=False,
        extra_patterns=[
            {"artifact_type": "Expected Scenario Path", "pattern": "**/Nitroba work.odt", "lane": "context"},
            {"artifact_type": "Expected Scenario Path", "pattern": "**/01.zip", "lane": "context"},
        ],
    )
    result = evaluate_e01_cache_bias([
        {"case_id": "m57_usb", "label": "data_leakage_scenario", "cache": cache},
    ])

    assert result["ok"] is True
    assert result["undercall_count"] == 0
    assert result["results"][0]["predicted"] == "data_leakage_candidate"
    assert result["results"][0]["scenario_evidence_count"] == 2


def test_e01_bias_evaluation_accepts_spear_phishing_data_leakage_label():
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias

    result = evaluate_e01_cache_bias([
        {
            "case_id": "m57_jean",
            "label": "spear_phishing_data_leakage",
            "cache": {
                "artifact_type_counts": {"Expected Scenario Path": 1, "Document Candidate": 1},
                "parser_failures": [],
            },
        },
    ])

    assert result["ok"] is True
    assert result["results"][0]["predicted"] == "data_leakage_candidate"


def test_e01_bias_evaluation_does_not_overcall_benign_documents_alone():
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias

    result = evaluate_e01_cache_bias([
        {
            "case_id": "benign_docs",
            "label": "benign",
            "cache": {"artifact_type_counts": {"Document Candidate": 12, "Archive Candidate": 2}, "parser_failures": []},
        },
    ])

    assert result["ok"] is True
    assert result["results"][0]["predicted"] == "benign_or_no_impact_candidate"
    assert result["results"][0]["data_exposure_candidate_count"] == 14
