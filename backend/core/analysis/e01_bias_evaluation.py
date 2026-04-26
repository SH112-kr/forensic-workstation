"""Bias evaluation for labelled E01-derived caches."""

from __future__ import annotations

from typing import Any


RANSOMWARE_IMPACT_TYPES = {"Ransom Note Candidate", "Encrypted Extension Candidate"}
SCENARIO_EVIDENCE_TYPES = {"Expected Scenario Path"}
DATA_EXPOSURE_TYPES = {"Document Candidate", "Archive Candidate"}
BASELINE_TYPES = {"EVTX Candidate", "Prefetch Candidate", "Registry Hive Candidate", "User Registry Hive Candidate"}


def evaluate_e01_cache_bias(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare labelled E01-derived caches for overcall/undercall bias.

    Each case:
      {"case_id": str, "label": "benign|incident|data_leakage_scenario|spear_phishing_data_leakage",
       "cache": build_e01_artifact_cache(...)}
    """
    results = []
    overcalls = []
    undercalls = []
    for case in cases:
        cache = case.get("cache", {}) or {}
        label = case.get("label", "unknown")
        type_counts = cache.get("artifact_type_counts", {}) or {}
        ransomware_impact_count = sum(int(type_counts.get(t, 0) or 0) for t in RANSOMWARE_IMPACT_TYPES)
        scenario_evidence_count = sum(int(type_counts.get(t, 0) or 0) for t in SCENARIO_EVIDENCE_TYPES)
        data_exposure_count = sum(int(type_counts.get(t, 0) or 0) for t in DATA_EXPOSURE_TYPES)
        baseline_count = sum(int(type_counts.get(t, 0) or 0) for t in BASELINE_TYPES)
        parser_failures = len(cache.get("parser_failures", []) or [])

        predicted = "benign_or_no_impact_candidate"
        if ransomware_impact_count > 0:
            predicted = "ransomware_impact_candidate"
        elif scenario_evidence_count > 0 and label in {"data_leakage_scenario", "spear_phishing_data_leakage"}:
            predicted = "data_leakage_candidate"
        elif scenario_evidence_count > 0:
            predicted = "scenario_evidence_candidate"

        confidence = "low"
        if ransomware_impact_count >= 2 and baseline_count >= 2:
            confidence = "moderate"
        if predicted == "data_leakage_candidate" and scenario_evidence_count >= 2:
            confidence = "moderate"
        if parser_failures:
            confidence = "incomplete"

        ok = False
        if label == "benign":
            ok = predicted == "benign_or_no_impact_candidate"
        elif label == "incident":
            ok = predicted == "ransomware_impact_candidate"
        elif label in {"data_leakage_scenario", "spear_phishing_data_leakage"}:
            ok = predicted == "data_leakage_candidate"

        item = {
            "case_id": case.get("case_id", ""),
            "label": label,
            "predicted": predicted,
            "ok": ok,
            "confidence": confidence,
            "impact_candidate_count": ransomware_impact_count,
            "ransomware_impact_candidate_count": ransomware_impact_count,
            "scenario_evidence_count": scenario_evidence_count,
            "data_exposure_candidate_count": data_exposure_count,
            "baseline_artifact_count": baseline_count,
            "parser_failures": parser_failures,
            "bias_notes": [],
        }
        if label == "benign" and predicted != "benign_or_no_impact_candidate":
            item["bias_notes"].append("overcall_risk: benign image has scenario or impact candidates")
            overcalls.append(item["case_id"])
        if label == "incident" and predicted != "ransomware_impact_candidate":
            item["bias_notes"].append("undercall_risk: incident image lacks ransomware impact candidates in current E01 cache")
            undercalls.append(item["case_id"])
        if label in {"data_leakage_scenario", "spear_phishing_data_leakage"} and predicted != "data_leakage_candidate":
            item["bias_notes"].append(
                "undercall_risk: data-leakage image lacks scenario evidence in current E01 cache"
            )
            undercalls.append(item["case_id"])
        if label in {"data_leakage_scenario", "spear_phishing_data_leakage"} and ransomware_impact_count > 0:
            item["bias_notes"].append("taxonomy_risk: data-leakage scenario also has ransomware-like filename candidates")
        if baseline_count == 0:
            item["bias_notes"].append("coverage_risk: baseline OS artifacts not indexed; do not trust absence")
        if label == "benign" and data_exposure_count > 0:
            item["bias_notes"].append("baseline_risk: benign images can contain documents or archives; do not overcall exposure alone")
        results.append(item)

    return {
        "ok": not overcalls and not undercalls,
        "policy": "e01_labelled_pair_bias_v2",
        "case_count": len(results),
        "overcall_count": len(overcalls),
        "undercall_count": len(undercalls),
        "overcalled_cases": overcalls,
        "undercalled_cases": undercalls,
        "results": results,
        "notes": [
            "E01 inventory candidates are not final verdicts. They only decide which deeper parsers to run.",
            "Benign and incident E01 images must be evaluated together to expose overcall/undercall bias.",
            "Document/archive candidates are exposure surface, not maliciousness, unless scenario evidence or semantic parsers support a data-leakage label.",
        ],
    }
