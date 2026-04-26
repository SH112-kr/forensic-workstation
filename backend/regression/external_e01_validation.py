"""Safe validation for public E01 images.

The real E01 files live under external/dfir_validation and are ignored by git.
This module validates read-only access and compares discovered paths against
small ground-truth expectations.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "external" / "dfir_validation"

SAFE_E01_DATASETS = {
    "normal_nps_2010_emails": {
        "url": "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2010-emails/nps-2010-emails.E01",
        "path": DATA_DIR / "nps-2010-emails.E01",
        "label": "benign",
        "expected_paths": [],
        "expected_missing_verdict": "no_impact_candidates",
        "required": True,
        "include_high_value_patterns": True,
    },
    "incident_m57_charlie_usb": {
        "url": "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/usb/charlie-work-usb-2009-12-11.E01",
        "path": DATA_DIR / "charlie-work-usb-2009-12-11.E01",
        "label": "data_leakage_scenario",
        "expected_paths": [
            "/Nitroba work.odt",
            "/01.zip",
            "/invsecr2.exe",
        ],
        "expected_missing_verdict": "",
        "required": True,
        "include_high_value_patterns": True,
    },
    "incident_m57_jean_laptop": {
        "url": "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E01",
        "path": DATA_DIR / "nps-2008-jean.E01",
        "companion_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E02",
        ],
        "companion_paths": [
            DATA_DIR / "nps-2008-jean.E02",
        ],
        "label": "spear_phishing_data_leakage",
        "expected_paths": [
            "/c:/Documents and Settings/Jean/Desktop/m57biz.xls",
        ],
        "expected_missing_verdict": "",
        "required": False,
        "include_high_value_patterns": False,
    },
}


def download_safe_e01(name: str) -> dict[str, Any]:
    spec = SAFE_E01_DATASETS[name]
    path = Path(spec["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        urllib.request.urlretrieve(spec["url"], path)
    companions = []
    for url, companion_path in zip(spec.get("companion_urls", []), spec.get("companion_paths", []), strict=False):
        companion = Path(companion_path)
        companion.parent.mkdir(parents=True, exist_ok=True)
        if not companion.exists():
            urllib.request.urlretrieve(url, companion)
        companions.append(str(companion))
    return {
        "name": name,
        "path": str(path),
        "companion_paths": companions,
        "label": spec["label"],
        "downloaded": path.exists() and all(Path(p).exists() for p in companions),
        "safety": {
            "allowlisted": True,
            "read_only": True,
            "execute_extracted_files": False,
        },
    }


def validate_safe_e01_pair(download: bool = True) -> dict[str, Any]:
    from core.analysis.e01_artifact_cache import build_e01_artifact_cache
    from core.analysis.e01_bias_evaluation import evaluate_e01_cache_bias
    from core.connectors.e01_image import E01ImageConnector

    downloads = []
    if download:
        for name in SAFE_E01_DATASETS:
            downloads.append(download_safe_e01(name))

    results = []
    bias_cases = []
    for name, spec in SAFE_E01_DATASETS.items():
        path = Path(spec["path"])
        if not path.exists():
            if not spec.get("required", False):
                results.append({
                    "case_id": name,
                    "label": spec["label"],
                    "ok": True,
                    "skipped": True,
                    "reason": "optional E01 not downloaded",
                })
                continue
            results.append({"case_id": name, "ok": False, "error": "E01 not downloaded"})
            continue
        connector = E01ImageConnector()
        try:
            meta = connector.connect(str(path))
            cache = build_e01_artifact_cache(
                connector,
                source_id=name,
                limit_per_pattern=50,
                include_high_value_patterns=bool(spec.get("include_high_value_patterns", True)),
            )
            found_paths = {record["value"]["internal_path"] for record in cache["records"]}
            missing = [
                expected for expected in spec["expected_paths"]
                if (
                    expected not in found_paths
                    and not any(str(path).endswith(expected) for path in found_paths)
                    and not _path_exists(connector, expected)
                )
            ]
            impact_candidates = (
                cache.get("artifact_type_counts", {}).get("Ransom Note Candidate", 0)
                + cache.get("artifact_type_counts", {}).get("Encrypted Extension Candidate", 0)
            )
            scenario_evidence = len(spec["expected_paths"]) - len(missing)
            ok = not missing
            if spec["label"] == "benign" and impact_candidates:
                ok = False
            if spec["label"] in {"data_leakage_scenario", "spear_phishing_data_leakage"} and not scenario_evidence:
                ok = False
            results.append({
                "case_id": name,
                "label": spec["label"],
                "ok": ok,
                "metadata": meta,
                "record_count": cache["record_count"],
                "artifact_type_counts": cache["artifact_type_counts"],
                "expected_paths": spec["expected_paths"],
                "missing_expected_paths": missing,
                "impact_candidates": impact_candidates,
                "scenario_evidence": scenario_evidence,
                "parser_failures": cache["parser_failures"],
            })
            bias_cache = dict(cache)
            bias_cache["artifact_type_counts"] = dict(cache.get("artifact_type_counts", {}))
            if scenario_evidence:
                bias_cache["artifact_type_counts"]["Expected Scenario Path"] = scenario_evidence
            bias_cases.append({"case_id": name, "label": spec["label"], "cache": bias_cache})
        except Exception as exc:  # noqa: BLE001
            results.append({"case_id": name, "label": spec["label"], "ok": False, "error": str(exc)})
        finally:
            connector.disconnect()

    bias = evaluate_e01_cache_bias(bias_cases) if bias_cases else {}
    return {
        "ok": all(r.get("ok") for r in results) and bool(results) and bool(bias.get("ok", True)),
        "dataset": "Digital Corpora safe E01 pair and M57 data-leakage images",
        "dataset_count": len(results),
        "downloads": downloads,
        "results": results,
        "bias_evaluation": bias,
        "safety": {
            "download_type": "allowlisted public E01 evidence images",
            "read_only": True,
            "executables_executed": False,
        },
        "notes": [
            "M57 Charlie USB is a data-leakage scenario, not a ransomware case; ransomware impact candidates should not be required.",
            "M57 Jean is a spear-phishing data-leakage scenario; the expected spreadsheet path is used as scenario evidence, not as a malware indicator.",
            "The benign NPS email image currently opens as a volume without a recognized filesystem in dissect; that is recorded as coverage risk, not maliciousness.",
        ],
    }


def _path_exists(connector: Any, internal_path: str) -> bool:
    try:
        return not bool(connector.get_file_info(internal_path).get("error"))
    except Exception:
        return False
