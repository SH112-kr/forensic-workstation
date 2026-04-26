"""Safe external DFIR validation runner.

Only downloads allowlisted, non-executable evidence/log datasets. This module is
intended for repeatable validation against public scenarios without pulling
malware samples or arbitrary archives.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from regression.external_evtx_attack_samples import validate_scenarios
from regression.external_apt_dataset import validate_apt29_dataset
from regression.external_cfreds_hacking_case import (
    CFREDS_HACKING_CASE,
    download_cfreds_hacking_case,
    validate_cfreds_hacking_case,
)
from regression.external_e01_validation import SAFE_E01_DATASETS, download_safe_e01, validate_safe_e01_pair
from regression.external_otrf_security_datasets import validate_otrf_scenario

DATA_DIR = PROJECT_ROOT / "external" / "dfir_validation"

SAFE_DATASETS = {
    "evtx_attack_samples_csv": {
        "url": "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/evtx_data.csv",
        "path": DATA_DIR / "evtx_attack_samples_evtx_data.csv",
        "type": "parsed_csv_event_log_metadata",
        "validator": "evtx_attack_samples",
    },
    "otrf_eventlog_service_json": {
        "url": (
            "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
            "datasets/atomic/windows/defense_evasion/host/"
            "psh_disable_eventlog_service_startuptype_modification.zip"
        ),
        "path": DATA_DIR / "otrf_psh_disable_eventlog_service.zip",
        "type": "zipped_json_event_logs",
        "validator": "otrf_eventlog_service",
    },
    "apt29_audit_json_zip": {
        "url": "https://github.com/skrghosh/apt-dataset/raw/main/apt29.json.zip",
        "path": DATA_DIR / "apt29.json.zip",
        "type": "zipped_json_audit_logs",
        "validator": "apt29_stage_reconstruction",
    },
    "cfreds_hacking_case_e01": {
        "url": CFREDS_HACKING_CASE["e01_url"],
        "path": CFREDS_HACKING_CASE["e01_path"],
        "type": "public_e01_hacking_training_image",
        "validator": "cfreds_hacking_case",
    },
    "normal_nps_2010_emails_e01": {
        "url": SAFE_E01_DATASETS["normal_nps_2010_emails"]["url"],
        "path": SAFE_E01_DATASETS["normal_nps_2010_emails"]["path"],
        "type": "public_e01_benign_training_image",
        "validator": "safe_e01_pair",
    },
    "incident_m57_charlie_usb_e01": {
        "url": SAFE_E01_DATASETS["incident_m57_charlie_usb"]["url"],
        "path": SAFE_E01_DATASETS["incident_m57_charlie_usb"]["path"],
        "type": "public_e01_data_leakage_training_image",
        "validator": "safe_e01_pair",
    },
    "incident_m57_jean_laptop_e01": {
        "url": SAFE_E01_DATASETS["incident_m57_jean_laptop"]["url"],
        "path": SAFE_E01_DATASETS["incident_m57_jean_laptop"]["path"],
        "type": "public_e01_spear_phishing_data_leakage_image",
        "validator": "safe_e01_pair",
    },
}


def download_allowlisted(name: str) -> dict[str, Any]:
    if name == "normal_nps_2010_emails_e01":
        return download_safe_e01("normal_nps_2010_emails")
    if name == "incident_m57_charlie_usb_e01":
        return download_safe_e01("incident_m57_charlie_usb")
    if name == "incident_m57_jean_laptop_e01":
        return download_safe_e01("incident_m57_jean_laptop")
    if name == "cfreds_hacking_case_e01":
        downloads = download_cfreds_hacking_case()
        return {
            "name": name,
            "path": str(CFREDS_HACKING_CASE["e01_path"]),
            "type": SAFE_DATASETS[name]["type"],
            "downloaded": all(item["downloaded"] for item in downloads),
            "parts": downloads,
            "safety": {
                "allowlisted": True,
                "executables_allowed": False,
                "malware_samples_allowed": False,
            },
        }
    spec = SAFE_DATASETS[name]
    target = Path(spec["path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        urllib.request.urlretrieve(spec["url"], target)
    return {
        "name": name,
        "path": str(target),
        "type": spec["type"],
        "downloaded": target.exists(),
        "safety": {
            "allowlisted": True,
            "executables_allowed": False,
            "malware_samples_allowed": False,
        },
    }


def run_external_validation(download: bool = True) -> dict[str, Any]:
    downloads = []
    if download:
        for name in SAFE_DATASETS:
            downloads.append(download_allowlisted(name))

    results = []
    evtx_path = SAFE_DATASETS["evtx_attack_samples_csv"]["path"]
    if Path(evtx_path).exists():
        results.append(validate_scenarios(evtx_path))

    otrf_path = SAFE_DATASETS["otrf_eventlog_service_json"]["path"]
    if Path(otrf_path).exists():
        results.append(validate_otrf_scenario(otrf_path))

    apt29_path = SAFE_DATASETS["apt29_audit_json_zip"]["path"]
    if Path(apt29_path).exists():
        results.append(validate_apt29_dataset(apt29_path))

    cfreds_path = SAFE_DATASETS["cfreds_hacking_case_e01"]["path"]
    if Path(cfreds_path).exists():
        results.append(validate_cfreds_hacking_case(download=False))

    required_e01_paths = [
        Path(spec["path"]) for spec in SAFE_E01_DATASETS.values()
        if spec.get("required", False)
    ]
    if all(p.exists() for p in required_e01_paths):
        results.append(validate_safe_e01_pair(download=False))

    passed = sum(1 for r in results if r.get("ok"))
    return {
        "ok": passed == len(results) and bool(results),
        "downloaded": downloads,
        "result_count": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
        "safety_policy": {
            "only_allowlisted_urls": True,
            "download_executables": False,
            "execute_extracted_files": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-download", action="store_true", help="Validate only already-downloaded datasets")
    parser.add_argument("--json", action="store_true", help="Emit full JSON")
    args = parser.parse_args()
    result = run_external_validation(download=not args.no_download)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"ok={result['ok']} passed={result['passed']} failed={result['failed']} results={result['result_count']}")
        for item in result["results"]:
            print(f"- {item.get('dataset')}: ok={item.get('ok')}")
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
