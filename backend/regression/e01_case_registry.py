"""Allowlisted E01 case registry for autonomous validation.

The registry separates scoring policy from parser behavior. Public cases may be
downloadable and useful for coverage testing without being valid accuracy
benchmarks yet.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "external" / "dfir_validation"


def _lonewolf_segments() -> tuple[list[str], list[Path]]:
    base = "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2018-lonewolf/LoneWolf_Image_Files"
    paths = [DATA_DIR / "lonewolf" / f"LoneWolf.E{index:02d}" for index in range(1, 10)]
    urls = [f"{base}/LoneWolf.E{index:02d}" for index in range(1, 10)]
    return urls, paths


LONEWOLF_URLS, LONEWOLF_PATHS = _lonewolf_segments()


E01_CASE_REGISTRY: list[dict[str, Any]] = [
    {
        "case_id": "cfreds_hacking",
        "path": DATA_DIR / "4Dell Latitude CPi.E01",
        "benchmark_type": "known_answer_regression",
        "expected_scope": "windows_system",
        "scoring_included": True,
        "download_urls": [],
        "companion_paths": [DATA_DIR / "4Dell Latitude CPi.E02"],
        "source": "NIST CFReDS Hacking Case",
    },
    {
        "case_id": "m57_jean",
        "path": DATA_DIR / "nps-2008-jean.E01",
        "benchmark_type": "known_answer_regression",
        "expected_scope": "windows_system",
        "scoring_included": True,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E01",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E02",
        ],
        "download_paths": [
            DATA_DIR / "nps-2008-jean.E01",
            DATA_DIR / "nps-2008-jean.E02",
        ],
        "companion_paths": [DATA_DIR / "nps-2008-jean.E02"],
        "source": "Digital Corpora M57 Jean",
    },
    {
        "case_id": "m57_charlie_usb",
        "path": DATA_DIR / "charlie-work-usb-2009-12-11.E01",
        "benchmark_type": "known_answer_regression",
        "expected_scope": "data_volume",
        "scoring_included": False,
        "validation_enabled": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/usb/charlie-work-usb-2009-12-11.E01",
        ],
        "download_paths": [DATA_DIR / "charlie-work-usb-2009-12-11.E01"],
        "companion_paths": [],
        "source": "Digital Corpora M57 Patents",
    },
    {
        "case_id": "m57_terry_usb",
        "path": DATA_DIR / "m57-usb" / "terry-work-usb-2009-12-11.E01",
        "benchmark_type": "coverage_regression",
        "expected_scope": "data_volume",
        "scoring_included": False,
        "validation_enabled": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted/terry-work-usb-2009-12-11.E01",
        ],
        "download_paths": [DATA_DIR / "m57-usb" / "terry-work-usb-2009-12-11.E01"],
        "companion_paths": [],
        "source": "Digital Corpora M57 Patents USB",
        "notes": "No project-local answer rubric yet; used for parser coverage and overcall-bias regression only.",
    },
    {
        "case_id": "m57_jo_work_usb",
        "path": DATA_DIR / "m57-usb" / "jo-work-usb-2009-12-11.E01",
        "benchmark_type": "coverage_regression",
        "expected_scope": "data_volume",
        "scoring_included": False,
        "validation_enabled": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted/jo-work-usb-2009-12-11.E01",
        ],
        "download_paths": [DATA_DIR / "m57-usb" / "jo-work-usb-2009-12-11.E01"],
        "companion_paths": [],
        "source": "Digital Corpora M57 Patents USB",
        "notes": "No project-local answer rubric yet; used for parser coverage and overcall-bias regression only.",
    },
    {
        "case_id": "m57_jo_favorites_usb",
        "path": DATA_DIR / "m57-usb" / "jo-favorites-usb-2009-12-11.E01",
        "benchmark_type": "coverage_regression",
        "expected_scope": "data_volume",
        "scoring_included": False,
        "validation_enabled": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted/jo-favorites-usb-2009-12-11.E01",
        ],
        "download_paths": [DATA_DIR / "m57-usb" / "jo-favorites-usb-2009-12-11.E01"],
        "companion_paths": [],
        "source": "Digital Corpora M57 Patents USB",
        "notes": "No project-local answer rubric yet; used for parser coverage and overcall-bias regression only.",
    },
    {
        "case_id": "m57_jo_newcomputer_20091120",
        "path": DATA_DIR / "m57-redacted" / "jo-2009-11-20-newComputer.E01",
        "benchmark_type": "coverage_regression",
        "expected_scope": "windows_system",
        "scoring_included": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/drives-redacted/jo-2009-11-20-newComputer.E01",
        ],
        "download_paths": [DATA_DIR / "m57-redacted" / "jo-2009-11-20-newComputer.E01"],
        "companion_paths": [],
        "source": "Digital Corpora M57 Patents redacted drive",
        "notes": "No project-local answer rubric yet; used for Windows-system parser coverage and degradation regression only.",
    },
    {
        "case_id": "magnet_2019_windows_desktop",
        "path": DATA_DIR / "magnet" / "2019-windows-desktop" / "2019 CTF - Windows-Desktop-001.E01",
        "benchmark_type": "coverage_regression",
        "expected_scope": "windows_system",
        "scoring_included": False,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/magnet/2019%20CTF%20-%20Windows-Desktop.zip",
        ],
        "download_paths": [DATA_DIR / "magnet" / "2019 CTF - Windows-Desktop.zip"],
        "companion_paths": [],
        "source": "Magnet Forensics CTF 2019 Windows Desktop via Digital Corpora",
        "notes": "ZIP contains the E01; extraction is performed manually before validation. No answer rubric is used for scoring.",
    },
    {
        "case_id": "nps_domexusers_redacted",
        "path": DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E01",
        "benchmark_type": "clean_baseline_regression",
        "expected_scope": "windows_system",
        "scoring_included": True,
        "label": "benign",
        "expected_malicious_findings": 0,
        "download_urls": [
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-domexusers/nps-2009-domexusers.redacted.E01",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-domexusers/nps-2009-domexusers.redacted.E02",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-domexusers/nps-2009-domexusers.redacted.E03",
        ],
        "download_paths": [
            DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E01",
            DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E02",
            DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E03",
        ],
        "companion_paths": [
            DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E02",
            DATA_DIR / "nps-2009-domexusers" / "nps-2009-domexusers.redacted.E03",
        ],
        "source": "Digital Corpora NPS DOMEX Users redacted Windows XP image",
    },
    {
        "case_id": "lonewolf",
        "path": DATA_DIR / "lonewolf" / "LoneWolf.E01",
        "benchmark_type": "known_answer_regression",
        "expected_scope": "windows_system",
        "scoring_included": True,
        "download_urls": LONEWOLF_URLS,
        "download_paths": LONEWOLF_PATHS,
        "companion_paths": LONEWOLF_PATHS[1:],
        "expected_marker_paths": [
            "/c:/Users/jcloudy/Downloads/rootkey.csv",
            "/c:/Users/jcloudy/Desktop/AIRPORT INFORMATION.docx",
            "/c:/Users/jcloudy/Desktop/The Cloudy Manifesto.docx",
            "/c:/Users/jcloudy/Dropbox/The Cloudy Manifesto.docx",
            "/c:/Users/jcloudy/Desktop/Cloudy thoughts (4apr).docx",
            "/c:/Users/jcloudy/Desktop/Planning.docx",
            "/c:/Users/jcloudy/OneDrive/Planning.docx",
            "/c:/Users/jcloudy/Desktop/Operation 2nd Hand Smoke.pptx",
            "/c:/Users/jcloudy/Dropbox/Operation 2nd Hand Smoke.pptx",
            "/c:/Users/jcloudy/Desktop/AMEN.pdf",
        ],
        "source": "Digital Corpora 2018 Lone Wolf",
    },
]


def download_registered_cases(*, case_ids: set[str] | None = None) -> list[dict[str, Any]]:
    downloads: list[dict[str, Any]] = []
    for spec in E01_CASE_REGISTRY:
        if case_ids and str(spec["case_id"]) not in case_ids:
            continue
        if not case_ids and not spec.get("validation_enabled", True):
            continue
        urls = [str(url) for url in spec.get("download_urls", [])]
        paths = [Path(path) for path in spec.get("download_paths", [])]
        for url, path in zip(urls, paths, strict=False):
            path.parent.mkdir(parents=True, exist_ok=True)
            before = path.exists()
            if not before:
                urllib.request.urlretrieve(url, path)
            downloads.append({
                "case_id": spec["case_id"],
                "url": url,
                "path": str(path),
                "downloaded": path.exists(),
                "already_present": before,
                "safety": {
                    "allowlisted": True,
                    "read_only": True,
                    "execute_extracted_files": False,
                },
            })
    return downloads
