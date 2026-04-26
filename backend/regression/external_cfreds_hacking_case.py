"""Validation adapter for the NIST CFReDS Hacking Case E01 image.

The image is public training evidence. Validation is read-only and checks a
small answer-key-derived set of paths/content markers without extracting or
executing any files.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "external" / "dfir_validation"

CFREDS_HACKING_CASE = {
    "e01_url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E01",
    "e02_url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E02",
    "answers_url": "https://cfreds-archive.nist.gov/images/TestAnswers.pdf",
    "e01_path": DATA_DIR / "4Dell Latitude CPi.E01",
    "e02_path": DATA_DIR / "4Dell Latitude CPi.E02",
    "answers_path": DATA_DIR / "cfreds_hacking_case_answers.pdf",
}

EXPECTED_PATHS = {
    "cain_password_tool": "/c:/Program Files/Cain",
    "ethereal_packet_sniffer": "/c:/Program Files/Ethereal",
    "stored_password_tool": "/c:/Program Files/123WASP",
    "anonymizer": "/c:/Program Files/Anonymizer",
    "cuteftp": "/c:/Program Files/GlobalSCAPE",
    "look_at_lan": "/c:/Program Files/Look@LAN",
    "netstumbler": "/c:/Program Files/Network Stumbler",
    "look_at_lan_identity_file": "/c:/Program Files/Look@LAN/irunin.ini",
    "mirc_settings": "/c:/Program Files/mIRC/mirc.ini",
    "ethereal_interception_output": "/c:/Documents and Settings/Mr. Evil/interception",
}

CONTENT_MARKERS = {
    "look_at_lan_identity_file": {
        "path": "/c:/Program Files/Look@LAN/irunin.ini",
        "markers": ["Mr. Evil", "192.168.1.111", "0010a4933e09"],
    },
    "mirc_settings": {
        "path": "/c:/Program Files/mIRC/mirc.ini",
        "markers": ["mrevilrulez"],
    },
    "ethereal_interception_output": {
        "path": "/c:/Documents and Settings/Mr. Evil/interception",
        "markers": ["mobile.msn.com", "Windows CE"],
    },
}


def download_cfreds_hacking_case() -> list[dict[str, Any]]:
    downloads = []
    for key in ("e01", "e02", "answers"):
        url = CFREDS_HACKING_CASE[f"{key}_url"]
        path = Path(CFREDS_HACKING_CASE[f"{key}_path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            urllib.request.urlretrieve(url, path)
        downloads.append({
            "name": f"cfreds_hacking_case_{key}",
            "path": str(path),
            "downloaded": path.exists(),
            "safety": {
                "allowlisted": True,
                "read_only": True,
                "execute_extracted_files": False,
            },
        })
    return downloads


def validate_cfreds_hacking_case(download: bool = False) -> dict[str, Any]:
    from core.connectors.e01_image import E01ImageConnector

    downloads = download_cfreds_hacking_case() if download else []
    e01_path = Path(CFREDS_HACKING_CASE["e01_path"])
    e02_path = Path(CFREDS_HACKING_CASE["e02_path"])
    answers_path = Path(CFREDS_HACKING_CASE["answers_path"])
    missing_files = [str(p) for p in (e01_path, e02_path, answers_path) if not p.exists()]
    if missing_files:
        return {
            "ok": False,
            "dataset": "NIST CFReDS Hacking Case E01",
            "error": "required files not downloaded",
            "missing_files": missing_files,
            "downloads": downloads,
        }

    connector = E01ImageConnector()
    try:
        metadata = connector.connect(str(e01_path))
        path_results = _validate_paths(connector)
        marker_results = _validate_content_markers(connector)
    finally:
        connector.disconnect()

    missing_paths = [item["name"] for item in path_results if not item["ok"]]
    missing_markers = [
        f"{item['name']}:{marker}"
        for item in marker_results
        for marker, present in item["markers_present"].items()
        if not present
    ]
    bias = _evaluate_bias(path_results, marker_results)
    return {
        "ok": not missing_paths and not missing_markers and bool(bias["ok"]),
        "dataset": "NIST CFReDS Hacking Case E01",
        "policy": "cfreds_hacking_case_v1",
        "downloads": downloads,
        "metadata": {
            "hostname": metadata.get("hostname", ""),
            "os_type": metadata.get("os_type", ""),
            "volume_count": len(metadata.get("volumes", [])),
        },
        "results": path_results,
        "content_marker_results": marker_results,
        "missing_paths": missing_paths,
        "missing_markers": missing_markers,
        "bias_evaluation": bias,
        "safety": {
            "download_type": "allowlisted public E01 evidence image and official answer PDF",
            "read_only": True,
            "executables_executed": False,
            "files_extracted": False,
        },
        "notes": [
            "The validator checks public answer-key markers without exposing raw sensitive content to LLM outputs.",
            "This is a hacking-tool and packet-sniffing scenario, not ransomware; ransomware impact evidence is not required.",
        ],
    }


def _validate_paths(connector: Any) -> list[dict[str, Any]]:
    results = []
    for name, path in EXPECTED_PATHS.items():
        info = connector.get_file_info(path)
        results.append({
            "name": name,
            "path": path,
            "ok": not bool(info.get("error")),
            "size": info.get("size", -1),
            "created": info.get("created", ""),
            "modified": info.get("modified", ""),
        })
    return results


def _validate_content_markers(connector: Any) -> list[dict[str, Any]]:
    results = []
    for name, spec in CONTENT_MARKERS.items():
        try:
            text = connector.read_file_content(spec["path"], max_size=250_000).decode(
                "latin-1",
                errors="ignore",
            )
        except Exception as exc:  # noqa: BLE001
            results.append({
                "name": name,
                "path": spec["path"],
                "ok": False,
                "error": str(exc),
                "markers_present": {marker: False for marker in spec["markers"]},
            })
            continue
        lowered = text.lower()
        markers_present = {marker: marker.lower() in lowered for marker in spec["markers"]}
        results.append({
            "name": name,
            "path": spec["path"],
            "ok": all(markers_present.values()),
            "markers_present": markers_present,
        })
    return results


def _evaluate_bias(
    path_results: list[dict[str, Any]],
    marker_results: list[dict[str, Any]],
) -> dict[str, Any]:
    tools_detected = {
        item["name"]
        for item in path_results
        if item["ok"] and item["name"] in {
            "cain_password_tool",
            "ethereal_packet_sniffer",
            "stored_password_tool",
            "anonymizer",
            "cuteftp",
            "look_at_lan",
            "netstumbler",
        }
    }
    marker_names = {item["name"] for item in marker_results if item["ok"]}
    notes = []
    if len(tools_detected) < 6:
        notes.append("undercall_risk: fewer than six answer-key hacking tools detected")
    if "look_at_lan_identity_file" not in marker_names:
        notes.append("attribution_gap: identity/IP/MAC marker file not verified")
    if "ethereal_interception_output" not in marker_names:
        notes.append("undercall_risk: packet-sniffing output not verified")
    return {
        "ok": not notes,
        "detected_hacking_tool_count": len(tools_detected),
        "expected_hacking_tool_count": 6,
        "bias_notes": notes,
        "missed_stage_count": len(notes),
    }
