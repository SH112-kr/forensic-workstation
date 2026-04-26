"""Validation adapter for the public APT simulation audit-log dataset.

The dataset is JSON audit logs, not executable samples. Validation is based on
campaign-stage evidence published by the dataset README and checked against
high-precision process/registry/file events.
"""

from __future__ import annotations

import json
import re
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


APT29_EXPECTED_STAGES = {
    "agent_execution": {
        "description": "CALDERA/agent-driven execution from the simulated implant context.",
        "mitre": ["T1059"],
    },
    "powershell_spawning": {
        "description": "PowerShell spawned by the simulated agent.",
        "mitre": ["T1059.001"],
    },
    "automated_systeminfo_collection": {
        "description": "Automated host information collection.",
        "mitre": ["T1082"],
    },
    "data_staging_for_exfil": {
        "description": "User files collected and compressed to Draft.zip.",
        "mitre": ["T1074.001", "T1560.001"],
    },
    "exfiltration": {
        "description": "Multipart HTTP upload of staged archive.",
        "mitre": ["T1041", "T1102"],
    },
    "uac_bypass": {
        "description": "sdclt DelegateExecute UAC bypass chain.",
        "mitre": ["T1548.002"],
    },
    "sysinternals_tool_transfer": {
        "description": "Sysinternals suite downloaded and planted.",
        "mitre": ["T1105"],
    },
    "screen_capture": {
        "description": "Screen capture capability invoked.",
        "mitre": ["T1113"],
    },
    "artifact_cleanup": {
        "description": "Cleanup removes jobs, staged files, and helper scripts.",
        "mitre": ["T1070.004"],
    },
}


def validate_apt29_dataset(zip_path: str | Path, *, use_cache: bool = True) -> dict[str, Any]:
    path = Path(zip_path)
    if not path.exists():
        return {"ok": False, "dataset": "skrghosh/apt-dataset APT29", "error": "APT29 zip not found"}

    cache_path = path.with_suffix(path.suffix + ".validation_cache.json")
    fingerprint = _fingerprint(path)
    if use_cache and cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("fingerprint") == fingerprint:
                cached["cache_hit"] = True
                return cached
        except Exception:
            pass

    started = time.perf_counter()
    scan = scan_apt29_zip(path)
    results = []
    missed = []
    for stage, expected in APT29_EXPECTED_STAGES.items():
        hits = scan["stage_hits"].get(stage, [])
        ok = bool(hits)
        if not ok:
            missed.append(stage)
        results.append({
            "stage": stage,
            "ok": ok,
            "hit_count": len(hits),
            "expected_mitre": expected["mitre"],
            "description": expected["description"],
            "examples": hits[:3],
        })

    result = {
        "ok": not missed,
        "dataset": "skrghosh/apt-dataset APT29",
        "policy": "apt29_stage_reconstruction_v1",
        "fingerprint": fingerprint,
        "records_scanned": scan["records_scanned"],
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "expected_stage_count": len(APT29_EXPECTED_STAGES),
        "detected_stage_count": len(APT29_EXPECTED_STAGES) - len(missed),
        "missed_stages": missed,
        "results": results,
        "object_counts": scan["object_counts"],
        "action_counts": scan["action_counts"],
        "bias_evaluation": _evaluate_apt_stage_bias(results),
        "safety": {
            "download_type": "zipped JSON audit logs",
            "executables_extracted": False,
            "malware_samples_downloaded": False,
        },
        "notes": [
            "This validates stage reconstruction from audit logs, not malware attribution.",
            "Rules require behavior chains such as parent process and command content to reduce keyword-only bias.",
        ],
    }
    if use_cache:
        cache_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result


def scan_apt29_zip(zip_path: str | Path) -> dict[str, Any]:
    stage_hits: dict[str, list[dict[str, Any]]] = {stage: [] for stage in APT29_EXPECTED_STAGES}
    object_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    records = 0
    with zipfile.ZipFile(zip_path) as zf:
        _validate_zip_members(zf)
        with zf.open("apt29.json") as f:
            for raw in f:
                records += 1
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                action = str(event.get("action", ""))
                obj = str(event.get("object", ""))
                props = event.get("properties", {}) or {}
                object_counts[obj] += 1
                action_counts[action] += 1
                for stage in _classify_event(event, props):
                    if len(stage_hits[stage]) < 25:
                        stage_hits[stage].append(_compact_event(event, props))

    return {
        "records_scanned": records,
        "stage_hits": stage_hits,
        "object_counts": dict(object_counts.most_common(10)),
        "action_counts": dict(action_counts.most_common(10)),
    }


def _classify_event(event: dict[str, Any], props: dict[str, Any]) -> set[str]:
    stages: set[str] = set()
    action = str(event.get("action", "")).upper()
    obj = str(event.get("object", "")).upper()
    command = str(props.get("command_line", ""))
    image = str(props.get("image_path", ""))
    parent = str(props.get("parent_image_path", ""))
    file_path = str(props.get("file_path", ""))
    key = str(props.get("key", ""))
    data = str(props.get("data", ""))
    text = " ".join([command, image, parent, file_path, key, data]).lower()
    parent_low = parent.lower()
    image_low = image.lower()

    if obj == "PROCESS" and action == "CREATE" and (
        parent_low.endswith(r"\users\public\splunkd.exe")
        or image_low.endswith(r"\users\public\splunkd.exe")
    ):
        stages.add("agent_execution")

    if obj == "PROCESS" and action == "CREATE" and image_low.endswith(r"\powershell.exe"):
        if r"\users\public\splunkd.exe" in parent_low or "-executionpolicy bypass" in command.lower():
            stages.add("powershell_spawning")

    if obj == "PROCESS" and action == "CREATE" and (
        image_low.endswith(r"\systeminfo.exe") or "systeminfo | findstr" in command.lower()
    ):
        stages.add("automated_systeminfo_collection")

    if obj == "PROCESS" and action == "CREATE" and "compress-archive" in text and "draft.zip" in text:
        stages.add("data_staging_for_exfil")

    if obj == "PROCESS" and action == "CREATE" and (
        "invoke-multipartformdataupload" in text or "/file/upload" in text
    ):
        stages.add("exfiltration")

    if obj == "PROCESS" and action == "CREATE" and "sdclt.exe" in text and "delegateexecute" in text:
        stages.add("uac_bypass")
    if obj == "REGISTRY" and action in {"ADD", "EDIT"} and "folder\\shell\\open\\command" in key.lower():
        stages.add("uac_bypass")

    if obj == "PROCESS" and action == "CREATE" and (
        "download.sysinternals.com" in text or "sysinternalssuite.zip" in text
    ):
        stages.add("sysinternals_tool_transfer")

    if obj == "PROCESS" and action == "CREATE" and "invoke-screencapture" in text:
        stages.add("screen_capture")

    if obj == "PROCESS" and action == "CREATE" and (
        "remove-item" in text
        and ("upload.ps1" in text or "officesupplies.7z" in text or "remove-job" in text)
    ):
        stages.add("artifact_cleanup")

    return stages


def _compact_event(event: dict[str, Any], props: dict[str, Any]) -> dict[str, Any]:
    command = str(props.get("command_line", ""))
    if len(command) > 360:
        command = command[:357] + "..."
    return {
        "timestamp": event.get("timestamp", ""),
        "action": event.get("action", ""),
        "object": event.get("object", ""),
        "pid": event.get("pid", ""),
        "ppid": event.get("ppid", ""),
        "image_path": props.get("image_path", ""),
        "parent_image_path": props.get("parent_image_path", ""),
        "file_path": props.get("file_path", ""),
        "registry_key": props.get("key", ""),
        "command_line": command,
    }


def _validate_zip_members(zf: zipfile.ZipFile) -> None:
    names = {info.filename for info in zf.infolist()}
    if "apt29.json" not in names:
        raise ValueError("APT29 zip does not contain apt29.json")
    forbidden = [
        name for name in names
        if not name.lower().endswith((".json", ".txt")) and not name.startswith("__MACOSX/")
    ]
    if forbidden:
        raise ValueError(f"Unexpected non-log files in APT29 zip: {forbidden[:5]}")


def _fingerprint(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {"path": str(path), "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _evaluate_apt_stage_bias(results: list[dict[str, Any]]) -> dict[str, Any]:
    missed = [r["stage"] for r in results if not r["ok"]]
    detected = {r["stage"] for r in results if r["ok"]}
    late_stage = {"data_staging_for_exfil", "exfiltration", "artifact_cleanup"}
    early_stage = {"agent_execution", "powershell_spawning", "automated_systeminfo_collection"}
    notes = []
    if late_stage & detected and early_stage - detected:
        notes.append("timeline_bias: late-stage evidence detected without enough early-stage context")
    if detected == {"powershell_spawning"}:
        notes.append("tool_bias: PowerShell-only detection is insufficient for APT reconstruction")
    return {
        "ok": not missed and not notes,
        "missed_stage_count": len(missed),
        "missed_stages": missed,
        "bias_notes": notes,
    }
