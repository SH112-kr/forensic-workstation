from __future__ import annotations

import struct
from datetime import datetime, timezone

from core.analysis.temporal_anchor_correlation import temporal_anchor_correlation


def _filetime(value: str) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def _prefetch_bytes(executable_name: str, last_runs: list[str], run_count: int = 1) -> bytes:
    data = bytearray(0x240)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    data[0x10:0x10 + 60] = executable_name.encode("utf-16le").ljust(60, b"\x00")
    for idx, value in enumerate(last_runs[:8]):
        struct.pack_into("<Q", data, 0x80 + idx * 8, _filetime(value))
    struct.pack_into("<I", data, 0xD0, run_count)
    raw_path = rf"\VOLUME{{abc}}\WINDOWS\SYSWOW64\{executable_name}"
    data[0x140:0x140 + len(raw_path.encode("utf-16le"))] = raw_path.encode("utf-16le")
    return bytes(data)


class _StubE01:
    def __init__(self) -> None:
        self.files = {
            "/c:/Windows/Prefetch/WERFAULT.EXE-94CE7668.pf": _prefetch_bytes(
                "WERFAULT.EXE",
                [
                    "2025-09-26T05:11:55Z",
                    "2025-10-21T04:43:09Z",
                ],
                run_count=2,
            ),
            "/c:/ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_whale/Report.wer": (
                "Version=1\n"
                "EventType=APPCRASH\n"
                "EventTime=134033371200000000\n"
                "NsAppName=whale.exe\n"
                "AppName=Whale\n"
                "AppPath=C:\\Program Files\\Naver\\Naver Whale\\Application\\whale.exe\n"
            ).encode("utf-8"),
        }

    def list_directory(self, path: str):
        if path == "/c:/Windows/Prefetch":
            return [
                {
                    "name": "WERFAULT.EXE-94CE7668.pf",
                    "path": "/c:/Windows/Prefetch/WERFAULT.EXE-94CE7668.pf",
                    "is_dir": False,
                    "size": len(self.files["/c:/Windows/Prefetch/WERFAULT.EXE-94CE7668.pf"]),
                }
            ]
        if path == "/c:/Users":
            return []
        return []

    def read_file_content(self, path: str, max_size: int = 1048576):
        return self.files[path][:max_size]

    def find_files(self, pattern: str, path: str = "/", limit: int = 100):
        if pattern == "Report.wer" and path.endswith("ReportArchive"):
            return [
                {
                    "path": "/c:/ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_whale/Report.wer",
                    "is_dir": False,
                    "size": len(self.files["/c:/ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_whale/Report.wer"]),
                }
            ]
        return []

    def get_file_info(self, path: str):
        return {"path": path, "size": len(self.files.get(path, b""))}


def test_temporal_anchor_correlation_marks_nearby_werfault_as_noncausal_lead():
    result = temporal_anchor_correlation(
        anchor_ts="2025-09-26T14:11:32+09:00",
        anchor_label="Naver Whale Cache IOC hxxps://www.winsystem.kr/share/inc/module.js",
        anchor_entities="winsystem.kr,module.js,whale",
        e01_connector=_StubE01(),
        source_filter="prefetch",
        window_before_minutes=5,
        window_after_minutes=5,
    )

    assert result["ok"] is True
    event = result["proximity_only"][0]
    assert event["object"] == "WERFAULT.EXE"
    assert event["delta_seconds"] == 23
    assert event["correlation_strength"] == "strong_temporal"
    assert event["causality"] == "unproven"
    assert "browser_or_url_anchor_near_werfault" in event["relationship_hints"]
    assert result["dominance_warning"]


def test_temporal_anchor_correlation_links_wer_report_by_anchor_token():
    result = temporal_anchor_correlation(
        anchor_ts="2025-09-26T14:11:32+09:00",
        anchor_label="Whale browser cache IOC",
        anchor_entities="whale",
        e01_connector=_StubE01(),
        source_filter="wer",
        window_before_minutes=5,
        window_after_minutes=5,
    )

    assert result["summary"]["token_linked_count"] == 1
    event = result["token_linked"][0]
    assert event["source_artifact"] == "WER Report"
    assert event["shared_anchor_tokens"] == ["whale"]
    assert event["correlation_strength"] == "confirmed_candidate"
    assert event["causality"] == "unproven"
