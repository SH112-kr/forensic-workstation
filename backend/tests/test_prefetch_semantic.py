import struct
from datetime import datetime, timezone

from core.analysis.prefetch_semantic import parse_prefetch_bytes


def _filetime(value: str) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def test_parse_windows_10_prefetch_metadata_without_verdict_escalation():
    data = bytearray(0x180)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    data[0x10:0x10 + 60] = "TEAMVIEWER_DESKTOP.EXE".encode("utf-16le").ljust(60, b"\x00")
    struct.pack_into("<Q", data, 0x80, _filetime("2019-03-18T18:36:49Z"))
    struct.pack_into("<Q", data, 0x88, _filetime("2019-03-18T18:34:19Z"))
    struct.pack_into("<I", data, 0xD0, 3)
    raw_path = "\\VOLUME{abc}\\PROGRAM FILES\\APP\\TEAMVIEWER_DESKTOP.EXE"
    data[0x100:0x100 + len(raw_path.encode("utf-16le"))] = raw_path.encode("utf-16le")

    result = parse_prefetch_bytes(bytes(data), source_path="TEAMVIEWER_DESKTOP.EXE-123.pf")

    assert result["ok"] is True
    assert result["version"] == 30
    assert result["executable_name"] == "TEAMVIEWER_DESKTOP.EXE"
    assert result["run_count"] == 3
    assert result["latest_run_time_utc"] == "2019-03-18T18:36:49Z"
    assert result["evidence_state"] == "pending_corroboration"
    assert result["guardrails"]["standalone_verdict_allowed"] is False
    assert result["guardrails"]["absence_is_negative_evidence"] is False
    assert result["guardrails"]["referenced_paths_are_execution_evidence"] is False
    assert result["raw_referenced_paths"] == [raw_path]
    assert result["referenced_paths"] == []


def test_parse_windows_xp_prefetch_reads_single_last_run_timestamp():
    data = bytearray(0xC0)
    struct.pack_into("<I", data, 0, 17)
    data[4:8] = b"SCCA"
    data[0x10:0x10 + 60] = "CMD.EXE".encode("utf-16le").ljust(60, b"\x00")
    struct.pack_into("<Q", data, 0x78, _filetime("2019-03-18T18:36:49Z"))
    struct.pack_into("<Q", data, 0x80, _filetime("2019-03-19T18:36:49Z"))
    struct.pack_into("<I", data, 0x90, 1)

    result = parse_prefetch_bytes(bytes(data), source_path="CMD.EXE-123.pf")

    assert result["ok"] is True
    assert result["version"] == 17
    assert result["last_run_times_utc"] == ["2019-03-18T18:36:49Z"]
