"""Conservative Windows Prefetch parser.

The parser extracts execution metadata but deliberately does not upgrade a hit
to a final malicious verdict. Prefetch proves an application was launched on
systems where Prefetch is enabled, but it still needs corroboration from SRUM,
EVTX, AmCache, MFT, or application logs before a strong conclusion.
"""

from __future__ import annotations

import ctypes
import platform
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def parse_prefetch_bytes(data: bytes, *, source_path: str = "") -> dict[str, Any]:
    try:
        raw = _decompress_if_needed(data)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "source_path": source_path, "error": str(exc)}
    if len(raw) < 0x94 or raw[4:8] != b"SCCA":
        return {"ok": False, "source_path": source_path, "error": "not_a_prefetch_file"}

    version = struct.unpack_from("<I", raw, 0)[0]
    executable_name = _read_utf16z(raw[0x10:0x4C])
    run_count_offset = _run_count_offset(version)
    last_run_offset = _last_run_offset(version)
    run_count = struct.unpack_from("<I", raw, run_count_offset)[0] if run_count_offset + 4 <= len(raw) else 0
    last_runs = []
    # Version 17 stores a single last-run timestamp. Vista+ formats can carry
    # multiple last-run slots; keep them as pending corroboration evidence.
    max_last_runs = 1 if version <= 17 else 8
    for idx in range(max_last_runs):
        off = last_run_offset + idx * 8
        if off + 8 > len(raw):
            break
        timestamp = _filetime_to_iso(struct.unpack_from("<Q", raw, off)[0])
        if timestamp:
            last_runs.append(timestamp)

    return {
        "ok": True,
        "source_path": source_path,
        "version": version,
        "executable_name": executable_name,
        "run_count": run_count,
        "last_run_times_utc": last_runs,
        "latest_run_time_utc": last_runs[0] if last_runs else "",
        "evidence_state": "pending_corroboration",
        "confidence_note": (
            "Prefetch is execution evidence, but this parser never turns it into "
            "a standalone incident verdict without independent corroboration."
        ),
        "raw_referenced_paths": _extract_raw_referenced_paths(raw),
        "referenced_paths": [],
        "guardrails": {
            "standalone_verdict_allowed": False,
            "absence_is_negative_evidence": False,
            "referenced_paths_are_execution_evidence": False,
        },
    }


def parse_prefetch_file(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_bytes()
    return parse_prefetch_bytes(data, source_path=str(path))


def _decompress_if_needed(data: bytes) -> bytes:
    if data.startswith(b"MAM\x04"):
        return _decompress_xpress_huffman(data)
    return data


def _decompress_xpress_huffman(data: bytes) -> bytes:
    if platform.system().lower() != "windows":
        raise RuntimeError("MAM compressed Prefetch requires Windows ntdll decompression")
    size = struct.unpack_from("<I", data, 4)[0]
    compressed = data[8:]
    ntdll = ctypes.WinDLL("ntdll")
    fmt = ctypes.c_ushort(4)  # COMPRESSION_FORMAT_XPRESS_HUFF
    workspace_size = ctypes.c_ulong()
    fragment_size = ctypes.c_ulong()
    status = ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(workspace_size), ctypes.byref(fragment_size))
    if status != 0:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status & 0xffffffff:x}")
    out = ctypes.create_string_buffer(size)
    final_size = ctypes.c_ulong()
    workspace = ctypes.create_string_buffer(workspace_size.value)
    status = ntdll.RtlDecompressBufferEx(
        fmt,
        out,
        ctypes.c_ulong(size),
        ctypes.c_char_p(compressed),
        ctypes.c_ulong(len(compressed)),
        ctypes.byref(final_size),
        workspace,
    )
    if status != 0:
        raise RuntimeError(f"RtlDecompressBufferEx failed: 0x{status & 0xffffffff:x}")
    return out.raw[:final_size.value]


def _run_count_offset(version: int) -> int:
    if version in {26, 30}:
        return 0xD0
    if version == 23:
        return 0x98
    return 0x90


def _last_run_offset(version: int) -> int:
    if version in {26, 30}:
        return 0x80
    if version == 23:
        return 0x80
    return 0x78


def _read_utf16z(data: bytes) -> str:
    text = data.decode("utf-16le", errors="ignore")
    return text.split("\x00", 1)[0]


def _filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value / 10)
    except OverflowError:
        return ""
    if dt.year < 1990 or dt.year > 2100:
        return ""
    return dt.isoformat().replace("+00:00", "Z")


def _extract_raw_referenced_paths(raw: bytes, *, limit: int = 500) -> list[str]:
    text = raw.decode("utf-16le", errors="ignore")
    out: list[str] = []
    seen = set()
    for token in text.split("\x00"):
        if not token.startswith("\\VOLUME{"):
            continue
        if len(token) < 15 or len(token) > 520:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= limit:
            break
    return out
