"""EVTX + registry artifact indexers for the raw-image sidecar.

Both indexers extract files from the mounted image into a temporary
directory for read-only parsing. The directory receives a DO_NOT_EXECUTE
marker and is removed afterwards; extracted bytes are never executed.

No-miss semantics: every unreadable channel, parse failure, or hit-limit
stop is recorded as a coverage gap on the parser run — absence of indexed
rows is never silently equated with absence of activity.
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from core.raw_index.store import RawIndexStore


# ── EVTX ───────────────────────────────────────────────────────────────────

# Roadmap P1 event set: logon/credential, service/task persistence,
# log clearing, PowerShell, RDP session tracking.
EVTX_TARGET_EVENT_IDS = {
    4624, 4625, 4648, 4672, 4720, 4722, 4728, 4732, 4756, 4776,
    7045, 4697, 4698, 4702, 1102, 104, 4103, 4104,
    1149, 21, 24, 25, 4778, 4779,
    300,  # OAlerts: Office alert dialogs (macro warnings, crash prompts)
    # Process creation — critical for raw-only mode where find_suspicious
    # (which owns 4688 on parsed cases) cannot run. Aligns with hunt_evtx
    # rules and lets execution chains be reconstructed from raw EVTX.
    4688,
    # Windows Defender detection / tamper (fw-evtx-034/035). The Defender
    # Operational channel is extracted but these EIDs were filtered out.
    1116, 1117, 1119, 5001, 5007,
    # BITS transfer jobs (fw-evtx-036) — download/exfil persistence.
    59, 60,
    # DCSync / WFP / outbound RDP client (fw-evtx-031/032/039).
    4662, 5156, 1024,
    # Outbound SMB client connections (lateral movement). SmbClient/Security
    # 31001 = failed SMB auth to a remote share; Connectivity 30803/30804 =
    # connection attempts. This host reaching out to remote shares.
    31001, 30803, 30804,
}

_EVTX_LOG_DIR = "/c:/Windows/System32/winevt/Logs"

CORE_EVTX_CHANNELS = (
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-SmbClient%4Connectivity.evtx",
    "OAlerts.evtx",
)

# Per-file matched-record ceiling. Hitting it is reported as a truncation
# gap so the analyst knows the channel holds more matching events.
EVTX_RECORDS_PER_FILE_CAP = 20000

# How many EventData fields to inline per record (largest channels carry
# dozens of fields; the full record stays recoverable from the source EVTX).
_MAX_INLINE_FIELDS = 14


def _write_do_not_execute_marker(directory: str) -> None:
    Path(directory, "DO_NOT_EXECUTE").write_text(
        "Files in this directory were extracted from forensic evidence for "
        "read-only parsing. NEVER execute them.",
        encoding="utf-8",
    )


def _parse_iso_ms(value: str) -> tuple[int, str] | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000), str(value)
    except Exception:
        return None


def index_evtx_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    channels: tuple[str, ...] = CORE_EVTX_CHANNELS,
    parse_evtx: Callable[..., dict] | None = None,
) -> dict[str, Any]:
    """Extract and semantically index high-value EVTX channels."""
    if parse_evtx is None:
        from core.analysis.evtx_semantic import parse_evtx_file as parse_evtx

    run_id = store.start_parser_run("evtx_indexer", _EVTX_LOG_DIR, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed_records = 0
    channels_indexed: list[str] = []

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_evtx_") as tmp:
        _write_do_not_execute_marker(tmp)
        for channel in channels:
            internal = f"{_EVTX_LOG_DIR}/{channel}"
            local = os.path.join(tmp, channel.replace("%4", "_"))
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "evtx_channel_unavailable",
                    "error": str(exc),
                })
                continue

            try:
                parsed = parse_evtx(
                    local,
                    target_event_ids=EVTX_TARGET_EVENT_IDS,
                    limit=EVTX_RECORDS_PER_FILE_CAP,
                    best_effort=True,
                )
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "evtx_parse_exception",
                    "error": str(exc),
                })
                continue
            if not parsed.get("ok"):
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "evtx_parse_failed",
                    "error": "; ".join(
                        str(f.get("error", "")) for f in parsed.get("parser_failures", [])[:3]
                    ) or "parser returned not-ok",
                })
                continue

            failures = parsed.get("parser_failures") or []
            if failures:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "evtx_records_unparsed",
                    "error": f"{len(failures)} records failed to parse in {channel}",
                })

            records = parsed.get("records") or []
            if len(records) >= EVTX_RECORDS_PER_FILE_CAP:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "evtx_record_cap_reached",
                    "error": (
                        f"{channel} reached the {EVTX_RECORDS_PER_FILE_CAP}-record cap; "
                        "additional matching events exist but were not indexed"
                    ),
                })

            for rec in records:
                event_id = rec.get("event_id", "")
                fields = rec.get("fields") or {}
                strings: dict[str, str] = {
                    "Event ID": str(event_id),
                    "Provider Name": str(rec.get("provider", "")),
                    "Channel": str(rec.get("channel", "")),
                    "Computer": str(rec.get("computer", "")),
                }
                for key, value in list(fields.items())[:_MAX_INLINE_FIELDS]:
                    if value and key not in strings:
                        strings[key] = str(value)
                semantic = str(rec.get("semantic") or "")
                description_bits = [f"Windows Event Logs | Event ID={event_id}"]
                if semantic:
                    description_bits.append(semantic)
                for hint_key in ("ServiceName", "ImagePath", "TargetUserName",
                                 "NewProcessName", "ScriptBlockText", "TaskName"):
                    hint = fields.get(hint_key)
                    if hint:
                        description_bits.append(f"{hint_key}={hint}")
                times = {}
                ts = _parse_iso_ms(str(rec.get("timestamp", "")))
                if ts:
                    times["Event Time"] = ts
                store.insert_artifact(
                    artifact_type="Windows Event Logs",
                    source_ref=internal,
                    source_path=internal,
                    primary_path=internal,
                    description=" | ".join(description_bits)[:512],
                    strings=strings,
                    times=times,
                    parser_run_id=run_id,
                )
                indexed_records += 1
            channels_indexed.append(channel)

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not channels_indexed:
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": bool(channels_indexed),
        "status": status,
        "indexed_records": indexed_records,
        "channels_indexed": channels_indexed,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── Registry (SYSTEM + NTUSER) ─────────────────────────────────────────────

_SYSTEM_HIVE_PATH = "/c:/Windows/System32/config/SYSTEM"
_USERS_ROOT = "/c:/Users"

_FILETIME_EPOCH_OFFSET_MS = 11644473600000
_BAM_NON_EXECUTABLE_VALUES = {"version", "sequencenumber"}


def _coerce_bytes(raw: Any) -> bytes | None:
    """Normalize a regipy registry value to bytes.

    regipy returns REG_BINARY values as a hex STRING (e.g.
    'c0c968c622efdc01...'), not bytes. A naive isinstance(raw, bytes) check
    therefore drops every binary value — which silently zeroed BAM last-run
    times and Office TrustRecords macro-enable flags. Accept both forms.
    """
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None
    return None


def _filetime_to_ms(raw: bytes) -> tuple[int, str] | None:
    if not raw or len(raw) < 8:
        return None
    ft = int.from_bytes(raw[:8], "little", signed=False)
    if ft <= 0:
        return None
    ms = ft // 10000 - _FILETIME_EPOCH_OFFSET_MS
    if ms <= 0:
        return None
    display = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return ms, display


def parse_bam_entries(hive: Any, control_sets: list[tuple[str, bool]]) -> list[dict[str, Any]]:
    """Parse BAM/DAM UserSettings: per-SID executable paths + last-run time.

    BAM is the only OS execution artifact with user-SID attribution; treat
    each row as strong-tier execution evidence (corroborate for confirmed).
    """
    entries: list[dict[str, Any]] = []
    for control_set, is_current in control_sets:
        for service in ("bam", "dam"):
            try:
                base = hive.get_key(f"\\{control_set}\\Services\\{service}\\State\\UserSettings")
            except Exception:
                continue
            try:
                sid_keys = list(base.iter_subkeys())
            except Exception:
                continue
            for sid_key in sid_keys:
                sid = str(sid_key.name)
                try:
                    values = list(sid_key.iter_values())
                except Exception:
                    continue
                for value in values:
                    name = str(getattr(value, "name", "") or "")
                    if not name or name.lower() in _BAM_NON_EXECUTABLE_VALUES:
                        continue
                    raw = _coerce_bytes(getattr(value, "value", None))
                    ts = _filetime_to_ms(raw) if raw else None
                    entries.append({
                        "service": service,
                        "control_set": control_set,
                        "is_current_control_set": is_current,
                        "user_sid": sid,
                        "executable": name,
                        "last_run": ts,
                    })
    return entries


def parse_usbstor_entries(hive: Any, control_sets: list[tuple[str, bool]]) -> list[dict[str, Any]]:
    """Parse USBSTOR device history: device model, serial, key timestamp."""
    entries: list[dict[str, Any]] = []
    for control_set, is_current in control_sets:
        try:
            base = hive.get_key(f"\\{control_set}\\Enum\\USBSTOR")
        except Exception:
            continue
        try:
            device_keys = list(base.iter_subkeys())
        except Exception:
            continue
        for device_key in device_keys:
            try:
                serial_keys = list(device_key.iter_subkeys())
            except Exception:
                continue
            for serial_key in serial_keys:
                friendly = ""
                try:
                    for value in serial_key.iter_values():
                        if str(getattr(value, "name", "")).lower() == "friendlyname":
                            friendly = str(getattr(value, "value", "") or "")
                            break
                except Exception:
                    pass
                timestamp = ""
                ts_raw = getattr(serial_key, "header", None)
                last_modified = getattr(serial_key, "last_modified", None) or getattr(
                    ts_raw, "last_modified", None)
                if last_modified:
                    timestamp = str(last_modified)
                entries.append({
                    "control_set": control_set,
                    "is_current_control_set": is_current,
                    "device": str(device_key.name),
                    "serial": str(serial_key.name),
                    "friendly_name": friendly,
                    "key_last_modified": timestamp,
                })
    return entries


def parse_run_keys(hive: Any, *, hive_label: str) -> list[dict[str, Any]]:
    """Parse Run/RunOnce autorun values from an NTUSER (or SOFTWARE) hive."""
    entries: list[dict[str, Any]] = []
    for key_path in (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ):
        try:
            key = hive.get_key(key_path)
        except Exception:
            continue
        try:
            values = list(key.iter_values())
        except Exception:
            continue
        for value in values:
            name = str(getattr(value, "name", "") or "")
            command = str(getattr(value, "value", "") or "")
            if not name and not command:
                continue
            entries.append({
                "hive": hive_label,
                "key_path": key_path.replace("\\\\", "\\"),
                "name": name,
                "command": command,
            })
    return entries


def _filetime_int_to_ms(filetime: Any) -> tuple[int, str] | None:
    """Convert a Windows FILETIME integer (regipy header.last_modified) to
    (epoch_ms, display). FILETIME is 100ns ticks since 1601-01-01 UTC."""
    try:
        ticks = int(filetime)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    ms = ticks // 10000 - 11644473600000
    if ms <= 0:
        return None
    display = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return ms, display


# IFEO subkeys exist on every host (PerfOptions etc.); only a Debugger value or
# a SilentProcessExit MonitorProcess is persistence — those are emitted, the
# benign majority are skipped. (Debugger hijack: T1546.012 / SilentProcessExit.)
_IFEO_PATH = "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
_SILENT_PROCESS_EXIT_PATH = "\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"


# regipy raises these when a key/subkey legitimately does not exist (a clean
# host has no SilentProcessExit key, etc.) — that is normal, NOT a gap. Any
# OTHER error (e.g. RegistryParsingException) is hive corruption and IS a gap.
# KeyError covers the duck-typed test fake.
_IFEO_ABSENT_EXC = ("RegistryKeyNotFoundException", "NoRegistrySubkeysException",
                    "RegistryValueNotFoundException", "KeyError")


def parse_ifeo_entries(
    hive: Any,
    *,
    hive_label: str = "SOFTWARE",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse IFEO Debugger / VerifierDlls + SilentProcessExit persistence from a
    SOFTWARE hive. Returns ``(entries, gaps)``.

    Only suspicious-shaped subkeys are emitted — a ``Debugger`` value (debugger
    hijack), a ``VerifierDlls`` value (Application Verifier DLL-injection
    persistence), or a SilentProcessExit ``MonitorProcess``. The benign
    PerfOptions/Mitigation subkeys that make up the bulk of IFEO are skipped.
    No-miss: an absent key is normal (no gap), but a corrupt key or an
    unreadable subkey's values is recorded as a coverage gap.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []

    def _subkey_ms(subkey: Any) -> tuple[int, str] | None:
        header = getattr(subkey, "header", None)
        if header is None:
            return None
        return _filetime_int_to_ms(getattr(header, "last_modified", None))

    def _read_values(subkey: Any) -> dict[str, str]:
        out: dict[str, str] = {}
        for value in subkey.iter_values():  # may raise — caller records a gap
            name = str(getattr(value, "name", "") or "")
            if name:
                out[name.lower()] = str(getattr(value, "value", "") or "")
        return out

    def _scan(path: str, handler) -> None:
        try:
            subs = list(hive.get_key(path).iter_subkeys())
        except Exception as exc:  # noqa: BLE001
            if type(exc).__name__ in _IFEO_ABSENT_EXC:
                return  # key/subkeys absent — normal
            gaps.append({
                "path": path, "status": "coverage_gap",
                "reason": "ifeo_key_error", "error": str(exc),
            })
            return
        for sub in subs:
            image = str(getattr(sub, "name", "") or "")
            try:
                values = _read_values(sub)
            except Exception as exc:  # noqa: BLE001 — one bad subkey is a gap
                gaps.append({
                    "path": f"{path}\\{image}", "status": "coverage_gap",
                    "reason": "ifeo_subkey_read_error", "error": str(exc),
                })
                continue
            handler(sub, image, values)

    def _ifeo_handler(sub: Any, image: str, values: dict[str, str]) -> None:
        ts = _subkey_ms(sub)
        if values.get("debugger"):
            entries.append({
                "kind": "ifeo_debugger", "hive": hive_label, "image": image,
                "debugger": values["debugger"], "global_flag": values.get("globalflag", ""),
                "key_path": f"{_IFEO_PATH}\\{image}", "key_last_modified": ts,
            })
        if values.get("verifierdlls"):
            entries.append({
                "kind": "ifeo_verifier_dll", "hive": hive_label, "image": image,
                "verifier_dlls": values["verifierdlls"],
                "global_flag": values.get("globalflag", ""),
                "key_path": f"{_IFEO_PATH}\\{image}", "key_last_modified": ts,
            })

    def _spe_handler(sub: Any, image: str, values: dict[str, str]) -> None:
        if values.get("monitorprocess"):
            entries.append({
                "kind": "silent_process_exit", "hive": hive_label, "image": image,
                "monitor_process": values["monitorprocess"],
                "reporting_mode": values.get("reportingmode", ""),
                "key_path": f"{_SILENT_PROCESS_EXIT_PATH}\\{image}",
                "key_last_modified": ts if (ts := _subkey_ms(sub)) else None,
            })

    _scan(_IFEO_PATH, _ifeo_handler)
    _scan(_SILENT_PROCESS_EXIT_PATH, _spe_handler)
    return entries, gaps


# ── Mark of the Web (Zone.Identifier ADS) ──────────────────────────────────

_MOTW_USER_DIRS = ("Downloads", "Desktop", "Documents")
# Per-dir Zone.Identifier scan ceiling. Raised from 500: a real Downloads
# folder routinely holds 1-2k files and the ingress lane must not miss a
# downloaded dropper. Still bounded + reported as a coverage gap when exceeded.
_MOTW_FILES_PER_DIR_CAP = 5000


def parse_zone_identifier(content: bytes | str) -> dict[str, str]:
    """Parse Zone.Identifier ADS ini content into ZoneId/Referrer/HostUrl."""
    if isinstance(content, (bytes, bytearray)):
        text = bytes(content).decode("utf-8", errors="replace")
    else:
        text = str(content)
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip().lstrip("﻿")
        if "=" not in line or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in ("ZoneId", "ReferrerUrl", "HostUrl") and value.strip():
            fields[key] = value.strip()
    return fields


def index_motw_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    users_root: str = _USERS_ROOT,
) -> dict[str, Any]:
    """Index Zone.Identifier ADS (Mark of the Web) for user-facing files.

    Scans Downloads/Desktop/Documents per profile and reads the ADS via
    ``<path>:Zone.Identifier``. A missing ADS on a file is normal (local
    file); a filesystem that rejects every ADS read is a coverage gap —
    MOTW is then not evaluable, which must not read as "no downloads".
    """
    run_id = store.start_parser_run("motw_indexer", users_root, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    files_checked = 0
    ads_read_errors = 0

    with store.batch():
        try:
            user_dirs = [
                e for e in (image.list_directory(users_root) or [])
                if e.get("is_dir") and not e.get("error")
            ]
        except Exception as exc:
            user_dirs = []
            coverage_gaps.append({
                "path": users_root,
                "status": "coverage_gap",
                "reason": "users_root_unavailable",
                "error": str(exc),
            })
        for profile_entry in user_dirs:
            profile = str(profile_entry.get("path", ""))
            user = str(profile_entry.get("name") or profile.rsplit("/", 1)[-1])
            for sub in _MOTW_USER_DIRS:
                directory = f"{profile}/{sub}"
                try:
                    entries = [
                        e for e in (image.list_directory(directory) or [])
                        if not e.get("is_dir") and not e.get("error")
                    ]
                except Exception:
                    continue  # profile without this folder is normal
                if len(entries) > _MOTW_FILES_PER_DIR_CAP:
                    coverage_gaps.append({
                        "path": directory,
                        "status": "coverage_gap",
                        "reason": "motw_file_cap_reached",
                        "error": (
                            f"{len(entries)} files; only first "
                            f"{_MOTW_FILES_PER_DIR_CAP} checked for Zone.Identifier"
                        ),
                    })
                    entries = entries[:_MOTW_FILES_PER_DIR_CAP]
                for entry in entries:
                    file_path = str(entry.get("path", ""))
                    if not file_path:
                        continue
                    files_checked += 1
                    try:
                        content = image.read_file_content(
                            f"{file_path}:Zone.Identifier", max_size=4096,
                        )
                    except Exception:
                        ads_read_errors += 1
                        continue
                    if not content:
                        continue
                    fields = parse_zone_identifier(content)
                    if not fields:
                        continue
                    times = _entry_times_from_listing(entry)
                    store.insert_artifact(
                        artifact_type="Mark of the Web (Zone.Identifier)",
                        source_ref=directory,
                        source_path=file_path,
                        primary_path=file_path,
                        description=(
                            f"Mark of the Web (Zone.Identifier) | {file_path} "
                            f"ZoneId={fields.get('ZoneId', '')} "
                            f"HostUrl={fields.get('HostUrl', '')}"
                        )[:512],
                        strings={
                            "File Path": file_path,
                            "Zone ID": fields.get("ZoneId", ""),
                            "Referrer URL": fields.get("ReferrerUrl", ""),
                            "Host URL": fields.get("HostUrl", ""),
                            "User": user,
                        },
                        times=times,
                        parser_run_id=run_id,
                    )
                    indexed += 1

    if files_checked > 0 and ads_read_errors >= files_checked:
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "ads_read_unsupported",
            "error": (
                f"all {files_checked} Zone.Identifier reads failed; the image "
                "backend may not expose alternate data streams — MOTW is not "
                "evaluable on this case"
            ),
        })

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if files_checked == 0:
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": files_checked > 0,
        "status": status,
        "indexed_records": indexed,
        "files_checked": files_checked,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


def _entry_times_from_listing(entry: dict[str, Any]) -> dict[str, tuple[int, str]]:
    times: dict[str, tuple[int, str]] = {}
    for label, keys in (("Created", ("created", "creation_time")),
                        ("Modified", ("modified", "mtime"))):
        for key in keys:
            parsed = _parse_iso_ms(str(entry.get(key, "") or ""))
            if parsed:
                times[label] = parsed
                break
    return times


# ── Defender MPLog ───────────────────────────────────────────────────────────
#
# MPLog is Defender's verbose protection log (C:\ProgramData\Microsoft\Windows
# Defender\Support\MPLog-*.log). It records process activity, real-time-scan
# events, and any detections. We aggregate the high-signal lines into bounded
# records instead of indexing every line (a single MPLog holds tens of
# thousands). Timestamps in MPLog are device-LOCAL wall-clock with no zone, so
# they are kept as strings (not UTC epochs) to avoid a false-precision shift.

_MPLOG_DIR = "/c:/ProgramData/Microsoft/Windows Defender/Support"
_MPLOG_MAX_BYTES = 64 * 1024 * 1024  # per-file read ceiling (Defender rotates ~16MB)
_MPLOG_MAX_RECORDS = 5000            # aggregated records emitted per run

_MPLOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_MPLOG_PROCESS_RE = re.compile(r"ProcessImageName:\s*(?P<name>.+?),\s*Pid:\s*(?P<pid>\d+)")
_MPLOG_INJECTION_RE = re.compile(
    r"Engine:Process\s+(?P<pid>\d+)\s+will be fully monitored because of "
    r"injection from\s+(?P<src>.+?)\s*$"
)
_MPLOG_THREAT_RE = re.compile(r"\bThreat:\s*(?P<vals>[0-9]+(?:,[0-9]+)*)")


def parse_mplog(
    text: str,
    *,
    max_records: int = _MPLOG_MAX_RECORDS,
) -> tuple[list[dict[str, Any]], bool]:
    """Aggregate high-signal Defender MPLog telemetry into bounded records.

    Returns ``(records, capped)``. Three record kinds:
      - ``threat_detection``: a non-zero ``Threat:`` line (real detection)
      - ``process_execution``: a distinct ProcessImageName Defender observed
        running (name + count + first/last device-local timestamp + pids)
      - ``injection_source``: a distinct image path Defender monitored as an
        injection source ("fully monitored because of injection from <path>")

    Detections are emitted first so they survive the cap. Timestamps stay
    device-local strings, never UTC epochs.
    """
    processes: dict[str, dict[str, Any]] = {}
    injections: dict[str, dict[str, Any]] = {}
    detections: list[dict[str, Any]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ts_match = _MPLOG_TS_RE.match(line)
        ts = ts_match.group(1) if ts_match else ""

        # Detections first: a real (non-zero) Threat line outranks any process
        # name it may also carry, so it is never downgraded to process_execution.
        threat = _MPLOG_THREAT_RE.search(line)
        if threat and set(threat.group("vals").split(",")) != {"0"}:
            detections.append({"timestamp": ts, "detail": line[:300]})
            continue

        proc = _MPLOG_PROCESS_RE.search(line)
        if proc:
            name = proc.group("name").strip()
            agg = processes.setdefault(
                name, {"count": 0, "first": "", "last": "", "pids": set()}
            )
            agg["count"] += 1
            agg["pids"].add(proc.group("pid"))
            if ts:
                agg["first"] = agg["first"] or ts
                agg["last"] = ts
            continue

        inj = _MPLOG_INJECTION_RE.search(line)
        if inj:
            src = inj.group("src").strip()
            agg = injections.setdefault(src, {"count": 0, "first": "", "last": ""})
            agg["count"] += 1
            if ts:
                agg["first"] = agg["first"] or ts
                agg["last"] = ts
            continue

    records: list[dict[str, Any]] = []
    for det in detections:  # real detections first — highest value, survive cap
        records.append({"kind": "threat_detection", **det})
    for name, agg in sorted(processes.items(), key=lambda kv: -kv[1]["count"]):
        records.append({
            "kind": "process_execution", "key": name, "count": agg["count"],
            "first": agg["first"], "last": agg["last"],
            "pids": ",".join(sorted(agg["pids"])[:10]),
        })
    for src, agg in sorted(injections.items(), key=lambda kv: -kv[1]["count"]):
        records.append({
            "kind": "injection_source", "key": src, "count": agg["count"],
            "first": agg["first"], "last": agg["last"],
        })

    capped = len(records) > max_records
    return records[:max_records], capped


def index_mplog_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    mplog_dir: str = _MPLOG_DIR,
) -> dict[str, Any]:
    """Index Defender MPLog process/injection/detection telemetry.

    No-miss: an unreadable directory or file, a read-size cap, and the
    aggregated-record cap are each recorded as coverage gaps. No MPLog files
    (Defender disabled/cleaned) is ``not_evaluable``, not "no activity".
    """
    run_id = store.start_parser_run("mplog_indexer", mplog_dir, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    files_parsed = 0

    with store.batch():
        try:
            listing = image.list_directory(mplog_dir) or []
        except Exception as exc:  # noqa: BLE001
            listing = []
            coverage_gaps.append({
                "path": mplog_dir, "status": "coverage_gap",
                "reason": "mplog_dir_unavailable", "error": str(exc),
            })
        entries = []
        for e in listing:
            # No-miss: a per-entry listing error is a gap, not a silent drop.
            if e.get("error"):
                coverage_gaps.append({
                    "path": mplog_dir, "status": "coverage_gap",
                    "reason": "mplog_listing_entry_error",
                    "error": str(e.get("error")),
                })
                continue
            if e.get("is_dir"):
                continue
            name = str(e.get("name", "")).lower()
            if name.startswith("mplog") and name.endswith(".log"):
                entries.append(e)
        for entry in entries:
            path = str(entry.get("path", ""))
            if not path:
                continue
            try:
                raw = image.read_file_content(path, max_size=_MPLOG_MAX_BYTES)
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": path, "status": "coverage_gap",
                    "reason": "mplog_unreadable", "error": str(exc),
                })
                continue
            if raw and len(raw) >= _MPLOG_MAX_BYTES:
                coverage_gaps.append({
                    "path": path, "status": "coverage_gap",
                    "reason": "mplog_read_cap_reached",
                    "error": f"file >= {_MPLOG_MAX_BYTES} bytes; parsed prefix only",
                })
            if raw:
                encoding = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-8"
                text = raw.decode(encoding, errors="replace")
            else:
                text = ""
            records, capped = parse_mplog(text)
            files_parsed += 1
            if capped:
                coverage_gaps.append({
                    "path": path, "status": "coverage_gap",
                    "reason": "mplog_record_cap_reached",
                    "error": (
                        f"more than {_MPLOG_MAX_RECORDS} aggregated records; "
                        "lowest-count entries truncated"
                    ),
                })
            fname = str(entry.get("name") or path.rsplit("/", 1)[-1])
            for rec in records:
                kind = rec["kind"]
                strings: dict[str, str] = {"Kind": kind, "MPLog File": fname}
                if kind == "process_execution":
                    strings.update({
                        "Process": rec["key"],
                        "Event Count": str(rec["count"]),
                        "PIDs": rec.get("pids", ""),
                        "First Seen (device-local)": rec.get("first", ""),
                        "Last Seen (device-local)": rec.get("last", ""),
                    })
                    desc = f"Defender MPLog | process={rec['key']} count={rec['count']}"
                elif kind == "injection_source":
                    strings.update({
                        "Injection Source": rec["key"],
                        "Event Count": str(rec["count"]),
                        "First Seen (device-local)": rec.get("first", ""),
                        "Last Seen (device-local)": rec.get("last", ""),
                    })
                    desc = (
                        f"Defender MPLog | injection_source={rec['key']} "
                        f"count={rec['count']}"
                    )
                else:  # threat_detection
                    strings.update({
                        "Detection": rec.get("detail", ""),
                        "Timestamp (device-local)": rec.get("timestamp", ""),
                    })
                    desc = f"Defender MPLog | DETECTION {rec.get('detail', '')[:160]}"
                store.insert_artifact(
                    artifact_type="Defender MPLog Activity",
                    source_ref=mplog_dir,
                    source_path=path,
                    primary_path=path,
                    description=desc[:512],
                    strings=strings,
                    times={},  # MPLog timestamps are device-local, not UTC
                    parser_run_id=run_id,
                )
                indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if files_parsed == 0:
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": files_parsed > 0,
        "status": status,
        "indexed_records": indexed,
        "files_parsed": files_parsed,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


_MACRO_ENABLED_MARKER = b"\xff\xff\xff\x7f"

_OFFICE_APPS = ("Word", "Excel", "PowerPoint")
_OFFICE_VERSIONS = ("16.0", "15.0", "14.0")


def parse_trust_records(hive: Any, *, hive_label: str) -> list[dict[str, Any]]:
    """Parse Office Trusted Documents TrustRecords from an NTUSER hive.

    Each value records a document the user explicitly trusted; data ends
    with FF FF FF 7F when the user clicked "Enable Content" (macros) —
    the single strongest ingress signal for document-based intrusion.
    """
    entries: list[dict[str, Any]] = []
    for version in _OFFICE_VERSIONS:
        for app in _OFFICE_APPS:
            key_path = (
                f"\\Software\\Microsoft\\Office\\{version}\\{app}"
                "\\Security\\Trusted Documents\\TrustRecords"
            )
            try:
                key = hive.get_key(key_path)
            except Exception:
                continue
            try:
                values = list(key.iter_values())
            except Exception:
                continue
            for value in values:
                doc = str(getattr(value, "name", "") or "")
                if not doc:
                    continue
                raw = _coerce_bytes(getattr(value, "value", None))
                trusted_at = None
                macro_enabled = False
                if raw and len(raw) >= 8:
                    trusted_at = _filetime_to_ms(raw)
                    macro_enabled = bytes(raw[-4:]) == _MACRO_ENABLED_MARKER
                entries.append({
                    "hive": hive_label,
                    "application": app,
                    "office_version": version,
                    "document": doc,
                    "trusted_at": trusted_at,
                    "macro_enabled": macro_enabled,
                })
    return entries


_MRU_ITEM_RE = None  # compiled lazily


def parse_office_mru(hive: Any, *, hive_label: str) -> list[dict[str, Any]]:
    """Parse Office File MRU entries: recently opened documents + open time.

    Item format: ``[F00000000][T01DBxxxxxxxxxxxx][O00000000]*<path>`` where
    T carries a hex FILETIME of the last open.
    """
    import re

    global _MRU_ITEM_RE
    if _MRU_ITEM_RE is None:
        _MRU_ITEM_RE = re.compile(r"\[T([0-9A-Fa-f]{16})\][^*]*\*(.+)$")

    entries: list[dict[str, Any]] = []

    def _collect_file_mru(key: Any, app: str, version: str) -> None:
        try:
            values = list(key.iter_values())
        except Exception:
            return
        for value in values:
            data = str(getattr(value, "value", "") or "")
            match = _MRU_ITEM_RE.search(data)
            if not match:
                continue
            filetime = int(match.group(1), 16)
            ms = filetime // 10000 - _FILETIME_EPOCH_OFFSET_MS
            opened = None
            if ms > 0:
                opened = (ms, datetime.fromtimestamp(
                    ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            entries.append({
                "hive": hive_label,
                "application": app,
                "office_version": version,
                "document": match.group(2).strip(),
                "last_opened": opened,
            })

    for version in _OFFICE_VERSIONS:
        for app in _OFFICE_APPS:
            base = f"\\Software\\Microsoft\\Office\\{version}\\{app}"
            # Modern layout: per-identity subkeys under "User MRU"
            try:
                user_mru = hive.get_key(f"{base}\\User MRU")
                for identity in user_mru.iter_subkeys():
                    try:
                        _collect_file_mru(
                            identity.get_subkey("File MRU"), app, version)
                    except Exception:
                        continue
            except Exception:
                pass
            # Legacy layout: File MRU directly under the app key
            try:
                _collect_file_mru(hive.get_key(f"{base}\\File MRU"), app, version)
            except Exception:
                pass
    return entries


def parse_rdp_client_mru(hive: Any, *, hive_label: str) -> list[dict[str, Any]]:
    """Parse Terminal Server Client\\Servers: outbound RDP destinations.

    Each subkey is a host this user connected TO via RDP — pivot/lateral
    evidence distinct from inbound RDP logons. UsernameHint, when present,
    names the account used at the destination.
    """
    entries: list[dict[str, Any]] = []
    for base in (
        "\\Software\\Microsoft\\Terminal Server Client\\Servers",
        "\\Software\\Microsoft\\Terminal Server Client\\Default",
    ):
        try:
            key = hive.get_key(base)
        except Exception:
            continue
        # Servers: subkeys are hostnames; Default: values MRU0..MRUn
        try:
            for sub in key.iter_subkeys():
                username = ""
                try:
                    for value in sub.iter_values():
                        if str(getattr(value, "name", "")).lower() == "usernamehint":
                            username = str(getattr(value, "value", "") or "")
                            break
                except Exception:
                    pass
                entries.append({
                    "hive": hive_label,
                    "destination": str(sub.name),
                    "username_hint": username,
                    "source": "Servers",
                })
        except Exception:
            pass
        try:
            for value in key.iter_values():
                name = str(getattr(value, "name", "") or "")
                if name.lower().startswith("mru"):
                    entries.append({
                        "hive": hive_label,
                        "destination": str(getattr(value, "value", "") or ""),
                        "username_hint": "",
                        "source": "Default",
                    })
        except Exception:
            pass
    return entries


def parse_mountpoints2(hive: Any, *, hive_label: str) -> list[dict[str, Any]]:
    """Parse Explorer MountPoints2: volumes/shares this user actually opened."""
    entries: list[dict[str, Any]] = []
    try:
        key = hive.get_key(
            "\\Software\\Microsoft\\Windows\\CurrentVersion"
            "\\Explorer\\MountPoints2"
        )
        subkeys = list(key.iter_subkeys())
    except Exception:
        return entries
    for sub in subkeys:
        name = str(sub.name)
        kind = "volume_guid" if name.startswith("{") else (
            "network_share" if name.startswith("#") else "drive_letter")
        entries.append({
            "hive": hive_label,
            "mount_point": name,
            "kind": kind,
        })
    return entries


_SETUPAPI_SECTION_RE = None


def parse_setupapi_device_installs(text: str) -> list[dict[str, Any]]:
    """Parse setupapi.dev.log device-install sections for USB storage.

    Yields (device_id, first_install_time) for USBSTOR / USB VID entries —
    the canonical first-connect timestamp for external media.
    """
    import re

    global _SETUPAPI_SECTION_RE
    if _SETUPAPI_SECTION_RE is None:
        _SETUPAPI_SECTION_RE = re.compile(
            r">>>\s+\[Device Install \(Hardware initiated\) - ([^\]]+)\]\s*\n"
            r">>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
            re.IGNORECASE,
        )
    entries: list[dict[str, Any]] = []
    for match in _SETUPAPI_SECTION_RE.finditer(text or ""):
        device_id = match.group(1).strip()
        upper = device_id.upper()
        if "USBSTOR" not in upper and "USB\\VID" not in upper:
            continue
        stamp = match.group(2)
        installed = None
        try:
            # setupapi logs LOCAL time with no zone marker. Epoch-ms is
            # computed as-if-UTC for ordering only; the display string keeps
            # the local-time caveat so it is never quoted as UTC.
            dt = datetime.strptime(stamp, "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
            installed = (int(dt.timestamp() * 1000), f"{stamp} (local time)")
        except Exception:
            pass
        entries.append({
            "device_id": device_id,
            "first_install": installed,
            "raw_timestamp": stamp,
        })
    return entries


def index_registry_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    max_user_hives: int = 20,
) -> dict[str, Any]:
    """Extract SYSTEM + NTUSER hives and index services / BAM / USB / Run keys."""
    run_id = store.start_parser_run("registry_indexer", _SYSTEM_HIVE_PATH, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    counts = {"System Services": 0, "BAM Execution Entries": 0,
              "USB Devices": 0, "AutoRun Items": 0,
              "Office Trusted Documents": 0, "Office Recent Documents": 0,
              "RDP Client Destinations": 0, "IFEO Persistence": 0}

    def _insert(artifact_type: str, source: str, description: str,
                strings: dict[str, str], times: dict | None = None) -> None:
        store.insert_artifact(
            artifact_type=artifact_type,
            source_ref=source,
            source_path=source,
            primary_path=source,
            description=description[:512],
            strings={k: str(v) for k, v in strings.items() if v},
            times=times or {},
            parser_run_id=run_id,
        )
        counts[artifact_type] += 1

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_reg_") as tmp:
        _write_do_not_execute_marker(tmp)

        # ── SYSTEM hive: services + BAM + USBSTOR ──
        system_local = os.path.join(tmp, "SYSTEM")
        system_ok = False
        try:
            extracted = image.extract_file(_SYSTEM_HIVE_PATH, system_local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            system_ok = True
        except Exception as exc:
            coverage_gaps.append({
                "path": _SYSTEM_HIVE_PATH,
                "status": "coverage_gap",
                "reason": "system_hive_unavailable",
                "error": str(exc),
            })

        if system_ok:
            try:
                from regipy.registry import RegistryHive
                from core.analysis.service_persistence import (
                    _control_sets,
                    services_from_system_hive,
                )

                services, _meta = services_from_system_hive(system_local)
                for svc in services:
                    if not svc.get("is_current_control_set"):
                        continue
                    times = {}
                    ts = _parse_iso_ms(str(svc.get("registry_modified", "")))
                    if ts:
                        times["Registry Modified"] = ts
                    _insert(
                        "System Services",
                        svc.get("registry_key_path", _SYSTEM_HIVE_PATH),
                        f"System Services | {svc.get('service_name', '')} "
                        f"ImagePath={svc.get('image_path', '')}",
                        {"Service Name": svc.get("service_name", ""),
                         "Display Name": svc.get("display_name", ""),
                         "Image Path": svc.get("image_path", ""),
                         "Service DLL": svc.get("service_dll", ""),
                         "Start": svc.get("start", ""),
                         "Account": svc.get("account", "")},
                        times,
                    )

                hive = RegistryHive(system_local)
                control_sets = _control_sets(hive)
                for entry in parse_bam_entries(hive, control_sets):
                    if not entry.get("is_current_control_set"):
                        continue
                    times = {}
                    if entry.get("last_run"):
                        times["Last Run"] = entry["last_run"]
                    _insert(
                        "BAM Execution Entries",
                        _SYSTEM_HIVE_PATH,
                        f"BAM Execution Entries | {entry['executable']} "
                        f"SID={entry['user_sid']}",
                        {"Executable": entry["executable"],
                         "User SID": entry["user_sid"],
                         "Source": entry["service"].upper()},
                        times,
                    )
                for dev in parse_usbstor_entries(hive, control_sets):
                    if not dev.get("is_current_control_set"):
                        continue
                    times = {}
                    ts = _parse_iso_ms(dev.get("key_last_modified", ""))
                    if ts:
                        times["Key Last Modified"] = ts
                    _insert(
                        "USB Devices",
                        _SYSTEM_HIVE_PATH,
                        f"USB Devices | {dev['device']} serial={dev['serial']}",
                        {"Device": dev["device"],
                         "Serial Number": dev["serial"],
                         "Friendly Name": dev["friendly_name"]},
                        times,
                    )
            except Exception as exc:
                coverage_gaps.append({
                    "path": _SYSTEM_HIVE_PATH,
                    "status": "coverage_gap",
                    "reason": "system_hive_parse_failed",
                    "error": str(exc),
                })

        # ── SOFTWARE hive: IFEO Debugger + SilentProcessExit persistence ──
        software_path = "/c:/Windows/System32/config/SOFTWARE"
        software_local = os.path.join(tmp, "SOFTWARE")
        try:
            extracted = image.extract_file(software_path, software_local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
        except Exception as exc:  # noqa: BLE001
            coverage_gaps.append({
                "path": software_path,
                "status": "coverage_gap",
                "reason": "software_hive_unavailable",
                "error": str(exc),
            })
        else:
            try:
                from regipy.registry import RegistryHive

                software_hive = RegistryHive(software_local)
                ifeo_entries, ifeo_gaps = parse_ifeo_entries(
                    software_hive, hive_label="SOFTWARE")
                coverage_gaps.extend(ifeo_gaps)
                for ifeo in ifeo_entries:
                    times = {}
                    if ifeo.get("key_last_modified"):
                        times["Key Last Modified"] = ifeo["key_last_modified"]
                    kind = ifeo["kind"]
                    image = ifeo["image"]
                    if kind == "ifeo_debugger":
                        strings = {
                            "Kind": kind, "Image": image,
                            "Debugger": ifeo["debugger"],
                            "Global Flag": ifeo.get("global_flag", ""),
                        }
                        desc = f"IFEO Persistence | Debugger | {image} -> {ifeo['debugger']}"
                    elif kind == "ifeo_verifier_dll":
                        strings = {
                            "Kind": kind, "Image": image,
                            "Verifier DLLs": ifeo["verifier_dlls"],
                            "Global Flag": ifeo.get("global_flag", ""),
                        }
                        desc = (
                            f"IFEO Persistence | VerifierDlls | {image} -> "
                            f"{ifeo['verifier_dlls']}"
                        )
                    else:  # silent_process_exit
                        strings = {
                            "Kind": kind, "Image": image,
                            "Monitor Process": ifeo.get("monitor_process", ""),
                            "Reporting Mode": ifeo.get("reporting_mode", ""),
                        }
                        desc = (
                            f"IFEO Persistence | SilentProcessExit | {image} -> "
                            f"{ifeo.get('monitor_process', '')}"
                        )
                    _insert("IFEO Persistence", ifeo["key_path"], desc, strings, times)
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": software_path,
                    "status": "coverage_gap",
                    "reason": "software_hive_parse_failed",
                    "error": str(exc),
                })

        # ── NTUSER hives: Run/RunOnce per user ──
        try:
            user_dirs = [
                e for e in (image.list_directory(_USERS_ROOT) or [])
                if e.get("is_dir") and not e.get("error")
            ]
        except Exception as exc:
            user_dirs = []
            coverage_gaps.append({
                "path": _USERS_ROOT,
                "status": "coverage_gap",
                "reason": "users_root_unavailable",
                "error": str(exc),
            })
        if len(user_dirs) > max_user_hives:
            coverage_gaps.append({
                "path": _USERS_ROOT,
                "status": "coverage_gap",
                "reason": "user_hive_cap_reached",
                "error": f"{len(user_dirs)} profiles found; only first "
                         f"{max_user_hives} NTUSER hives parsed",
            })
            user_dirs = user_dirs[:max_user_hives]
        for idx, entry in enumerate(user_dirs):
            profile = str(entry.get("path", ""))
            user = str(entry.get("name") or profile.rsplit("/", 1)[-1])
            internal = f"{profile}/NTUSER.DAT"
            local = os.path.join(tmp, f"NTUSER_{idx}.DAT")
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "ntuser_hive_unavailable",
                    "error": str(exc),
                })
                continue
            try:
                from regipy.registry import RegistryHive

                user_hive = RegistryHive(local)
                for run in parse_run_keys(user_hive, hive_label=f"NTUSER:{user}"):
                    _insert(
                        "AutoRun Items",
                        internal,
                        f"AutoRun Items | {run['name']} = {run['command']}",
                        {"Name": run["name"],
                         "Command": run["command"],
                         "User": user,
                         "Key Path": run["key_path"]},
                    )
                for rec in parse_trust_records(user_hive, hive_label=f"NTUSER:{user}"):
                    times = {}
                    if rec.get("trusted_at"):
                        times["Trusted At"] = rec["trusted_at"]
                    _insert(
                        "Office Trusted Documents",
                        internal,
                        f"Office Trusted Documents | {rec['document']} "
                        f"macro_enabled={rec['macro_enabled']}",
                        {"Document": rec["document"],
                         "Application": rec["application"],
                         "Macro Enabled": str(rec["macro_enabled"]),
                         "User": user},
                        times,
                    )
                for mru in parse_office_mru(user_hive, hive_label=f"NTUSER:{user}"):
                    times = {}
                    if mru.get("last_opened"):
                        times["Last Opened"] = mru["last_opened"]
                    _insert(
                        "Office Recent Documents",
                        internal,
                        f"Office Recent Documents | {mru['document']} "
                        f"({mru['application']})",
                        {"Document": mru["document"],
                         "Application": mru["application"],
                         "User": user},
                        times,
                    )
                for mp in parse_mountpoints2(user_hive, hive_label=f"NTUSER:{user}"):
                    _insert(
                        "USB Devices",
                        internal,
                        f"USB Devices | MountPoints2 {mp['mount_point']} "
                        f"user={user}",
                        {"Mount Point": mp["mount_point"],
                         "Kind": mp["kind"],
                         "User": user,
                         "Source": "MountPoints2"},
                    )
                for rdp in parse_rdp_client_mru(user_hive, hive_label=f"NTUSER:{user}"):
                    if not rdp.get("destination"):
                        continue
                    _insert(
                        "RDP Client Destinations",
                        internal,
                        f"RDP Client Destinations | {user} -> {rdp['destination']}",
                        {"Destination": rdp["destination"],
                         "Username Hint": rdp["username_hint"],
                         "User": user,
                         "Source": rdp["source"]},
                    )
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "ntuser_hive_parse_failed",
                    "error": str(exc),
                })

        # ── setupapi.dev.log: first-connect timestamps for USB media ──
        setupapi_internal = "/c:/Windows/INF/setupapi.dev.log"
        setupapi_local = os.path.join(tmp, "setupapi.dev.log")
        try:
            extracted = image.extract_file(setupapi_internal, setupapi_local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            with open(setupapi_local, "r", encoding="utf-8", errors="replace") as fh:
                setupapi_text = fh.read()
            for dev in parse_setupapi_device_installs(setupapi_text):
                times = {}
                if dev.get("first_install"):
                    times["First Install (local time)"] = dev["first_install"]
                _insert(
                    "USB Devices",
                    setupapi_internal,
                    f"USB Devices | setupapi install {dev['device_id']}",
                    {"Device ID": dev["device_id"],
                     "Source": "setupapi.dev.log",
                     "Install Time (local)": dev.get("raw_timestamp", "")},
                    times,
                )
        except Exception as exc:
            coverage_gaps.append({
                "path": setupapi_internal,
                "status": "coverage_gap",
                "reason": "setupapi_log_unavailable",
                "error": str(exc),
            })

    indexed_total = sum(counts.values())
    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if indexed_total == 0 and coverage_gaps:
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": indexed_total > 0 or not coverage_gaps,
        "status": status,
        "indexed_records": indexed_total,
        "indexed_by_type": counts,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── WMI subscription persistence ─────────────────────────────────────────────
#
# WMI event-subscription persistence (the __EventFilter -> __FilterToConsumer
# Binding -> __EventConsumer triad) is a classic fileless persistence technique
# and a documented MFDB/KAPE gap. We parse the CIM repository directly with
# dissect.cim and enumerate EVERY namespace, because a consumer planted outside
# root\subscription is itself a strong anomaly. No-miss: the analyst sees all
# subscriptions and the suspicious one stands out (e.g. a CommandLineEvent
# Consumer running a script, or a filter with a high-frequency polling query).

_WMI_REPO_DIR = "/c:/Windows/System32/wbem/Repository"
_WMI_REPO_FILES = (
    "OBJECTS.DATA", "INDEX.BTR", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP",
)
_WMI_CONSUMER_CLASSES = (
    "CommandLineEventConsumer", "ActiveScriptEventConsumer",
    "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer",
)
# High-value payload fields to inline per consumer type (union across types).
_WMI_CONSUMER_FIELDS = (
    "Name", "CommandLineTemplate", "ExecutablePath", "WorkingDirectory",
    "ScriptText", "ScriptFileName", "ScriptingEngine", "FileName",
)
_WMI_MAX_NAMESPACES = 1000  # recursion safety bound
_WMI_MAX_INSTANCES = 5000   # per-class instance bound


def _wmi_value(instance: Any, name: str) -> str:
    """Return a property's value as a string, '' if absent/uninitialized."""
    try:
        prop = instance.properties.get(name)
    except Exception:
        return ""
    if prop is None:
        return ""
    try:
        value = prop.value
    except Exception:
        return ""
    if isinstance(value, (bytes, bytearray, list, tuple)):
        return _wmi_sid_from_bytes(value) if name == "CreatorSID" else str(value)
    return "" if value is None else str(value)


def _wmi_sid_from_bytes(raw: Any) -> str:
    try:
        b = bytes(raw)
    except Exception:
        return ""
    if len(b) < 8:
        return ""
    revision = b[0]
    sub_count = b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = []
    offset = 8
    for _ in range(sub_count):
        if offset + 4 > len(b):
            break
        subs.append(int.from_bytes(b[offset:offset + 4], "little"))
        offset += 4
    return "S-%d-%d%s" % (revision, authority,
                          "".join("-%d" % s for s in subs))


def parse_wmi_persistence(
    root_namespace: Any,
    *,
    max_namespaces: int = _WMI_MAX_NAMESPACES,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Walk every namespace under ``root_namespace`` and return
    ``(records, gaps)`` for WMI subscription persistence.

    Record kinds: ``event_filter`` (trigger query), ``event_consumer`` (action
    — command line / script / etc.), ``filter_to_consumer_binding`` (the link).
    Each record carries the WMI namespace it was found in. Duck-typed so it can
    be tested with fakes: a namespace exposes ``.name``, ``.namespaces`` and
    ``.class_(name).instances``; an instance exposes ``.properties`` (a dict of
    objects with a ``.value``).
    """
    records: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    visited = 0

    def collect(ns: Any, path: str) -> None:
        nonlocal visited
        if visited >= max_namespaces:
            return
        visited += 1
        # __EventFilter
        for inst in _wmi_instances(ns, "__EventFilter", path, gaps):
            records.append({
                "kind": "event_filter",
                "namespace": path,
                "name": _wmi_value(inst, "Name"),
                "query": _wmi_value(inst, "Query"),
                "query_language": _wmi_value(inst, "QueryLanguage"),
                "event_namespace": _wmi_value(inst, "EventNamespace"),
                "creator_sid": _wmi_value(inst, "CreatorSID"),
            })
        # __EventConsumer subclasses
        for cls_name in _WMI_CONSUMER_CLASSES:
            for inst in _wmi_instances(ns, cls_name, path, gaps):
                payload = {
                    f: _wmi_value(inst, f) for f in _WMI_CONSUMER_FIELDS
                }
                records.append({
                    "kind": "event_consumer",
                    "consumer_type": cls_name,
                    "namespace": path,
                    "name": payload.get("Name", ""),
                    "payload": {k: v for k, v in payload.items() if v},
                    "creator_sid": _wmi_value(inst, "CreatorSID"),
                })
        # __FilterToConsumerBinding
        for inst in _wmi_instances(ns, "__FilterToConsumerBinding", path, gaps):
            records.append({
                "kind": "filter_to_consumer_binding",
                "namespace": path,
                "filter": _wmi_value(inst, "Filter"),
                "consumer": _wmi_value(inst, "Consumer"),
                "creator_sid": _wmi_value(inst, "CreatorSID"),
            })
        # recurse child namespaces
        try:
            children = list(ns.namespaces)
        except Exception as exc:  # noqa: BLE001
            gaps.append({
                "path": path, "status": "coverage_gap",
                "reason": "wmi_namespace_enum_error", "error": str(exc),
            })
            return
        for child in children:
            # dissect.cim Namespace.name is already the FULL path (e.g.
            # "root\subscription"), so use it directly rather than concatenating
            # (which produced "root\root\subscription").
            child_name = str(getattr(child, "name", "") or "")
            collect(child, child_name or path)

    collect(root_namespace, "root")
    if visited >= max_namespaces:
        gaps.append({
            "path": "root", "status": "coverage_gap",
            "reason": "wmi_namespace_cap_reached",
            "error": f"stopped after {max_namespaces} namespaces",
        })
    return records, gaps


def _wmi_instances(ns: Any, class_name: str, path: str,
                   gaps: list[dict[str, Any]]):
    """Return instances of class_name in ns.

    A class simply not defined in a namespace is normal (dissect.cim raises
    ReferenceNotFoundError / the duck-typed fake raises KeyError) — return
    nothing without a gap. Any OTHER class-lookup error is repository corruption
    and IS a gap. Instances are streamed with a cap and partial results are
    preserved if iteration fails partway (no-miss)."""
    try:
        cls = ns.class_(class_name)
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ in ("ReferenceNotFoundError", "KeyError"):
            return []  # class not defined in this namespace — normal
        gaps.append({
            "path": f"{path}:{class_name}", "status": "coverage_gap",
            "reason": "wmi_class_lookup_error", "error": str(exc),
        })
        return []
    out: list[Any] = []
    try:
        for inst in cls.instances:
            out.append(inst)
            if len(out) >= _WMI_MAX_INSTANCES:
                gaps.append({
                    "path": f"{path}:{class_name}", "status": "coverage_gap",
                    "reason": "wmi_instance_cap_reached",
                    "error": f"more than {_WMI_MAX_INSTANCES} instances; truncated",
                })
                break
    except Exception as exc:  # noqa: BLE001 — keep the instances gathered so far
        gaps.append({
            "path": f"{path}:{class_name}", "status": "coverage_gap",
            "reason": "wmi_instance_enum_error", "error": str(exc),
        })
    return out


def index_wmi_persistence(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    repo_dir: str = _WMI_REPO_DIR,
) -> dict[str, Any]:
    """Index WMI subscription persistence from the CIM repository.

    Extracts the repository files to a temp dir (DO_NOT_EXECUTE marker, removed
    afterwards) and parses them with dissect.cim. No-miss: a missing/unreadable
    repository, an unavailable CIM library, and per-namespace enum errors are
    each recorded as coverage gaps; no repository is ``not_evaluable``.
    """
    run_id = store.start_parser_run("wmi_indexer", repo_dir, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_wmi_") as tmp:
        _write_do_not_execute_marker(tmp)
        missing = False
        for fname in _WMI_REPO_FILES:
            internal = f"{repo_dir}/{fname}"
            try:
                extracted = image.extract_file(internal, os.path.join(tmp, fname)) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
            except Exception as exc:  # noqa: BLE001
                missing = True
                coverage_gaps.append({
                    "path": internal, "status": "coverage_gap",
                    "reason": "wmi_repo_file_unavailable", "error": str(exc),
                })
        records: list[dict[str, Any]] = []
        if not missing:
            handles: list[Any] = []
            try:
                from dissect.cim import CIM

                findex = open(os.path.join(tmp, "INDEX.BTR"), "rb")
                fobjects = open(os.path.join(tmp, "OBJECTS.DATA"), "rb")
                fmappings = [
                    open(os.path.join(tmp, f"MAPPING{i}.MAP"), "rb")
                    for i in range(1, 4)
                ]
                handles = [findex, fobjects, *fmappings]
                cim = CIM(findex, fobjects, fmappings)
                root = cim.namespace("root")
                records, parse_gaps = parse_wmi_persistence(root)
                coverage_gaps.extend(parse_gaps)
                parsed_ok = True
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": repo_dir, "status": "coverage_gap",
                    "reason": "wmi_repo_parse_error", "error": str(exc),
                })
            finally:
                # Close repo handles BEFORE the TemporaryDirectory cleanup, or
                # Windows refuses to delete the still-open OBJECTS.DATA/INDEX.BTR.
                for handle in handles:
                    try:
                        handle.close()
                    except Exception:
                        pass

        for rec in records:
            kind = rec["kind"]
            ns_path = rec.get("namespace", "")
            strings: dict[str, str] = {"Kind": kind, "WMI Namespace": ns_path}
            if rec.get("creator_sid"):
                strings["Creator SID"] = rec["creator_sid"]
            if kind == "event_filter":
                strings.update({
                    "Name": rec.get("name", ""),
                    "Query": rec.get("query", ""),
                    "Query Language": rec.get("query_language", ""),
                    "Event Namespace": rec.get("event_namespace", ""),
                })
                desc = f"WMI Event Filter | {rec.get('name', '')} | {rec.get('query', '')}"
            elif kind == "event_consumer":
                strings["Consumer Type"] = rec.get("consumer_type", "")
                strings["Name"] = rec.get("name", "")
                for field_name, value in (rec.get("payload") or {}).items():
                    strings[field_name] = str(value)
                desc = (
                    f"WMI Event Consumer | {rec.get('consumer_type', '')} | "
                    f"{rec.get('name', '')}"
                )
            else:  # filter_to_consumer_binding
                strings.update({
                    "Filter": rec.get("filter", ""),
                    "Consumer": rec.get("consumer", ""),
                })
                desc = (
                    f"WMI FilterToConsumerBinding | {rec.get('filter', '')} -> "
                    f"{rec.get('consumer', '')}"
                )
            store.insert_artifact(
                artifact_type="WMI Persistence",
                source_ref=ns_path or repo_dir,
                source_path=repo_dir,
                primary_path=repo_dir,
                description=desc[:512],
                strings={k: v for k, v in strings.items() if v},
                times={},  # CIM instances carry no reliable per-record UTC time
                parser_run_id=run_id,
            )
            indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not parsed_ok and indexed == 0:
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": parsed_ok,
        "status": status,
        "indexed_records": indexed,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }
