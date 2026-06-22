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
import codecs
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree as ET
from urllib.parse import unquote

from core.raw_index.store import RawIndexStore


# ── EVTX ───────────────────────────────────────────────────────────────────

# Roadmap P1/P2 event set: logon/credential, execution, service/task
# persistence, log clearing, PowerShell, RDP/SMB/WinRM/WMI/Sysmon tracking.
EVTX_TARGET_EVENT_IDS = {
    # Authentication, privilege, account, audit, share, and directory access.
    4624, 4625, 4648, 4672, 4674, 4720, 4722, 4728, 4732, 4756,
    4768, 4769, 4771, 4776, 4798, 4799, 5136, 5140, 5145, 4662, 4663,
    4616, 4719, 4946, 4947, 4950,
    # Service and task persistence/state.
    7045, 7036, 7040, 4697, 4698, 4702, 106, 129, 140, 141, 200, 201,
    # Log clearing and PowerShell.
    1102, 104, 400, 600, 4103, 4104,
    # RDP, WinRM, WMI, and Office alerts.
    1149, 21, 24, 25, 4778, 4779, 91, 168, 6,
    5857, 5858, 5859, 5860, 5861,
    300,  # OAlerts: Office alert dialogs (macro warnings, crash prompts)
    # Process creation — critical for raw-only mode where find_suspicious
    # (which owns 4688 on parsed cases) cannot run. Aligns with hunt_evtx
    # rules and lets execution chains be reconstructed from raw EVTX.
    4688,
    # Sysmon execution, network, file, registry, injection, pipe, and DNS.
    1, 3, 8, 10, 11, 12, 13, 18, 22,
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
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx",
    "Microsoft-Windows-DNS-Client%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
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


# COM hijack (T1546.015): a per-user CLSID server registration in UsrClass.dat
# (HKCU\Software\Classes\CLSID) is resolved BEFORE the machine HKLM entry, so a
# user-writable server DLL/EXE hijacks that COM object. We surface user-COM
# registrations whose server path is in a user-writable location — the hijack
# surface. NOTE: legitimate modern apps (Teams, Slack, ...) also register here,
# so each hit is a lead to verify, not a verdict.
_COM_SUSPICIOUS_PATH_RE = re.compile(
    r"(\\AppData\\|\\Temp\\|\\Tmp\\|\\ProgramData\\|\\Users\\Public\\|"
    r"\\Downloads\\|\\Roaming\\|\\Local\\Temp\\|\\Windows\\Temp\\)", re.I)
_COM_CLSID_CAP = 5000
_COM_ABSENT_EXC = ("RegistryKeyNotFoundException", "NoRegistrySubkeysException",
                   "RegistryValueNotFoundException", "KeyError")


def _com_suspicious_reason(server: str) -> str:
    """Classify why a COM server registration is a hijack lead, or '' if it
    looks like a normal Program Files / System32 install.

    Broadened beyond user-writable paths so scriptlet COM (scrobj.dll) and
    environment-variable paths — both used for COM hijack — are not missed.
    """
    low = server.lower()
    if "scrobj.dll" in low or ".sct" in low or "scriptlet" in low:
        return "scriptlet_com"          # scrobj.dll / .sct scriptlet COM
    if "%" in server:
        return "env_var_path"           # %APPDATA% etc. — resolves user-writable
    if _COM_SUSPICIOUS_PATH_RE.search(server):
        return "user_writable_path"     # AppData / Temp / ProgramData / ...
    return ""


def parse_com_hijack(
    hive: Any,
    *,
    user: str,
    hive_label: str = "UsrClass",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse per-user COM server hijack candidates from a UsrClass.dat hive.

    Emits CLSID InprocServer32 / LocalServer32 registrations whose server is a
    hijack lead (user-writable path, environment-variable path, or a scrobj.dll
    /.sct scriptlet). Returns ``(entries, gaps)``. No-miss: an absent CLSID root
    or absent server subkey is normal; a corrupt key / unreadable values is a
    coverage gap. Subkeys are streamed with a cap so a huge hive stays bounded.

    Known limitation: machine-CLSID-override and protected-path (System32)
    hijacks are not surfaced here (they need an HKLM SOFTWARE\\Classes cross-
    reference) — recorded in the roadmap, not silently dropped.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []

    for clsid_root in ("\\CLSID", "\\Software\\Classes\\CLSID"):
        try:
            subkey_iter = hive.get_key(clsid_root).iter_subkeys()
        except Exception as exc:  # noqa: BLE001
            if type(exc).__name__ in _COM_ABSENT_EXC:
                continue  # this layout absent — try the other / normal
            gaps.append({
                "path": f"{hive_label}:{clsid_root}", "status": "coverage_gap",
                "reason": "com_clsid_key_error", "error": str(exc),
            })
            continue

        scanned = 0
        capped = False
        for guid_key in subkey_iter:  # streamed — not materialized via list()
            if scanned >= _COM_CLSID_CAP:
                capped = True
                break
            scanned += 1
            guid = str(getattr(guid_key, "name", "") or "")
            for server_kind, subkey_name in (("inproc", "InprocServer32"),
                                             ("local", "LocalServer32")):
                try:
                    server_key = guid_key.get_subkey(subkey_name)
                except Exception as exc:  # noqa: BLE001
                    if type(exc).__name__ in _COM_ABSENT_EXC:
                        continue  # this CLSID has no such server — normal
                    gaps.append({
                        "path": f"{hive_label}:{clsid_root}\\{guid}\\{subkey_name}",
                        "status": "coverage_gap",
                        "reason": "com_subkey_read_error", "error": str(exc),
                    })
                    continue
                try:
                    server = ""
                    threading = ""
                    for value in (server_key.iter_values() or ()):
                        vname = str(getattr(value, "name", "") or "").lower()
                        if vname in ("", "(default)"):
                            server = str(getattr(value, "value", "") or "")
                        elif vname == "threadingmodel":
                            threading = str(getattr(value, "value", "") or "")
                except Exception as exc:  # noqa: BLE001
                    gaps.append({
                        "path": f"{hive_label}:{clsid_root}\\{guid}\\{subkey_name}",
                        "status": "coverage_gap",
                        "reason": "com_subkey_read_error", "error": str(exc),
                    })
                    continue
                if not server:
                    continue
                reason = _com_suspicious_reason(server)
                if not reason:
                    continue  # standard Program Files / System32 install
                entries.append({
                    "clsid": guid,
                    "server": server,
                    "server_kind": server_kind,
                    "threading_model": threading,
                    "suspicious_reason": reason,
                    "user": user,
                    "key_path": f"{clsid_root}\\{guid}\\{subkey_name}",
                })
        if capped:
            gaps.append({
                "path": f"{hive_label}:{clsid_root}", "status": "coverage_gap",
                "reason": "com_clsid_cap_reached",
                "error": f"more than {_COM_CLSID_CAP} CLSIDs; truncated",
            })
        break  # found a CLSID root; do not also scan the alternate layout

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
    ads_decode_errors = 0

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
                    if isinstance(content, (bytes, bytearray)):
                        try:
                            bytes(content).decode("utf-8")
                        except UnicodeDecodeError:
                            # parse_zone_identifier decodes with
                            # errors="replace"; count the lossy decode so it
                            # surfaces as a gap instead of silent corruption.
                            ads_decode_errors += 1
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

    if ads_decode_errors:
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "zone_identifier_decode_errors",
            "error": (
                f"{ads_decode_errors} Zone.Identifier stream(s) held invalid "
                "UTF-8; replacement characters were substituted — affected "
                "Referrer/Host URLs may be partially corrupted"
            ),
        })
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


# ── Scheduled Task XML ──────────────────────────────────────────────────────

_TASKS_ROOT = "/c:/Windows/System32/Tasks"
_SCHEDULED_TASK_FILE_CAP = 10000


def _xml_local_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _first_child_text(node: ET.Element | None, local_name: str) -> str:
    if node is None:
        return ""
    for child in list(node):
        if _xml_local_name(child.tag) == local_name:
            return (child.text or "").strip()
    return ""


def _first_descendant(node: ET.Element, local_name: str) -> ET.Element | None:
    for child in node.iter():
        if _xml_local_name(child.tag) == local_name:
            return child
    return None


def _first_descendant_text(node: ET.Element, local_name: str) -> str:
    found = _first_descendant(node, local_name)
    return (found.text or "").strip() if found is not None else ""


def _decode_task_xml(raw: bytes) -> tuple[str, bool]:
    candidates = ["utf-8-sig"]
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        candidates.insert(0, "utf-16")
    else:
        candidates.append("utf-16")
    for encoding in candidates:
        try:
            return raw.decode(encoding), False
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), True


def parse_scheduled_task_xml(text: str, *, task_path: str = "") -> dict[str, Any]:
    """Parse one Task Scheduler XML file into raw-index fields.

    Task XML is configuration state, not execution evidence. It is a strong
    persistence lead when the action points to a suspicious path, and it should
    be corroborated with TaskScheduler EVTX, Prefetch, SRUM, BAM, or file
    timestamps before concluding execution.
    """
    root = ET.fromstring(str(text).lstrip("\ufeff"))
    task_name = task_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]

    actions = _first_descendant(root, "Actions")
    exec_node = _first_descendant(root, "Exec")
    principals = _first_descendant(root, "Principal")
    settings = _first_descendant(root, "Settings")
    triggers = _first_descendant(root, "Triggers")

    trigger_types: list[str] = []
    if triggers is not None:
        for child in list(triggers):
            trigger_types.append(_xml_local_name(child.tag))

    registered = _parse_iso_ms(_first_descendant_text(root, "Date"))
    start_boundary = _parse_iso_ms(_first_descendant_text(root, "StartBoundary"))

    return {
        "task_name": task_name,
        "task_path": task_path,
        "author": _first_descendant_text(root, "Author"),
        "description": _first_descendant_text(root, "Description"),
        "user_id": _first_child_text(principals, "UserId"),
        "run_level": _first_child_text(principals, "RunLevel"),
        "enabled": _first_child_text(settings, "Enabled"),
        "hidden": _first_child_text(settings, "Hidden"),
        "actions_context": str(actions.attrib.get("Context", "")) if actions is not None else "",
        "command": _first_child_text(exec_node, "Command"),
        "arguments": _first_child_text(exec_node, "Arguments"),
        "working_directory": _first_child_text(exec_node, "WorkingDirectory"),
        "trigger_types": ",".join(trigger_types),
        "registered_at": registered,
        "start_boundary": start_boundary,
    }


def _iter_task_file_entries(
    image: Any,
    root: str,
    coverage_gaps: list[dict[str, Any]],
    *,
    max_tasks: int,
) -> tuple[list[dict[str, Any]], bool]:
    entries: list[dict[str, Any]] = []
    stack = [root]
    root_read = False
    while stack and len(entries) < max_tasks:
        directory = stack.pop()
        try:
            children = image.list_directory(directory) or []
            if directory == root:
                root_read = True
        except Exception as exc:  # noqa: BLE001
            coverage_gaps.append({
                "path": directory,
                "status": "coverage_gap",
                "reason": "scheduled_task_dir_unavailable",
                "error": str(exc),
            })
            continue
        for child in children:
            if child.get("error"):
                coverage_gaps.append({
                    "path": str(child.get("path") or directory),
                    "status": "coverage_gap",
                    "reason": "scheduled_task_listing_error",
                    "error": str(child.get("error", "")),
                })
                continue
            path = str(child.get("path", "") or "")
            if not path:
                continue
            name = str(child.get("name", "") or path.rsplit("/", 1)[-1])
            if child.get("is_dir"):
                stack.append(path)
                continue
            if name.lower() == "desktop.ini":
                continue
            entries.append(child)
            if len(entries) >= max_tasks:
                coverage_gaps.append({
                    "path": root,
                    "status": "coverage_gap",
                    "reason": "scheduled_task_file_cap_reached",
                    "error": f"stopped after {max_tasks} task XML files",
                })
                break
    return entries, root_read


def index_scheduled_task_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    tasks_root: str = _TASKS_ROOT,
    max_tasks: int = _SCHEDULED_TASK_FILE_CAP,
) -> dict[str, Any]:
    """Index Task Scheduler XML files under Windows\\System32\\Tasks."""
    run_id = store.start_parser_run("scheduled_task_xml_indexer", tasks_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    task_files_seen = 0

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_tasks_") as tmp:
        _write_do_not_execute_marker(tmp)
        entries, root_read = _iter_task_file_entries(
            image, tasks_root, coverage_gaps, max_tasks=max_tasks)
        task_files_seen = len(entries)
        for idx, entry in enumerate(entries):
            task_path = str(entry.get("path", "") or "")
            if not task_path:
                continue
            local = os.path.join(tmp, f"task_{idx}.xml")
            try:
                extracted = image.extract_file(task_path, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                with open(local, "rb") as fh:
                    raw = fh.read(1024 * 1024)
                text, lossy = _decode_task_xml(raw)
                if lossy:
                    coverage_gaps.append({
                        "path": task_path,
                        "status": "coverage_gap",
                        "reason": "scheduled_task_xml_decode_errors",
                        "error": "Task XML decode used replacement characters",
                    })
                task = parse_scheduled_task_xml(text, task_path=task_path)
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": task_path,
                    "status": "coverage_gap",
                    "reason": "scheduled_task_xml_parse_failed",
                    "error": str(exc),
                })
                continue
            times = _entry_times_from_listing(entry)
            if task.get("registered_at"):
                times["Registered At"] = task["registered_at"]
            if task.get("start_boundary"):
                times["Start Boundary"] = task["start_boundary"]
            description = (
                f"Scheduled Tasks | {task.get('task_name', '')} "
                f"Command={task.get('command', '')} "
                f"Arguments={task.get('arguments', '')}"
            )
            store.insert_artifact(
                artifact_type="Scheduled Tasks",
                source_ref=tasks_root,
                source_path=task_path,
                primary_path=task_path,
                description=description[:512],
                strings={
                    "Task Name": task.get("task_name", ""),
                    "Task Path": task_path,
                    "Author": task.get("author", ""),
                    "Description": task.get("description", ""),
                    "User ID": task.get("user_id", ""),
                    "Run Level": task.get("run_level", ""),
                    "Enabled": task.get("enabled", ""),
                    "Hidden": task.get("hidden", ""),
                    "Actions Context": task.get("actions_context", ""),
                    "Command": task.get("command", ""),
                    "Arguments": task.get("arguments", ""),
                    "Working Directory": task.get("working_directory", ""),
                    "Trigger Types": task.get("trigger_types", ""),
                },
                times=times,
                parser_run_id=run_id,
            )
            indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not root_read:
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
        "ok": root_read,
        "status": status,
        "indexed_records": indexed,
        "task_files_seen": task_files_seen,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


_TASKCACHE_TREE_ROOT = "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
_TASKCACHE_TASKS_ROOT = "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
_TASKCACHE_ACTION_STRING_RE = re.compile(r"[\x20-\x7e]{3,}")


def _registry_value_dict(key: Any) -> dict[str, Any]:
    values: dict[str, Any] = {}
    try:
        iterator = key.iter_values()
    except Exception:
        return values
    for value in iterator or ():
        values[str(getattr(value, "name", "") or "")] = getattr(value, "value", None)
    return values


def _extract_utf16_strings(raw: Any, *, min_len: int = 3) -> list[str]:
    data = _coerce_bytes(raw)
    if not data:
        return []
    try:
        text = data.decode("utf-16-le", errors="ignore")
    except Exception:
        return []
    seen: set[str] = set()
    strings: list[str] = []
    for match in _TASKCACHE_ACTION_STRING_RE.finditer(text.replace("\x00", "\n")):
        value = match.group(0).strip()
        if len(value) < min_len or value in seen:
            continue
        seen.add(value)
        strings.append(value)
    return strings


# ── AmCache / UserAssist / ShimCache ───────────────────────────────────────

_AMCACHE_HIVE_PATH = "/c:/Windows/AppCompat/Programs/Amcache.hve"
_USERASSIST_VALUE_CAP = 20000
_SHIMCACHE_VALUE_CAP = 20000
_AMCACHE_SUBKEY_CAP = 50000
_RAW_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\r\n\t\x00|]{2,}")


def _iter_subkeys_safe(key: Any) -> list[Any]:
    try:
        return list(key.iter_subkeys() or [])
    except Exception:
        return []


def _iter_values_safe(key: Any) -> list[Any]:
    try:
        return list(key.iter_values() or [])
    except Exception:
        return []


def _registry_key_lastwrite(key: Any) -> tuple[int, str] | None:
    header = getattr(key, "header", None)
    if header is None:
        return None
    return _filetime_int_to_ms(getattr(header, "last_modified", None))


def _value_timestamp(value: Any) -> tuple[int, str] | None:
    parsed = _parse_iso_ms(_pca_value_text(value))
    if parsed:
        return parsed
    return _pca_timestamp(value)


def _first_value(fields: dict[str, Any], *names: str) -> str:
    lowered = {str(k).lower(): v for k, v in fields.items()}
    for name in names:
        value = lowered.get(name.lower())
        text = _pca_value_text(value).strip()
        if text:
            return text
    return ""


def _registry_values_dict(key: Any) -> dict[str, Any]:
    return {
        str(getattr(value, "name", "") or ""): getattr(value, "value", None)
        for value in _iter_values_safe(key)
    }


def _walk_registry_subtree(root: Any, *, max_nodes: int) -> tuple[list[Any], bool]:
    nodes: list[Any] = []
    stack = list(reversed(_iter_subkeys_safe(root)))
    capped = False
    while stack:
        if len(nodes) >= max_nodes:
            capped = True
            break
        node = stack.pop()
        nodes.append(node)
        children = _iter_subkeys_safe(node)
        stack.extend(reversed(children))
    return nodes, capped


def parse_userassist_entries(
    hive: Any,
    *,
    user: str,
    hive_label: str,
    max_values: int = _USERASSIST_VALUE_CAP,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse Explorer UserAssist Count values.

    UserAssist records GUI-initiated launches and shell interactions. It is
    moderate execution context: it misses services, console-only launches, and
    command lines.
    """
    root_path = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    try:
        root = hive.get_key(root_path)
    except Exception:
        return entries, gaps
    scanned = 0
    for guid_key in _iter_subkeys_safe(root):
        guid = str(getattr(guid_key, "name", "") or "")
        try:
            count_key = guid_key.get_subkey("Count")
        except Exception:
            continue
        for value in _iter_values_safe(count_key):
            if scanned >= max_values:
                gaps.append({
                    "path": f"{hive_label}:{root_path}",
                    "status": "coverage_gap",
                    "reason": "userassist_value_cap_reached",
                    "error": f"more than {max_values} UserAssist values; truncated",
                })
                return entries, gaps
            scanned += 1
            encoded = str(getattr(value, "name", "") or "")
            if not encoded:
                continue
            try:
                decoded = codecs.decode(encoded, "rot_13")
            except Exception:
                decoded = encoded
            raw = _coerce_bytes(getattr(value, "value", None))
            run_count = 0
            last_run = None
            if raw:
                if len(raw) >= 8:
                    run_count = int.from_bytes(raw[4:8], "little", signed=False)
                for offset in (60, 68, 8):
                    if len(raw) >= offset + 8:
                        last_run = _filetime_to_ms(raw[offset:offset + 8])
                        if last_run:
                            break
            entries.append({
                "user": user,
                "hive": hive_label,
                "guid": guid,
                "encoded_name": encoded,
                "decoded_name": decoded,
                "run_count": run_count,
                "last_run": last_run,
            })
    return entries, gaps


def parse_shimcache_entries(
    hive: Any,
    control_sets: list[tuple[str, bool]],
    *,
    max_values: int = _SHIMCACHE_VALUE_CAP,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Best-effort ShimCache/AppCompatCache path extraction.

    This deliberately avoids claiming full AppCompatCacheParser parity. Paths
    recovered from the binary blob are weak file-existence context, not
    execution proof.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    scanned = 0
    for control_set, is_current in control_sets:
        key_path = f"\\{control_set}\\Control\\Session Manager\\AppCompatCache"
        try:
            key = hive.get_key(key_path)
        except Exception:
            continue
        key_time = _registry_key_lastwrite(key)
        for value in _iter_values_safe(key):
            if scanned >= max_values:
                gaps.append({
                    "path": key_path,
                    "status": "coverage_gap",
                    "reason": "shimcache_value_cap_reached",
                    "error": f"more than {max_values} ShimCache values; truncated",
                })
                return entries, gaps
            scanned += 1
            raw = _coerce_bytes(getattr(value, "value", None))
            if not raw:
                continue
            for text in _extract_utf16_strings(raw, min_len=5):
                for match in _RAW_WINDOWS_PATH_RE.finditer(text):
                    path = match.group(0).strip()
                    dedupe = (control_set, path.lower())
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    entries.append({
                        "path": path,
                        "control_set": control_set,
                        "is_current_control_set": is_current,
                        "cache_entry_position": len(entries),
                        "last_modified": key_time,
                        "executed": "",
                    })
    return entries, gaps


def parse_amcache_hive(
    hive: Any,
    *,
    max_subkeys: int = _AMCACHE_SUBKEY_CAP,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse high-value AmCache file/program/driver entries from Amcache.hve.

    AmCache proves file/program metadata was recorded; it does not prove
    execution. The parser is schema-tolerant and keeps fields with the same
    family names used by parsed KAPE/AXIOM connectors.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    scanned = 0

    def _scan_file_root(path: str) -> None:
        nonlocal scanned
        try:
            root = hive.get_key(path)
        except Exception:
            return
        nodes, capped = _walk_registry_subtree(root, max_nodes=max_subkeys)
        if capped:
            gaps.append({
                "path": path,
                "status": "coverage_gap",
                "reason": "amcache_subkey_cap_reached",
                "error": f"more than {max_subkeys} AmCache subkeys; truncated",
            })
        for node in nodes:
            scanned += 1
            fields = _registry_values_dict(node)
            full_path = _first_value(
                fields, "FullPath", "LowerCaseLongPath", "LongPath", "Path")
            if not full_path:
                name = _first_value(fields, "ApplicationName", "Name")
                if name and "\\" in name:
                    full_path = name
            if not full_path:
                continue
            ts = (
                _value_timestamp(fields.get("FileKeyLastWriteTimestamp"))
                or _registry_key_lastwrite(node)
            )
            entries.append({
                "artifact_type": "AmCache File Entries",
                "path": full_path,
                "name": _first_value(fields, "ApplicationName", "Name")
                        or full_path.rsplit("\\", 1)[-1],
                "sha1": _first_value(fields, "SHA1", "SHA-1"),
                "product_name": _first_value(fields, "ProductName"),
                "company_name": _first_value(fields, "CompanyName"),
                "file_version": _first_value(fields, "FileVersion", "Version"),
                "file_description": _first_value(fields, "FileDescription"),
                "size": _first_value(fields, "Size"),
                "publisher": _first_value(fields, "Publisher"),
                "is_pe_file": _first_value(fields, "IsPeFile", "Is PE File"),
                "binary_type": _first_value(fields, "BinaryType"),
                "program_id": _first_value(fields, "ProgramId"),
                "timestamp": ts,
                "source_key": str(getattr(node, "name", "") or ""),
            })

    def _scan_program_root(path: str) -> None:
        nonlocal scanned
        try:
            root = hive.get_key(path)
        except Exception:
            return
        nodes, capped = _walk_registry_subtree(root, max_nodes=max_subkeys)
        if capped:
            gaps.append({
                "path": path,
                "status": "coverage_gap",
                "reason": "amcache_program_subkey_cap_reached",
                "error": f"more than {max_subkeys} AmCache program subkeys; truncated",
            })
        for node in nodes:
            scanned += 1
            fields = _registry_values_dict(node)
            name = _first_value(fields, "Name", "ProgramName")
            install_path = _first_value(fields, "RootDirPath", "InstallPath")
            if not name and not install_path:
                continue
            ts = (
                _value_timestamp(fields.get("KeyLastWriteTimestamp"))
                or _value_timestamp(fields.get("InstallDateArpLastModified"))
                or _registry_key_lastwrite(node)
            )
            entries.append({
                "artifact_type": "AmCache Program Entries",
                "name": name,
                "version": _first_value(fields, "Version"),
                "publisher": _first_value(fields, "Publisher"),
                "manufacturer": _first_value(fields, "Manufacturer"),
                "install_date": _first_value(fields, "InstallDate"),
                "install_path": install_path,
                "uninstall_string": _first_value(fields, "UninstallString"),
                "program_id": _first_value(fields, "ProgramId")
                              or str(getattr(node, "name", "") or ""),
                "timestamp": ts,
            })

    def _scan_driver_root(path: str) -> None:
        nonlocal scanned
        try:
            root = hive.get_key(path)
        except Exception:
            return
        nodes, capped = _walk_registry_subtree(root, max_nodes=max_subkeys)
        if capped:
            gaps.append({
                "path": path,
                "status": "coverage_gap",
                "reason": "amcache_driver_subkey_cap_reached",
                "error": f"more than {max_subkeys} AmCache driver subkeys; truncated",
            })
        for node in nodes:
            scanned += 1
            fields = _registry_values_dict(node)
            driver_name = _first_value(fields, "DriverName", "Name")
            if not driver_name:
                continue
            ts = (
                _value_timestamp(fields.get("KeyLastWriteTimestamp"))
                or _registry_key_lastwrite(node)
            )
            entries.append({
                "artifact_type": "AmCache Driver Binaries",
                "driver_name": driver_name,
                "company": _first_value(fields, "DriverCompany", "Company"),
                "version": _first_value(fields, "DriverVersion", "Version"),
                "product": _first_value(fields, "Product"),
                "checksum": _first_value(fields, "DriverCheckSum", "Checksum"),
                "signed": _first_value(fields, "DriverSigned", "Signed"),
                "service": _first_value(fields, "Service"),
                "timestamp": ts,
            })

    for root_path in (
        "\\Root\\File",
        "\\Root\\InventoryApplicationFile",
    ):
        _scan_file_root(root_path)
    for root_path in (
        "\\Root\\Programs",
        "\\Root\\InventoryApplication",
    ):
        _scan_program_root(root_path)
    _scan_driver_root("\\Root\\InventoryDriverBinary")

    if scanned == 0:
        gaps.append({
            "path": "Amcache.hve",
            "status": "coverage_gap",
            "reason": "amcache_supported_roots_absent",
            "error": "No supported AmCache roots were readable.",
        })
    return entries, gaps


def _registry_hive_factory(local_path: str, hive_factory: Callable[[str], Any] | None):
    if hive_factory is not None:
        return hive_factory(local_path)
    from regipy.registry import RegistryHive

    return RegistryHive(local_path)


def index_userassist_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    users_root: str = _USERS_ROOT,
    max_user_hives: int = 20,
    hive_factory: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    run_id = store.start_parser_run("userassist_indexer", users_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    hives_parsed = 0
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_userassist_") as tmp:
        _write_do_not_execute_marker(tmp)
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
        if len(user_dirs) > max_user_hives:
            coverage_gaps.append({
                "path": users_root,
                "status": "coverage_gap",
                "reason": "userassist_user_hive_cap_reached",
                "error": f"{len(user_dirs)} profiles; only first {max_user_hives} parsed",
            })
            user_dirs = user_dirs[:max_user_hives]
        for idx, entry in enumerate(user_dirs):
            profile = str(entry.get("path", ""))
            user = str(entry.get("name") or profile.rsplit("/", 1)[-1])
            internal = f"{profile}/NTUSER.DAT"
            local = os.path.join(tmp, f"NTUSER_UserAssist_{idx}.DAT")
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                hive = _registry_hive_factory(local, hive_factory)
                hives_parsed += 1
                entries, gaps = parse_userassist_entries(
                    hive, user=user, hive_label=f"NTUSER:{user}")
                coverage_gaps.extend(gaps)
                for rec in entries:
                    times = {"Last Run": rec["last_run"]} if rec.get("last_run") else {}
                    store.insert_artifact(
                        artifact_type="UserAssist",
                        source_ref=internal,
                        source_path=internal,
                        primary_path=rec["decoded_name"],
                        description=(
                            f"UserAssist | {user} | {rec['decoded_name']} "
                            f"runs={rec['run_count']}"
                        )[:512],
                        strings={
                            "User": user,
                            "Decoded Name": rec["decoded_name"],
                            "Encoded Name": rec["encoded_name"],
                            "Run Count": str(rec["run_count"]),
                            "GUID": rec["guid"],
                        },
                        times=times,
                        parser_run_id=run_id,
                    )
                    indexed += 1
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "userassist_hive_parse_failed",
                    "error": str(exc),
                })
    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if hives_parsed == 0:
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
        "ok": hives_parsed > 0,
        "status": status,
        "indexed_records": indexed,
        "hives_parsed": hives_parsed,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


def index_shimcache_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    system_hive_path: str = _SYSTEM_HIVE_PATH,
    hive_factory: Callable[[str], Any] | None = None,
    control_sets_factory: Callable[[Any], list[tuple[str, bool]]] | None = None,
) -> dict[str, Any]:
    run_id = store.start_parser_run("shimcache_indexer", system_hive_path,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_shimcache_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "SYSTEM")
        try:
            extracted = image.extract_file(system_hive_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            hive = _registry_hive_factory(local, hive_factory)
            if control_sets_factory is None:
                from core.analysis.service_persistence import _control_sets

                control_sets = _control_sets(hive)
            else:
                control_sets = control_sets_factory(hive)
            entries, gaps = parse_shimcache_entries(hive, control_sets)
            coverage_gaps.extend(gaps)
            parsed_ok = True
            for rec in entries:
                times = {}
                if rec.get("last_modified"):
                    times["Last Modified Time"] = rec["last_modified"]
                store.insert_artifact(
                    artifact_type="Shim Cache",
                    source_ref=system_hive_path,
                    source_path=system_hive_path,
                    primary_path=rec["path"],
                    description=f"Shim Cache | {rec['path']}"[:512],
                    strings={
                        "Path": rec["path"],
                        "Control Set": rec["control_set"],
                        "Executed": rec.get("executed", ""),
                        "Cache Entry Position": str(rec["cache_entry_position"]),
                    },
                    times=times,
                    parser_run_id=run_id,
                )
                indexed += 1
        except Exception as exc:
            coverage_gaps.append({
                "path": system_hive_path,
                "status": "coverage_gap",
                "reason": "shimcache_hive_parse_failed",
                "error": str(exc),
            })
    if parsed_ok and indexed == 0 and not coverage_gaps:
        coverage_gaps.append({
            "path": system_hive_path,
            "status": "coverage_gap",
            "reason": "shimcache_entries_absent",
            "error": "No ShimCache paths were recovered from AppCompatCache values.",
        })
    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not parsed_ok:
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


def index_amcache_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    hive_path: str = _AMCACHE_HIVE_PATH,
    hive_factory: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    run_id = store.start_parser_run("amcache_indexer", hive_path, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_amcache_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "Amcache.hve")
        try:
            extracted = image.extract_file(hive_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            hive = _registry_hive_factory(local, hive_factory)
            entries, gaps = parse_amcache_hive(hive)
            coverage_gaps.extend(gaps)
            parsed_ok = True
            for rec in entries:
                artifact_type = rec["artifact_type"]
                if artifact_type == "AmCache File Entries":
                    primary = rec.get("path", "")
                    desc = f"AmCache File Entries | {primary}"
                    fields = {
                        "Name": rec.get("name", ""),
                        "Full Path": primary,
                        "SHA-1": rec.get("sha1", ""),
                        "Product Name": rec.get("product_name", ""),
                        "Company Name": rec.get("company_name", ""),
                        "File Version": rec.get("file_version", ""),
                        "File Description": rec.get("file_description", ""),
                        "Size": rec.get("size", ""),
                        "Publisher": rec.get("publisher", ""),
                        "Is PE File": rec.get("is_pe_file", ""),
                        "Binary Type": rec.get("binary_type", ""),
                        "Program ID": rec.get("program_id", ""),
                    }
                    times = (
                        {"File Key Last Write Time": rec["timestamp"]}
                        if rec.get("timestamp") else {}
                    )
                elif artifact_type == "AmCache Program Entries":
                    primary = rec.get("install_path", "") or rec.get("name", "")
                    desc = f"AmCache Program Entries | {rec.get('name', '')}"
                    fields = {
                        "Program Name": rec.get("name", ""),
                        "Version": rec.get("version", ""),
                        "Publisher": rec.get("publisher", ""),
                        "Manufacturer": rec.get("manufacturer", ""),
                        "Install Date": rec.get("install_date", ""),
                        "Install Path": rec.get("install_path", ""),
                        "Uninstall String": rec.get("uninstall_string", ""),
                        "Program ID": rec.get("program_id", ""),
                    }
                    times = (
                        {"Key Last Write Time": rec["timestamp"]}
                        if rec.get("timestamp") else {}
                    )
                else:
                    primary = rec.get("driver_name", "")
                    desc = f"AmCache Driver Binaries | {primary}"
                    fields = {
                        "Driver Name": rec.get("driver_name", ""),
                        "Company": rec.get("company", ""),
                        "Version": rec.get("version", ""),
                        "Product": rec.get("product", ""),
                        "Checksum": rec.get("checksum", ""),
                        "Signed": rec.get("signed", ""),
                        "Service": rec.get("service", ""),
                    }
                    times = (
                        {"Key Last Write Time": rec["timestamp"]}
                        if rec.get("timestamp") else {}
                    )
                store.insert_artifact(
                    artifact_type=artifact_type,
                    source_ref=hive_path,
                    source_path=hive_path,
                    primary_path=primary or hive_path,
                    description=desc[:512],
                    strings=fields,
                    times=times,
                    parser_run_id=run_id,
                )
                indexed += 1
        except Exception as exc:
            coverage_gaps.append({
                "path": hive_path,
                "status": "coverage_gap",
                "reason": "amcache_hive_parse_failed",
                "error": str(exc),
            })
    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not parsed_ok:
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


def parse_taskcache_entries(
    hive: Any,
    *,
    hive_label: str = "SOFTWARE",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse TaskCache Tree/Tasks registry state from the SOFTWARE hive.

    TaskCache is registration/configuration state. It complements task XML and
    TaskScheduler EVTX, but it does not prove the task executed.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    try:
        tree_root = hive.get_key(_TASKCACHE_TREE_ROOT)
    except Exception as exc:  # noqa: BLE001
        return [], [{
            "path": f"{hive_label}:{_TASKCACHE_TREE_ROOT}",
            "status": "coverage_gap",
            "reason": "taskcache_tree_unavailable",
            "error": str(exc),
        }]

    def walk_tree(key: Any, parts: list[str]) -> None:
        values = _registry_value_dict(key)
        task_id = str(values.get("Id") or values.get("ID") or "").strip()
        if task_id:
            task_name = str(getattr(key, "name", "") or "")
            tree_path = "\\" + "\\".join([*parts, task_name]).strip("\\")
            task_values: dict[str, Any] = {}
            try:
                task_key = hive.get_key(f"{_TASKCACHE_TASKS_ROOT}\\{task_id}")
                task_values = _registry_value_dict(task_key)
            except Exception as exc:  # noqa: BLE001
                gaps.append({
                    "path": f"{hive_label}:{_TASKCACHE_TASKS_ROOT}\\{task_id}",
                    "status": "coverage_gap",
                    "reason": "taskcache_task_key_unavailable",
                    "error": str(exc),
                })
            action_strings = _extract_utf16_strings(task_values.get("Actions"))
            entries.append({
                "hive": hive_label,
                "task_name": task_name,
                "tree_path": tree_path,
                "task_guid": task_id,
                "uri": str(task_values.get("URI") or task_values.get("Path") or ""),
                "index": str(values.get("Index") or ""),
                "action_strings": " | ".join(action_strings),
            })
        try:
            children = list(key.iter_subkeys())
        except Exception as exc:  # noqa: BLE001
            partial_path = "\\".join(parts)
            gaps.append({
                "path": f"{hive_label}:{_TASKCACHE_TREE_ROOT}\\{partial_path}",
                "status": "coverage_gap",
                "reason": "taskcache_tree_enum_error",
                "error": str(exc),
            })
            return
        next_parts = [*parts, str(getattr(key, "name", "") or "")]
        if key is tree_root:
            next_parts = parts
        for child in children:
            walk_tree(child, next_parts)

    walk_tree(tree_root, [])
    return entries, gaps


# ── ShellBags (UsrClass.dat BagMRU) ─────────────────────────────────────────

_SHELLBAG_ROOTS = (
    "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
)
_SHELLBAG_VALUE_NAME_RE = re.compile(r"^\d+$")
_SHELLBAG_ASCII_RE = re.compile(rb"[\x20-\x7e]{3,}")


def _extract_ascii_strings(raw: bytes) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in _SHELLBAG_ASCII_RE.finditer(raw):
        value = match.group(0).decode("ascii", errors="ignore").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _shellbag_item_name(raw: Any) -> str:
    data = _coerce_bytes(raw)
    if not data:
        return ""
    candidates = [
        item for item in [*_extract_utf16_strings(data), *_extract_ascii_strings(data)]
        if item and not item.startswith("::")
    ]
    if not candidates:
        return ""
    return max(candidates, key=len)


def parse_shellbags(
    hive: Any,
    *,
    user: str,
    hive_label: str = "UsrClass",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Best-effort parse ShellBags BagMRU navigation context.

    ShellBags show folder navigation / view-state context, not file execution.
    This parser preserves path hints from the BagMRU tree and strings recovered
    from ShellItem blobs without claiming full binary ShellItem semantics.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []

    def walk(key: Any, root_path: str, segments: list[str]) -> None:
        values = _registry_value_dict(key)
        node_slot = str(values.get("NodeSlot") or "")
        child_segment_by_key: dict[str, str] = {}
        for name, raw in values.items():
            if not _SHELLBAG_VALUE_NAME_RE.match(str(name)):
                continue
            item = _shellbag_item_name(raw)
            if not item:
                continue
            path_segments = [*segments, item]
            child_segment_by_key[str(name)] = item
            entries.append({
                "hive": hive_label,
                "user": user,
                "root": root_path,
                "value_name": str(name),
                "item_name": item,
                "path_hint": "\\".join(path_segments),
                "node_slot": node_slot,
            })
        try:
            children = list(key.iter_subkeys())
        except Exception as exc:  # noqa: BLE001
            gaps.append({
                "path": f"{hive_label}:{root_path}",
                "status": "coverage_gap",
                "reason": "shellbags_subkey_enum_error",
                "error": str(exc),
            })
            return
        for child in children:
            child_name = str(getattr(child, "name", "") or "")
            next_segment = child_segment_by_key.get(child_name, child_name)
            next_segments = [*segments, next_segment] if next_segment else segments
            walk(child, f"{root_path}\\{child_name}", next_segments)

    found_root = False
    for root_path in _SHELLBAG_ROOTS:
        try:
            root_key = hive.get_key(root_path)
        except Exception:
            continue
        found_root = True
        walk(root_key, root_path, [])

    if not found_root:
        gaps.append({
            "path": f"{hive_label}:Shell BagMRU",
            "status": "coverage_gap",
            "reason": "shellbags_bagmru_unavailable",
            "error": "BagMRU roots not found in UsrClass.dat",
        })
    return entries, gaps


# ── Program Compatibility Assistant (PCA) pca.db ────────────────────────────

_PCA_DB_PATH = "/c:/Windows/appcompat/pca/pca.db"
_PCA_ROW_CAP = 5000
_PCA_EXECUTABLE_RE = re.compile(
    r"[A-Za-z]:[\\/][^\r\n\t\x00|]*?\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js|msi)",
    re.I,
)
_PCA_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\r\n\t\x00|]+")
_PCA_TIME_FIELD_HINTS = (
    "time", "date", "run", "start", "end", "created", "modified", "last",
)
_PCA_PATH_FIELD_HINTS = (
    "path", "file", "exe", "image", "program", "application", "app",
)


def _sqlite_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _pca_value_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        strings = _extract_utf16_strings(value)
        if strings:
            return " | ".join(strings)
        return bytes(value).decode("utf-8", errors="replace").strip("\x00")
    return str(value)


def _pca_timestamp(value: Any) -> tuple[int, str] | None:
    parsed = _parse_iso_ms(_pca_value_text(value))
    if parsed:
        return parsed
    try:
        number = int(str(value).strip())
    except Exception:
        return None
    if number <= 0:
        return None
    if number > 10_000_000_000_000_000:
        ms = number // 10000 - _FILETIME_EPOCH_OFFSET_MS
    elif number > 10_000_000_000:
        ms = number
    elif number > 1_000_000_000:
        ms = number * 1000
    else:
        return None
    try:
        display = datetime.fromtimestamp(
            ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
    return ms, display


def _pca_extract_path(fields: dict[str, str]) -> str:
    keys = list(fields.keys())
    preferred = [
        key for key in keys
        if any(hint in key.lower() for hint in _PCA_PATH_FIELD_HINTS)
    ]
    for key in [*preferred, *[k for k in keys if k not in preferred]]:
        value = fields.get(key, "")
        match = _PCA_EXECUTABLE_RE.search(value) or _PCA_WINDOWS_PATH_RE.search(value)
        if match:
            return match.group(0).strip()
    return ""


def _pca_extract_timestamp(fields: dict[str, Any]) -> tuple[str, tuple[int, str] | None]:
    preferred = [
        key for key in fields
        if any(hint in key.lower() for hint in _PCA_TIME_FIELD_HINTS)
    ]
    for key in preferred:
        parsed = _pca_timestamp(fields.get(key))
        if parsed:
            return key, parsed
    return "", None


def parse_pca_db(db_path: str, *, max_rows: int = _PCA_ROW_CAP) -> dict[str, Any]:
    """Parse Program Compatibility Assistant pca.db with schema introspection.

    PCA schemas vary between Windows builds. This parser intentionally avoids a
    brittle table-name contract: it walks user tables, preserves scalar fields,
    and extracts path/timestamp candidates for timeline correlation.
    """
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    capped = False
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        tables = [
            str(row["name"])
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]
        for table in tables:
            if len(entries) >= max_rows:
                capped = True
                break
            try:
                rows = conn.execute(
                    f"SELECT rowid AS __fw_rowid, * FROM {_sqlite_ident(table)} "
                    "LIMIT ?",
                    (max_rows - len(entries) + 1,),
                )
            except sqlite3.DatabaseError:
                rows = conn.execute(
                    f"SELECT * FROM {_sqlite_ident(table)} "
                    "LIMIT ?",
                    (max_rows - len(entries) + 1,),
                )
            for idx, row in enumerate(rows):
                if len(entries) >= max_rows:
                    capped = True
                    break
                raw = dict(row)
                rowid = str(raw.pop("__fw_rowid", idx + 1))
                text_fields = {
                    str(key): _pca_value_text(value)
                    for key, value in raw.items()
                    if _pca_value_text(value)
                }
                executable = _pca_extract_path(text_fields)
                ts_field, timestamp = _pca_extract_timestamp(raw)
                if not executable and not timestamp and not text_fields:
                    continue
                entries.append({
                    "source_table": table,
                    "row_id": rowid,
                    "executable_path": executable,
                    "timestamp_field": ts_field,
                    "timestamp": timestamp,
                    "fields": text_fields,
                })
    finally:
        conn.close()

    if capped:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "pca_row_cap_reached",
            "error": f"stopped after {max_rows} PCA rows",
        })

    return {
        "ok": True,
        "status": "partial" if coverage_gaps else "completed",
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def index_pca_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    db_path: str = _PCA_DB_PATH,
    max_rows: int = _PCA_ROW_CAP,
) -> dict[str, Any]:
    """Index PCA pca.db execution-context rows from a mounted image."""
    run_id = store.start_parser_run("pca_db_indexer", db_path, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_pca_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "pca.db")
        try:
            extracted = image.extract_file(db_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
        except Exception as exc:  # noqa: BLE001
            coverage_gaps.append({
                "path": db_path,
                "status": "coverage_gap",
                "reason": "pca_db_unavailable",
                "error": str(exc),
            })
            parsed = {"ok": False, "entries": [], "coverage_gaps": []}
        else:
            try:
                parsed = parse_pca_db(local, max_rows=max_rows)
                coverage_gaps.extend(parsed.get("coverage_gaps", []))
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": db_path,
                    "status": "coverage_gap",
                    "reason": "pca_db_parse_failed",
                    "error": str(exc),
                })
                parsed = {"ok": False, "entries": [], "coverage_gaps": []}

        for entry in parsed.get("entries", []):
            executable = str(entry.get("executable_path") or "")
            timestamp = entry.get("timestamp")
            times = {"PCA Timestamp": timestamp} if timestamp else {}
            fields = {
                "Executable Path": executable,
                "Source Table": str(entry.get("source_table") or ""),
                "Row ID": str(entry.get("row_id") or ""),
                "Timestamp Field": str(entry.get("timestamp_field") or ""),
            }
            for key, value in list((entry.get("fields") or {}).items())[:16]:
                fields[f"PCA {key}"] = str(value)
            store.insert_artifact(
                artifact_type="PCA Program Compatibility Activity",
                source_ref=db_path,
                source_path=db_path,
                primary_path=executable or db_path,
                description=(
                    f"PCA Program Compatibility Activity | "
                    f"{entry.get('source_table', '')} | {executable}"
                )[:512],
                strings=fields,
                times=times,
                parser_run_id=run_id,
            )
            indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if coverage_gaps and indexed == 0:
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
        "ok": indexed > 0 or not coverage_gaps,
        "status": status,
        "indexed_records": indexed,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── Windows Timeline ActivitiesCache.db ─────────────────────────────────────

_ACTIVITIES_DB_NAME = "ActivitiesCache.db"
_ACTIVITIES_ROW_CAP = 5000
_ACTIVITY_APP_FIELD_HINTS = ("appid", "app_id", "application", "app", "aumid")
_ACTIVITY_DISPLAY_FIELD_HINTS = (
    "display", "title", "name", "description", "text", "activity",
)


def _activity_first_field(fields: dict[str, str], hints: tuple[str, ...]) -> str:
    for key, value in fields.items():
        key_lower = key.lower()
        if value and any(hint in key_lower for hint in hints):
            return value
    return ""


def _activity_path_hint(fields: dict[str, str]) -> str:
    preferred_keys = [
        key for key in fields
        if any(hint in key.lower() for hint in (
            "payload", "file", "document", "uri", "url", "content", "display",
        ))
    ]
    ordered_values = [
        *(fields[key] for key in preferred_keys),
        *(value for key, value in fields.items() if key not in preferred_keys),
    ]
    for value in ordered_values:
        text = str(value).replace("\\\\", "\\")
        match = _PCA_WINDOWS_PATH_RE.search(text) or _PCA_EXECUTABLE_RE.search(text)
        if match:
            return match.group(0).strip()
    return ""


def parse_activities_cache_db(
    db_path: str,
    *,
    max_rows: int = _ACTIVITIES_ROW_CAP,
) -> dict[str, Any]:
    """Parse Windows Timeline ActivitiesCache.db with schema introspection."""
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    capped = False
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        tables = [
            str(row["name"])
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]
        for table in tables:
            if len(entries) >= max_rows:
                capped = True
                break
            try:
                rows = conn.execute(
                    f"SELECT rowid AS __fw_rowid, * FROM {_sqlite_ident(table)} "
                    "LIMIT ?",
                    (max_rows - len(entries) + 1,),
                )
            except sqlite3.DatabaseError:
                rows = conn.execute(
                    f"SELECT * FROM {_sqlite_ident(table)} "
                    "LIMIT ?",
                    (max_rows - len(entries) + 1,),
                )
            for idx, row in enumerate(rows):
                if len(entries) >= max_rows:
                    capped = True
                    break
                raw = dict(row)
                rowid = str(raw.pop("__fw_rowid", idx + 1))
                text_fields = {
                    str(key): _pca_value_text(value)
                    for key, value in raw.items()
                    if _pca_value_text(value)
                }
                ts_field, timestamp = _pca_extract_timestamp(raw)
                app_id = _activity_first_field(text_fields, _ACTIVITY_APP_FIELD_HINTS)
                display = _activity_first_field(
                    text_fields, _ACTIVITY_DISPLAY_FIELD_HINTS)
                path_hint = _activity_path_hint(text_fields)
                if not app_id and not display and not path_hint and not timestamp:
                    continue
                entries.append({
                    "source_table": table,
                    "row_id": rowid,
                    "app_id": app_id,
                    "display_text": display,
                    "path_hint": path_hint,
                    "timestamp_field": ts_field,
                    "timestamp": timestamp,
                    "fields": text_fields,
                })
    finally:
        conn.close()

    if capped:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "activities_row_cap_reached",
            "error": f"stopped after {max_rows} ActivitiesCache rows",
        })

    return {
        "ok": True,
        "status": "partial" if coverage_gaps else "completed",
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def _discover_activities_cache_paths(
    image: Any,
    users_root: str,
    coverage_gaps: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    discovered: list[tuple[str, str]] = []
    try:
        user_dirs = [
            e for e in (image.list_directory(users_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
    except Exception as exc:  # noqa: BLE001
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "activities_users_root_unavailable",
            "error": str(exc),
        })
        return discovered

    for profile in user_dirs:
        profile_path = str(profile.get("path", "") or "")
        user = str(profile.get("name") or profile_path.rsplit("/", 1)[-1])
        cdp_root = f"{profile_path}/AppData/Local/ConnectedDevicesPlatform"
        candidates: list[tuple[str, str]] = []
        try:
            for entry in image.list_directory(cdp_root) or []:
                if entry.get("error"):
                    continue
                entry_path = str(entry.get("path", "") or "")
                entry_name = str(entry.get("name", "") or "")
                if entry.get("is_dir"):
                    candidates.append((
                        user,
                        f"{entry_path}/{_ACTIVITIES_DB_NAME}",
                    ))
                elif entry_name.lower() == _ACTIVITIES_DB_NAME.lower():
                    candidates.append((user, entry_path))
        except Exception:
            pass
        discovered.extend((u, p) for u, p in candidates if p)
    return discovered


def index_activities_cache_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    users_root: str = _USERS_ROOT,
    max_rows: int = _ACTIVITIES_ROW_CAP,
) -> dict[str, Any]:
    """Index Windows Timeline ActivitiesCache.db files from user profiles."""
    run_id = store.start_parser_run("activities_cache_indexer", users_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    databases_seen = 0

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_activities_") as tmp:
        _write_do_not_execute_marker(tmp)
        for idx, (user, internal) in enumerate(
            _discover_activities_cache_paths(image, users_root, coverage_gaps)
        ):
            local = os.path.join(tmp, f"ActivitiesCache_{idx}.db")
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                databases_seen += 1
                parsed = parse_activities_cache_db(local, max_rows=max_rows)
                coverage_gaps.extend(parsed.get("coverage_gaps", []))
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "activities_cache_unavailable_or_parse_failed",
                    "error": str(exc),
                })
                continue
            for entry in parsed.get("entries", []):
                timestamp = entry.get("timestamp")
                times = {"Activity Timestamp": timestamp} if timestamp else {}
                fields = {
                    "User": user,
                    "App ID": str(entry.get("app_id") or ""),
                    "Display Text": str(entry.get("display_text") or ""),
                    "Path Hint": str(entry.get("path_hint") or ""),
                    "Source Table": str(entry.get("source_table") or ""),
                    "Row ID": str(entry.get("row_id") or ""),
                    "Timestamp Field": str(entry.get("timestamp_field") or ""),
                }
                for key, value in list((entry.get("fields") or {}).items())[:16]:
                    fields[f"Activity {key}"] = str(value)
                primary = str(entry.get("path_hint") or internal)
                store.insert_artifact(
                    artifact_type="Windows Timeline Activity",
                    source_ref=internal,
                    source_path=internal,
                    primary_path=primary,
                    description=(
                        f"Windows Timeline Activity | {user} | "
                        f"{entry.get('app_id', '')} | {entry.get('display_text', '')}"
                    )[:512],
                    strings=fields,
                    times=times,
                    parser_run_id=run_id,
                )
                indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if databases_seen == 0:
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
        "ok": databases_seen > 0,
        "status": status,
        "indexed_records": indexed,
        "databases_seen": databases_seen,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── LNK shortcuts and Jump Lists ────────────────────────────────────────────

# ── Browser History / Downloads / Cache ────────────────────────────────────

_CHROMIUM_HISTORY_NAME = "History"
_CHROMIUM_HISTORY_ROW_CAP = 10000
_BROWSER_CACHE_FILE_CAP = 20000
_CHROME_EPOCH_OFFSET_MS = 11644473600000
_FIREFOX_PLACES_NAME = "places.sqlite"
_WEBCACHE_DB_RE = re.compile(r"^WebCacheV\d+\.dat$", re.I)
_WEBCACHE_ROW_CAP = 20000
_WEBCACHE_URL_RE = re.compile(r"(?:https?|ftp)://[^\x00-\x1f\s\"'<>|]{4,}", re.I)
_CHROMIUM_BROWSER_ROOTS = (
    ("Chrome", "AppData/Local/Google/Chrome/User Data"),
    ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
    ("Naver Whale", "AppData/Local/Naver/Naver Whale/User Data"),
)
_FIREFOX_PROFILES_REL = "AppData/Roaming/Mozilla/Firefox/Profiles"
_WEBCACHE_REL = "AppData/Local/Microsoft/Windows/WebCache"
_CHROMIUM_CACHE_DIRS = (
    ("Browser Cache File", "Cache/Cache_Data"),
    ("Browser Code Cache File", "Code Cache/js"),
    ("Browser Code Cache File", "Code Cache/wasm"),
)


def _browser_artifact_type(browser_name: str, kind: str) -> str:
    normalized = browser_name.lower()
    if "chrome" in normalized:
        return "Chrome Web Visits" if kind == "visit" else "Chrome Downloads"
    if "edge" in normalized:
        return "Edge Web Visits" if kind == "visit" else "Edge Downloads"
    return "Chromium Web Visits" if kind == "visit" else "Chromium Downloads"


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table,),
    ).fetchone()
    return row is not None


def _sqlite_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in conn.execute(
            f"PRAGMA table_info({_sqlite_ident(table)})"
        )}
    except sqlite3.DatabaseError:
        return set()


def _chrome_timestamp(value: Any) -> tuple[int, str] | None:
    parsed = _parse_iso_ms(_pca_value_text(value))
    if parsed:
        return parsed
    try:
        number = int(str(value).strip())
    except Exception:
        return None
    if number <= 0:
        return None
    if number > 10_000_000_000_000:
        ms = number // 1000 - _CHROME_EPOCH_OFFSET_MS
    elif number > 10_000_000_000:
        ms = number
    elif number > 1_000_000_000:
        ms = number * 1000
    else:
        return None
    try:
        display = datetime.fromtimestamp(
            ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
    return ms, display


def _firefox_timestamp(value: Any) -> tuple[int, str] | None:
    parsed = _parse_iso_ms(_pca_value_text(value))
    if parsed:
        return parsed
    try:
        number = int(str(value).strip())
    except Exception:
        return None
    if number <= 0:
        return None
    if number > 10_000_000_000_000:
        ms = number // 1000
    elif number > 10_000_000_000:
        ms = number
    elif number > 1_000_000_000:
        ms = number * 1000
    else:
        return None
    try:
        display = datetime.fromtimestamp(
            ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
    return ms, display


def _first_existing_value(fields: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        if name in fields and fields.get(name) not in (None, ""):
            return _pca_value_text(fields.get(name))
    return ""


def _firefox_file_uri_to_path(value: str) -> str:
    text = unquote(str(value or ""))
    if not text.lower().startswith("file:"):
        return text
    text = re.sub(r"^file:/+", "", text, flags=re.I)
    if text.startswith("/") and re.match(r"^/[A-Za-z]:", text):
        text = text[1:]
    return text.replace("/", "\\")


def _chromium_download_url_chains(
    conn: sqlite3.Connection,
) -> dict[str, list[str]]:
    if not _sqlite_table_exists(conn, "downloads_url_chains"):
        return {}
    columns = _sqlite_columns(conn, "downloads_url_chains")
    if "id" not in columns or "url" not in columns:
        return {}
    order = "chain_index" if "chain_index" in columns else "rowid"
    chains: dict[str, list[str]] = {}
    try:
        rows = conn.execute(
            "SELECT id, url FROM downloads_url_chains "
            f"ORDER BY id, {_sqlite_ident(order)}"
        )
    except sqlite3.DatabaseError:
        return {}
    for row in rows:
        download_id = str(row[0])
        url = _pca_value_text(row[1])
        if url:
            chains.setdefault(download_id, []).append(url)
    return chains


def _parse_chromium_visits(
    conn: sqlite3.Connection,
    *,
    browser_name: str,
    user: str,
    profile: str,
    max_rows: int,
) -> list[dict[str, Any]]:
    if max_rows <= 0:
        return []
    if not _sqlite_table_exists(conn, "urls"):
        return []
    url_columns = _sqlite_columns(conn, "urls")
    entries: list[dict[str, Any]] = []
    artifact_type = _browser_artifact_type(browser_name, "visit")
    if _sqlite_table_exists(conn, "visits"):
        visit_columns = _sqlite_columns(conn, "visits")
        if {"url", "visit_time"} <= visit_columns and "id" in url_columns:
            select_bits = [
                "visits.rowid AS __fw_rowid",
                "visits.visit_time AS visit_time",
                (
                    "visits.from_visit AS from_visit"
                    if "from_visit" in visit_columns else "NULL AS from_visit"
                ),
                (
                    "visits.transition AS transition"
                    if "transition" in visit_columns else "NULL AS transition"
                ),
                (
                    "urls.url AS url"
                    if "url" in url_columns else "NULL AS url"
                ),
                (
                    "urls.title AS title"
                    if "title" in url_columns else "NULL AS title"
                ),
                (
                    "urls.visit_count AS visit_count"
                    if "visit_count" in url_columns else "NULL AS visit_count"
                ),
                (
                    "urls.typed_count AS typed_count"
                    if "typed_count" in url_columns else "NULL AS typed_count"
                ),
                (
                    "urls.last_visit_time AS last_visit_time"
                    if "last_visit_time" in url_columns else "NULL AS last_visit_time"
                ),
            ]
            try:
                rows = conn.execute(
                    f"SELECT {', '.join(select_bits)} "
                    "FROM visits JOIN urls ON visits.url = urls.id "
                    "ORDER BY visits.visit_time LIMIT ?",
                    (max_rows + 1,),
                )
            except sqlite3.DatabaseError:
                rows = []
            for row in rows:
                raw = dict(row)
                visit_time = _chrome_timestamp(raw.get("visit_time"))
                url = _pca_value_text(raw.get("url"))
                title = _pca_value_text(raw.get("title"))
                if not url and not title:
                    continue
                entries.append({
                    "artifact_type": artifact_type,
                    "kind": "visit",
                    "browser": browser_name,
                    "user": user,
                    "profile": profile,
                    "source_table": "visits",
                    "row_id": str(raw.get("__fw_rowid", "")),
                    "url": url,
                    "title": title,
                    "visit_count": _pca_value_text(raw.get("visit_count")),
                    "typed_count": _pca_value_text(raw.get("typed_count")),
                    "transition": _pca_value_text(raw.get("transition")),
                    "visit_time": visit_time,
                })
                if len(entries) >= max_rows:
                    break
            return entries

    if {"url", "last_visit_time"} <= url_columns:
        rows = conn.execute(
            "SELECT rowid AS __fw_rowid, url, title, visit_count, typed_count, "
            "last_visit_time FROM urls ORDER BY last_visit_time LIMIT ?",
            (max_rows,),
        )
        for row in rows:
            raw = dict(row)
            entries.append({
                "artifact_type": artifact_type,
                "kind": "visit",
                "browser": browser_name,
                "user": user,
                "profile": profile,
                "source_table": "urls",
                "row_id": str(raw.get("__fw_rowid", "")),
                "url": _pca_value_text(raw.get("url")),
                "title": _pca_value_text(raw.get("title")),
                "visit_count": _pca_value_text(raw.get("visit_count")),
                "typed_count": _pca_value_text(raw.get("typed_count")),
                "transition": "",
                "visit_time": _chrome_timestamp(raw.get("last_visit_time")),
            })
    return entries


def _parse_chromium_downloads(
    conn: sqlite3.Connection,
    *,
    browser_name: str,
    user: str,
    profile: str,
    max_rows: int,
) -> list[dict[str, Any]]:
    if max_rows <= 0:
        return []
    if not _sqlite_table_exists(conn, "downloads"):
        return []
    columns = _sqlite_columns(conn, "downloads")
    chains = _chromium_download_url_chains(conn)
    entries: list[dict[str, Any]] = []
    artifact_type = _browser_artifact_type(browser_name, "download")
    try:
        rows = conn.execute(
            "SELECT rowid AS __fw_rowid, * FROM downloads ORDER BY rowid LIMIT ?",
            (max_rows + 1,),
        )
    except sqlite3.DatabaseError:
        return entries
    for row in rows:
        if len(entries) >= max_rows:
            break
        raw = dict(row)
        row_id = str(raw.get("id") or raw.get("__fw_rowid") or "")
        chain = chains.get(row_id) or []
        url = chain[-1] if chain else _first_existing_value(
            raw, ("url", "tab_url", "site_url", "referrer"))
        target_path = _first_existing_value(
            raw, ("target_path", "full_path", "opened_path", "current_path"))
        current_path = _first_existing_value(raw, ("current_path", "temp_path"))
        fields = {
            key: _pca_value_text(raw.get(key))
            for key in sorted(columns)
            if key in raw and _pca_value_text(raw.get(key))
        }
        if not url and not target_path and not current_path:
            continue
        entries.append({
            "artifact_type": artifact_type,
            "kind": "download",
            "browser": browser_name,
            "user": user,
            "profile": profile,
            "source_table": "downloads",
            "row_id": row_id,
            "url": url,
            "target_path": target_path,
            "current_path": current_path,
            "start_time": _chrome_timestamp(raw.get("start_time")),
            "end_time": _chrome_timestamp(raw.get("end_time")),
            "received_bytes": _pca_value_text(raw.get("received_bytes")),
            "total_bytes": _pca_value_text(raw.get("total_bytes")),
            "state": _pca_value_text(raw.get("state")),
            "danger_type": _pca_value_text(raw.get("danger_type")),
            "fields": fields,
        })
    return entries


def parse_chromium_history_db(
    db_path: str,
    *,
    browser_name: str,
    user: str = "",
    profile: str = "",
    max_rows: int = _CHROMIUM_HISTORY_ROW_CAP,
) -> dict[str, Any]:
    """Parse Chromium History SQLite visits and downloads.

    This is schema-tolerant enough for Chrome/Edge/Whale History databases,
    but it does not claim full browser-forensics parity for cookies, session
    restore, WebCache, or every Chromium build-specific column.
    """
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        entries.extend(_parse_chromium_visits(
            conn,
            browser_name=browser_name,
            user=user,
            profile=profile,
            max_rows=max_rows - len(entries),
        ))
        if len(entries) < max_rows:
            entries.extend(_parse_chromium_downloads(
                conn,
                browser_name=browser_name,
                user=user,
                profile=profile,
                max_rows=max_rows - len(entries),
            ))
    finally:
        conn.close()

    if len(entries) >= max_rows:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "browser_history_row_cap_reached",
            "error": f"stopped after {max_rows} browser history/download rows",
        })
    if not entries:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "browser_history_supported_rows_absent",
            "error": "No supported Chromium visits/download rows were recovered.",
        })
    return {
        "ok": bool(entries),
        "status": "partial" if coverage_gaps and entries else (
            "not_evaluable" if coverage_gaps else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def _parse_firefox_visits(
    conn: sqlite3.Connection,
    *,
    user: str,
    profile: str,
    max_rows: int,
) -> list[dict[str, Any]]:
    if max_rows <= 0 or not _sqlite_table_exists(conn, "moz_places"):
        return []
    place_columns = _sqlite_columns(conn, "moz_places")
    entries: list[dict[str, Any]] = []
    if _sqlite_table_exists(conn, "moz_historyvisits"):
        visit_columns = _sqlite_columns(conn, "moz_historyvisits")
        if {"place_id", "visit_date"} <= visit_columns and "id" in place_columns:
            select_bits = [
                "visits.rowid AS __fw_rowid",
                "visits.visit_date AS visit_date",
                (
                    "visits.from_visit AS from_visit"
                    if "from_visit" in visit_columns else "NULL AS from_visit"
                ),
                (
                    "visits.visit_type AS visit_type"
                    if "visit_type" in visit_columns else "NULL AS visit_type"
                ),
                (
                    "places.url AS url"
                    if "url" in place_columns else "NULL AS url"
                ),
                (
                    "places.title AS title"
                    if "title" in place_columns else "NULL AS title"
                ),
                (
                    "places.visit_count AS visit_count"
                    if "visit_count" in place_columns else "NULL AS visit_count"
                ),
                (
                    "places.typed AS typed_count"
                    if "typed" in place_columns else "NULL AS typed_count"
                ),
            ]
            try:
                rows = conn.execute(
                    f"SELECT {', '.join(select_bits)} "
                    "FROM moz_historyvisits visits "
                    "JOIN moz_places places ON visits.place_id = places.id "
                    "ORDER BY visits.visit_date LIMIT ?",
                    (max_rows + 1,),
                )
            except sqlite3.DatabaseError:
                rows = []
            for row in rows:
                raw = dict(row)
                url = _pca_value_text(raw.get("url"))
                title = _pca_value_text(raw.get("title"))
                if not url and not title:
                    continue
                entries.append({
                    "artifact_type": "Firefox Web Visits",
                    "kind": "visit",
                    "browser": "Firefox",
                    "user": user,
                    "profile": profile,
                    "source_table": "moz_historyvisits",
                    "row_id": str(raw.get("__fw_rowid", "")),
                    "url": url,
                    "title": title,
                    "visit_count": _pca_value_text(raw.get("visit_count")),
                    "typed_count": _pca_value_text(raw.get("typed_count")),
                    "transition": _pca_value_text(raw.get("visit_type")),
                    "visit_time": _firefox_timestamp(raw.get("visit_date")),
                })
                if len(entries) >= max_rows:
                    break
            return entries

    if {"url", "last_visit_date"} <= place_columns:
        rows = conn.execute(
            "SELECT rowid AS __fw_rowid, url, title, visit_count, typed, "
            "last_visit_date FROM moz_places ORDER BY last_visit_date LIMIT ?",
            (max_rows,),
        )
        for row in rows:
            raw = dict(row)
            entries.append({
                "artifact_type": "Firefox Web Visits",
                "kind": "visit",
                "browser": "Firefox",
                "user": user,
                "profile": profile,
                "source_table": "moz_places",
                "row_id": str(raw.get("__fw_rowid", "")),
                "url": _pca_value_text(raw.get("url")),
                "title": _pca_value_text(raw.get("title")),
                "visit_count": _pca_value_text(raw.get("visit_count")),
                "typed_count": _pca_value_text(raw.get("typed")),
                "transition": "",
                "visit_time": _firefox_timestamp(raw.get("last_visit_date")),
            })
    return entries


def _firefox_metadata(content: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(content or ""))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_firefox_downloads(
    conn: sqlite3.Connection,
    *,
    user: str,
    profile: str,
    max_rows: int,
) -> list[dict[str, Any]]:
    required = ("moz_annos", "moz_anno_attributes", "moz_places")
    if max_rows <= 0 or not all(_sqlite_table_exists(conn, t) for t in required):
        return []
    attr_columns = _sqlite_columns(conn, "moz_anno_attributes")
    anno_columns = _sqlite_columns(conn, "moz_annos")
    place_columns = _sqlite_columns(conn, "moz_places")
    if not ({"id", "name"} <= attr_columns and
            {"place_id", "anno_attribute_id", "content"} <= anno_columns and
            "id" in place_columns):
        return []
    select_bits = [
        "annos.place_id AS place_id",
        "annos.rowid AS __fw_rowid",
        "attrs.name AS attr_name",
        "annos.content AS content",
        (
            "annos.dateAdded AS date_added"
            if "dateAdded" in anno_columns else "NULL AS date_added"
        ),
        (
            "annos.lastModified AS last_modified"
            if "lastModified" in anno_columns else "NULL AS last_modified"
        ),
        "places.url AS url" if "url" in place_columns else "NULL AS url",
        "places.title AS title" if "title" in place_columns else "NULL AS title",
    ]
    try:
        rows = conn.execute(
            f"SELECT {', '.join(select_bits)} "
            "FROM moz_annos annos "
            "JOIN moz_anno_attributes attrs ON annos.anno_attribute_id = attrs.id "
            "JOIN moz_places places ON annos.place_id = places.id "
            "WHERE attrs.name LIKE 'downloads/%' "
            "ORDER BY annos.place_id, annos.dateAdded LIMIT ?",
            (max_rows * 4 + 4,),
        )
    except sqlite3.DatabaseError:
        return []

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        raw = dict(row)
        place_id = str(raw.get("place_id") or "")
        if not place_id:
            continue
        item = grouped.setdefault(place_id, {
            "row_id": str(raw.get("__fw_rowid") or ""),
            "url": _pca_value_text(raw.get("url")),
            "title": _pca_value_text(raw.get("title")),
            "target_path": "",
            "start_time": _firefox_timestamp(raw.get("date_added")),
            "end_time": _firefox_timestamp(raw.get("last_modified")),
            "total_bytes": "",
            "state": "",
            "annotation_names": [],
        })
        attr_name = _pca_value_text(raw.get("attr_name"))
        content = _pca_value_text(raw.get("content"))
        if attr_name:
            item["annotation_names"].append(attr_name)
        if attr_name.endswith("destinationFileURI"):
            item["target_path"] = _firefox_file_uri_to_path(content)
        elif attr_name.endswith("metaData"):
            metadata = _firefox_metadata(content)
            if metadata:
                if metadata.get("endTime"):
                    item["end_time"] = _firefox_timestamp(metadata.get("endTime"))
                if metadata.get("fileSize") is not None:
                    item["total_bytes"] = str(metadata.get("fileSize"))
                if metadata.get("state") is not None:
                    item["state"] = str(metadata.get("state"))
        elif attr_name.endswith("destinationFileName") and not item["target_path"]:
            item["target_path"] = content

    entries: list[dict[str, Any]] = []
    for place_id, item in grouped.items():
        if len(entries) >= max_rows:
            break
        if not item.get("url") and not item.get("target_path"):
            continue
        entries.append({
            "artifact_type": "Firefox Downloads",
            "kind": "download",
            "browser": "Firefox",
            "user": user,
            "profile": profile,
            "source_table": "moz_annos",
            "row_id": item.get("row_id", place_id),
            "url": item.get("url", ""),
            "title": item.get("title", ""),
            "target_path": item.get("target_path", ""),
            "current_path": "",
            "start_time": item.get("start_time"),
            "end_time": item.get("end_time"),
            "received_bytes": "",
            "total_bytes": item.get("total_bytes", ""),
            "state": item.get("state", ""),
            "danger_type": "",
            "fields": {
                "Annotation Names": ",".join(item.get("annotation_names", [])),
            },
        })
    return entries


def parse_firefox_places_db(
    db_path: str,
    *,
    user: str = "",
    profile: str = "",
    max_rows: int = _CHROMIUM_HISTORY_ROW_CAP,
) -> dict[str, Any]:
    """Parse Firefox places.sqlite visits and download annotations."""
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        entries.extend(_parse_firefox_visits(
            conn,
            user=user,
            profile=profile,
            max_rows=max_rows - len(entries),
        ))
        if len(entries) < max_rows:
            entries.extend(_parse_firefox_downloads(
                conn,
                user=user,
                profile=profile,
                max_rows=max_rows - len(entries),
            ))
    finally:
        conn.close()

    if len(entries) >= max_rows:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "browser_history_row_cap_reached",
            "error": f"stopped after {max_rows} Firefox places rows",
        })
    if not entries:
        coverage_gaps.append({
            "path": db_path,
            "status": "coverage_gap",
            "reason": "browser_history_supported_rows_absent",
            "error": "No supported Firefox visits/download rows were recovered.",
        })
    return {
        "ok": bool(entries),
        "status": "partial" if coverage_gaps and entries else (
            "not_evaluable" if coverage_gaps else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def _webcache_table_names(db: Any) -> list[str]:
    raw: Any = []
    try:
        tables = getattr(db, "tables")
        raw = tables() if callable(tables) else tables
    except Exception:
        raw = []
    names: list[str] = []
    for item in raw or []:
        name = getattr(item, "name", item)
        if name is not None:
            names.append(str(name))
    if not names:
        raw_attr = getattr(db, "_tables", None)
        if isinstance(raw_attr, dict):
            names.extend(str(k) for k in raw_attr)
    return list(dict.fromkeys(names))


def _webcache_table(db: Any, table_name: str) -> Any:
    table = getattr(db, "table", None)
    if callable(table):
        return table(table_name)
    tables = getattr(db, "_tables", None)
    if isinstance(tables, dict) and table_name in tables:
        return tables[table_name]
    raise KeyError(table_name)


def _webcache_records(table: Any):
    records = getattr(table, "records", None)
    return records() if callable(records) else iter(records or [])


def _webcache_container_map(db: Any) -> dict[str, str]:
    try:
        table = _webcache_table(db, "Containers")
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    try:
        for rec in _webcache_records(table):
            fields = dict(rec)
            cid = (
                fields.get("ContainerId")
                or fields.get("ContainerID")
                or fields.get("Id")
                or fields.get("ID")
            )
            name = (
                fields.get("Name")
                or fields.get("ContainerName")
                or fields.get("Directory")
                or fields.get("PartitionId")
            )
            if cid is not None and name is not None:
                mapping[str(cid)] = _pca_value_text(name)
    except Exception:
        return mapping
    return mapping


def _webcache_url(fields: dict[str, Any]) -> str:
    preferred = [
        key for key in fields
        if "url" in str(key).lower() or "uri" in str(key).lower()
    ]
    for key in [*preferred, *[k for k in fields if k not in preferred]]:
        text = _pca_value_text(fields.get(key))
        if not text:
            continue
        match = _WEBCACHE_URL_RE.search(text)
        if match:
            return match.group(0)
    return ""


def _webcache_path(fields: dict[str, Any]) -> str:
    preferred = [
        key for key in fields
        if any(hint in str(key).lower() for hint in (
            "file", "path", "filename", "cache", "local",
        ))
    ]
    for key in [*preferred, *[k for k in fields if k not in preferred]]:
        text = _pca_value_text(fields.get(key))
        if not text:
            continue
        if text.lower().startswith("file:"):
            return _firefox_file_uri_to_path(text)
        if _WEBCACHE_URL_RE.search(text):
            continue
        match = _PCA_WINDOWS_PATH_RE.search(text)
        if match:
            return match.group(0).strip()
    return ""


def _webcache_container_id(table_name: str) -> str:
    match = re.search(r"Container[_ ]?(\d+)", str(table_name), re.I)
    return match.group(1) if match else ""


def _webcache_artifact_type(container_name: str, target_path: str, url: str) -> str:
    haystack = f"{container_name} {target_path} {url}".lower()
    if "download" in haystack or "\\downloads\\" in haystack:
        return "IE/Edge WebCache Downloads"
    if target_path or "cache" in haystack or "content" in haystack:
        return "IE/Edge WebCache Cache"
    return "IE/Edge WebCache History"


def parse_webcache_esedb(
    db: Any,
    *,
    user: str = "",
    max_records: int = _WEBCACHE_ROW_CAP,
) -> dict[str, Any]:
    """Parse IE/Legacy Edge WebCacheV*.dat ESE records best-effort.

    WebCache table layouts vary by Windows/browser version. This parser walks
    Container_* tables, extracts URL/path/timestamp candidates, and classifies
    records as history/download/cache leads without claiming cache-content
    reconstruction or credential/session coverage.
    """
    coverage_gaps: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    containers = _webcache_container_map(db)
    scanned = 0
    supported_tables_seen = False
    capped = False
    for table_name in _webcache_table_names(db):
        if capped:
            break
        if not re.match(r"Container[_ ]?\d+", table_name, re.I):
            continue
        supported_tables_seen = True
        container_id = _webcache_container_id(table_name)
        container_name = containers.get(container_id, "")
        try:
            rec_iter = iter(_webcache_records(_webcache_table(db, table_name)))
        except Exception as exc:
            coverage_gaps.append({
                "path": table_name,
                "status": "coverage_gap",
                "reason": "webcache_table_unavailable",
                "error": str(exc),
            })
            continue
        while True:
            try:
                rec = next(rec_iter)
            except StopIteration:
                break
            except Exception as exc:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "webcache_record_iter_error",
                    "error": str(exc),
                })
                break
            if scanned >= max_records:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "webcache_record_cap_reached",
                    "error": f"more than {max_records} WebCache records; truncated",
                })
                capped = True
                break
            scanned += 1
            try:
                fields = dict(rec)
                url = _webcache_url(fields)
                target_path = _webcache_path(fields)
                ts_field, timestamp = _pca_extract_timestamp(fields)
                if not url and not target_path and not timestamp:
                    continue
                artifact_type = _webcache_artifact_type(
                    container_name, target_path, url)
                scalar_fields = {
                    str(key): _pca_value_text(value)
                    for key, value in fields.items()
                    if _pca_value_text(value)
                }
                entries.append({
                    "artifact_type": artifact_type,
                    "kind": "download" if artifact_type.endswith("Downloads")
                    else "cache" if artifact_type.endswith("Cache") else "visit",
                    "browser": "IE/Legacy Edge",
                    "user": user,
                    "source_table": table_name,
                    "container_id": container_id,
                    "container_name": container_name,
                    "row_id": str(fields.get("EntryId") or fields.get("Id") or scanned),
                    "url": url,
                    "target_path": target_path,
                    "timestamp_field": ts_field,
                    "timestamp": timestamp,
                    "fields": scalar_fields,
                })
            except Exception as exc:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "webcache_record_parse_error",
                    "error": str(exc),
                })
    if not supported_tables_seen:
        coverage_gaps.append({
            "path": "WebCacheV*.dat",
            "status": "coverage_gap",
            "reason": "webcache_supported_tables_absent",
            "error": "No Container_* tables were recognized in the ESE schema.",
        })
    ok = supported_tables_seen
    return {
        "ok": ok,
        "status": (
            "not_evaluable" if not ok
            else "partial" if coverage_gaps
            else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def _discover_chromium_profiles(
    image: Any,
    users_root: str,
    coverage_gaps: list[dict[str, Any]],
) -> list[dict[str, str]]:
    profiles: list[dict[str, str]] = []
    try:
        user_dirs = [
            e for e in (image.list_directory(users_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
    except Exception as exc:
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "browser_users_root_unavailable",
            "error": str(exc),
        })
        return profiles

    for user_entry in user_dirs:
        user_path = str(user_entry.get("path", "") or "")
        user = str(user_entry.get("name") or user_path.rsplit("/", 1)[-1])
        if not user_path:
            continue
        for browser_name, relative_root in _CHROMIUM_BROWSER_ROOTS:
            browser_root = f"{user_path}/{relative_root}"
            try:
                root_entries = image.list_directory(browser_root) or []
            except Exception:
                continue
            for entry in root_entries:
                if not entry.get("is_dir") or entry.get("error"):
                    continue
                profile_name = str(entry.get("name") or "")
                profile_path = str(entry.get("path", "") or "")
                if not profile_path:
                    continue
                if profile_name.lower() in ("default", "guest profile"):
                    pass
                elif not profile_name.lower().startswith("profile"):
                    continue
                profiles.append({
                    "browser": browser_name,
                    "parser": "chromium",
                    "user": user,
                    "profile": profile_name,
                    "profile_path": profile_path,
                })
    return profiles


def _discover_firefox_profiles(
    image: Any,
    users_root: str,
    coverage_gaps: list[dict[str, Any]],
) -> list[dict[str, str]]:
    profiles: list[dict[str, str]] = []
    try:
        user_dirs = [
            e for e in (image.list_directory(users_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
    except Exception as exc:
        if not any(g.get("reason") == "browser_users_root_unavailable"
                   for g in coverage_gaps):
            coverage_gaps.append({
                "path": users_root,
                "status": "coverage_gap",
                "reason": "browser_users_root_unavailable",
                "error": str(exc),
            })
        return profiles

    for user_entry in user_dirs:
        user_path = str(user_entry.get("path", "") or "")
        user = str(user_entry.get("name") or user_path.rsplit("/", 1)[-1])
        if not user_path:
            continue
        profiles_root = f"{user_path}/{_FIREFOX_PROFILES_REL}"
        try:
            root_entries = image.list_directory(profiles_root) or []
        except Exception:
            continue
        for entry in root_entries:
            if not entry.get("is_dir") or entry.get("error"):
                continue
            profile_name = str(entry.get("name") or "")
            profile_path = str(entry.get("path", "") or "")
            if not profile_path:
                continue
            profiles.append({
                "browser": "Firefox",
                "parser": "firefox",
                "user": user,
                "profile": profile_name,
                "profile_path": profile_path,
            })
    return profiles


def _discover_webcache_databases(
    image: Any,
    users_root: str,
    coverage_gaps: list[dict[str, Any]],
) -> list[dict[str, str]]:
    databases: list[dict[str, str]] = []
    try:
        user_dirs = [
            e for e in (image.list_directory(users_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
    except Exception as exc:
        if not any(g.get("reason") == "browser_users_root_unavailable"
                   for g in coverage_gaps):
            coverage_gaps.append({
                "path": users_root,
                "status": "coverage_gap",
                "reason": "browser_users_root_unavailable",
                "error": str(exc),
            })
        return databases

    for user_entry in user_dirs:
        user_path = str(user_entry.get("path", "") or "")
        user = str(user_entry.get("name") or user_path.rsplit("/", 1)[-1])
        if not user_path:
            continue
        webcache_root = f"{user_path}/{_WEBCACHE_REL}"
        try:
            root_entries = image.list_directory(webcache_root) or []
        except Exception:
            continue
        for entry in root_entries:
            if entry.get("is_dir") or entry.get("error"):
                continue
            name = str(entry.get("name") or "")
            path = str(entry.get("path") or "")
            if path and _WEBCACHE_DB_RE.match(name):
                databases.append({
                    "browser": "IE/Legacy Edge",
                    "user": user,
                    "database_name": name,
                    "database_path": path,
                })
    return databases


def _index_browser_cache_files(
    image: Any,
    store: RawIndexStore,
    *,
    run_id: int,
    profile: dict[str, str],
    coverage_gaps: list[dict[str, Any]],
    remaining_cap: int,
) -> int:
    indexed = 0
    for artifact_type, relative in _CHROMIUM_CACHE_DIRS:
        if indexed >= remaining_cap:
            break
        cache_dir = f"{profile['profile_path']}/{relative}"
        try:
            entries = image.list_directory(cache_dir) or []
        except Exception:
            continue
        for entry in entries:
            if indexed >= remaining_cap:
                coverage_gaps.append({
                    "path": cache_dir,
                    "status": "coverage_gap",
                    "reason": "browser_cache_file_cap_reached",
                    "error": f"stopped after {_BROWSER_CACHE_FILE_CAP} cache files",
                })
                return indexed
            if entry.get("is_dir") or entry.get("error"):
                continue
            path = str(entry.get("path", "") or "")
            name = str(entry.get("name") or path.rsplit("/", 1)[-1])
            if not path:
                continue
            store.insert_artifact(
                artifact_type=artifact_type,
                source_ref=cache_dir,
                source_path=path,
                primary_path=path,
                description=(
                    f"{artifact_type} | {profile['browser']} | "
                    f"{profile['user']} | {name}"
                )[:512],
                strings={
                    "Browser": profile["browser"],
                    "User": profile["user"],
                    "Profile": profile["profile"],
                    "File Name": name,
                    "Cache Directory": cache_dir,
                },
                times=_entry_times_from_listing(entry),
                parser_run_id=run_id,
            )
            indexed += 1
    return indexed


def index_browser_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    users_root: str = _USERS_ROOT,
    max_rows: int = _CHROMIUM_HISTORY_ROW_CAP,
    max_cache_files: int = _BROWSER_CACHE_FILE_CAP,
    webcache_ese_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Index Chromium and Firefox browser history/download artifacts."""
    run_id = store.start_parser_run("browser_indexer", users_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    cache_indexed = 0
    histories_seen = 0
    webcache_dbs_seen = 0
    profiles = [
        *_discover_chromium_profiles(image, users_root, coverage_gaps),
        *_discover_firefox_profiles(image, users_root, coverage_gaps),
    ]
    webcache_databases = _discover_webcache_databases(
        image, users_root, coverage_gaps)
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_browser_") as tmp:
        _write_do_not_execute_marker(tmp)
        for idx, profile in enumerate(profiles):
            if profile.get("parser") == "firefox":
                internal = f"{profile['profile_path']}/{_FIREFOX_PLACES_NAME}"
                local = os.path.join(tmp, f"places_{idx}.sqlite")
                parser = parse_firefox_places_db
                parser_kwargs = {
                    "user": profile["user"],
                    "profile": profile["profile"],
                    "max_rows": max_rows,
                }
            else:
                internal = f"{profile['profile_path']}/{_CHROMIUM_HISTORY_NAME}"
                local = os.path.join(tmp, f"History_{idx}.sqlite")
                parser = parse_chromium_history_db
                parser_kwargs = {
                    "browser_name": profile["browser"],
                    "user": profile["user"],
                    "profile": profile["profile"],
                    "max_rows": max_rows,
                }
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                parsed = parser(local, **parser_kwargs)
                histories_seen += 1
                coverage_gaps.extend(parsed.get("coverage_gaps", []))
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "browser_history_unavailable_or_parse_failed",
                    "error": str(exc),
                })
                parsed = {"entries": []}

            for entry in parsed.get("entries", []):
                if entry.get("kind") == "visit":
                    times = (
                        {"Visit Time": entry["visit_time"]}
                        if entry.get("visit_time") else {}
                    )
                    primary = str(entry.get("url") or internal)
                    fields = {
                        "Browser": profile["browser"],
                        "User": profile["user"],
                        "Profile": profile["profile"],
                        "URL": str(entry.get("url") or ""),
                        "Title": str(entry.get("title") or ""),
                        "Visit Count": str(entry.get("visit_count") or ""),
                        "Typed Count": str(entry.get("typed_count") or ""),
                        "Transition": str(entry.get("transition") or ""),
                        "Source Table": str(entry.get("source_table") or ""),
                        "Row ID": str(entry.get("row_id") or ""),
                    }
                    desc = (
                        f"{entry['artifact_type']} | {profile['user']} | "
                        f"{entry.get('url', '')}"
                    )
                else:
                    times = {}
                    if entry.get("start_time"):
                        times["Start Time"] = entry["start_time"]
                    if entry.get("end_time"):
                        times["End Time"] = entry["end_time"]
                    primary = str(
                        entry.get("target_path")
                        or entry.get("current_path")
                        or entry.get("url")
                        or internal
                    )
                    fields = {
                        "Browser": profile["browser"],
                        "User": profile["user"],
                        "Profile": profile["profile"],
                        "URL": str(entry.get("url") or ""),
                        "Target Path": str(entry.get("target_path") or ""),
                        "Current Path": str(entry.get("current_path") or ""),
                        "Received Bytes": str(entry.get("received_bytes") or ""),
                        "Total Bytes": str(entry.get("total_bytes") or ""),
                        "State": str(entry.get("state") or ""),
                        "Danger Type": str(entry.get("danger_type") or ""),
                        "Source Table": str(entry.get("source_table") or ""),
                        "Row ID": str(entry.get("row_id") or ""),
                    }
                    desc = (
                        f"{entry['artifact_type']} | {profile['user']} | "
                        f"{primary} | {entry.get('url', '')}"
                    )
                store.insert_artifact(
                    artifact_type=str(entry["artifact_type"]),
                    source_ref=internal,
                    source_path=internal,
                    primary_path=primary,
                    description=desc[:512],
                    strings=fields,
                    times=times,
                    parser_run_id=run_id,
                )
                indexed += 1
            if profile.get("parser") == "chromium" and cache_indexed < max_cache_files:
                added_cache = _index_browser_cache_files(
                    image,
                    store,
                    run_id=run_id,
                    profile=profile,
                    coverage_gaps=coverage_gaps,
                    remaining_cap=max_cache_files - cache_indexed,
                )
                cache_indexed += added_cache
                indexed += added_cache

        for idx, source in enumerate(webcache_databases):
            internal = source["database_path"]
            local = os.path.join(tmp, f"WebCache_{idx}.dat")
            fh = None
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                if webcache_ese_factory is None:
                    from dissect.esedb import EseDB

                    webcache_ese_factory = EseDB
                fh = open(local, "rb")
                parsed = parse_webcache_esedb(
                    webcache_ese_factory(fh),
                    user=source["user"],
                    max_records=max_rows,
                )
                webcache_dbs_seen += 1
                coverage_gaps.extend(parsed.get("coverage_gaps", []))
            except Exception as exc:
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "webcache_unavailable_or_parse_failed",
                    "error": str(exc),
                })
                parsed = {"entries": []}
            finally:
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass

            for entry in parsed.get("entries", []):
                times = {}
                if entry.get("timestamp"):
                    times["Timestamp"] = entry["timestamp"]
                primary = str(
                    entry.get("target_path")
                    or entry.get("url")
                    or internal
                )
                fields = {
                    "Browser": "IE/Legacy Edge",
                    "User": source["user"],
                    "Database": source["database_name"],
                    "URL": str(entry.get("url") or ""),
                    "Target Path": str(entry.get("target_path") or ""),
                    "Container ID": str(entry.get("container_id") or ""),
                    "Container Name": str(entry.get("container_name") or ""),
                    "Source Table": str(entry.get("source_table") or ""),
                    "Row ID": str(entry.get("row_id") or ""),
                    "Timestamp Field": str(entry.get("timestamp_field") or ""),
                }
                for key, value in list((entry.get("fields") or {}).items())[:12]:
                    if key not in fields:
                        fields[f"WebCache {key}"] = str(value)
                store.insert_artifact(
                    artifact_type=str(entry.get("artifact_type") or ""),
                    source_ref=internal,
                    source_path=(
                        f"{internal}:{entry.get('source_table', '')}"
                    ),
                    primary_path=primary,
                    description=(
                        f"{entry.get('artifact_type', '')} | {source['user']} | "
                        f"{primary} | {entry.get('url', '')}"
                    )[:512],
                    strings={k: v for k, v in fields.items() if v},
                    times=times,
                    parser_run_id=run_id,
                )
                indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not profiles and not webcache_databases:
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
        "ok": bool(profiles or webcache_databases),
        "status": status,
        "indexed_records": indexed,
        "profiles_seen": len(profiles),
        "histories_seen": histories_seen,
        "webcache_dbs_seen": webcache_dbs_seen,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── NTFS USN Journal $J ────────────────────────────────────────────────────

_USN_JOURNAL_PATH = "/c:/$Extend/$UsnJrnl:$J"
_USN_RECORD_CAP = 100000
_USN_READ_CAP_BYTES = 64 * 1024 * 1024
_USN_MFT_PATH_MAP_CAP = 1000000
_USN_RENAME_PAIR_WINDOW_MS = 5 * 60 * 1000
_USN_RENAME_PAIR_USN_DELTA = 1024
_USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def _usn_reason_names(reason: int) -> list[str]:
    return [
        name for bit, name in _USN_REASON_FLAGS.items()
        if int(reason or 0) & bit
    ] or ["UNKNOWN"]


def _usn_file_reference(raw: bytes) -> str:
    if len(raw) == 8:
        return str(int.from_bytes(raw, "little", signed=False))
    return raw[::-1].hex()


def _usn_reference_segment(ref: Any) -> int | None:
    value = str(ref or "").strip()
    if not value:
        return None
    try:
        number = int(value, 10)
    except ValueError:
        try:
            number = int(value, 16)
        except ValueError:
            return None
    return number & 0x0000FFFFFFFFFFFF


def _usn_reference_sequence(ref: Any) -> int | None:
    value = str(ref or "").strip()
    if not value:
        return None
    try:
        number = int(value, 10)
    except ValueError:
        try:
            number = int(value, 16)
        except ValueError:
            return None
    if number < 0 or number > 0xFFFFFFFFFFFFFFFF:
        return None
    sequence = (number >> 48) & 0xFFFF
    return sequence if sequence else None


def _mft_path_map_entry(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        out = dict(value)
        out["path"] = str(out.get("path") or "")
        try:
            out["sequence"] = int(out["sequence"]) if out.get("sequence") not in (None, "") else None
        except (TypeError, ValueError):
            out["sequence"] = None
        return out
    return {"path": str(value or ""), "sequence": None}


def _sequence_confidence(usn_sequence: int | None, mft_sequence: int | None) -> tuple[str, bool | None]:
    if usn_sequence is None or mft_sequence is None:
        return "candidate", None
    if int(usn_sequence) == int(mft_sequence):
        return "sequence_verified", True
    return "sequence_mismatch_candidate", False


def _join_internal_parent_path(parent_path: str, file_name: str) -> str:
    parent = str(parent_path or "").rstrip("\\/")
    name = str(file_name or "").strip("\\/")
    if not parent:
        return name
    if not name:
        return parent
    sep = "\\" if "\\" in parent and "/" not in parent else "/"
    return f"{parent}{sep}{name}"


def _parse_usn_record_at(raw: bytes, offset: int) -> dict[str, Any] | None:
    if offset + 8 > len(raw):
        return None
    record_len = int.from_bytes(raw[offset:offset + 4], "little", signed=False)
    major = int.from_bytes(raw[offset + 4:offset + 6], "little", signed=False)
    minor = int.from_bytes(raw[offset + 6:offset + 8], "little", signed=False)
    if record_len < 60 or record_len > 1024 * 1024:
        return None
    if offset + record_len > len(raw):
        return None
    rec = raw[offset:offset + record_len]
    if major == 2:
        header_len = 60
        file_ref = _usn_file_reference(rec[8:16])
        parent_ref = _usn_file_reference(rec[16:24])
        usn_value = int.from_bytes(rec[24:32], "little", signed=True)
        timestamp = _filetime_to_ms(rec[32:40])
        reason = int.from_bytes(rec[40:44], "little", signed=False)
        source_info = int.from_bytes(rec[44:48], "little", signed=False)
        security_id = int.from_bytes(rec[48:52], "little", signed=False)
        file_attributes = int.from_bytes(rec[52:56], "little", signed=False)
        name_len = int.from_bytes(rec[56:58], "little", signed=False)
        name_offset = int.from_bytes(rec[58:60], "little", signed=False)
    elif major == 3:
        header_len = 76
        if record_len < header_len:
            return None
        file_ref = _usn_file_reference(rec[8:24])
        parent_ref = _usn_file_reference(rec[24:40])
        usn_value = int.from_bytes(rec[40:48], "little", signed=True)
        timestamp = _filetime_to_ms(rec[48:56])
        reason = int.from_bytes(rec[56:60], "little", signed=False)
        source_info = int.from_bytes(rec[60:64], "little", signed=False)
        security_id = int.from_bytes(rec[64:68], "little", signed=False)
        file_attributes = int.from_bytes(rec[68:72], "little", signed=False)
        name_len = int.from_bytes(rec[72:74], "little", signed=False)
        name_offset = int.from_bytes(rec[74:76], "little", signed=False)
    else:
        return None
    if name_offset < header_len or name_len <= 0 or name_offset + name_len > record_len:
        return None
    try:
        file_name = rec[name_offset:name_offset + name_len].decode(
            "utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None
    if not file_name:
        return None
    reason_names = _usn_reason_names(reason)
    return {
        "artifact_type": "USN Journal Entries",
        "offset": offset,
        "record_length": record_len,
        "major_version": major,
        "minor_version": minor,
        "file_reference_number": file_ref,
        "parent_file_reference_number": parent_ref,
        "usn": usn_value,
        "timestamp": timestamp,
        "reason": reason,
        "reason_names": reason_names,
        "reason_text": "|".join(reason_names),
        "source_info": source_info,
        "security_id": security_id,
        "file_attributes": file_attributes,
        "file_name": file_name,
    }


def parse_usn_journal_records(
    raw: bytes,
    *,
    max_records: int = _USN_RECORD_CAP,
) -> dict[str, Any]:
    """Parse NTFS USN_RECORD_V2/V3 entries from a $UsnJrnl:$J byte stream."""
    data = bytes(raw or b"")
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    offset = 0
    while offset + 8 <= len(data):
        if len(entries) >= max_records:
            coverage_gaps.append({
                "path": "$UsnJrnl:$J",
                "status": "coverage_gap",
                "reason": "usn_record_cap_reached",
                "error": f"stopped after {max_records} USN records",
            })
            break
        parsed = _parse_usn_record_at(data, offset)
        if parsed:
            entries.append(parsed)
            offset += max(1, parsed["record_length"])
            continue
        offset += 1
    if not entries:
        coverage_gaps.append({
            "path": "$UsnJrnl:$J",
            "status": "coverage_gap",
            "reason": "usn_records_absent_or_unrecognized",
            "error": "No USN_RECORD_V2/V3 entries were recognized.",
        })
    return {
        "ok": bool(entries),
        "status": "partial" if coverage_gaps and entries else (
            "not_evaluable" if coverage_gaps else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def enrich_usn_entries_with_mft_paths(
    entries: list[dict[str, Any]],
    paths_by_segment: dict[int, Any],
) -> dict[str, Any]:
    """Attach best-effort full-path candidates to USN entries from MFT paths."""
    enriched: list[dict[str, Any]] = []
    reconstructed = 0
    parent_hits = 0
    file_hits = 0
    sequence_verified = 0
    sequence_mismatch = 0
    coverage_gaps: list[dict[str, Any]] = []

    for entry in entries:
        item = dict(entry)
        file_segment = _usn_reference_segment(item.get("file_reference_number"))
        parent_segment = _usn_reference_segment(item.get("parent_file_reference_number"))
        file_info = _mft_path_map_entry(paths_by_segment.get(file_segment)) if file_segment is not None else {}
        parent_info = _mft_path_map_entry(paths_by_segment.get(parent_segment)) if parent_segment is not None else {}
        file_path = str(file_info.get("path") or "")
        parent_path = str(parent_info.get("path") or "")
        if parent_path:
            parent_hits += 1
            item["parent_path_candidate"] = parent_path
            item["path_candidate"] = _join_internal_parent_path(
                parent_path, str(item.get("file_name") or ""))
            item["path_reconstruction_method"] = "mft_parent_frn_map"
            confidence, verified = _sequence_confidence(
                _usn_reference_sequence(item.get("parent_file_reference_number")),
                parent_info.get("sequence"),
            )
            item["path_reconstruction_confidence"] = confidence
            item["parent_sequence_verified"] = verified
            if verified is True:
                sequence_verified += 1
            elif verified is False:
                sequence_mismatch += 1
            reconstructed += 1
        elif file_path:
            file_hits += 1
            item["path_candidate"] = file_path
            item["path_reconstruction_method"] = "mft_file_frn_map"
            confidence, verified = _sequence_confidence(
                _usn_reference_sequence(item.get("file_reference_number")),
                file_info.get("sequence"),
            )
            item["path_reconstruction_confidence"] = confidence
            item["file_sequence_verified"] = verified
            if verified is True:
                sequence_verified += 1
            elif verified is False:
                sequence_mismatch += 1
            reconstructed += 1
        enriched.append(item)

    if entries and not paths_by_segment:
        coverage_gaps.append({
            "path": "$UsnJrnl:$J",
            "status": "coverage_gap",
            "reason": "usn_mft_path_map_unavailable",
            "error": (
                "No File System Entry MFT Segment map was available; "
                "USN full-path candidates were not reconstructed."
            ),
        })
    return {
        "entries": enriched,
        "reconstructed_paths": reconstructed,
        "parent_frn_hits": parent_hits,
        "file_frn_hits": file_hits,
        "sequence_verified_paths": sequence_verified,
        "sequence_mismatch_paths": sequence_mismatch,
        "coverage_gaps": coverage_gaps,
        "method": "mft_parent_frn_map",
    }


def build_mft_frn_path_map(
    store: RawIndexStore,
    *,
    max_entries: int = _USN_MFT_PATH_MAP_CAP,
) -> dict[str, Any]:
    """Build a best-effort MFT segment -> path map from raw File System Entry artifacts."""
    coverage_gaps: list[dict[str, Any]] = []
    paths_by_segment: dict[int, str] = {}
    try:
        conn = store._conn()
        rows = conn.execute(
            """
            SELECT
                a.artifact_id,
                COALESCE(
                    MAX(CASE WHEN s.field_name = 'MFT Segment' THEN s.value END),
                    ''
                ) AS segment,
                COALESCE(
                    MAX(CASE WHEN s.field_name = 'Path' THEN s.value END),
                    a.primary_path,
                    ''
                ) AS path,
                COALESCE(
                    MAX(CASE WHEN s.field_name = 'MFT Sequence Number' THEN s.value END),
                    ''
                ) AS sequence
            FROM raw_index_artifacts a
            LEFT JOIN raw_index_artifact_strings s
                ON s.artifact_id = a.artifact_id
            WHERE a.artifact_type = 'File System Entry'
            GROUP BY a.artifact_id
            HAVING segment != ''
            ORDER BY a.artifact_id
            LIMIT ?
            """,
            (int(max_entries) + 1,),
        ).fetchall()
    except Exception as exc:
        return {
            "paths_by_segment": {},
            "entries_seen": 0,
            "coverage_gaps": [{
                "path": "$MFT/File System Entry",
                "status": "coverage_gap",
                "reason": "usn_mft_path_map_query_failed",
                "error": str(exc),
            }],
        }

    capped = len(rows) > max_entries
    for row in rows[:max_entries]:
        try:
            segment = int(str(row["segment"]), 10)
        except (TypeError, ValueError):
            continue
        path = str(row["path"] or "")
        if path and segment not in paths_by_segment:
            try:
                sequence = int(str(row["sequence"]), 10) if row["sequence"] not in (None, "") else None
            except (TypeError, ValueError):
                sequence = None
            paths_by_segment[segment] = {"path": path, "sequence": sequence}
    if capped:
        coverage_gaps.append({
            "path": "$MFT/File System Entry",
            "status": "coverage_gap",
            "reason": "usn_mft_path_map_cap_reached",
            "error": f"used first {max_entries} MFT segment/path entries",
        })
    return {
        "paths_by_segment": paths_by_segment,
        "entries_seen": min(len(rows), max_entries),
        "coverage_gaps": coverage_gaps,
    }


def _usn_entry_time_ms(entry: dict[str, Any]) -> int | None:
    ts = entry.get("timestamp")
    if isinstance(ts, (tuple, list)) and ts:
        try:
            return int(ts[0])
        except (TypeError, ValueError):
            return None
    return None


def _usn_entry_sort_key(entry: dict[str, Any]) -> tuple[int, int, int]:
    time_ms = _usn_entry_time_ms(entry)
    try:
        usn = int(entry.get("usn") or 0)
    except (TypeError, ValueError):
        usn = 0
    try:
        offset = int(entry.get("offset") or 0)
    except (TypeError, ValueError):
        offset = 0
    return (time_ms if time_ms is not None else 0, usn, offset)


def _usn_has_reason(entry: dict[str, Any], reason_name: str) -> bool:
    return str(reason_name) in set(str(v) for v in (entry.get("reason_names") or []))


def build_usn_rename_transitions(
    entries: list[dict[str, Any]],
    *,
    max_time_delta_ms: int = _USN_RENAME_PAIR_WINDOW_MS,
    max_usn_delta: int = _USN_RENAME_PAIR_USN_DELTA,
) -> dict[str, Any]:
    """Pair USN RENAME_OLD_NAME and RENAME_NEW_NAME records into candidates."""
    pending_old_by_ref: dict[str, list[dict[str, Any]]] = {}
    transitions: list[dict[str, Any]] = []
    unpaired_new = 0

    for entry in sorted(entries, key=_usn_entry_sort_key):
        file_ref = str(entry.get("file_reference_number") or "")
        if not file_ref:
            continue
        if _usn_has_reason(entry, "RENAME_OLD_NAME"):
            pending_old_by_ref.setdefault(file_ref, []).append(entry)
            continue
        if not _usn_has_reason(entry, "RENAME_NEW_NAME"):
            continue

        pending = pending_old_by_ref.get(file_ref) or []
        new_time = _usn_entry_time_ms(entry)
        try:
            new_usn = int(entry.get("usn") or 0)
        except (TypeError, ValueError):
            new_usn = 0
        pair_index: int | None = None
        pair: dict[str, Any] | None = None
        for idx in range(len(pending) - 1, -1, -1):
            old = pending[idx]
            old_time = _usn_entry_time_ms(old)
            try:
                old_usn = int(old.get("usn") or 0)
            except (TypeError, ValueError):
                old_usn = 0
            if old_usn and new_usn and new_usn < old_usn:
                continue
            usn_delta = new_usn - old_usn if old_usn and new_usn else 0
            if old_usn and new_usn and usn_delta > max_usn_delta:
                continue
            time_delta = (
                new_time - old_time
                if old_time is not None and new_time is not None
                else None
            )
            if time_delta is not None and (time_delta < 0 or time_delta > max_time_delta_ms):
                continue
            pair_index = idx
            pair = old
            break
        if pair is None or pair_index is None:
            unpaired_new += 1
            continue
        old = pending.pop(pair_index)
        old_time = _usn_entry_time_ms(old)
        time_delta = (
            new_time - old_time
            if old_time is not None and new_time is not None
            else None
        )
        try:
            old_usn = int(old.get("usn") or 0)
        except (TypeError, ValueError):
            old_usn = 0
        usn_delta = new_usn - old_usn if old_usn and new_usn else 0
        transitions.append({
            "artifact_type": "USN Rename Transitions",
            "file_reference_number": file_ref,
            "parent_file_reference_number": str(
                entry.get("parent_file_reference_number") or
                old.get("parent_file_reference_number") or ""),
            "old_name": str(old.get("file_name") or ""),
            "new_name": str(entry.get("file_name") or ""),
            "old_path_candidate": str(old.get("path_candidate") or ""),
            "new_path_candidate": str(entry.get("path_candidate") or ""),
            "old_path_confidence": str(old.get("path_reconstruction_confidence") or ""),
            "new_path_confidence": str(entry.get("path_reconstruction_confidence") or ""),
            "old_usn": old_usn,
            "new_usn": new_usn,
            "usn_delta": usn_delta,
            "old_timestamp": old.get("timestamp"),
            "new_timestamp": entry.get("timestamp"),
            "time_delta_ms": time_delta,
            "old_record_offset": old.get("offset"),
            "new_record_offset": entry.get("offset"),
            "pairing_method": "same_frn_usn_time_window",
        })

    unpaired_old = sum(len(values) for values in pending_old_by_ref.values())
    return {
        "transitions": transitions,
        "transition_count": len(transitions),
        "unpaired_old_count": unpaired_old,
        "unpaired_new_count": unpaired_new,
        "pairing_method": "same_frn_usn_time_window",
    }


def index_usn_journal_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    journal_path: str = _USN_JOURNAL_PATH,
    read_cap_bytes: int = _USN_READ_CAP_BYTES,
    max_records: int = _USN_RECORD_CAP,
) -> dict[str, Any]:
    """Index NTFS $UsnJrnl:$J USN_RECORD_V2/V3 file-change records."""
    run_id = store.start_parser_run("usn_journal_indexer", journal_path,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False
    path_reconstruction: dict[str, Any] = {
        "method": "mft_parent_frn_map",
        "mft_entries_seen": 0,
        "reconstructed_paths": 0,
        "parent_frn_hits": 0,
        "file_frn_hits": 0,
        "sequence_verified_paths": 0,
        "sequence_mismatch_paths": 0,
        "coverage_gaps": [],
    }
    rename_transitions: dict[str, Any] = {
        "transitions": [],
        "transition_count": 0,
        "unpaired_old_count": 0,
        "unpaired_new_count": 0,
        "pairing_method": "same_frn_usn_time_window",
    }
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_usn_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "UsnJrnl_J.bin")
        try:
            extracted = image.extract_file(journal_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            with open(local, "rb") as fh:
                raw = fh.read(read_cap_bytes + 1)
            if len(raw) > read_cap_bytes:
                coverage_gaps.append({
                    "path": journal_path,
                    "status": "coverage_gap",
                    "reason": "usn_read_cap_reached",
                    "error": f"read only first {read_cap_bytes} bytes of $J stream",
                })
                raw = raw[:read_cap_bytes]
            parsed = parse_usn_journal_records(raw, max_records=max_records)
            parsed_ok = bool(parsed.get("ok"))
            coverage_gaps.extend(parsed.get("coverage_gaps") or [])
            mft_map = build_mft_frn_path_map(store)
            enriched = enrich_usn_entries_with_mft_paths(
                list(parsed.get("entries") or []),
                dict(mft_map.get("paths_by_segment") or {}),
            )
            parsed["entries"] = enriched.get("entries") or []
            path_reconstruction = {
                "method": str(enriched.get("method") or "mft_parent_frn_map"),
                "mft_entries_seen": int(mft_map.get("entries_seen") or 0),
                "reconstructed_paths": int(enriched.get("reconstructed_paths") or 0),
                "parent_frn_hits": int(enriched.get("parent_frn_hits") or 0),
                "file_frn_hits": int(enriched.get("file_frn_hits") or 0),
                "sequence_verified_paths": int(
                    enriched.get("sequence_verified_paths") or 0),
                "sequence_mismatch_paths": int(
                    enriched.get("sequence_mismatch_paths") or 0),
                "coverage_gaps": (
                    list(mft_map.get("coverage_gaps") or []) +
                    list(enriched.get("coverage_gaps") or [])
                ),
            }
            rename_transitions = build_usn_rename_transitions(
                list(parsed.get("entries") or []))
        except Exception as exc:
            coverage_gaps.append({
                "path": journal_path,
                "status": "coverage_gap",
                "reason": "usn_journal_unavailable_or_parse_failed",
                "error": str(exc),
            })
            parsed = {"entries": []}

        for entry in parsed.get("entries", []):
            times = {}
            if entry.get("timestamp"):
                times["Event Time"] = entry["timestamp"]
            fields = {
                "File Name": str(entry.get("file_name") or ""),
                "Reason": str(entry.get("reason_text") or ""),
                "Reason Hex": f"0x{int(entry.get('reason') or 0):08x}",
                "File Reference Number": str(entry.get("file_reference_number") or ""),
                "Parent File Reference Number": str(
                    entry.get("parent_file_reference_number") or ""),
                "Path Candidate": str(entry.get("path_candidate") or ""),
                "Parent Path Candidate": str(entry.get("parent_path_candidate") or ""),
                "Path Reconstruction": str(entry.get("path_reconstruction_method") or ""),
                "Path Reconstruction Confidence": str(
                    entry.get("path_reconstruction_confidence") or ""),
                "USN": str(entry.get("usn") or ""),
                "Record Offset": str(entry.get("offset") or 0),
                "Major Version": str(entry.get("major_version") or ""),
                "Minor Version": str(entry.get("minor_version") or ""),
                "Source Info": str(entry.get("source_info") or ""),
                "Security ID": str(entry.get("security_id") or ""),
                "File Attributes": f"0x{int(entry.get('file_attributes') or 0):08x}",
            }
            store.insert_artifact(
                artifact_type="USN Journal Entries",
                source_ref=journal_path,
                source_path=f"{journal_path}:offset:{entry.get('offset', 0)}",
                primary_path=str(
                    entry.get("path_candidate") or entry.get("file_name") or journal_path),
                description=(
                    f"USN Journal Entries | {entry.get('reason_text', '')} | "
                    f"{entry.get('path_candidate') or entry.get('file_name', '')}"
                )[:512],
                strings={k: v for k, v in fields.items() if v},
                times=times,
                parser_run_id=run_id,
            )
            indexed += 1

        for transition in rename_transitions.get("transitions", []) or []:
            times = {}
            if transition.get("old_timestamp"):
                times["Old Name Time"] = transition["old_timestamp"]
            if transition.get("new_timestamp"):
                times["New Name Time"] = transition["new_timestamp"]
            fields = {
                "Old Name": str(transition.get("old_name") or ""),
                "New Name": str(transition.get("new_name") or ""),
                "Old Path Candidate": str(transition.get("old_path_candidate") or ""),
                "New Path Candidate": str(transition.get("new_path_candidate") or ""),
                "Old Path Confidence": str(transition.get("old_path_confidence") or ""),
                "New Path Confidence": str(transition.get("new_path_confidence") or ""),
                "File Reference Number": str(transition.get("file_reference_number") or ""),
                "Parent File Reference Number": str(
                    transition.get("parent_file_reference_number") or ""),
                "Old USN": str(transition.get("old_usn") or ""),
                "New USN": str(transition.get("new_usn") or ""),
                "USN Delta": str(transition.get("usn_delta") or 0),
                "Time Delta MS": str(transition.get("time_delta_ms") or ""),
                "Old Record Offset": str(transition.get("old_record_offset") or 0),
                "New Record Offset": str(transition.get("new_record_offset") or 0),
                "Pairing Method": str(transition.get("pairing_method") or ""),
            }
            primary = (
                transition.get("new_path_candidate") or
                transition.get("new_name") or
                journal_path
            )
            store.insert_artifact(
                artifact_type="USN Rename Transitions",
                source_ref=journal_path,
                source_path=(
                    f"{journal_path}:rename:{transition.get('old_record_offset', 0)}:"
                    f"{transition.get('new_record_offset', 0)}"
                ),
                primary_path=str(primary),
                description=(
                    "USN Rename Transitions | "
                    f"{transition.get('old_name', '')} -> "
                    f"{transition.get('new_name', '')}"
                )[:512],
                strings={k: v for k, v in fields.items() if v},
                times=times,
                parser_run_id=run_id,
            )

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not parsed_ok:
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
        "path_reconstruction": path_reconstruction,
        "rename_transitions": {
            "transition_count": int(rename_transitions.get("transition_count") or 0),
            "unpaired_old_count": int(rename_transitions.get("unpaired_old_count") or 0),
            "unpaired_new_count": int(rename_transitions.get("unpaired_new_count") or 0),
            "pairing_method": str(rename_transitions.get("pairing_method") or ""),
        },
    }


# ── NTFS $LogFile RSTR/RCRD page candidates ─────────────────────────────────

_LOGFILE_PATH = "/c:/$LogFile"
_LOGFILE_PAGE_SIZE = 4096
_LOGFILE_PAGE_CAP = 20000
_LOGFILE_READ_CAP_BYTES = 64 * 1024 * 1024
_LOGFILE_OPERATION_TERMS = (
    "DeleteFile",
    "Rename",
    "Create",
    "Write",
    "Truncate",
    "SetEndOfFile",
    "AddIndexEntry",
    "DeleteIndexEntry",
    "CreateAttribute",
    "DeleteAttribute",
    "InitializeFileRecordSegment",
    "DeallocateFileRecordSegment",
)
_LOGFILE_INTERESTING_NAME_RE = re.compile(
    r"(?i)(?:\.[a-z0-9]{1,8}$|delete|rename|create|write|index|attribute|record|segment)"
)


def _logfile_ascii_strings(raw: bytes, *, min_len: int = 4) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    pattern = rb"[\x20-\x7e]{%d,}" % int(max(1, min_len))
    for match in re.finditer(pattern, bytes(raw or b"")):
        value = match.group(0).decode("ascii", errors="ignore").strip()
        if value and value not in seen:
            seen.add(value)
            strings.append(value)
    return strings


def _logfile_utf16_strings(raw: bytes, *, min_len: int = 4) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    data = bytes(raw or b"")
    for start in (0, 1):
        try:
            text = data[start:].decode("utf-16-le", errors="ignore")
        except Exception:
            continue
        for match in _TASKCACHE_ACTION_STRING_RE.finditer(text.replace("\x00", "\n")):
            value = match.group(0).strip()
            if len(value) < min_len or value in seen:
                continue
            seen.add(value)
            strings.append(value)
    return strings


def _logfile_candidate_windows_paths(raw: bytes) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = str(value or "").strip().strip("\x00")
        if value and value not in seen:
            seen.add(value)
            merged.append(value)

    for value in _candidate_windows_paths_from_bytes(raw):
        add(value)
    for text in _logfile_utf16_strings(raw) + _logfile_ascii_strings(raw):
        for match in _PCA_WINDOWS_PATH_RE.finditer(text.replace("\\\\", "\\")):
            add(match.group(0))
    return merged


def _logfile_candidate_names(raw: bytes, candidate_paths: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = str(value or "").strip().strip("\x00")
        if not value or len(value) > 260 or value in seen:
            return
        seen.add(value)
        names.append(value)

    for path in candidate_paths:
        add(_path_basename(path))

    for value in _logfile_utf16_strings(raw) + _logfile_ascii_strings(raw):
        value = value.strip()
        basename = _path_basename(value)
        if _LOGFILE_INTERESTING_NAME_RE.search(value):
            add(basename or value)

    return names[:25]


def _logfile_operation_hints(
    raw: bytes,
    *,
    candidate_paths: list[str],
    candidate_names: list[str],
) -> list[str]:
    text = "\n".join(_logfile_ascii_strings(raw) + _logfile_utf16_strings(raw))
    hints: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            hints.append(value)

    for term in _LOGFILE_OPERATION_TERMS:
        if re.search(re.escape(term), text, re.I):
            add(term)
    if not hints:
        if candidate_paths:
            add("path_candidate")
        if candidate_names:
            add("name_candidate")
    return hints


def parse_logfile_records(
    raw: bytes,
    *,
    page_size: int = _LOGFILE_PAGE_SIZE,
    max_pages: int = _LOGFILE_PAGE_CAP,
) -> dict[str, Any]:
    """Extract page-level RSTR/RCRD candidates from NTFS $LogFile bytes.

    This is intentionally not a redo/undo transaction replay parser. It records
    page signatures and embedded path/name/operation strings so the raw timeline
    has filesystem-transaction anchors without overstating semantics.
    """
    data = bytes(raw or b"")
    entries: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    page_size = max(512, int(page_size or _LOGFILE_PAGE_SIZE))
    pages_seen = 0

    for offset in range(0, len(data), page_size):
        if pages_seen >= max_pages:
            coverage_gaps.append({
                "path": "$LogFile",
                "status": "coverage_gap",
                "reason": "logfile_page_cap_reached",
                "error": f"stopped after {max_pages} $LogFile pages",
            })
            break
        page = data[offset:offset + page_size]
        if len(page) < 4:
            continue
        signature = page[:4]
        if signature not in (b"RSTR", b"RCRD"):
            continue
        pages_seen += 1
        signature_text = signature.decode("ascii", errors="replace")
        candidate_paths = _logfile_candidate_windows_paths(page)[:25]
        candidate_names = _logfile_candidate_names(page, candidate_paths)
        operation_hints = _logfile_operation_hints(
            page,
            candidate_paths=candidate_paths,
            candidate_names=candidate_names,
        )
        strings = (_logfile_ascii_strings(page) + _logfile_utf16_strings(page))[:25]
        artifact_type = (
            "NTFS LogFile Restart Areas"
            if signature == b"RSTR"
            else "NTFS LogFile Operation Candidates"
        )
        entries.append({
            "artifact_type": artifact_type,
            "page_offset": offset,
            "page_signature": signature_text,
            "candidate_paths": candidate_paths,
            "candidate_names": candidate_names,
            "operation_hints": operation_hints,
            "string_candidates": strings,
            "parser_scope": "page_candidate_no_replay",
        })

    if not entries:
        coverage_gaps.append({
            "path": "$LogFile",
            "status": "coverage_gap",
            "reason": "logfile_pages_absent_or_unrecognized",
            "error": "No RSTR/RCRD $LogFile pages were recognized.",
        })
    return {
        "ok": bool(entries),
        "status": "partial" if coverage_gaps and entries else (
            "not_evaluable" if coverage_gaps else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def index_logfile_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    logfile_path: str = _LOGFILE_PATH,
    read_cap_bytes: int = _LOGFILE_READ_CAP_BYTES,
    max_pages: int = _LOGFILE_PAGE_CAP,
) -> dict[str, Any]:
    """Index page-level NTFS $LogFile restart/operation candidates."""
    run_id = store.start_parser_run("ntfs_logfile_indexer", logfile_path,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False
    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_logfile_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "LogFile.bin")
        try:
            extracted = image.extract_file(logfile_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            with open(local, "rb") as fh:
                raw = fh.read(read_cap_bytes + 1)
            if len(raw) > read_cap_bytes:
                coverage_gaps.append({
                    "path": logfile_path,
                    "status": "coverage_gap",
                    "reason": "logfile_read_cap_reached",
                    "error": f"read only first {read_cap_bytes} bytes of $LogFile",
                })
                raw = raw[:read_cap_bytes]
            parsed = parse_logfile_records(raw, max_pages=max_pages)
            parsed_ok = bool(parsed.get("ok"))
            coverage_gaps.extend(parsed.get("coverage_gaps") or [])
        except Exception as exc:
            coverage_gaps.append({
                "path": logfile_path,
                "status": "coverage_gap",
                "reason": "logfile_unavailable_or_parse_failed",
                "error": str(exc),
            })
            parsed = {"entries": []}

        for entry in parsed.get("entries", []):
            candidates = list(entry.get("candidate_paths") or [])
            names = list(entry.get("candidate_names") or [])
            primary = candidates[0] if candidates else (names[0] if names else logfile_path)
            hints = list(entry.get("operation_hints") or [])
            fields = {
                "Page Signature": str(entry.get("page_signature") or ""),
                "Page Offset": str(entry.get("page_offset") or 0),
                "Candidate Paths": "; ".join(candidates),
                "Candidate Names": "; ".join(names),
                "Operation Hints": "; ".join(hints),
                "String Candidates": "; ".join(entry.get("string_candidates") or []),
                "Parser Scope": str(entry.get("parser_scope") or "page_candidate_no_replay"),
            }
            store.insert_artifact(
                artifact_type=str(entry.get("artifact_type") or "NTFS LogFile"),
                source_ref=logfile_path,
                source_path=f"{logfile_path}:page:{entry.get('page_offset', 0)}",
                primary_path=str(primary),
                description=(
                    f"{entry.get('artifact_type', 'NTFS LogFile')} | "
                    f"{entry.get('page_signature', '')} | "
                    f"{'; '.join(hints or names or candidates)}"
                )[:512],
                strings={k: v for k, v in fields.items() if v},
                times={},
                parser_run_id=run_id,
            )
            indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not parsed_ok:
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
        "section": "logfile",
    }


# ── Recycle Bin $I / $R ─────────────────────────────────────────────────────

_RECYCLE_BIN_ROOT = "/c:/$Recycle.Bin"
_RECYCLE_BIN_FILE_CAP = 20000


def _path_basename(path: str) -> str:
    return str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _recycle_record_id(path: str) -> str:
    name = _path_basename(path)
    if len(name) >= 3 and name[:2].lower() in ("$i", "$r"):
        return name[2:]
    return ""


def _decode_recycle_original_path(raw: bytes, version: int) -> str:
    candidates: list[str] = []
    if version >= 2 and len(raw) >= 28:
        length = int.from_bytes(raw[24:28], "little", signed=False)
        if 0 < length < 32768:
            chunk = raw[28:28 + length * 2]
            candidates.append(
                chunk.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
            )
    if len(raw) > 24:
        candidates.append(
            raw[24:].decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
        )
    for candidate in candidates:
        text = str(candidate or "").strip().strip("\x00")
        if text:
            return text
    return ""


def parse_recycle_bin_i_file(
    raw: bytes,
    *,
    source_path: str = "",
) -> dict[str, Any]:
    """Parse a Windows Recycle Bin $I metadata file.

    $I records prove the Recycle Bin held metadata for a deleted item: original
    path, original size, and deletion time. They do not prove wiping, execution,
    or final absence of the original file.
    """
    data = bytes(raw or b"")
    if len(data) < 24:
        return {
            "ok": False,
            "status": "not_evaluable",
            "error": "Recycle Bin $I metadata is shorter than 24 bytes.",
        }
    version = int.from_bytes(data[0:8], "little", signed=False)
    original_size = int.from_bytes(data[8:16], "little", signed=False)
    deleted_at = _filetime_to_ms(data[16:24])
    original_path = _decode_recycle_original_path(data, version)
    recycle_id = _recycle_record_id(source_path)
    ok = bool(original_path or deleted_at)
    return {
        "ok": ok,
        "status": "completed" if ok else "not_evaluable",
        "version": version,
        "recycle_id": recycle_id,
        "original_size": original_size,
        "deleted_at": deleted_at,
        "original_path": original_path,
        "source_path": source_path,
    }


def _discover_recycle_bin_records(
    image: Any,
    recycle_root: str,
    coverage_gaps: list[dict[str, Any]],
    *,
    max_files: int,
) -> tuple[list[dict[str, Any]], bool]:
    try:
        sid_dirs = [
            e for e in (image.list_directory(recycle_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
        root_read = True
    except Exception as exc:
        coverage_gaps.append({
            "path": recycle_root,
            "status": "coverage_gap",
            "reason": "recycle_bin_root_unavailable",
            "error": str(exc),
        })
        return [], False

    records: list[dict[str, Any]] = []
    for sid_entry in sid_dirs:
        sid_path = str(sid_entry.get("path") or "")
        sid = str(sid_entry.get("name") or _path_basename(sid_path))
        if not sid_path:
            continue
        try:
            entries = image.list_directory(sid_path) or []
        except Exception as exc:
            coverage_gaps.append({
                "path": sid_path,
                "status": "coverage_gap",
                "reason": "recycle_bin_sid_dir_unavailable",
                "error": str(exc),
            })
            continue
        payloads: dict[str, dict[str, Any]] = {}
        metadata: list[dict[str, Any]] = []
        for entry in entries:
            if entry.get("is_dir") or entry.get("error"):
                continue
            name = str(entry.get("name") or _path_basename(str(entry.get("path"))))
            if name.lower().startswith("$r"):
                payloads[_recycle_record_id(name)] = entry
            elif name.lower().startswith("$i"):
                metadata.append(entry)
        for entry in metadata:
            if len(records) >= max_files:
                coverage_gaps.append({
                    "path": recycle_root,
                    "status": "coverage_gap",
                    "reason": "recycle_bin_file_cap_reached",
                    "error": f"stopped after {max_files} Recycle Bin metadata files",
                })
                return records, root_read
            record_id = _recycle_record_id(str(entry.get("name") or entry.get("path")))
            records.append({
                "sid": sid,
                "metadata": entry,
                "payload": payloads.get(record_id),
                "recycle_id": record_id,
            })
    return records, root_read


def index_recycle_bin_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    recycle_root: str = _RECYCLE_BIN_ROOT,
    max_files: int = _RECYCLE_BIN_FILE_CAP,
) -> dict[str, Any]:
    """Index Windows Recycle Bin $I metadata and $R companion paths."""
    run_id = store.start_parser_run("recycle_bin_indexer", recycle_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    metadata_files_seen = 0
    records, root_read = _discover_recycle_bin_records(
        image, recycle_root, coverage_gaps, max_files=max_files)

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_recycle_") as tmp:
        _write_do_not_execute_marker(tmp)
        for idx, record in enumerate(records):
            meta_entry = record["metadata"]
            metadata_path = str(meta_entry.get("path") or "")
            if not metadata_path:
                continue
            local = os.path.join(tmp, f"recycle_i_{idx}.bin")
            try:
                extracted = image.extract_file(metadata_path, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                with open(local, "rb") as fh:
                    parsed = parse_recycle_bin_i_file(
                        fh.read(1024 * 1024),
                        source_path=metadata_path,
                    )
                metadata_files_seen += 1
                if not parsed.get("ok"):
                    raise RuntimeError(str(parsed.get("error") or "unparsed $I metadata"))
            except Exception as exc:
                coverage_gaps.append({
                    "path": metadata_path,
                    "status": "coverage_gap",
                    "reason": "recycle_bin_i_parse_failed",
                    "error": str(exc),
                })
                continue

            payload = record.get("payload") or {}
            recycled_path = str(payload.get("path") or "")
            times = {}
            if parsed.get("deleted_at"):
                times["Deleted Time"] = parsed["deleted_at"]
            for label, value in _entry_times_from_listing(payload).items():
                times[f"Recycled {label}"] = value
            original_path = str(parsed.get("original_path") or "")
            strings = {
                "User SID": str(record.get("sid") or ""),
                "Recycle ID": str(parsed.get("recycle_id") or record.get("recycle_id") or ""),
                "Original Path": original_path,
                "Original Size": str(parsed.get("original_size") or ""),
                "Recycled Path": recycled_path,
                "Metadata Path": metadata_path,
                "Metadata Version": str(parsed.get("version") or ""),
                "Payload Present": "true" if recycled_path else "false",
            }
            store.insert_artifact(
                artifact_type="Recycle Bin Deleted Items",
                source_ref=recycle_root,
                source_path=metadata_path,
                primary_path=original_path or recycled_path or metadata_path,
                description=(
                    f"Recycle Bin Deleted Items | {record.get('sid', '')} | "
                    f"{original_path or metadata_path}"
                )[:512],
                strings={k: v for k, v in strings.items() if v},
                times=times,
                parser_run_id=run_id,
            )
            indexed += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if not root_read:
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
        "ok": root_read,
        "status": status,
        "indexed_records": indexed,
        "metadata_files_seen": metadata_files_seen,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


_LNK_JUMPLIST_FILE_CAP = 10000
_LNK_SCAN_DIRS = (
    "AppData/Roaming/Microsoft/Windows/Recent",
    "Desktop",
    "Downloads",
    "Documents",
)
_JUMPLIST_SUBDIRS = ("AutomaticDestinations", "CustomDestinations")
_JUMPLIST_EXTS = (".automaticdestinations-ms", ".customdestinations-ms")


def _candidate_windows_paths_from_bytes(raw: bytes) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    utf16_text = ""
    try:
        utf16_text = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        pass
    ascii_text = raw.decode("utf-8", errors="ignore")
    for text in (utf16_text, ascii_text):
        text = text.replace("\\\\", "\\")
        for match in _PCA_WINDOWS_PATH_RE.finditer(text):
            value = match.group(0).strip().strip("\x00")
            if value and value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def parse_lnk_bytes(raw: bytes, *, source_path: str = "") -> dict[str, Any]:
    """Best-effort parse a .lnk shortcut for path strings and header times."""
    data = bytes(raw)
    candidates = _candidate_windows_paths_from_bytes(data)
    target = candidates[0] if candidates else ""
    created = accessed = modified = None
    if len(data) >= 0x4C and int.from_bytes(data[:4], "little") == 0x4C:
        created = _filetime_to_ms(data[0x1C:0x24])
        accessed = _filetime_to_ms(data[0x24:0x2C])
        modified = _filetime_to_ms(data[0x2C:0x34])
    return {
        "source_path": source_path,
        "target_path": target,
        "string_candidates": candidates,
        "created_time": created,
        "accessed_time": accessed,
        "modified_time": modified,
    }


def parse_jumplist_bytes(raw: bytes, *, source_path: str = "") -> dict[str, Any]:
    """Best-effort extract embedded path strings from JumpList destination files."""
    candidates = _candidate_windows_paths_from_bytes(bytes(raw))
    return {
        "source_path": source_path,
        "target_paths": candidates,
        "primary_target": candidates[0] if candidates else "",
    }


def _discover_lnk_jumplist_files(
    image: Any,
    users_root: str,
    coverage_gaps: list[dict[str, Any]],
    *,
    max_files: int,
) -> list[tuple[str, str, str]]:
    discovered: list[tuple[str, str, str]] = []
    try:
        user_dirs = [
            e for e in (image.list_directory(users_root) or [])
            if e.get("is_dir") and not e.get("error")
        ]
    except Exception as exc:  # noqa: BLE001
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "lnk_users_root_unavailable",
            "error": str(exc),
        })
        return discovered

    def add_file(user: str, path: str, artifact_kind: str) -> None:
        if len(discovered) >= max_files:
            return
        discovered.append((user, path, artifact_kind))

    for profile in user_dirs:
        if len(discovered) >= max_files:
            break
        profile_path = str(profile.get("path", "") or "")
        user = str(profile.get("name") or profile_path.rsplit("/", 1)[-1])
        for rel in _LNK_SCAN_DIRS:
            directory = f"{profile_path}/{rel}"
            try:
                children = image.list_directory(directory) or []
            except Exception:
                continue
            for child in children:
                if child.get("error"):
                    continue
                path = str(child.get("path", "") or "")
                name = str(child.get("name", "") or path.rsplit("/", 1)[-1])
                if child.get("is_dir"):
                    if rel.endswith("/Recent") and name in _JUMPLIST_SUBDIRS:
                        try:
                            dests = image.list_directory(path) or []
                        except Exception:
                            continue
                        for dest in dests:
                            dest_path = str(dest.get("path", "") or "")
                            dest_name = str(dest.get("name", "") or "")
                            if (
                                not dest.get("is_dir")
                                and not dest.get("error")
                                and dest_name.lower().endswith(_JUMPLIST_EXTS)
                            ):
                                add_file(user, dest_path, "jumplist")
                    continue
                if name.lower().endswith(".lnk"):
                    add_file(user, path, "lnk")
    if len(discovered) >= max_files:
        coverage_gaps.append({
            "path": users_root,
            "status": "coverage_gap",
            "reason": "lnk_jumplist_file_cap_reached",
            "error": f"stopped after {max_files} LNK/JumpList files",
        })
    return discovered


def index_lnk_jumplist_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    users_root: str = _USERS_ROOT,
    max_files: int = _LNK_JUMPLIST_FILE_CAP,
) -> dict[str, Any]:
    """Index .lnk and JumpList destination files from user profiles."""
    run_id = store.start_parser_run("lnk_jumplist_indexer", users_root,
                                    started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    files_seen = 0

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_lnk_") as tmp:
        _write_do_not_execute_marker(tmp)
        for idx, (user, internal, kind) in enumerate(
            _discover_lnk_jumplist_files(
                image, users_root, coverage_gaps, max_files=max_files)
        ):
            local = os.path.join(tmp, f"lnk_jump_{idx}.bin")
            try:
                extracted = image.extract_file(internal, local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
                with open(local, "rb") as fh:
                    raw = fh.read(8 * 1024 * 1024)
                files_seen += 1
                if kind == "lnk":
                    parsed = parse_lnk_bytes(raw, source_path=internal)
                    times = _entry_times_from_listing({"path": internal})
                    if parsed.get("created_time"):
                        times["LNK Created Time"] = parsed["created_time"]
                    if parsed.get("accessed_time"):
                        times["LNK Accessed Time"] = parsed["accessed_time"]
                    if parsed.get("modified_time"):
                        times["LNK Modified Time"] = parsed["modified_time"]
                    target = str(parsed.get("target_path") or "")
                    store.insert_artifact(
                        artifact_type="LNK Files",
                        source_ref=internal,
                        source_path=internal,
                        primary_path=target or internal,
                        description=f"LNK Files | {user} | {internal} -> {target}"[:512],
                        strings={
                            "User": user,
                            "LNK Path": internal,
                            "Target Path": target,
                            "String Candidates": " | ".join(
                                parsed.get("string_candidates") or []),
                        },
                        times=times,
                        parser_run_id=run_id,
                    )
                else:
                    parsed = parse_jumplist_bytes(raw, source_path=internal)
                    target = str(parsed.get("primary_target") or "")
                    store.insert_artifact(
                        artifact_type="Jump Lists",
                        source_ref=internal,
                        source_path=internal,
                        primary_path=target or internal,
                        description=f"Jump Lists | {user} | {internal} | {target}"[:512],
                        strings={
                            "User": user,
                            "JumpList Path": internal,
                            "Primary Target": target,
                            "Target Paths": " | ".join(
                                parsed.get("target_paths") or []),
                        },
                        parser_run_id=run_id,
                    )
                indexed += 1
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": internal,
                    "status": "coverage_gap",
                    "reason": "lnk_jumplist_parse_failed",
                    "error": str(exc),
                })

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    if files_seen == 0:
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
        "ok": files_seen > 0,
        "status": status,
        "indexed_records": indexed,
        "files_seen": files_seen,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


# ── Defender MPLog ───────────────────────────────────────────────────────────
#
# MPLog is Defender's verbose protection log (C:\ProgramData\Microsoft\Windows
# Defender\Support\MPLog-*.log). It records process activity, real-time-scan
# events, and any detections. We aggregate the high-signal lines into bounded
# records instead of indexing every line (a single MPLog holds tens of
# thousands). Timestamps in MPLog are device-LOCAL wall-clock with no zone, so
# they are kept as strings (not UTC epochs) to avoid a false-precision shift.

# ── SRUM SRUDB.dat ─────────────────────────────────────────────────────────

_SRUM_DB_PATH = "/c:/Windows/System32/sru/SRUDB.dat"
_SRUM_MAX_RECORDS = 50000
_SRUM_ID_TABLE = "SruDbIdMapTable"
_SRUM_NETWORK_FIELD_HINTS = {
    "bytessent", "bytesreceived", "interfaceluid", "l2profileid",
}
_SRUM_APP_FIELD_HINTS = {
    "foregroundcycletime", "backgroundcycletime", "facetime",
    "foregroundbytesread", "foregroundbyteswritten",
    "backgroundbytesread", "backgroundbyteswritten",
}
_SRUM_TIME_FIELD_HINTS = (
    "timestamp", "time_stamp", "endtime", "starttime", "connectstarttime",
)


def _compact_field_name(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _srum_table_names(db: Any) -> list[str]:
    raw: Any = []
    try:
        tables = getattr(db, "tables")
        raw = tables() if callable(tables) else tables
    except Exception:
        raw = []
    names: list[str] = []
    for item in raw or []:
        name = getattr(item, "name", item)
        if name is not None:
            names.append(str(name))
    if not names:
        for attr in ("table_names", "_tables"):
            raw_attr = getattr(db, attr, None)
            if isinstance(raw_attr, dict):
                names.extend(str(k) for k in raw_attr)
            elif raw_attr:
                names.extend(str(x) for x in raw_attr)
    return list(dict.fromkeys(names))


def _srum_table(db: Any, table_name: str) -> Any:
    table = getattr(db, "table", None)
    if callable(table):
        return table(table_name)
    tables = getattr(db, "_tables", None)
    if isinstance(tables, dict) and table_name in tables:
        return tables[table_name]
    raise KeyError(table_name)


def _srum_records(table: Any):
    records = getattr(table, "records", None)
    return records() if callable(records) else iter(records or [])


def _srum_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if 0 < len(raw) <= 8:
            return int.from_bytes(raw, "little", signed=False)
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except Exception:
        return None


def _srum_text(value: Any) -> str:
    return _pca_value_text(value).strip()


def _build_srum_id_map(db: Any, coverage_gaps: list[dict[str, Any]]) -> dict[str, str]:
    try:
        table = _srum_table(db, _SRUM_ID_TABLE)
    except Exception as exc:
        coverage_gaps.append({
            "path": _SRUM_ID_TABLE,
            "status": "coverage_gap",
            "reason": "srum_id_map_unavailable",
            "error": str(exc),
        })
        return {}
    mapping: dict[str, str] = {}
    try:
        for rec in _srum_records(table):
            fields = dict(rec)
            raw_id = (
                fields.get("IdIndex")
                or fields.get("Id")
                or fields.get("ID")
                or fields.get("Index")
            )
            raw_blob = (
                fields.get("IdBlob")
                or fields.get("Blob")
                or fields.get("Name")
                or fields.get("Value")
            )
            key = _srum_int(raw_id)
            text = _srum_text(raw_blob)
            if key is not None and text:
                mapping[str(key)] = text
    except Exception as exc:
        coverage_gaps.append({
            "path": _SRUM_ID_TABLE,
            "status": "coverage_gap",
            "reason": "srum_id_map_parse_error",
            "error": str(exc),
        })
    return mapping


def _srum_app_name(fields: dict[str, Any], id_map: dict[str, str]) -> str:
    for key in ("Application Name", "ApplicationName", "ExeInfo", "AppName"):
        text = _srum_text(fields.get(key))
        if text:
            return text
    app_id = fields.get("AppId")
    app_key = _srum_int(app_id)
    if app_key is not None and str(app_key) in id_map:
        return id_map[str(app_key)]
    text = _srum_text(app_id)
    return id_map.get(text, text)


def _srum_timestamp(fields: dict[str, Any]) -> tuple[str, tuple[int, str] | None]:
    normalized_time_hints = {_compact_field_name(h) for h in _SRUM_TIME_FIELD_HINTS}
    preferred = [
        key for key in fields
        if _compact_field_name(key) in normalized_time_hints
    ]
    for key in [*preferred, *[k for k in fields if k not in preferred]]:
        parsed = _pca_timestamp(fields.get(key))
        if parsed:
            return str(key), parsed
    return "", None


def _srum_artifact_type(table_name: str, fields: dict[str, Any]) -> str:
    compact_keys = {_compact_field_name(k) for k in fields}
    compact_table = _compact_field_name(table_name)
    if compact_keys & _SRUM_NETWORK_FIELD_HINTS or "network" in compact_table:
        return "SRUM Network Usage"
    if compact_keys & _SRUM_APP_FIELD_HINTS or "appresource" in compact_table:
        return "SRUM Application Resource Usage"
    return ""


def parse_srum_esedb(db: Any, *, max_records: int = _SRUM_MAX_RECORDS) -> dict[str, Any]:
    """Parse SRUDB.dat ESE records with schema-introspection.

    SRUM table names and column sets vary by Windows build. This parser keeps
    to two high-value families (Network Usage and Application Resource Usage),
    preserves source table names, resolves AppId via SruDbIdMapTable when
    available, and records table/record failures as coverage gaps.
    """
    coverage_gaps: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    id_map = _build_srum_id_map(db, coverage_gaps)
    scanned = 0
    capped = False
    supported_tables_seen = False
    for table_name in _srum_table_names(db):
        if capped:
            break
        if table_name == _SRUM_ID_TABLE:
            continue
        try:
            rec_iter = iter(_srum_records(_srum_table(db, table_name)))
        except Exception as exc:
            coverage_gaps.append({
                "path": table_name,
                "status": "coverage_gap",
                "reason": "srum_table_unavailable",
                "error": str(exc),
            })
            continue
        while True:
            try:
                rec = next(rec_iter)
            except StopIteration:
                break
            except Exception as exc:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "srum_record_iter_error",
                    "error": str(exc),
                })
                break
            if scanned >= max_records:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "srum_record_cap_reached",
                    "error": f"more than {max_records} SRUM records; truncated",
                })
                capped = True
                break
            scanned += 1
            try:
                fields = dict(rec)
                artifact_type = _srum_artifact_type(table_name, fields)
                if not artifact_type:
                    continue
                supported_tables_seen = True
                app_name = _srum_app_name(fields, id_map)
                ts_field, timestamp = _srum_timestamp(fields)
                strings: dict[str, str] = {
                    "Table": table_name,
                    "Application Name": app_name,
                    "Timestamp Field": ts_field,
                }
                for src, dst in (
                    ("UserId", "User ID"),
                    ("User ID", "User ID"),
                    ("Sid", "SID"),
                    ("BytesSent", "Bytes Sent"),
                    ("BytesReceived", "Bytes Received"),
                    ("InterfaceLuid", "Interface LUID"),
                    ("L2ProfileId", "L2 Profile ID"),
                    ("ForegroundCycleTime", "Foreground Cycle Time"),
                    ("BackgroundCycleTime", "Background Cycle Time"),
                    ("ForegroundBytesRead", "Foreground Bytes Read"),
                    ("ForegroundBytesWritten", "Foreground Bytes Written"),
                    ("BackgroundBytesRead", "Background Bytes Read"),
                    ("BackgroundBytesWritten", "Background Bytes Written"),
                    ("FaceTime", "Face Time"),
                ):
                    value = fields.get(src)
                    if value is not None:
                        strings[dst] = _srum_text(value)
                entry = {
                    "artifact_type": artifact_type,
                    "source_table": table_name,
                    "application_name": app_name,
                    "timestamp_field": ts_field,
                    "timestamp": timestamp,
                    "fields": {k: v for k, v in strings.items() if v},
                    "bytes_sent": _srum_int(fields.get("BytesSent")) or 0,
                    "bytes_received": _srum_int(fields.get("BytesReceived")) or 0,
                    "foreground_cycle_time": (
                        _srum_int(fields.get("ForegroundCycleTime")) or 0
                    ),
                }
                if app_name or timestamp or len(entry["fields"]) > 2:
                    entries.append(entry)
            except Exception as exc:
                coverage_gaps.append({
                    "path": table_name,
                    "status": "coverage_gap",
                    "reason": "srum_record_parse_error",
                    "error": str(exc),
                })
    if not supported_tables_seen:
        coverage_gaps.append({
            "path": "SRUDB.dat",
            "status": "coverage_gap",
            "reason": "srum_supported_tables_absent",
            "error": (
                "No SRUM Network Usage or Application Resource Usage records "
                "were recognized in the ESE schema."
            ),
        })
    ok = supported_tables_seen
    return {
        "ok": ok,
        "status": (
            "not_evaluable" if not ok
            else "partial" if coverage_gaps
            else "completed"
        ),
        "indexed_records": len(entries),
        "entries": entries,
        "coverage_gaps": coverage_gaps,
    }


def index_srum_artifacts(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    db_path: str = _SRUM_DB_PATH,
    ese_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Index SRUM SRUDB.dat network and app-resource records from raw image."""
    run_id = store.start_parser_run("srum_indexer", db_path, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_srum_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "SRUDB.dat")
        try:
            extracted = image.extract_file(db_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            available = True
        except Exception as exc:
            available = False
            coverage_gaps.append({
                "path": db_path,
                "status": "coverage_gap",
                "reason": "srum_db_unavailable",
                "error": str(exc),
            })

        fh = None
        if available:
            try:
                if ese_factory is None:
                    from dissect.esedb import EseDB

                    ese_factory = EseDB
                fh = open(local, "rb")
                parsed = parse_srum_esedb(ese_factory(fh))
                parsed_ok = bool(parsed.get("ok"))
                coverage_gaps.extend(parsed.get("coverage_gaps") or [])
                for entry in parsed.get("entries") or []:
                    artifact_type = str(entry.get("artifact_type") or "")
                    app_name = str(entry.get("application_name") or "")
                    source_table = str(entry.get("source_table") or "")
                    times = {}
                    timestamp = entry.get("timestamp")
                    if timestamp:
                        times["Timestamp"] = timestamp
                    fields = dict(entry.get("fields") or {})
                    desc = f"{artifact_type} | {app_name or source_table}"
                    store.insert_artifact(
                        artifact_type=artifact_type,
                        source_ref=db_path,
                        source_path=f"{db_path}:{source_table}",
                        primary_path=app_name or db_path,
                        description=desc[:512],
                        strings=fields,
                        times=times,
                        parser_run_id=run_id,
                    )
                    indexed += 1
            except Exception as exc:
                coverage_gaps.append({
                    "path": db_path,
                    "status": "coverage_gap",
                    "reason": "srum_db_parse_error",
                    "error": str(exc),
                })
            finally:
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass

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
                try:
                    text = raw.decode(encoding)
                except UnicodeDecodeError:
                    text = raw.decode(encoding, errors="replace")
                    coverage_gaps.append({
                        "path": path, "status": "coverage_gap",
                        "reason": "mplog_decode_errors",
                        "error": (
                            f"{encoding} decode errors; "
                            f"{text.count(chr(0xFFFD))} replacement "
                            "character(s) substituted — affected log lines "
                            "may be partially corrupted (a single trailing "
                            "error is expected when the read cap cut a "
                            "multi-byte character)"
                        ),
                    })
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
              "RDP Client Destinations": 0, "IFEO Persistence": 0,
              "COM Hijack": 0, "ShellBags": 0, "Scheduled Tasks": 0}

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
                taskcache_entries, taskcache_gaps = parse_taskcache_entries(
                    software_hive, hive_label="SOFTWARE")
                coverage_gaps.extend(taskcache_gaps)
                for task in taskcache_entries:
                    _insert(
                        "Scheduled Tasks",
                        task.get("tree_path", software_path),
                        (
                            f"Scheduled Tasks | TaskCache | "
                            f"{task.get('tree_path', '')} "
                            f"GUID={task.get('task_guid', '')} "
                            f"Actions={task.get('action_strings', '')}"
                        ),
                        {"Task Name": task.get("task_name", ""),
                         "Task Path": task.get("tree_path", ""),
                         "Task GUID": task.get("task_guid", ""),
                         "URI": task.get("uri", ""),
                         "Index": task.get("index", ""),
                         "Action Strings": task.get("action_strings", ""),
                         "Source": "TaskCache registry"},
                    )
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

            # ── UsrClass.dat: per-user COM hijack (HKCU\Software\Classes\CLSID) ──
            # Done first / independently so a missing NTUSER.DAT does not skip
            # COM coverage for this profile.
            usrclass_internal = (
                f"{profile}/AppData/Local/Microsoft/Windows/UsrClass.dat"
            )
            usrclass_local = os.path.join(tmp, f"UsrClass_{idx}.dat")
            usrclass_ok = True
            try:
                extracted = image.extract_file(usrclass_internal, usrclass_local) or {}
                if extracted.get("error"):
                    raise RuntimeError(str(extracted["error"]))
            except Exception as exc:  # noqa: BLE001
                usrclass_ok = False
                coverage_gaps.append({
                    "path": usrclass_internal,
                    "status": "coverage_gap",
                    "reason": "usrclass_hive_unavailable",
                    "error": str(exc),
                })
            if usrclass_ok:
                try:
                    from regipy.registry import RegistryHive

                    usrclass_hive = RegistryHive(usrclass_local)
                    com_entries, com_gaps = parse_com_hijack(
                        usrclass_hive, user=user, hive_label=f"UsrClass:{user}")
                    coverage_gaps.extend(com_gaps)
                    for com in com_entries:
                        _insert(
                            "COM Hijack",
                            usrclass_internal,
                            f"COM Hijack | {com['clsid']} -> {com['server']}",
                            {"CLSID": com["clsid"],
                             "Server": com["server"],
                             "Server Kind": com["server_kind"],
                             "Threading Model": com.get("threading_model", ""),
                             "Suspicious Reason": com.get("suspicious_reason", ""),
                             "User": user,
                             "Key Path": com["key_path"]},
                        )
                    shellbag_entries, shellbag_gaps = parse_shellbags(
                        usrclass_hive, user=user, hive_label=f"UsrClass:{user}")
                    coverage_gaps.extend(shellbag_gaps)
                    for shellbag in shellbag_entries:
                        _insert(
                            "ShellBags",
                            usrclass_internal,
                            (
                                f"ShellBags | {shellbag['user']} | "
                                f"{shellbag['path_hint']}"
                            ),
                            {"User": shellbag["user"],
                             "Item Name": shellbag["item_name"],
                             "Path Hint": shellbag["path_hint"],
                             "Node Slot": shellbag.get("node_slot", ""),
                             "Root": shellbag["root"],
                             "Value Name": shellbag["value_name"],
                             "Hive": shellbag["hive"]},
                        )
                except Exception as exc:  # noqa: BLE001
                    coverage_gaps.append({
                        "path": usrclass_internal,
                        "status": "coverage_gap",
                        "reason": "usrclass_hive_parse_failed",
                        "error": str(exc),
                    })

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
            decode_errors = setupapi_text.count("�")
            if decode_errors:
                coverage_gaps.append({
                    "path": setupapi_internal,
                    "status": "coverage_gap",
                    "reason": "setupapi_decode_errors",
                    "error": (
                        f"utf-8 decode errors; {decode_errors} replacement "
                        "character(s) substituted — affected device-install "
                        "lines may be partially corrupted"
                    ),
                })
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


# ── BITS transfer jobs (qmgr.db) ─────────────────────────────────────────────
#
# BITS (Background Intelligent Transfer Service) is a common malware
# download / C2 / exfil channel. Win10+ stores jobs in an ESE database
# (C:\ProgramData\Microsoft\Network\Downloader\qmgr.db) whose Jobs/Files tables
# carry the job detail in an opaque binary Blob. Rather than reverse the full
# job-blob struct, we best-effort extract the UTF-16 RemoteName (download URL)
# and LocalName (destination path) strings — the core forensic signal (what was
# fetched from where to where). A BITS job pulling an EXE/DLL from an external
# host, or writing to a suspicious path, is the lead.

_BITS_DB_PATH = "/c:/ProgramData/Microsoft/Network/Downloader/qmgr.db"
_BITS_URL_RE = re.compile(r"(?:https?|ftp)://[^\x00-\x1f\s\"'<>|]{4,}", re.I)
_BITS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\x00-\x1f<>\"|?*]{2,}")
_BITS_MAX_RECORDS = 5000
_BITS_MAX_STR = 2048       # per-URL / per-path length cap
_BITS_MAX_PER_KIND = 20    # URLs / paths kept per blob


def parse_bits_blob(blob: bytes) -> tuple[list[str], list[str]]:
    """Best-effort extract (urls, local_paths) from a BITS job/file Blob.

    The blob stores RemoteName/LocalName as UTF-16; we scan the decoded text
    rather than parse the opaque struct. Both 2-byte alignments are scanned
    (a string can start at an odd offset after a binary field), paths are cut
    where a greedy match runs into the adjacent URL field, and each string is
    length-capped so a corrupt blob cannot emit a multi-MB value.
    """
    if not isinstance(blob, (bytes, bytearray)):
        return [], []
    raw = bytes(blob)
    urls: list[str] = []
    paths: list[str] = []
    for start in (0, 1):  # scan both UTF-16LE byte alignments
        text = raw[start:].decode("utf-16-le", errors="replace")
        for match in _BITS_URL_RE.finditer(text):
            url = match.group(0)[:_BITS_MAX_STR]
            if url not in urls:
                urls.append(url)
        for match in _BITS_PATH_RE.finditer(text):
            candidate = re.split(
                r"(?:https?|ftp)://", match.group(0), 1)[0].strip()[:_BITS_MAX_STR]
            if candidate and candidate not in paths:
                paths.append(candidate)
    return urls[:_BITS_MAX_PER_KIND], paths[:_BITS_MAX_PER_KIND]


def index_bits_jobs(
    image: Any,
    store: RawIndexStore,
    *,
    started_at: str,
    db_path: str = _BITS_DB_PATH,
) -> dict[str, Any]:
    """Index BITS transfer jobs from qmgr.db (ESE) — download/C2/exfil channel.

    No-miss: a missing/unreadable qmgr.db, an unavailable ESE library, a
    per-record blob error, and the record cap are each coverage gaps; no
    database is ``not_evaluable``.
    """
    run_id = store.start_parser_run("bits_indexer", db_path, started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed = 0
    parsed_ok = False

    with store.batch(), tempfile.TemporaryDirectory(prefix="fw_raw_bits_") as tmp:
        _write_do_not_execute_marker(tmp)
        local = os.path.join(tmp, "qmgr.db")
        try:
            extracted = image.extract_file(db_path, local) or {}
            if extracted.get("error"):
                raise RuntimeError(str(extracted["error"]))
            available = True
        except Exception as exc:  # noqa: BLE001
            available = False
            coverage_gaps.append({
                "path": db_path, "status": "coverage_gap",
                "reason": "bits_db_unavailable", "error": str(exc),
            })

        fh = None
        if available:
            try:
                from dissect.esedb import EseDB

                fh = open(local, "rb")
                db = EseDB(fh)
                parsed_ok = True
                scanned = 0
                capped = False
                for table_name in ("Jobs", "Files"):
                    if capped:
                        break
                    try:
                        rec_iter = iter(db.table(table_name).records())
                    except Exception as exc:  # noqa: BLE001
                        coverage_gaps.append({
                            "path": f"{db_path}:{table_name}",
                            "status": "coverage_gap",
                            "reason": "bits_table_unavailable", "error": str(exc),
                        })
                        continue
                    while True:
                        try:
                            rec = next(rec_iter)
                        except StopIteration:
                            break
                        except Exception as exc:  # noqa: BLE001 — corrupt page: stop
                            coverage_gaps.append({   # this table, not the whole DB
                                "path": f"{db_path}:{table_name}",
                                "status": "coverage_gap",
                                "reason": "bits_record_iter_error", "error": str(exc),
                            })
                            break
                        if scanned >= _BITS_MAX_RECORDS:
                            coverage_gaps.append({
                                "path": f"{db_path}:{table_name}",
                                "status": "coverage_gap",
                                "reason": "bits_record_cap_reached",
                                "error": f"more than {_BITS_MAX_RECORDS} records; truncated",
                            })
                            capped = True
                            break
                        scanned += 1
                        try:
                            job_id = str(rec.get("Id") or "")
                            urls, paths = parse_bits_blob(rec.get("Blob"))
                        except Exception as exc:  # noqa: BLE001
                            coverage_gaps.append({
                                "path": f"{db_path}:{table_name}",
                                "status": "coverage_gap",
                                "reason": "bits_record_parse_error", "error": str(exc),
                            })
                            continue
                        if not urls and not paths:
                            continue  # job/file blob with no recoverable URL/path
                        strings = {
                            "Job Id": job_id,
                            "Table": table_name,
                            "URLs": " | ".join(urls),
                            "Local Paths": " | ".join(paths),
                        }
                        desc = f"BITS Transfer | {table_name} | {(urls or paths or [''])[0]}"
                        store.insert_artifact(
                            artifact_type="BITS Transfer",
                            source_ref=db_path,
                            source_path=db_path,
                            primary_path=db_path,
                            description=desc[:512],
                            strings={k: v for k, v in strings.items() if v},
                            times={},  # job blob timestamps are not struct-parsed here
                            parser_run_id=run_id,
                        )
                        indexed += 1
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": db_path, "status": "coverage_gap",
                    "reason": "bits_db_parse_error", "error": str(exc),
                })
            finally:
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass

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
