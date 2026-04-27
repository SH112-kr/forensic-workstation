"""Service persistence gate and svchost ServiceDll deep dive.

This module exists to prevent a common IR miss: treating the absence of
service-install events as absence of service persistence. It inspects service
registry state directly when possible, follows svchost services to
Parameters\\ServiceDll, and emits follow-up work for payload verification.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable


_REFERENCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reference",
    "windows_baseline.json",
)

_SUSPICIOUS_PATH_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\appdata\\",
    "\\perflogs\\",
)

_START_TYPES = {
    0: "Boot",
    1: "System",
    2: "Auto",
    3: "Demand",
    4: "Disabled",
}

_TYPE_FLAGS = {
    0x1: "Kernel Driver",
    0x2: "File System Driver",
    0x10: "Own Process",
    0x20: "Share Process",
    0x100: "Interactive",
}


def services_from_artifact_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize System Services artifact rows into service records."""
    services: list[dict[str, Any]] = []
    for row in rows or []:
        text_values = [str(v or "") for v in row.values()]
        image_path = (
            _field(row, "Service Location", "ImagePath", "Image Path", "Binary Path", "Path")
            or _extract_labeled_value(text_values, ("Image path", "ImagePath"))
        )
        service_dll = (
            _field(row, "ServiceDll", "Service DLL", "ServiceDLL", "DLL")
            or _extract_labeled_value(text_values, ("ServiceDLL", "ServiceDll", "Service DLL"))
        )
        service_name = _field(row, "Service Name", "ServiceName", "Name", "ValueName")
        if not service_name and row.get("Registry Key Path"):
            service_name = str(row.get("Registry Key Path", "")).rstrip("\\/").split("\\")[-1]
        if not service_name and not image_path and not service_dll:
            continue
        services.append({
            "source": "parsed_case",
            "hit_id": row.get("hit_id"),
            "service_name": service_name,
            "display_name": _field(row, "Display Name", "DisplayName", "Description"),
            "image_path": image_path,
            "service_dll": service_dll,
            "start": _field(row, "Start Type", "StartType", "Start"),
            "type": _field(row, "Service Type", "ServiceType", "Type"),
            "account": _field(row, "User Account", "ObjectName", "AccountName", "Account"),
            "registry_modified": _field(
                row,
                "Registry Modified",
                "Registry Key Modified Date/Time - UTC (yyyy-mm-dd)",
                "LastWriteTimestamp",
            ),
            "registry_key_path": _field(row, "Registry Key Path", "KeyPath"),
            "raw": {k: v for k, v in row.items() if k != "Event Data"},
        })
    return services


def services_from_system_hive(hive_path: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse services directly from a SYSTEM hive using regipy.

    Returns (services, metadata). Errors are raised to the caller so the MCP
    wrapper can surface the source-specific failure without failing other
    sources.
    """
    from regipy.registry import RegistryHive

    hive = RegistryHive(hive_path)
    control_sets = _control_sets(hive)
    services: list[dict[str, Any]] = []
    for control_set, is_current in control_sets:
        try:
            services_key = hive.get_key(f"\\{control_set}\\Services")
        except Exception:
            continue
        try:
            subkeys = list(services_key.iter_subkeys())
        except Exception:
            subkeys = []
        for key in subkeys:
            values = _values_dict(key)
            try:
                try:
                    params_key = key.get_subkey("Parameters")
                except Exception:
                    params_key = hive.get_key(f"\\{control_set}\\Services\\{key.name}\\Parameters")
                params = _values_dict(params_key)
                params_modified = _key_timestamp(params_key)
            except Exception:
                params = {}
                params_modified = ""

            services.append({
                "source": "system_hive",
                "control_set": control_set,
                "is_current_control_set": is_current,
                "service_name": str(key.name),
                "display_name": _clean_value(values.get("DisplayName")),
                "image_path": _clean_value(values.get("ImagePath")),
                "service_dll": _clean_value(params.get("ServiceDll")),
                "start": _format_start(values.get("Start")),
                "start_raw": values.get("Start"),
                "type": _format_type(values.get("Type")),
                "type_raw": values.get("Type"),
                "account": _clean_value(values.get("ObjectName")),
                "registry_modified": _key_timestamp(key),
                "parameters_modified": params_modified,
                "registry_key_path": f"HKLM\\SYSTEM\\{control_set}\\Services\\{key.name}",
            })

    return services, {
        "hive_path": hive_path,
        "control_sets": [{"name": cs, "current": cur} for cs, cur in control_sets],
        "service_count": len(services),
    }


def build_service_persistence_gate(
    services: list[dict[str, Any]],
    *,
    service_filter: str = "",
    limit: int = 50,
    file_info_lookup: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Score service records and build an evidence-first persistence gate."""
    baseline = _baseline_services()
    normalized_filter = service_filter.strip().lower()
    candidates: list[dict[str, Any]] = []
    normalized_services: list[dict[str, Any]] = []
    svchost_total = 0
    svchost_with_dll = 0

    for svc in services:
        normalized = _normalize_service_record(svc)
        normalized_services.append(normalized)
        if normalized["is_svchost"]:
            svchost_total += 1
        if normalized["is_svchost"] and normalized.get("service_dll"):
            svchost_with_dll += 1
        if normalized_filter and normalized_filter not in _service_search_blob(normalized):
            continue

        candidate = _score_service(normalized, baseline)
        if file_info_lookup and candidate.get("payload_path"):
            _attach_payload_file_info(candidate, file_info_lookup)
            _rescore_after_file_info(candidate)
        if candidate.get("_sort_score", 0) > 0 or normalized_filter:
            candidates.append(candidate)

    candidates.sort(
        key=lambda x: (
            -int(x.get("_sort_score", 0)),
            str(x.get("registry_modified", "")),
            str(x.get("service_name", "")).lower(),
        )
    )
    returned = candidates[: max(limit, 0)]
    for candidate in returned:
        candidate.pop("_sort_score", None)

    source_counts: dict[str, int] = {}
    for svc in services:
        source = str(svc.get("source") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1

    registry_checked = bool(services)
    payload_checks = [
        c for c in candidates
        if c.get("payload_file") and c["payload_file"].get("checked")
    ]
    missing_payloads = [
        c for c in candidates
        if c.get("payload_file") and not c["payload_file"].get("present")
    ]
    unverified_payloads = [
        c for c in candidates
        if c.get("payload_path") and not c.get("payload_file")
    ]

    return {
        "ok": True,
        "schema": "fw.service_persistence_gate.v1",
        "summary": {
            "total_services_observed": len(services),
            "source_counts": source_counts,
            "svchost_services": svchost_total,
            "svchost_services_with_servicedll": svchost_with_dll,
            "candidate_count": len(candidates),
            "returned_count": len(returned),
            "truncated": len(returned) < len(candidates),
            "service_filter": service_filter,
        },
        "gates": [
            {
                "id": "system_services_registry_state",
                "status": "passed" if registry_checked else "blocked",
                "note": (
                    "Service registry state was inspected."
                    if registry_checked
                    else "No service registry/artifact source was available. Do not finalize persistence findings."
                ),
            },
            {
                "id": "svchost_servicedll_followed",
                "status": "passed" if registry_checked else "blocked",
                "note": (
                    f"Observed {svchost_with_dll} svchost service(s) with Parameters\\ServiceDll."
                    if registry_checked
                    else "Requires SYSTEM hive or System Services artifact."
                ),
            },
            {
                "id": "payload_file_verification",
                "status": (
                    "passed"
                    if payload_checks and not missing_payloads and not unverified_payloads
                    else "partial"
                    if payload_checks or unverified_payloads
                    else "skipped"
                ),
                "note": _payload_gate_note(payload_checks, missing_payloads, unverified_payloads),
            },
        ],
        "candidates": returned,
        "source_conflicts": _source_conflicts(normalized_services),
        "zero_result_interpretation": (
            "0 candidates means no service matched the current heuristics in the loaded sources. "
            "It does not mean no service persistence exists if SYSTEM hive or System Services artifacts were unavailable."
        ),
        "reading_guide": [
            "EID 7045 is not a prerequisite for service persistence. Registry state is primary evidence.",
            "For svchost services, ImagePath alone is incomplete. Review Parameters\\ServiceDll.",
            "Evidence flags are leads, not verdicts. Verify payload timestamps, hash, signature, and service-event context.",
            "Coverage gaps describe work still needed; do not quote them as findings.",
        ],
    }


def _normalize_service_record(svc: dict[str, Any]) -> dict[str, Any]:
    out = dict(svc)
    image_path = _clean_value(out.get("image_path"))
    service_dll = _clean_value(out.get("service_dll"))
    out["service_name"] = _clean_value(out.get("service_name"))
    out["display_name"] = _clean_value(out.get("display_name"))
    out["image_path"] = image_path
    out["service_dll"] = service_dll
    out["start"] = _clean_value(out.get("start"))
    out["type"] = _clean_value(out.get("type"))
    out["account"] = _clean_value(out.get("account"))
    out["registry_modified"] = _clean_value(out.get("registry_modified"))
    out["is_svchost"] = "svchost.exe" in image_path.lower()
    out["is_auto_start"] = _is_auto_start(out["start"])
    out["is_localsystem"] = out["account"].lower() in {"localsystem", "local system", "nt authority\\system"}
    return out


def _source_conflicts(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for svc in services:
        key = str(svc.get("service_name", "") or "").strip().lower()
        if not key:
            continue
        by_name.setdefault(key, []).append(svc)

    conflicts: list[dict[str, Any]] = []
    compare_fields = ("image_path", "service_dll", "start", "account")
    for name, rows in by_name.items():
        sources = {str(r.get("source") or "") for r in rows}
        if len(rows) < 2 or len(sources) < 2:
            continue
        field_diffs: dict[str, list[str]] = {}
        for field in compare_fields:
            values = sorted({_clean_value(r.get(field)) for r in rows if _clean_value(r.get(field))})
            if len(values) > 1:
                field_diffs[field] = values
        if field_diffs:
            conflicts.append({
                "service_name": name,
                "sources": sorted(sources),
                "field_differences": field_diffs,
                "interpretation": (
                    "Parsed case and mounted hive disagree. Treat this as a source-conflict "
                    "to investigate, not as a merged finding."
                ),
            })
    return conflicts


def _score_service(svc: dict[str, Any], baseline: set[str]) -> dict[str, Any]:
    name = svc.get("service_name", "")
    image_path = svc.get("image_path", "")
    service_dll = svc.get("service_dll", "")
    payload = service_dll or image_path
    sort_score = 0
    evidence_flags: list[dict[str, str]] = []
    context_flags: list[dict[str, str]] = []
    coverage_gaps: list[dict[str, str]] = []
    followups: list[dict[str, Any]] = []
    baseline_known = name.strip().lower() in baseline

    if svc.get("is_svchost"):
        context_flags.append(_flag(
            "svchost_service",
            "context",
            "Service runs under svchost; ImagePath alone is not enough to identify the payload.",
        ))
        if service_dll:
            sort_score += 3
            evidence_flags.append(_flag(
                "svchost_servicedll_chain_present",
                "moderate",
                "Registry state links the svchost service to a Parameters\\ServiceDll payload.",
            ))
        else:
            sort_score += 1
            coverage_gaps.append(_flag(
                "svchost_service_without_visible_servicedll",
                "coverage_gap",
                "Parsed service data did not expose Parameters\\ServiceDll; inspect the SYSTEM hive before concluding.",
            ))
            followups.append({
                "tool_name": "service_persistence_gate",
                "reason": "Follow the SYSTEM hive Parameters\\ServiceDll for this svchost service.",
            })

    if service_dll and not baseline_known:
        sort_score += 2
        evidence_flags.append(_flag(
            "non_baseline_service_dll",
            "weak",
            "Service name is absent from the small built-in baseline and has a ServiceDll. This is a triage lead only.",
        ))

    if svc.get("is_auto_start"):
        sort_score += 1
        context_flags.append(_flag(
            "auto_start",
            "context",
            "Service is configured to start automatically.",
        ))
    if svc.get("is_localsystem"):
        sort_score += 1
        context_flags.append(_flag(
            "localsystem_account",
            "context",
            "Service runs as LocalSystem or equivalent.",
        ))

    lower_payload = payload.lower()
    if any(marker in lower_payload for marker in _SUSPICIOUS_PATH_MARKERS):
        sort_score += 2
        evidence_flags.append(_flag(
            "payload_in_user_writable_or_staging_path",
            "moderate",
            "Payload path is in a user-writable or staging location. Managed deployment tooling can also use these paths.",
        ))

    if service_dll and "\\windows\\system32\\" in _expand_env_path(service_dll).lower() and not baseline_known:
        coverage_gaps.append(_flag(
            "system32_dll_signature_not_verified",
            "coverage_gap",
            "Non-baseline System32 ServiceDll requires signature and hash verification before suspicion is raised.",
        ))

    if not baseline_known:
        context_flags.append(_flag(
            "service_name_not_in_builtin_baseline",
            "context",
            "Service name is absent from the intentionally small built-in baseline; legitimate enterprise services often appear here.",
        ))

    if payload:
        internal_path = windows_path_to_internal_path(payload)
        followups.append({
            "tool_name": "get_file_timestamps",
            "params": {"internal_path": internal_path},
            "reason": "Verify service payload creation and modification time from the mounted image.",
        })
        followups.append({
            "tool_name": "extract_file",
            "params": {"internal_path": internal_path},
            "reason": "Extract payload for hash, signature, strings, and static analysis. Do not execute.",
        })

    return {
        **svc,
        "baseline_known": baseline_known,
        "payload_path": payload,
        "payload_path_internal": windows_path_to_internal_path(payload) if payload else "",
        "evidence_flags": evidence_flags,
        "context_flags": context_flags,
        "coverage_gaps": coverage_gaps,
        "required_followups": followups,
        "_sort_score": sort_score,
    }


def _attach_payload_file_info(candidate: dict[str, Any], lookup: Callable[[str], dict[str, Any]]) -> None:
    internal_path = candidate.get("payload_path_internal") or windows_path_to_internal_path(candidate.get("payload_path", ""))
    if not internal_path:
        return
    try:
        info = lookup(internal_path)
    except Exception as e:
        info = {"error": str(e)}
    present = not bool(info.get("error"))
    candidate["payload_file"] = {
        "checked": True,
        "present": present,
        "internal_path": internal_path,
        "info": info,
    }


def _rescore_after_file_info(candidate: dict[str, Any]) -> None:
    payload_file = candidate.get("payload_file") or {}
    if payload_file.get("checked") and not payload_file.get("present"):
        candidate.setdefault("evidence_flags", []).append(_flag(
            "payload_missing_on_mounted_image",
            "moderate",
            "Service payload path was not present on the mounted image. Correlate with uninstall, cleanup, 7045/7036 events, and file deletion evidence.",
        ))
        candidate.setdefault("coverage_gaps", []).append(_flag(
            "missing_payload_event_context_not_verified",
            "coverage_gap",
            "Missing payload requires service install/stop/delete context before interpreting it as cleanup or evasion.",
        ))
        candidate["_sort_score"] = int(candidate.get("_sort_score", 0)) + 2


def windows_path_to_internal_path(path: str, default_drive: str = "c") -> str:
    """Convert a Windows service path to a mounted-image internal path."""
    extracted = _extract_path_token(_expand_env_path(path))
    if not extracted:
        return ""
    extracted = extracted.replace("\\", "/").strip().strip('"')
    if extracted.startswith("/"):
        return extracted
    if len(extracted) >= 2 and extracted[1] == ":":
        return f"/{extracted[0].lower()}:{extracted[2:]}"
    return f"/{default_drive.lower()}:/{extracted.lstrip('/')}"


def _extract_path_token(path: str) -> str:
    text = _clean_value(path)
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 1:
            return text[1:end]
    match = re.search(
        r"((?:[A-Za-z]:\\|\\SystemRoot\\|SystemRoot\\)[^\r\n\t\"]+?\.(?:exe|dll|sys|bat|cmd|ps1))",
        text,
        flags=re.IGNORECASE,
    )
    if match:
        token = match.group(1).strip()
        return re.split(r"\s+-[A-Za-z]", token, maxsplit=1)[0].strip()
    return text.split()[0].strip()


def _expand_env_path(path: str) -> str:
    text = _clean_value(path)
    replacements = {
        "%systemroot%": "C:\\Windows",
        "%windir%": "C:\\Windows",
        "%programdata%": "C:\\ProgramData",
        "%programfiles%": "C:\\Program Files",
        "%programfiles(x86)%": "C:\\Program Files (x86)",
        "\\systemroot\\": "C:\\Windows\\",
        "systemroot\\": "C:\\Windows\\",
    }
    lower = text.lower()
    for key, value in replacements.items():
        if lower.startswith(key):
            return value + text[len(key):]
    if lower.startswith("system32\\"):
        return "C:\\Windows\\" + text
    return text


def _control_sets(hive: Any) -> list[tuple[str, bool]]:
    current_num = None
    try:
        select = hive.get_key("\\Select")
        for value in _iter_values(select):
            if str(value.name).lower() == "current":
                current_num = int(value.value)
                break
    except Exception:
        current_num = None

    names: list[str] = []
    try:
        root_subkeys = list(hive.root.iter_subkeys())
    except Exception:
        root_subkeys = []
    for key in root_subkeys:
        name = str(key.name)
        if re.fullmatch(r"ControlSet\d{3}", name, flags=re.IGNORECASE):
            names.append(name)

    if current_num is not None:
        current = f"ControlSet{current_num:03d}"
        if current not in names:
            names.insert(0, current)

    names = sorted(set(names))
    return [(name, current_num is not None and name.lower() == f"controlset{current_num:03d}") for name in names]


def _values_dict(key: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for value in _iter_values(key):
        out[str(value.name)] = value.value
    return out


def _iter_values(key: Any) -> list[Any]:
    try:
        return list(key.iter_values())
    except Exception:
        pass
    try:
        return list(key.get_values())
    except Exception:
        pass
    try:
        return list(key.values or [])
    except Exception:
        return []


def _key_timestamp(key: Any) -> str:
    try:
        return str(key.header.last_modified)
    except Exception:
        return ""


def _field(row: dict[str, Any], *names: str) -> str:
    wanted = {_field_key(n) for n in names}
    for key, value in row.items():
        if _field_key(key) in wanted and value not in (None, ""):
            return _clean_value(value)
    return ""


def _field_key(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _extract_labeled_value(values: list[str], labels: tuple[str, ...]) -> str:
    label_pattern = "|".join(re.escape(label) for label in labels)
    next_label = (
        "ServiceDLL|ServiceDll|Service DLL|Image path|ImagePath|Start|Type|"
        "ObjectName|Account|User Account|DisplayName|Description"
    )
    for text in values:
        match = re.search(
            rf"(?:{label_pattern})\s*[:=]\s*(.+?)(?=\s+(?:{next_label})\s*[:=]|$)",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            return _clean_value(match.group(1).strip().strip('"'))
    return ""


def _clean_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for encoding in ("utf-16le", "utf-8", "latin1"):
            try:
                return value.decode(encoding, errors="ignore").replace("\x00", "").strip()
            except Exception:
                continue
        return repr(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(_clean_value(v) for v in value if v is not None)
    return str(value).replace("\x00", "").strip()


def _format_start(value: Any) -> str:
    try:
        num = int(value)
        return f"{_START_TYPES.get(num, 'Unknown')} ({num})"
    except Exception:
        return _clean_value(value)


def _format_type(value: Any) -> str:
    try:
        num = int(value)
    except Exception:
        return _clean_value(value)
    parts = [label for bit, label in _TYPE_FLAGS.items() if num & bit]
    return f"{' | '.join(parts) if parts else 'Unknown'} ({num})"


def _is_auto_start(value: str) -> bool:
    lower = value.lower()
    return lower in {"2", "auto", "automatic", "auto start"} or lower.startswith("auto") or "(2)" in lower or "자동" in lower


def _baseline_services() -> set[str]:
    try:
        with open(_REFERENCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(s).strip().lower() for s in data.get("services", []) if s}
    except Exception:
        return set()


def _service_search_blob(svc: dict[str, Any]) -> str:
    return " ".join(
        str(svc.get(k, "") or "").lower()
        for k in ("service_name", "display_name", "image_path", "service_dll", "registry_key_path")
    )


def _flag(name: str, weight: str, interpretation: str) -> dict[str, str]:
    return {
        "name": name,
        "weight": weight,
        "interpretation": interpretation,
    }


def _payload_gate_note(
    payload_checks: list[dict[str, Any]],
    missing_payloads: list[dict[str, Any]],
    unverified_payloads: list[dict[str, Any]],
) -> str:
    if not payload_checks and not unverified_payloads:
        return "No payload file checks were requested or no candidate had a payload path."
    if missing_payloads:
        return f"{len(missing_payloads)} candidate payload(s) were not present on the mounted image."
    if unverified_payloads:
        return f"{len(unverified_payloads)} candidate payload(s) still need mounted-image timestamp/hash/signature review."
    return f"{len(payload_checks)} candidate payload(s) were checked on the mounted image."
