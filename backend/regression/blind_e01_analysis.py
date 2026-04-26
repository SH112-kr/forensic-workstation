"""Blind Windows E01 analysis runner.

This module intentionally does not load answer keys, writeups, comparison JSON,
or scenario-specific markers. It extracts only high-value artifacts from an E01
image and builds a conservative first-pass incident hypothesis.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.analysis.e01_artifact_cache import build_e01_artifact_cache
from core.analysis.evtx_semantic import parse_evtx_file, summarize_semantic_events
from core.analysis.prefetch_semantic import parse_prefetch_bytes
from core.analysis.timeline_schema import build_timeline_chains, make_timeline_event, sort_timeline_events, summarize_timeline
from core.connectors.e01_image import E01ImageConnector


SUSPICIOUS_PREFETCH_TERMS = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "psexec.exe",
    "procdump.exe",
    "mimikatz.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "whoami.exe",
    "vssadmin.exe",
    "wevtutil.exe",
    "sdelete.exe",
}


def run_blind_e01_analysis(
    image_path: str | Path,
    *,
    case_id: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    connector = E01ImageConnector()
    try:
        metadata = connector.connect(str(image_path))
        cache = build_e01_artifact_cache(connector, source_id=case_id, limit_per_pattern=500)
        evtx = _analyze_evtx(connector, cache, out_dir, case_id)
        browser = _analyze_browser_history(connector, cache, out_dir, case_id)
        remote_access = _analyze_remote_access(connector, cache)
        notifications = _analyze_notifications(connector, cache)
        prefetch = _analyze_prefetch(connector, cache)
        timeline = _build_integrated_timeline(evtx, browser, remote_access, prefetch)
        assessment = _assess(metadata, cache, evtx, browser, prefetch, remote_access)
        result = {
            "schema_version": "fw.blind_e01_analysis.v1",
            "case_id": case_id,
            "image_path": str(image_path),
            "answer_material_used": False,
            "safety": {
                "static_analysis_only": True,
                "executables_executed": False,
                "known_answer_material_loaded": False,
            },
            "metadata": _compact_metadata(metadata),
            "artifact_counts": cache.get("artifact_type_counts", {}),
            "evtx": evtx,
            "browser": browser,
            "remote_access": remote_access,
            "notifications": notifications,
            "prefetch": prefetch,
            "timeline": timeline,
            "assessment": assessment,
            "limitations": _limitations(cache, evtx),
        }
    finally:
        connector.disconnect()

    json_path = out_dir / f"{case_id}_blind_analysis.json"
    md_path = out_dir / f"{case_id}_blind_analysis.md"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    md_path.write_text(_render_markdown(result), encoding="utf-8")
    result["output_json"] = str(json_path)
    result["output_markdown"] = str(md_path)
    return result


def _analyze_evtx(connector: E01ImageConnector, cache: dict[str, Any], out_dir: Path, case_id: str) -> dict[str, Any]:
    extracted_dir = out_dir / f"{case_id}_evtx"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    logs = [
        record["value"]["internal_path"]
        for record in cache.get("records", [])
        if record.get("artifact_type") == "EVTX Candidate"
    ]
    parsed_logs = []
    all_records = []
    failures = []
    for internal_path in logs:
        safe_name = internal_path.strip("/").replace("/", "_").replace(":", "")
        output_path = extracted_dir / safe_name
        try:
            connector.extract_file(internal_path, str(output_path))
            parsed = parse_evtx_file(output_path, limit=0)
        except Exception as exc:  # noqa: BLE001
            failures.append({"path": internal_path, "error": str(exc)})
            continue
        records = parsed.get("records", [])
        all_records.extend(records)
        parsed_logs.append({
            "internal_path": internal_path,
            "extracted_path": str(output_path),
            "ok": parsed.get("ok", False),
            "target_record_count": len(records),
            "event_id_counts": parsed.get("event_id_counts", {}),
            "semantic_counts": summarize_semantic_events(records).get("semantic_counts", {}),
            "parser_failures": parsed.get("parser_failures", [])[:25],
        })
    return {
        "logs_seen": logs,
        "parsed_logs": parsed_logs,
        "summary": summarize_semantic_events(all_records),
        "interesting_events": _interesting_events(all_records),
        "failures": failures,
    }


def _interesting_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for record in sorted(records, key=lambda r: str(r.get("timestamp", ""))):
        semantic = record.get("semantic", {}) or {}
        label = semantic.get("label", "")
        if label not in {
            "failed_logon",
            "rdp_logon",
            "explicit_credential_use",
            "service_install",
            "account_created_or_enabled",
            "group_membership_added",
            "audit_log_cleared",
        }:
            continue
        fields = record.get("fields", {}) or {}
        out.append({
            "timestamp": record.get("timestamp", ""),
            "event_id": record.get("event_id"),
            "label": label,
            "source_file": record.get("source_file", ""),
            "computer": record.get("computer", ""),
            "user": fields.get("TargetUserName") or fields.get("SubjectUserName") or fields.get("AccountName", ""),
            "ip": fields.get("IpAddress", ""),
            "workstation": fields.get("WorkstationName", ""),
            "service": fields.get("ServiceName", ""),
            "service_image_path": fields.get("ImagePath", ""),
            "service_type": fields.get("ServiceType", ""),
            "service_start_type": fields.get("StartType", ""),
            "service_classification": _classify_service_install(fields) if label == "service_install" else "",
            "process": fields.get("ProcessName", ""),
        })
    return out[:500]


def _classify_service_install(fields: dict[str, str]) -> str:
    name = str(fields.get("ServiceName", "")).lower()
    image_path = str(fields.get("ImagePath", "")).lower().replace("/", "\\")
    service_type = str(fields.get("ServiceType", "")).lower()
    if "kernel mode driver" in service_type and "\\system32\\drivers\\" in image_path:
        return "likely_system_driver"
    if image_path.startswith("\\systemroot\\system32\\drivers\\"):
        return "likely_system_driver"
    system_role_terms = (
        "active directory",
        "dns server",
        "ds role server",
        "dfs ",
        "kerberos",
        "file replication",
        "intersite messaging",
        "vmware ",
        "microsoft ",
        "intel(",
        "intel ",
    )
    if any(term in name for term in system_role_terms):
        return "likely_platform_or_role_service"
    risky_locations = (
        "\\users\\",
        "\\appdata\\",
        "\\programdata\\",
        "\\temp\\",
        "\\public\\",
        "\\downloads\\",
        "\\recycle",
    )
    if any(term in image_path for term in risky_locations):
        return "unusual_service_path"
    if image_path.endswith(".exe") and "\\system32\\" in image_path:
        return "system32_executable_service_needs_context"
    if image_path.endswith(".exe"):
        return "executable_service_needs_context"
    return "unknown_service_install"


def _analyze_browser_history(
    connector: E01ImageConnector,
    cache: dict[str, Any],
    out_dir: Path,
    case_id: str,
) -> dict[str, Any]:
    histories = [
        record["value"]["internal_path"]
        for record in cache.get("records", [])
        if record.get("artifact_type") == "Browser History Candidate"
    ]
    histories = _dedupe_internal_paths(histories)
    output = []
    for internal_path in histories:
        try:
            data = connector.read_file_content(internal_path, max_size=100_000_000)
        except Exception as exc:  # noqa: BLE001
            output.append({"internal_path": internal_path, "ok": False, "error": str(exc)})
            continue
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            output.append(_read_chrome_history(tmp_path, internal_path))
        finally:
            tmp_path.unlink(missing_ok=True)
    return {
        "history_files": histories,
        "parsed": output,
    }


def _read_chrome_history(path: Path, internal_path: str) -> dict[str, Any]:
    visits = []
    downloads = []
    try:
        shutil.copy2(path, f"{path}.copy")
        db_path = Path(f"{path}.copy")
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            for row in conn.execute(
                "select url, title, visit_count, typed_count, last_visit_time from urls "
                "order by last_visit_time desc limit 50"
            ):
                item = dict(row)
                item["last_visit_time_utc"] = _chrome_time(item.get("last_visit_time"))
                visits.append(item)
            tables = {r[0] for r in conn.execute("select name from sqlite_master where type='table'")}
            if "downloads" in tables:
                for row in conn.execute("select * from downloads order by start_time desc limit 25"):
                    item = {key: _jsonable(row[key]) for key in row.keys()}
                    for field in ("start_time", "end_time", "last_access_time"):
                        if field in item:
                            item[f"{field}_utc"] = _chrome_time(item.get(field))
                    downloads.append(item)
        finally:
            conn.close()
            db_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        return {"internal_path": internal_path, "ok": False, "error": str(exc)}
    return {
        "internal_path": internal_path,
        "ok": True,
        "visit_count": len(visits),
        "download_count": len(downloads),
        "top_visits": visits,
        "downloads": downloads,
    }


def _dedupe_internal_paths(paths: list[str]) -> list[str]:
    out = []
    seen = set()
    for path in paths:
        key = path.replace("\\", "/")
        key = key.replace("/c:/Documents and Settings/", "/c:/Users/")
        key = key.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _chrome_time(value: Any) -> str:
    try:
        raw = int(value or 0)
    except Exception:
        return ""
    if raw <= 0:
        return ""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return (epoch + timedelta(microseconds=raw)).isoformat().replace("+00:00", "Z")


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    return value


def _analyze_prefetch(connector: E01ImageConnector, cache: dict[str, Any]) -> dict[str, Any]:
    names = []
    suspicious = []
    parsed = []
    for record in cache.get("records", []):
        if record.get("artifact_type") != "Prefetch Candidate":
            continue
        path = str(record.get("value", {}).get("internal_path", ""))
        name = Path(path).name
        app = name.split("-", 1)[0].lower()
        names.append(name)
        if app in SUSPICIOUS_PREFETCH_TERMS:
            suspicious.append(path)
        try:
            data = connector.read_file_content(path, max_size=1_000_000)
            item = parse_prefetch_bytes(data, source_path=path)
        except Exception as exc:  # noqa: BLE001
            item = {"ok": False, "source_path": path, "error": str(exc)}
        if item.get("ok"):
            parsed.append(item)
    return {
        "count": len(names),
        "parsed_count": len(parsed),
        "suspicious_count": len(suspicious),
        "suspicious_prefetch": suspicious[:100],
        "parsed": parsed[:500],
        "notable_prefetch": _notable_prefetch(parsed),
        "sample": names[:100],
    }


def _notable_prefetch(parsed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in parsed:
        exe = str(item.get("executable_name", "")).lower()
        if exe in SUSPICIOUS_PREFETCH_TERMS or "teamviewer" in exe:
            out.append({
                "source_path": item.get("source_path"),
                "executable_name": item.get("executable_name"),
                "run_count": item.get("run_count"),
                "latest_run_time_utc": item.get("latest_run_time_utc"),
                "last_run_times_utc": item.get("last_run_times_utc", []),
                "evidence_state": item.get("evidence_state"),
            })
    return out[:100]


def _analyze_remote_access(connector: E01ImageConnector, cache: dict[str, Any]) -> dict[str, Any]:
    artifacts = [
        record["value"]["internal_path"]
        for record in cache.get("records", [])
        if record.get("artifact_type") == "Remote Access Log Candidate"
    ]
    parsed = []
    for path in _dedupe_internal_paths(artifacts):
        try:
            data = connector.read_file_content(path, max_size=5_000_000)
        except Exception as exc:  # noqa: BLE001
            parsed.append({"internal_path": path, "ok": False, "error": str(exc)})
            continue
        text = data.decode("utf-8-sig", errors="ignore")
        if path.lower().endswith("connections_incoming.txt"):
            parsed.append({
                "internal_path": path,
                "ok": True,
                "type": "teamviewer_connections_incoming",
                "connections": _parse_teamviewer_connections(text),
            })
        else:
            parsed.append({
                "internal_path": path,
                "ok": True,
                "type": "teamviewer_log",
                "line_count": len(text.splitlines()),
                "interesting_lines": [
                    line for line in text.splitlines()
                    if any(term in line.lower() for term in ("connect", "session", "service install", "remote"))
                ][:100],
            })
    hosts = Counter()
    for item in parsed:
        for conn in item.get("connections", []):
            if conn.get("remote_host"):
                hosts[conn["remote_host"]] += 1
    return {
        "artifacts": artifacts,
        "parsed": parsed,
        "unique_remote_hosts": sorted(hosts),
        "remote_host_counts": dict(hosts),
    }


def _parse_teamviewer_connections(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        rows.append({
            "teamviewer_id": parts[0].strip(),
            "remote_host": parts[1].strip(),
            "start_local": parts[2].strip(),
            "end_local": parts[3].strip(),
            "user": parts[4].strip(),
            "mode": parts[5].strip(),
            "session_guid": parts[6].strip() if len(parts) > 6 else "",
        })
    return rows


def _build_integrated_timeline(
    evtx: dict[str, Any],
    browser: dict[str, Any],
    remote_access: dict[str, Any],
    prefetch: dict[str, Any],
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    events.extend(_timeline_from_evtx(evtx))
    events.extend(_timeline_from_browser(browser))
    events.extend(_timeline_from_remote_access(remote_access))
    events.extend(_timeline_from_prefetch(prefetch))
    ordered = sort_timeline_events(events)
    return {
        "schema_version": "fw.timeline.v1",
        "summary": summarize_timeline(ordered),
        "events": ordered[:1000],
        "chains": build_timeline_chains(ordered),
        "limitations": [
            "TeamViewer connection timestamps are treated as local_or_unknown unless independently normalized.",
            "Timeline proximity is a lead for follow-up, not proof of causation.",
            "Prefetch events remain pending_corroboration and cannot independently produce a strong verdict.",
        ],
    }


def _timeline_from_evtx(evtx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    role_by_label = {
        "failed_logon": "ingress_attempt",
        "rdp_logon": "remote_access",
        "explicit_credential_use": "credential_use",
        "service_install": "persistence",
        "account_created_or_enabled": "account_change",
        "group_membership_added": "privilege_change",
        "audit_log_cleared": "anti_forensics",
    }
    for item in evtx.get("interesting_events", []) or []:
        label = item.get("label", "")
        sequence_role = role_by_label.get(label, "event")
        confidence = "moderate"
        notes = ""
        if label == "service_install":
            service_class = item.get("service_classification", "")
            if service_class in {"likely_system_driver", "likely_platform_or_role_service"}:
                sequence_role = "system_service_install"
                confidence = "low"
                notes = f"classification={service_class}"
            else:
                notes = f"classification={service_class or 'unknown'}"
        out.append(make_timeline_event(
            event_time=item.get("timestamp", ""),
            event_time_type=f"evtx_{label}",
            source_artifact="evtx",
            sequence_role=sequence_role,
            actor=item.get("user", ""),
            asset=item.get("computer", ""),
            object=item.get("service_image_path") or item.get("service") or item.get("process") or item.get("ip") or item.get("workstation", ""),
            confidence=confidence,
            corroboration_state="source_observed",
            source_path=item.get("source_file", ""),
            notes=notes,
            raw_ref={"event_id": item.get("event_id"), "label": label, "service": item.get("service", "")},
        ))
    return out


def _timeline_from_browser(browser: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for history in browser.get("parsed", []) or []:
        if not history.get("ok"):
            continue
        actor = _actor_from_internal_path(history.get("internal_path", ""))
        for visit in history.get("top_visits", []) or []:
            if not visit.get("last_visit_time_utc"):
                continue
            out.append(make_timeline_event(
                event_time=visit.get("last_visit_time_utc", ""),
                event_time_type="browser_last_visit",
                source_artifact="browser_history",
                sequence_role="browser_activity",
                actor=actor,
                object=visit.get("url", ""),
                confidence="moderate",
                corroboration_state="source_observed",
                source_path=history.get("internal_path", ""),
                raw_ref={"title": visit.get("title", ""), "visit_count": visit.get("visit_count")},
            ))
        for download in history.get("downloads", []) or []:
            target = download.get("target_path") or download.get("current_path") or download.get("tab_url") or ""
            for field, role in (("start_time_utc", "download"), ("end_time_utc", "download_complete")):
                if not download.get(field):
                    continue
                out.append(make_timeline_event(
                    event_time=download.get(field, ""),
                    event_time_type=f"browser_{field}",
                    source_artifact="browser_downloads",
                    sequence_role=role,
                    actor=actor,
                    object=target,
                    confidence="moderate",
                    corroboration_state="source_observed",
                    source_path=history.get("internal_path", ""),
                    raw_ref={"url": download.get("tab_url") or download.get("url", ""), "mime_type": download.get("mime_type", "")},
                ))
    return out


def _timeline_from_remote_access(remote_access: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for artifact in remote_access.get("parsed", []) or []:
        source_path = artifact.get("internal_path", "")
        for conn in artifact.get("connections", []) or []:
            common = {
                "source_artifact": "remote_access_log",
                "sequence_role": "remote_access",
                "actor": conn.get("user", ""),
                "asset": conn.get("remote_host", ""),
                "object": f"TeamViewer {conn.get('mode', '')}".strip(),
                "confidence": "moderate",
                "corroboration_state": "source_observed",
                "source_path": source_path,
                "timezone_note": "local_or_unknown",
                "raw_ref": {"teamviewer_id": conn.get("teamviewer_id", ""), "session_guid": conn.get("session_guid", "")},
            }
            if conn.get("start_local"):
                out.append(make_timeline_event(
                    event_time=conn.get("start_local", ""),
                    event_time_type="teamviewer_session_start_local",
                    **common,
                ))
            if conn.get("end_local"):
                out.append(make_timeline_event(
                    event_time=conn.get("end_local", ""),
                    event_time_type="teamviewer_session_end_local",
                    **common,
                ))
    return out


def _timeline_from_prefetch(prefetch: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in prefetch.get("notable_prefetch", []) or []:
        for timestamp in item.get("last_run_times_utc", []) or []:
            out.append(make_timeline_event(
                event_time=timestamp,
                event_time_type="prefetch_last_run",
                source_artifact="prefetch",
                sequence_role="execution",
                object=item.get("executable_name", ""),
                confidence="strong",
                corroboration_state=item.get("evidence_state", "pending_corroboration"),
                source_path=item.get("source_path", ""),
                notes="Execution evidence only; not standalone maliciousness evidence.",
                raw_ref={"run_count": item.get("run_count")},
            ))
    return out


def _actor_from_internal_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "users" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _analyze_notifications(connector: E01ImageConnector, cache: dict[str, Any]) -> dict[str, Any]:
    paths = [
        record["value"]["internal_path"]
        for record in cache.get("records", [])
        if record.get("artifact_type") == "Windows Notification DB Candidate"
    ]
    parsed = []
    for internal_path in _dedupe_internal_paths(paths):
        try:
            data = connector.read_file_content(internal_path, max_size=20_000_000)
        except Exception as exc:  # noqa: BLE001
            parsed.append({"internal_path": internal_path, "ok": False, "error": str(exc)})
            continue
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            parsed.append(_read_notification_db(tmp_path, internal_path))
        finally:
            tmp_path.unlink(missing_ok=True)
    return {"artifacts": paths, "parsed": parsed}


def _read_notification_db(path: Path, internal_path: str) -> dict[str, Any]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            tables = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
            samples = {}
            for table in tables[:20]:
                try:
                    rows = conn.execute(f"select * from [{table}] limit 10").fetchall()
                except Exception:
                    continue
                samples[table] = [{key: _jsonable(row[key]) for key in row.keys()} for row in rows]
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        return {"internal_path": internal_path, "ok": False, "error": str(exc)}
    return {"internal_path": internal_path, "ok": True, "tables": tables, "samples": samples}


def _assess(
    metadata: dict[str, Any],
    cache: dict[str, Any],
    evtx: dict[str, Any],
    browser: dict[str, Any],
    prefetch: dict[str, Any],
    remote_access: dict[str, Any],
) -> dict[str, Any]:
    sem = evtx.get("summary", {}).get("semantic_counts", {}) or {}
    interesting = evtx.get("interesting_events", []) or []
    browser_downloads = sum(len(item.get("downloads", [])) for item in browser.get("parsed", []) if item.get("ok"))
    service_classes = Counter(
        item.get("service_classification", "unknown_service_install")
        for item in interesting
        if item.get("label") == "service_install"
    )
    service_followup_count = sum(
        count for service_class, count in service_classes.items()
        if service_class not in {"likely_system_driver", "likely_platform_or_role_service"}
    )
    signals = []
    if sem.get("failed_logon", 0):
        signals.append("failed_logons_present")
    if sem.get("rdp_logon", 0):
        signals.append("rdp_logons_present")
    if service_followup_count:
        signals.append("service_install_events_present")
    if sem.get("explicit_credential_use", 0):
        signals.append("explicit_credential_use_present")
    if prefetch.get("suspicious_count", 0):
        signals.append("common_admin_tool_prefetch_present")
    if browser_downloads:
        signals.append("browser_download_history_present")
    if remote_access.get("unique_remote_hosts"):
        signals.append("remote_access_application_logs_present")

    if "remote_access_application_logs_present" in signals:
        verdict = "third_party_remote_access_activity_observed"
    elif {"failed_logons_present", "rdp_logons_present"} <= set(signals):
        verdict = "suspicious_remote_access_possible"
    elif "service_install_events_present" in signals:
        verdict = "persistence_or_admin_service_activity_possible"
    elif signals:
        verdict = "activity_requires_followup"
    else:
        verdict = "insufficient_incident_signal_from_first_pass"
    return {
        "verdict": verdict,
        "allow_strong_conclusion": False,
        "signals": signals,
        "top_hypotheses": [
            {
                "hypothesis": "interactive or remote user activity",
                "support": [s for s in signals if s in {"failed_logons_present", "rdp_logons_present", "browser_download_history_present", "remote_access_application_logs_present"}],
                "caveat": "Remote access evidence does not prove compromise without authorization context.",
            },
            {
                "hypothesis": "persistence or administrative tooling",
                "support": [s for s in signals if s in {"service_install_events_present", "common_admin_tool_prefetch_present"}],
                "caveat": "Service and LOLBin traces require timeline/process correlation before malicious verdict.",
            },
        ],
        "key_events_sample": interesting[:50],
        "metadata_hint": {
            "hostname": metadata.get("hostname", ""),
            "os_type": metadata.get("os_type", ""),
            "artifact_counts": cache.get("artifact_type_counts", {}),
        },
        "service_install_class_counts": dict(service_classes),
        "service_install_followup_count": service_followup_count,
        "remote_access_hosts": remote_access.get("unique_remote_hosts", []),
    }


def _limitations(cache: dict[str, Any], evtx: dict[str, Any]) -> list[str]:
    limitations = [
        "Blind first pass only; no public writeup or answer key has been loaded.",
        "Registry hive semantic parsing is not yet implemented in this runner.",
        "Prefetch run counts and last-run timestamps are decoded as pending_corroboration evidence only.",
    ]
    if evtx.get("failures"):
        limitations.append("Some EVTX files failed extraction or parsing.")
    if cache.get("parser_failures"):
        limitations.append("Lazy artifact inventory reported parser failures.")
    return limitations


def _compact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": metadata.get("hostname", ""),
        "os_type": metadata.get("os_type", ""),
        "volumes": metadata.get("volumes", []),
        "root_listing": metadata.get("root_listing", [])[:25],
    }


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Blind E01 Analysis: {result['case_id']}",
        "",
        f"- answer_material_used: {result['answer_material_used']}",
        f"- verdict: {result['assessment']['verdict']}",
        f"- allow_strong_conclusion: {result['assessment']['allow_strong_conclusion']}",
        f"- signals: {', '.join(result['assessment']['signals']) or 'none'}",
        "",
        "## Artifact Counts",
    ]
    for key, value in sorted(result.get("artifact_counts", {}).items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## EVTX Summary"])
    for key, value in sorted(result.get("evtx", {}).get("summary", {}).get("semantic_counts", {}).items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Prefetch Suspicious Names"])
    for item in result.get("prefetch", {}).get("suspicious_prefetch", [])[:50]:
        lines.append(f"- {item}")
    lines.extend(["", "## Prefetch Parsed Notables"])
    for item in result.get("prefetch", {}).get("notable_prefetch", [])[:50]:
        lines.append(
            f"- {item.get('executable_name')} run_count={item.get('run_count')} "
            f"latest={item.get('latest_run_time_utc')} state={item.get('evidence_state')}"
        )
    lines.extend(["", "## Browser History Files"])
    for item in result.get("browser", {}).get("parsed", []):
        lines.append(f"- {item.get('internal_path')}: ok={item.get('ok')} visits={item.get('visit_count', 0)} downloads={item.get('download_count', 0)}")
    lines.extend(["", "## Remote Access"])
    ra = result.get("remote_access", {})
    lines.append(f"- unique_remote_hosts: {', '.join(ra.get('unique_remote_hosts', [])) or 'none'}")
    for item in ra.get("parsed", []):
        lines.append(f"- {item.get('internal_path')}: ok={item.get('ok')} type={item.get('type', '')}")
        for conn in item.get("connections", [])[:10]:
            lines.append(
                f"  - {conn.get('remote_host')} {conn.get('start_local')} -> {conn.get('end_local')} user={conn.get('user')} mode={conn.get('mode')}"
            )
    lines.extend(["", "## Integrated Timeline"])
    timeline = result.get("timeline", {})
    summary = timeline.get("summary", {})
    lines.append(f"- event_count: {summary.get('event_count', 0)}")
    lines.append(f"- first_event_time: {summary.get('first_event_time', '')}")
    lines.append(f"- last_event_time: {summary.get('last_event_time', '')}")
    lines.append(f"- sequence_role_counts: {summary.get('sequence_role_counts', {})}")
    for item in timeline.get("events", [])[:100]:
        lines.append(
            f"- {item.get('event_time')} [{item.get('timezone')}] {item.get('sequence_role')} "
            f"{item.get('source_artifact')} actor={item.get('actor')} asset={item.get('asset')} object={item.get('object')}"
        )
    lines.extend(["", "## Timeline Candidate Chains"])
    for chain in timeline.get("chains", [])[:10]:
        lines.append(
            f"- {chain.get('anchor_time')} role={chain.get('anchor_role')} "
            f"object={chain.get('anchor_object')} events={chain.get('event_count')}"
        )
    lines.extend(["", "## Notification DBs"])
    for item in result.get("notifications", {}).get("parsed", []):
        lines.append(f"- {item.get('internal_path')}: ok={item.get('ok')} tables={', '.join(item.get('tables', [])[:8])}")
    lines.extend(["", "## Limitations"])
    for item in result.get("limitations", []):
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image_path")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", default=str(Path("..") / "external" / "dfir_validation" / "blind_runs"))
    args = parser.parse_args()
    result = run_blind_e01_analysis(args.image_path, case_id=args.case_id, output_dir=args.output_dir)
    print(f"ok output={result['output_json']} report={result['output_markdown']}")
    print(f"verdict={result['assessment']['verdict']} signals={','.join(result['assessment']['signals'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
