"""Small semantic parser for Windows EVTX records.

This parser is intentionally narrow: it turns high-value Windows event XML
into structured fields that the existing suspicious/entity/correlation layers
already understand. It treats parsing failures as gaps, not negative evidence.
"""

from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import tempfile
from typing import Any
from xml.etree import ElementTree as ET


TARGET_EVENT_IDS = {
    4624, 4625, 4648, 4672, 4720, 4722, 4728, 4732, 4756, 4776, 7045, 1102,
}
EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_HEADER_SIZE = 0x1000
EVTX_CHUNK_SIZE = 0x10000


def parse_event_xml(xml_text: str, *, source_file: str = "") -> dict[str, Any]:
    """Parse one Windows event XML record into a normalized dictionary."""
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    event_data = root.find("e:EventData", ns)
    user_data = root.find("e:UserData", ns)

    event_id = _text(system.find("e:EventID", ns) if system is not None else None)
    time_node = system.find("e:TimeCreated", ns) if system is not None else None
    provider_node = system.find("e:Provider", ns) if system is not None else None

    fields: dict[str, str] = {}
    if event_data is not None:
        for data in event_data.findall("e:Data", ns):
            name = data.attrib.get("Name", "")
            if name:
                fields[name] = _text(data)
    if user_data is not None:
        for node in user_data.iter():
            tag = _strip_ns(node.tag)
            if tag and node is not user_data and (node.text or "").strip():
                fields[tag] = _text(node)

    return {
        "source_file": source_file,
        "event_id": int(event_id) if str(event_id).isdigit() else event_id,
        "timestamp": time_node.attrib.get("SystemTime", "") if time_node is not None else "",
        "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
        "channel": _text(system.find("e:Channel", ns) if system is not None else None),
        "computer": _text(system.find("e:Computer", ns) if system is not None else None),
        "fields": fields,
        "semantic": _semantic_label(int(event_id) if str(event_id).isdigit() else 0, fields),
    }


def parse_evtx_file(
    path: str | Path,
    *,
    target_event_ids: set[int] | None = None,
    limit: int = 0,
    best_effort: bool = False,
) -> dict[str, Any]:
    """Parse high-value records from an EVTX file using python-evtx if present."""
    target_event_ids = target_event_ids or TARGET_EVENT_IDS
    recovery = analyze_evtx_recovery(path)
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except Exception as exc:  # noqa: BLE001
        fallback = _parse_evtx_file_with_get_winevent(
            path,
            target_event_ids=target_event_ids,
            limit=limit,
            prior_error=str(exc),
        )
        if fallback.get("ok"):
            fallback["recovery"] = recovery
            return fallback
        if best_effort:
            return _parse_evtx_file_best_effort(
                path,
                target_event_ids=target_event_ids,
                limit=limit,
                prior_failures=fallback.get("parser_failures", []),
                recovery=recovery,
            )
        fallback["recovery"] = recovery
        return fallback

    records: list[dict[str, Any]] = []
    counts: Counter[int | str] = Counter()
    failures: list[dict[str, str]] = []
    try:
        with evtx.Evtx(str(path)) as log:
            for idx, record in enumerate(log.records()):
                try:
                    item = parse_event_xml(record.xml(), source_file=str(path))
                except Exception as exc:  # noqa: BLE001
                    failures.append({"record": str(idx), "error": str(exc)})
                    continue
                counts[item["event_id"]] += 1
                if item["event_id"] in target_event_ids:
                    records.append(item)
                    if limit and len(records) >= limit:
                        break
    except Exception as exc:  # noqa: BLE001
        fallback = _parse_evtx_file_with_get_winevent(
            path,
            target_event_ids=target_event_ids,
            limit=limit,
            prior_error=str(exc),
        )
        if fallback.get("ok"):
            fallback["recovery"] = recovery
            return fallback
        if best_effort:
            return _parse_evtx_file_best_effort(
                path,
                target_event_ids=target_event_ids,
                limit=limit,
                prior_failures=fallback.get("parser_failures", []),
                recovery=recovery,
            )
        fallback["recovery"] = recovery
        return fallback
    result = {
        "ok": True,
        "records": records,
        "record_count": len(records),
        "event_id_counts": dict(counts),
        "parser_failures": failures,
        "parser_backend": "python-evtx",
        "recovery": recovery,
    }
    return result


def analyze_evtx_recovery(path: str | Path, *, best_effort: bool = False) -> dict[str, Any]:
    """Return structural EVTX chunk coverage metadata without making absence claims."""
    path = Path(path)
    failures: list[dict[str, Any]] = []
    total_chunks = 0
    valid_chunks = 0
    partial_records_dropped = 0

    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            header = fh.read(EVTX_HEADER_SIZE)
            if not header.startswith(EVTX_FILE_MAGIC):
                failures.append({
                    "chunk_number": -1,
                    "chunk_offset": 0,
                    "error": "invalid EVTX file magic",
                    "records_unrecoverable": "unknown",
                })
            if size > EVTX_HEADER_SIZE:
                for chunk_number, chunk_offset in enumerate(range(EVTX_HEADER_SIZE, size, EVTX_CHUNK_SIZE)):
                    total_chunks += 1
                    fh.seek(chunk_offset)
                    chunk = fh.read(EVTX_CHUNK_SIZE)
                    if len(chunk) < EVTX_CHUNK_SIZE:
                        partial_records_dropped += 1
                        failures.append({
                            "chunk_number": chunk_number,
                            "chunk_offset": chunk_offset,
                            "error": "short EVTX chunk",
                            "records_unrecoverable": "unknown",
                        })
                        continue
                    if not chunk.startswith(EVTX_CHUNK_MAGIC):
                        failures.append({
                            "chunk_number": chunk_number,
                            "chunk_offset": chunk_offset,
                            "error": "invalid EVTX chunk magic",
                            "records_unrecoverable": "unknown",
                        })
                        continue
                    valid_chunks += 1
    except Exception as exc:  # noqa: BLE001
        failures.append({
            "chunk_number": -1,
            "chunk_offset": 0,
            "error": str(exc),
            "records_unrecoverable": "unknown",
        })

    chunks_failed = len(failures)
    if chunks_failed:
        coverage_note = f"Events from {chunks_failed} failed chunks are absent from results."
    else:
        coverage_note = f"All {total_chunks} chunks passed structural scan."
    return {
        "total_chunks_detected": total_chunks,
        "chunks_parsed_ok": valid_chunks,
        "chunks_failed": chunks_failed,
        "parser_failures": failures,
        "best_effort": bool(best_effort),
        "coverage_note": coverage_note,
        "partial_records_dropped": partial_records_dropped,
        "validation_scope": "structural_chunk_magic",
    }


def _parse_evtx_file_best_effort(
    path: str | Path,
    *,
    target_event_ids: set[int],
    limit: int = 0,
    prior_failures: list[dict[str, Any]] | None = None,
    recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Try one bounded recovery pass by rebuilding an EVTX from structurally valid chunks."""
    recovery = dict(recovery or analyze_evtx_recovery(path))
    recovery["best_effort"] = True
    recovery["recovery_attempts"] = ["valid_chunk_rebuild"]
    prior_failures = prior_failures or []

    rebuilt_path = _rebuild_evtx_from_valid_chunks(path)
    if not rebuilt_path:
        recovery["coverage_note"] = (
            recovery.get("coverage_note")
            or "No structurally valid chunks were available for best-effort parsing."
        )
        return {
            "ok": False,
            "records": [],
            "record_count": 0,
            "event_id_counts": {},
            "parser_failures": prior_failures,
            "parser_backend": "best-effort-unavailable",
            "recovery": recovery,
        }
    try:
        parsed = _parse_evtx_file_with_get_winevent(
            rebuilt_path,
            target_event_ids=target_event_ids,
            limit=limit,
            prior_error="best-effort valid chunk rebuild",
        )
        if parsed.get("ok"):
            parsed["records"] = sorted(
                parsed.get("records", []) or [],
                key=lambda record: str(record.get("timestamp", "") or ""),
            )
            parsed["record_count"] = len(parsed["records"])
            parsed["parser_backend"] = f"best-effort:{parsed.get('parser_backend', 'unknown')}"
            parsed["parser_failures"] = prior_failures + (parsed.get("parser_failures", []) or [])
            parsed["recovery"] = recovery
            return parsed
        parsed["parser_failures"] = prior_failures + (parsed.get("parser_failures", []) or [])
        parsed["recovery"] = recovery
        return parsed
    finally:
        try:
            os.remove(rebuilt_path)
        except Exception:
            pass


def _rebuild_evtx_from_valid_chunks(path: str | Path) -> str:
    path = Path(path)
    try:
        with path.open("rb") as src:
            header = src.read(EVTX_HEADER_SIZE)
            if not header.startswith(EVTX_FILE_MAGIC):
                return ""
            chunks: list[bytes] = []
            while True:
                chunk = src.read(EVTX_CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) == EVTX_CHUNK_SIZE and chunk.startswith(EVTX_CHUNK_MAGIC):
                    chunks.append(chunk)
            if not chunks:
                return ""
        fd, rebuilt = tempfile.mkstemp(prefix="evtx_recovered_", suffix=".evtx", dir=str(path.parent))
        with os.fdopen(fd, "wb") as dst:
            dst.write(header)
            for chunk in chunks:
                dst.write(chunk)
        return rebuilt
    except Exception:
        return ""


def summarize_semantic_events(records: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(str(r.get("semantic", {}).get("label") or "unknown") for r in records)
    event_ids = Counter(str(r.get("event_id")) for r in records)
    entities = Counter()
    for record in records:
        fields = record.get("fields", {}) or {}
        for key in ("TargetUserName", "SubjectUserName", "ServiceName", "IpAddress", "WorkstationName"):
            value = fields.get(key)
            if value and value not in {"-", "::1"}:
                entities[f"{key}:{value}"] += 1
    return {
        "record_count": len(records),
        "semantic_counts": dict(labels),
        "event_id_counts": dict(event_ids),
        "top_entities": entities.most_common(25),
    }


def filter_evtx_records(
    records: list[dict[str, Any]],
    *,
    event_ids: set[int] | None = None,
    keyword: str = "",
    start_date: str = "",
    end_date: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Filter parsed EVTX records with explicit query semantics."""
    keyword_lc = keyword.strip().lower()
    matched: list[dict[str, Any]] = []
    for record in records:
        event_id = record.get("event_id")
        if event_ids and event_id not in event_ids:
            continue
        ts = str(record.get("timestamp", "") or "")
        day = ts[:10]
        if start_date and day and day < start_date:
            continue
        if end_date and day and day > end_date:
            continue
        if keyword_lc and keyword_lc not in _record_search_text(record):
            continue
        matched.append(record)

    safe_limit = max(0, limit)
    safe_offset = max(0, offset)
    returned = matched[safe_offset:safe_offset + safe_limit] if safe_limit else matched[safe_offset:]
    return {
        "total": len(matched),
        "returned": len(returned),
        "offset": safe_offset,
        "limit": safe_limit,
        "truncated": safe_offset + len(returned) < len(matched),
        "records": returned,
        "summary": summarize_semantic_events(matched),
        "query_semantics": {
            "event_ids": sorted(event_ids) if event_ids else [],
            "keyword": keyword,
            "start_date": start_date,
            "end_date": end_date,
            "note": "Filters apply to parsed EVTX XML records, not live host event logs.",
        },
    }


def _semantic_label(event_id: int, fields: dict[str, str]) -> dict[str, Any]:
    if event_id == 4624:
        logon_type = fields.get("LogonType", "")
        return {"label": "rdp_logon" if logon_type == "10" else "successful_logon", "lane": "ingress_access"}
    if event_id == 4625:
        return {"label": "failed_logon", "lane": "ingress_access"}
    if event_id == 4648:
        return {"label": "explicit_credential_use", "lane": "credential_access"}
    if event_id == 7045:
        return {"label": "service_install", "lane": "persistence_cleanup"}
    if event_id in {4720, 4722}:
        return {"label": "account_created_or_enabled", "lane": "persistence_cleanup"}
    if event_id in {4728, 4732, 4756}:
        return {"label": "group_membership_added", "lane": "persistence_cleanup"}
    if event_id == 1102:
        return {"label": "audit_log_cleared", "lane": "persistence_cleanup"}
    return {"label": "high_value_event", "lane": "context"}


def _text(node: Any) -> str:
    return "" if node is None or node.text is None else str(node.text).strip()


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _record_search_text(record: dict[str, Any]) -> str:
    parts = [
        str(record.get("event_id", "")),
        str(record.get("provider", "")),
        str(record.get("channel", "")),
        str(record.get("computer", "")),
        str(record.get("source_file", "")),
    ]
    fields = record.get("fields", {}) or {}
    parts.extend(str(k) for k in fields.keys())
    parts.extend(str(v) for v in fields.values())
    semantic = record.get("semantic", {}) or {}
    parts.extend(str(v) for v in semantic.values())
    return " ".join(parts).lower()


def _parse_evtx_file_with_get_winevent(
    path: str | Path,
    *,
    target_event_ids: set[int],
    limit: int = 0,
    prior_error: str = "",
) -> dict[str, Any]:
    """Fallback EVTX parser for Windows hosts using Get-WinEvent -Path."""
    import base64
    import os
    import subprocess

    if os.name != "nt":
        return {
            "ok": False,
            "records": [],
            "event_id_counts": {},
            "parser_failures": [{
                "path": str(path),
                "error": f"python-evtx unavailable: {prior_error}; Get-WinEvent fallback requires Windows",
            }],
            "parser_backend": "unavailable",
        }

    ids = sorted(int(v) for v in target_event_ids)
    id_expr = " or ".join(f"EventID={event_id}" for event_id in ids)
    limit_int = max(0, int(limit or 0))
    script = f"""
$Path = $env:FW_EVTX_QUERY_PATH
$Filter = '*[System[({id_expr})]]'
$Events = Get-WinEvent -Path $Path -FilterXPath $Filter -ErrorAction Stop
if ({limit_int} -gt 0) {{
  $Events = $Events | Select-Object -First {limit_int}
}}
$Events | ForEach-Object {{
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.ToXml()))
}}
"""
    try:
        env = dict(os.environ)
        env["FW_EVTX_QUERY_PATH"] = str(path)
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env=env,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "records": [],
            "event_id_counts": {},
            "parser_failures": [{
                "path": str(path),
                "error": f"python-evtx unavailable: {prior_error}; Get-WinEvent fallback failed: {exc}",
            }],
            "parser_backend": "unavailable",
        }
    if proc.returncode != 0:
        if _get_winevent_no_matching_events(proc.stderr):
            return {
                "ok": True,
                "records": [],
                "record_count": 0,
                "event_id_counts": {},
                "parser_failures": [],
                "parser_backend": "get-winevent",
                "fallback_note": (
                    "python-evtx was unavailable; Get-WinEvent parsed the offline EVTX "
                    "but found no records matching the requested event filter."
                ),
            }
        return {
            "ok": False,
            "records": [],
            "event_id_counts": {},
            "parser_failures": [{
                "path": str(path),
                "error": f"python-evtx unavailable: {prior_error}; Get-WinEvent failed: {proc.stderr.strip()}",
            }],
            "parser_backend": "get-winevent",
        }

    records: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    counts: Counter[int | str] = Counter()
    for idx, line in enumerate(proc.stdout.splitlines()):
        if not line.strip():
            continue
        try:
            xml = base64.b64decode(line.strip()).decode("utf-8", errors="replace")
            item = parse_event_xml(xml, source_file=str(path))
            counts[item["event_id"]] += 1
            records.append(item)
        except Exception as exc:  # noqa: BLE001
            failures.append({"record": str(idx), "error": str(exc)})

    return {
        "ok": True,
        "records": records,
        "record_count": len(records),
        "event_id_counts": dict(counts),
        "parser_failures": failures,
        "parser_backend": "get-winevent",
        "fallback_note": "python-evtx was unavailable; parsed offline EVTX via Get-WinEvent -Path.",
    }


def _get_winevent_no_matching_events(stderr: str) -> bool:
    text = str(stderr or "")
    markers = (
        "NoMatchingEventsFound",
        "No events were found that match the specified selection criteria",
        "No events were found",
        "지정한 선택 조건과 일치하는 이벤트를 찾을 수 없습니다",
    )
    return any(marker.lower() in text.lower() for marker in markers)
