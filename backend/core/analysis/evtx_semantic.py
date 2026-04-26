"""Small semantic parser for Windows EVTX records.

This parser is intentionally narrow: it turns high-value Windows event XML
into structured fields that the existing suspicious/entity/correlation layers
already understand. It treats parsing failures as gaps, not negative evidence.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


TARGET_EVENT_IDS = {
    4624, 4625, 4648, 4672, 4720, 4722, 4728, 4732, 4756, 4776, 7045, 1102,
}


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


def parse_evtx_file(path: str | Path, *, target_event_ids: set[int] | None = None, limit: int = 0) -> dict[str, Any]:
    """Parse high-value records from an EVTX file using python-evtx if present."""
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "records": [],
            "event_id_counts": {},
            "parser_failures": [{"path": str(path), "error": f"python-evtx unavailable: {exc}"}],
        }

    target_event_ids = target_event_ids or TARGET_EVENT_IDS
    records: list[dict[str, Any]] = []
    counts: Counter[int | str] = Counter()
    failures: list[dict[str, str]] = []
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
    return {
        "ok": True,
        "records": records,
        "record_count": len(records),
        "event_id_counts": dict(counts),
        "parser_failures": failures,
    }


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
