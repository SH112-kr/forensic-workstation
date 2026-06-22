"""IOC / MITRE relationship graph composition.

The graph is a review aid, not a verdict engine. IOC nodes are observables,
manual nodes are analyst-only context, and IOC nodes are not directly mapped to
MITRE techniques unless an existing finding supplies that relationship through
a finding node.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from core.analysis.ioc_extractor import KNOWN_GOOD_DOMAINS, PATTERNS
from core.analysis.mitre_mapper import TECHNIQUE_DB, get_attack_narrative

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
ALIAS_OR_HMAC_RE = re.compile(r"\b[A-Z][A-Z0-9]*_[0-9]{3}\b|\b[A-Z]+_HMAC_[a-f0-9]{12}\b")


def build_ioc_mitre_graph(
    connectors: dict[str, Any],
    *,
    ioc_types: str = "",
    exclude_private_ips: bool = True,
    exclude_known_good: bool = True,
    max_iocs: int = 120,
    max_findings: int = 80,
    manual_observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build graph-ready IOC/MITRE context from active case connectors."""
    warnings: list[str] = []
    limitations = [
        "IOC nodes are observables extracted from artifacts; they are not maliciousness verdicts.",
        "IOC and MITRE technique nodes are not directly connected unless a finding supplies the behavior.",
        "Edges through artifact families indicate shared evidence context, not causation.",
        "Analyst-added graph nodes are visual context only and are not fed back into LLM analysis by this graph builder.",
        "Context IOC nodes are low-signal observables. Hide or show them as review aids, not as incident conclusions.",
    ]
    source_mode = _source_mode(connectors)
    case_label = _case_label(connectors)

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    case_id = _merge_graph_node(nodes, "case:active", "case", case_label, subtitle=source_mode.upper())

    ioc_payload, ioc_warning = _extract_iocs_for_graph(
        connectors,
        ioc_types=ioc_types,
        exclude_private_ips=exclude_private_ips,
        exclude_known_good=exclude_known_good,
        max_iocs=max_iocs,
    )
    if ioc_warning:
        warnings.append(ioc_warning)

    for ioc in ioc_payload.get("iocs", [])[:max_iocs]:
        ioc_type = str(ioc.get("ioc_type") or "ioc")
        value = str(ioc.get("value") or "")
        if not value:
            continue
        ioc_id = _merge_graph_node(
            nodes,
            f"ioc:{ioc_type}:{value.lower()}",
            "ioc",
            value,
            subtitle=ioc_type.upper(),
            ioc_type=ioc_type,
            count=int(ioc.get("count") or 1),
            confidence=ioc.get("confidence") or "context",
            source_reason=ioc.get("source_reason") or "case text match",
            source_artifact_types=ioc.get("source_artifact_types") or [],
        )
        source_types = list(ioc.get("source_artifact_types") or [])
        if not source_types:
            _merge_graph_edge(edges, case_id, ioc_id, "observed_ioc", "observed", weight=int(ioc.get("count") or 1))
        for artifact_type in source_types[:12]:
            if not artifact_type:
                continue
            artifact_id = _merge_graph_node(
                nodes,
                f"artifact:{artifact_type}",
                "artifact",
                str(artifact_type),
                subtitle="artifact family",
            )
            _merge_graph_edge(edges, case_id, artifact_id, "has_artifact_family", "contains")
            _merge_graph_edge(edges, artifact_id, ioc_id, "contains_ioc", "contains IOC", weight=int(ioc.get("count") or 1))

    findings = []
    mitre_payload = {"narrative": [], "summary": {}}
    axiom = _active_axiom(connectors)
    if axiom is None:
        warnings.append("MITRE finding graph is unavailable without a parsed AXIOM/KAPE artifact connector.")
        if source_mode == "raw_image_sidecar":
            limitations.append(
                "Raw sidecar graph output is lower-bound IOC/artifact context; ATT&CK technique nodes require parsed finding rules."
            )
    else:
        try:
            from core.analysis.suspicious import find_suspicious

            query_source = getattr(axiom, "artifact_queries", axiom)
            suspicious = find_suspicious(query_source)
            findings = list(suspicious.get("findings", []) or [])[:max_findings]
            mitre_payload = get_attack_narrative(findings)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"MITRE mapping unavailable: {exc}")

    _add_finding_nodes(nodes, edges, case_id, findings)
    if not any(n.get("type") == "mitre" for n in nodes.values()):
        limitations.append("No ATT&CK technique node was produced; absence here is not evidence that no ATT&CK behavior occurred.")

    manual_count = _add_manual_observations(nodes, edges, case_id, manual_observations)

    return {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_mode": source_mode,
        "nodes": sorted(nodes.values(), key=lambda n: (n["type"], n["label"])),
        "edges": sorted(edges.values(), key=lambda e: e["id"]),
        "stats": _graph_stats(nodes, edges, manual_count),
        "ioc_summary": {
            "total_iocs": ioc_payload.get("total_iocs", 0),
            "by_type": ioc_payload.get("by_type", {}),
            "truncated": ioc_payload.get("truncated", False),
        },
        "mitre_summary": mitre_payload.get("summary", {}),
        "warnings": warnings,
        "analysis_limitations": limitations,
    }


def build_analysis_session_graph(
    events: list[dict[str, Any]],
    *,
    exclude_private_ips: bool = True,
    exclude_known_good: bool = True,
    max_iocs: int = 140,
    max_findings: int = 120,
    manual_observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a graph only from accumulated MCP analysis events."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    session_id = _merge_graph_node(nodes, "session:mcp", "case", "LLM Analysis Session", subtitle="MCP accumulated evidence")
    ioc_rows: dict[tuple[str, str], dict[str, Any]] = {}
    finding_count = 0

    for idx, event in enumerate(events):
        if str(event.get("type") or "") != "response":
            continue
        tool = str(event.get("tool") or "tool")
        result = event.get("result") if isinstance(event.get("result"), dict) else event.get("data")
        if not isinstance(result, dict):
            continue
        tool_id = _merge_graph_node(nodes, f"tool:{tool}", "tool", tool, subtitle="MCP tool")
        _merge_graph_edge(edges, session_id, tool_id, "called_tool", "called")

        extracted = _iocs_from_payload(
            result,
            exclude_private_ips=exclude_private_ips,
            exclude_known_good=exclude_known_good,
            source_tool=tool,
            high_confidence=tool == "extract_iocs",
        )
        for row in extracted:
            key = (row["ioc_type"], row["value"].lower())
            existing = ioc_rows.get(key)
            if existing:
                existing["count"] += row.get("count", 1)
                existing["source_artifact_types"].update(row.get("source_artifact_types", []))
                existing["source_tools"].add(tool)
                if row.get("confidence") == "high":
                    existing["confidence"] = "high"
            else:
                ioc_rows[key] = {
                    **row,
                    "source_artifact_types": set(row.get("source_artifact_types", [])),
                    "source_tools": {tool},
                }

        findings = _findings_from_payload(result)[:max_findings]
        for finding in findings:
            finding_count += 1
            rule_name = str(finding.get("rule_name") or finding.get("name") or f"finding_{idx}_{finding_count}")
            finding_id = _merge_graph_node(
                nodes,
                f"finding:{_stable_slug(rule_name)}",
                "finding",
                _display_rule(rule_name),
                subtitle=str(finding.get("severity") or finding.get("priority_tier") or "finding").upper(),
                count=int(finding.get("matching_count") or 0),
                severity=str(finding.get("severity") or finding.get("priority_tier") or "info"),
            )
            _merge_graph_edge(edges, tool_id, finding_id, "reported_finding", "reported")
            for artifact_type in _artifact_types_from_finding(finding):
                artifact_id = _merge_graph_node(nodes, f"artifact:{artifact_type}", "artifact", artifact_type, subtitle="artifact family")
                _merge_graph_edge(edges, tool_id, artifact_id, "reported_artifact", "reported")
                _merge_graph_edge(edges, artifact_id, finding_id, "supports_finding", "supports")
            _add_mitre_edges(nodes, edges, finding_id, finding)

    for row in list(ioc_rows.values())[:max_iocs]:
        source_artifact_types = sorted(row.get("source_artifact_types") or [])
        source_tools = sorted(row.get("source_tools") or [])
        ioc_id = _merge_graph_node(
            nodes,
            f"ioc:{row['ioc_type']}:{row['value'].lower()}",
            "ioc",
            row["value"],
            subtitle=row["ioc_type"].upper(),
            ioc_type=row["ioc_type"],
            count=int(row.get("count") or 1),
            confidence=row.get("confidence") or "context",
            visibility="hidden_by_default" if row.get("confidence") == "context" else "",
            source_artifact_types=source_artifact_types,
            source_tool=", ".join(source_tools),
            source_reason=row.get("source_reason") or _ioc_source_reason(row),
        )
        for tool in source_tools:
            _merge_graph_edge(edges, f"tool:{tool}", ioc_id, "reported_ioc", "reported IOC", weight=int(row.get("count") or 1))
        for artifact_type in source_artifact_types[:12]:
            artifact_id = _merge_graph_node(nodes, f"artifact:{artifact_type}", "artifact", artifact_type, subtitle="artifact family")
            _merge_graph_edge(edges, artifact_id, ioc_id, "contains_ioc", "contains IOC", weight=int(row.get("count") or 1))

    if not events:
        warnings.append("No MCP response events are available yet. Run LLM/MCP analysis first, then build the graph.")
    if len(ioc_rows) > max_iocs:
        warnings.append(f"IOC nodes capped at {max_iocs}; graph is a lower-bound session view.")

    manual_count = _add_manual_observations(nodes, edges, session_id, manual_observations)
    return {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_mode": "analysis_session",
        "nodes": sorted(nodes.values(), key=lambda n: (n["type"], n["label"])),
        "edges": sorted(edges.values(), key=lambda e: e["id"]),
        "stats": _graph_stats(nodes, edges, manual_count),
        "warnings": warnings,
        "analysis_limitations": [
            "This graph is built from accumulated MCP/LLM analysis events, not a full-case scan.",
            "Edges mean the entities co-occurred in an analysis result; they do not prove causation.",
            "IOC and MITRE technique nodes remain bridged through tools/findings/evidence to avoid overclaiming.",
            "Analyst-added graph nodes are visual context only and are not fed back into LLM analysis by this graph builder.",
            "Context IOC nodes are low-signal text matches and are hidden by default in the UI.",
        ],
    }


def _add_finding_nodes(
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, Any]],
    case_id: str,
    findings: list[dict[str, Any]],
) -> None:
    for finding in findings:
        rule_name = str(finding.get("rule_name") or finding.get("name") or "finding")
        finding_id = _merge_graph_node(
            nodes,
            f"finding:{_stable_slug(rule_name)}",
            "finding",
            _display_rule(rule_name),
            subtitle=str(finding.get("severity") or finding.get("priority_tier") or "finding").upper(),
            count=int(finding.get("matching_count") or 0),
            severity=str(finding.get("severity") or finding.get("priority_tier") or "info"),
        )
        _merge_graph_edge(edges, case_id, finding_id, "has_finding", "finding", weight=max(1, int(finding.get("matching_count") or 1)))
        for artifact_type in _artifact_types_from_finding(finding):
            artifact_id = _merge_graph_node(nodes, f"artifact:{artifact_type}", "artifact", artifact_type, subtitle="artifact family")
            _merge_graph_edge(edges, case_id, artifact_id, "has_artifact_family", "contains")
            _merge_graph_edge(edges, artifact_id, finding_id, "supports_finding", "supports")
        _add_mitre_edges(nodes, edges, finding_id, finding)


def _add_mitre_edges(
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, Any]],
    finding_id: str,
    finding: dict[str, Any],
) -> None:
    for technique_id in _mitre_ids_from_finding(finding):
        technique = TECHNIQUE_DB.get(technique_id, {"name": technique_id, "tactic": "Unknown"})
        technique_node = _merge_graph_node(
            nodes,
            f"mitre:{technique_id}",
            "mitre",
            technique_id,
            subtitle=technique["name"],
            tactic=technique["tactic"],
            technique_name=technique["name"],
        )
        tactic_node = _merge_graph_node(
            nodes,
            f"tactic:{technique['tactic']}",
            "tactic",
            technique["tactic"],
            subtitle="ATT&CK tactic",
        )
        _merge_graph_edge(edges, tactic_node, technique_node, "contains_technique", "contains")
        _merge_graph_edge(edges, finding_id, technique_node, "maps_to_mitre", "maps to")


def _add_manual_observations(
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, Any]],
    root_id: str,
    manual_observations: list[dict[str, Any]] | None,
) -> int:
    count = 0
    for obs in manual_observations or []:
        value = str(obs.get("value") or "").strip()
        if not value:
            continue
        count += 1
        source_label = str(obs.get("source_label") or "Analyst-added")
        source_id = _merge_graph_node(
            nodes,
            f"manual:{obs.get('id') or _stable_slug(source_label + value)}",
            "manual",
            source_label,
            subtitle="analyst-only context",
            source_type="analyst_external",
            visibility="analyst_only",
            note=str(obs.get("note") or ""),
            observed_at=str(obs.get("timestamp") or ""),
        )
        _merge_graph_edge(edges, root_id, source_id, "analyst_added", "analyst added")
        target_id, node_type, label, extra = _manual_target_node(obs, value)
        target = _merge_graph_node(nodes, target_id, node_type, label, **extra)
        _merge_graph_edge(edges, source_id, target, "analyst_added", "analyst added")
    return count


def _manual_target_node(obs: dict[str, Any], value: str) -> tuple[str, str, str, dict[str, Any]]:
    node_kind = _normalize_manual_node_kind(str(obs.get("node_type") or "ioc"))
    common = {
        "source_type": "analyst_external",
        "visibility": "analyst_only",
        "manual_subtype": node_kind,
        "note": str(obs.get("note") or ""),
        "created_at": str(obs.get("created_at") or ""),
    }
    if node_kind == "mitre":
        mitre_id = _normalize_mitre_id(value)
        technique = TECHNIQUE_DB.get(mitre_id, {"name": mitre_id, "tactic": "Unknown"})
        return (
            f"mitre:{mitre_id}",
            "mitre",
            mitre_id,
            {**common, "subtitle": technique["name"], "tactic": technique["tactic"], "technique_name": technique["name"]},
        )
    if node_kind == "finding":
        return (f"finding:manual:{_stable_slug(value)}", "finding", value, {**common, "subtitle": "analyst hypothesis"})
    if node_kind == "evidence":
        return (f"artifact:manual:{_stable_slug(value)}", "artifact", value, {**common, "subtitle": "external evidence"})
    if node_kind == "note":
        return (f"manual-note:{_stable_slug(value)}", "manual", value[:80], {**common, "subtitle": "analyst note"})
    ioc_type = _normalize_ioc_type(str(obs.get("ioc_type") or "")) or _infer_ioc_type(value)
    return (
        f"ioc:{ioc_type}:{value.lower()}",
        "ioc",
        value,
        {**common, "subtitle": ioc_type.upper(), "ioc_type": ioc_type, "confidence": "analyst_context"},
    )


def _extract_iocs_for_graph(
    connectors: dict[str, Any],
    *,
    ioc_types: str,
    exclude_private_ips: bool,
    exclude_known_good: bool,
    max_iocs: int,
) -> tuple[dict[str, Any], str]:
    axiom = _active_axiom(connectors)
    if axiom is not None:
        try:
            from core.analysis.ioc_extractor import extract_iocs

            payload = extract_iocs(
                axiom,
                ioc_types=ioc_types,
                exclude_private=exclude_private_ips,
                exclude_known_good=exclude_known_good,
            )
            return payload, ""
        except Exception as exc:  # noqa: BLE001
            return _extract_iocs_from_searchable(
                axiom,
                ioc_types=ioc_types,
                exclude_private_ips=exclude_private_ips,
                exclude_known_good=exclude_known_good,
                max_iocs=max_iocs,
            ), f"Parsed-case IOC extractor unavailable; used searchable fallback: {exc}"

    searchable = _active_searchable(connectors)
    if searchable is not None:
        return (
            _extract_iocs_from_searchable(
                searchable,
                ioc_types=ioc_types,
                exclude_private_ips=exclude_private_ips,
                exclude_known_good=exclude_known_good,
                max_iocs=max_iocs,
            ),
            "IOC extraction used searchable artifact text fallback; counts are lower-bound observations.",
        )

    return {"total_iocs": 0, "by_type": {}, "iocs": [], "truncated": False}, "No searchable IOC source is loaded."


def _extract_iocs_from_searchable(
    connector: Any,
    *,
    ioc_types: str = "",
    exclude_private_ips: bool = True,
    exclude_known_good: bool = True,
    max_iocs: int = 120,
) -> dict[str, Any]:
    requested = _requested_ioc_types(ioc_types)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        search_result = connector.search("", limit=max(200, max_iocs * 20), offset=0)
    except TypeError:
        search_result = connector.search(keyword="", limit=max(200, max_iocs * 20), offset=0)
    hits = search_result.get("hits", []) if isinstance(search_result, dict) else []
    for hit in hits:
        artifact_type = str(hit.get("artifact_type") or hit.get("type") or "")
        for row in _iocs_from_payload(
            hit,
            requested=requested,
            exclude_private_ips=exclude_private_ips,
            exclude_known_good=exclude_known_good,
            high_confidence=False,
        ):
            key = (row["ioc_type"], row["value"].lower())
            current = rows.setdefault(
                key,
                {
                    **row,
                    "count": 0,
                    "source_artifact_types": set(),
                    "confidence": "context",
                    "source_reason": "matched by IOC pattern in searchable artifact text",
                },
            )
            current["count"] += max(1, int(row.get("count") or 1))
            if artifact_type:
                current["source_artifact_types"].add(artifact_type)
            for source_type in row.get("source_artifact_types", []) or []:
                if source_type:
                    current["source_artifact_types"].add(source_type)

    results = []
    for item in rows.values():
        copied = dict(item)
        copied["source_artifact_types"] = sorted(copied.get("source_artifact_types") or [])
        results.append(copied)
    results.sort(key=lambda x: (-int(x.get("count") or 0), str(x.get("ioc_type")), str(x.get("value"))))

    by_type: dict[str, int] = {}
    for row in results:
        by_type[row["ioc_type"]] = by_type.get(row["ioc_type"], 0) + 1

    return {
        "total_iocs": len(results),
        "by_type": by_type,
        "iocs": results[:max_iocs],
        "truncated": len(results) > max_iocs,
    }


def _iocs_from_payload(
    payload: Any,
    *,
    requested: set[str] | None = None,
    exclude_private_ips: bool = True,
    exclude_known_good: bool = True,
    source_tool: str = "",
    high_confidence: bool = False,
) -> list[dict[str, Any]]:
    requested = requested or set()
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    if isinstance(payload, dict) and isinstance(payload.get("iocs"), list):
        for item in payload.get("iocs") or []:
            if not isinstance(item, dict):
                continue
            ioc_type = _normalize_ioc_type(str(item.get("ioc_type") or item.get("type") or ""))
            value = str(item.get("value") or "").strip()
            if not ioc_type or not value:
                continue
            if requested and ioc_type not in requested:
                continue
            if _skip_ioc_value(ioc_type, value, exclude_private_ips, exclude_known_good):
                continue
            key = (ioc_type, value.lower())
            rows[key] = {
                "ioc_type": ioc_type,
                "value": value,
                "count": int(item.get("count") or 1),
                "source_artifact_types": list(item.get("source_artifact_types") or []),
                "confidence": "high" if high_confidence else item.get("confidence") or "context",
                "source_tool": source_tool,
                "source_reason": item.get("source_reason") or ("reported by an IOC-producing tool response" if high_confidence else "matched by IOC pattern inside an MCP response"),
            }

    for text, artifact_type in _walk_text_with_artifact(payload):
        for ioc_type, value in _extract_ioc_matches(text):
            if requested and ioc_type not in requested:
                continue
            if _skip_ioc_value(ioc_type, value, exclude_private_ips, exclude_known_good):
                continue
            key = (ioc_type, value.lower())
            row = rows.setdefault(
                key,
                {
                    "ioc_type": ioc_type,
                    "value": value,
                    "count": 0,
                    "source_artifact_types": [],
                    "confidence": "context",
                    "source_tool": source_tool,
                    "source_reason": "matched by IOC pattern inside an MCP response",
                },
            )
            row["count"] = int(row.get("count") or 0) + 1
            if artifact_type and artifact_type not in row["source_artifact_types"]:
                row["source_artifact_types"].append(artifact_type)

    return list(rows.values())


def _extract_ioc_matches(text: str) -> list[tuple[str, str]]:
    if not text or ALIAS_OR_HMAC_RE.search(text):
        return []
    out: list[tuple[str, str]] = []
    for match in HASH_RE.findall(text):
        value = match.lower()
        out.append((_hash_type(value), value))
    for ioc_type, regex in PATTERNS.items():
        for raw in regex.findall(text):
            value = str(raw).strip().rstrip(".,;:)")
            if value:
                out.append((_normalize_ioc_type(ioc_type), value))
    return out


def _walk_text_with_artifact(value: Any, artifact_type: str = ""):
    if isinstance(value, dict):
        next_artifact = str(value.get("artifact_type") or value.get("Artifact Type") or artifact_type or "")
        for child in value.values():
            yield from _walk_text_with_artifact(child, next_artifact)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_text_with_artifact(child, artifact_type)
    elif isinstance(value, str):
        yield value, artifact_type


def _findings_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            return [f for f in payload["findings"] if isinstance(f, dict)]
        if payload.get("rule_name") or payload.get("mitre_techniques"):
            return [payload]
    return []


def _artifact_types_from_finding(finding: dict[str, Any]) -> list[str]:
    types: list[str] = []
    for key in ("artifact_types", "source_artifact_types"):
        value = finding.get(key)
        if isinstance(value, list):
            types.extend(str(v) for v in value if v)
    for detail in finding.get("details", []) or []:
        if isinstance(detail, dict):
            artifact_type = detail.get("artifact_type") or detail.get("Artifact Type")
            if artifact_type:
                types.append(str(artifact_type))
    return sorted(dict.fromkeys(types))


def _mitre_ids_from_finding(finding: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for key in ("mitre_techniques", "mitre_ids", "techniques"):
        value = finding.get(key)
        if isinstance(value, list):
            ids.extend(_normalize_mitre_id(str(v)) for v in value if str(v).strip())
        elif isinstance(value, str):
            ids.extend(_normalize_mitre_id(v) for v in re.findall(r"T\d{4}(?:\.\d{3})?", value))
    return sorted(dict.fromkeys(i for i in ids if i))


def _active_axiom(connectors: dict[str, Any]) -> Any | None:
    for key in ("axiom", "kape"):
        connector = connectors.get(key)
        if connector is not None and getattr(connector, "is_connected", lambda: True)():
            return connector
    for key, connector in connectors.items():
        if str(key).startswith("axiom:") and getattr(connector, "is_connected", lambda: True)():
            return connector
    return None


def _active_searchable(connectors: dict[str, Any]) -> Any | None:
    for key in ("raw_index", "e01_index", "e01"):
        connector = connectors.get(key)
        if connector is not None and hasattr(connector, "search") and getattr(connector, "is_connected", lambda: True)():
            return connector
    return None


def _source_mode(connectors: dict[str, Any]) -> str:
    if _active_axiom(connectors) is not None:
        return "parsed_case"
    raw = connectors.get("raw_index")
    if raw is not None and getattr(raw, "is_connected", lambda: True)():
        return "raw_image_sidecar"
    e01_index = connectors.get("e01_index")
    if e01_index is not None and getattr(e01_index, "is_connected", lambda: True)():
        return "e01_direct"
    e01 = connectors.get("e01")
    if e01 is not None and getattr(e01, "is_connected", lambda: True)():
        return "e01_direct"
    return "no_case"


def _case_label(connectors: dict[str, Any]) -> str:
    for connector in (_active_axiom(connectors), _active_searchable(connectors)):
        if connector is None:
            continue
        try:
            meta = connector.get_metadata()
            return str(meta.get("case_name") or meta.get("hostname") or meta.get("image_path") or "Active Case")
        except Exception:
            continue
    return "Active Case"


def _requested_ioc_types(value: str) -> set[str]:
    requested = {_normalize_ioc_type(t) for t in str(value or "").split(",") if t.strip()}
    if "ip" in requested:
        requested.add("ipv4")
    if "hash" in requested or "hashes" in requested:
        requested.update({"md5", "sha1", "sha256"})
    return {item for item in requested if item}


def _normalize_ioc_type(value: str) -> str:
    value = str(value or "").strip().lower()
    aliases = {"ip": "ipv4", "hashes": "hash"}
    return aliases.get(value, value)


def _infer_ioc_type(value: str) -> str:
    value = value.strip()
    if _valid_ip(value):
        return "ipv4"
    if re.match(r"^https?://", value, re.IGNORECASE):
        return "url"
    if "@" in value:
        return "email"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return _hash_type(value)
    if "." in value:
        return "domain"
    return "ioc"


def _hash_type(value: str) -> str:
    if len(value) == 32:
        return "md5"
    if len(value) == 40:
        return "sha1"
    return "sha256"


def _skip_ioc_value(ioc_type: str, value: str, exclude_private_ips: bool, exclude_known_good: bool) -> bool:
    if ioc_type == "ipv4":
        if not _valid_ip(value):
            return True
        if exclude_private_ips and ipaddress.ip_address(value).is_private:
            return True
    if ioc_type == "domain" and exclude_known_good and _known_good_domain(value):
        return True
    if ioc_type == "url" and exclude_known_good:
        host = re.sub(r"^https?://", "", value, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
        if _known_good_domain(host):
            return True
    return False


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _known_good_domain(value: str) -> bool:
    domain = value.lower().strip(".")
    return any(domain == known or domain.endswith("." + known) for known in KNOWN_GOOD_DOMAINS)


def _normalize_manual_node_kind(value: str) -> str:
    value = str(value or "").strip().lower()
    if value in {"ioc", "mitre", "finding", "evidence", "note"}:
        return value
    return "ioc"


def _normalize_mitre_id(value: str) -> str:
    match = re.search(r"T\d{4}(?:\.\d{3})?", str(value or "").upper())
    return match.group(0) if match else str(value or "").upper().strip()


def _stable_slug(value: str) -> str:
    text = str(value or "").strip().lower()
    slug = re.sub(r"[^a-z0-9_.-]+", "_", text).strip("_")
    if slug:
        return slug[:80]
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _display_rule(rule_name: str) -> str:
    return str(rule_name or "finding").replace("_", " ")


def _ioc_source_reason(row: dict[str, Any]) -> str:
    if row.get("confidence") == "high":
        return "reported by an IOC-producing tool response"
    return "matched by IOC pattern inside an MCP response"


def _merge_graph_node(
    nodes: dict[str, dict[str, Any]],
    node_id: str,
    node_type: str,
    label: str,
    **extra: Any,
) -> str:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label, **extra}
    else:
        nodes[node_id].update({k: v for k, v in extra.items() if v not in (None, "", [])})
    return node_id


def _merge_graph_edge(
    edges: dict[str, dict[str, Any]],
    source: str,
    target: str,
    edge_type: str,
    label: str = "",
    weight: int = 1,
    **extra: Any,
) -> None:
    edge_id = f"{source}->{target}#{edge_type}"
    if edge_id not in edges:
        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "type": edge_type,
            "label": label or edge_type,
            "weight": max(1, int(weight or 1)),
            **extra,
        }
    else:
        edges[edge_id]["weight"] = int(edges[edge_id].get("weight", 1)) + max(1, int(weight or 1))


def _graph_stats(nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], manual_count: int) -> dict[str, int]:
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "iocs": len([n for n in nodes.values() if n["type"] == "ioc"]),
        "mitre_techniques": len([n for n in nodes.values() if n["type"] == "mitre"]),
        "findings": len([n for n in nodes.values() if n["type"] == "finding"]),
        "artifact_families": len([n for n in nodes.values() if n["type"] == "artifact"]),
        "manual_observations": manual_count,
        "context_iocs": len([n for n in nodes.values() if n["type"] == "ioc" and n.get("confidence") == "context"]),
    }
