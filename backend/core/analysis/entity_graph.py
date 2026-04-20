"""Entity-centric case graph — deterministic, auditable nodes + edges.

Builds a typed graph (users, hosts, files, hashes, services, processes)
from existing artifacts. Every node carries ``collapsed_from`` so the
analyst can see which raw values were merged and under which rule; every
edge carries ``derived_from`` so the analyst can see which artifact rows
supported it. An envelope-level ``construction_rules`` block publishes
the exact criteria each edge type uses.

Design constraints (Codex-agreed):
- Pure data. No LLM interpretation. No scoring or confidence fields.
- LLM tunes parameters only (entity_types / edge_types / match_key).
- ``match_key='raw'`` (default) never collapses identity beyond the
  safe Tier-1 normalization helpers in ``core.analysis.normalization``.
  ``match_key='loose'`` invokes Tier-2 and writes the warning to BOTH
  the envelope and every affected node.
- Per-type caps keep big cases from producing unbounded JSON.

Entity types v1: user, host, file, hash, service, process
Edge types   v1: logon, executed, has_hash, created_svc, parent_of

v1 is intentionally conservative. New edge types must:
(a) use only publicly documented ATT&CK-grade artifacts,
(b) cite the exact artifact + field it reads, and
(c) extend ``CONSTRUCTION_RULES`` so the audit block names them.
"""

from __future__ import annotations

import re
from typing import Any

from core.analysis import normalization as _norm


# Normalizer versioning — included in every collapsed_from entry so audits
# survive future normalization upgrades.
NORMALIZER_VERSION = "fw.norm.v1"
CONSTRUCTION_RULES_VERSION = "fw.graph.v1"
UNKNOWN_PRINCIPAL = "<unknown>"  # Explicit fallback for missing subject user.

ENTITY_TYPES = ("user", "host", "file", "hash", "service", "process")
EDGE_TYPES = (
    "logon", "executed",
    # Codex Round-7: separated because Prefetch Hash is a lookup token
    # (path+volume fingerprint), not a cryptographic file hash. Merging
    # them into one edge type would misrepresent trust.
    "has_prefetch_hash", "has_sha1",
    "created_svc", "parent_of",
)


CONSTRUCTION_RULES: list[dict[str, str]] = [
    {
        "edge_type": "logon",
        "derived_from_rule": (
            "Windows Event Log EID 4624: TargetUserName -> Computer. Logon is "
            "recorded when an account successfully authenticates to a host."
        ),
    },
    {
        "edge_type": "executed",
        "derived_from_rule": (
            "Prefetch: Application Name / Application Path -> Computer. "
            "Prefetch Last Run implies the binary executed on the host; "
            "it does NOT record command-line arguments."
        ),
    },
    {
        "edge_type": "has_prefetch_hash",
        "derived_from_rule": (
            "Prefetch 'Prefetch Hash' field: file -> hash. Prefetch hash is "
            "a volume/path fingerprint, NOT a cryptographic file hash. Do "
            "not treat equality as file-content equality."
        ),
    },
    {
        "edge_type": "has_sha1",
        "derived_from_rule": (
            "AmCache SHA-1: file -> hash. Cryptographic hash of the file "
            "as seen at AmCache write time. File existed; does not prove "
            "execution (pair with 'executed' edges for that)."
        ),
    },
    {
        "edge_type": "created_svc",
        "derived_from_rule": (
            "Windows Event Log EID 7045: SubjectUserName -> ServiceName. "
            "When SubjectUserName is missing the edge still emits with "
            f"source set to '{UNKNOWN_PRINCIPAL}' so service installs "
            "are never silently dropped; callers must handle the "
            "unknown-principal case."
        ),
    },
    {
        "edge_type": "parent_of",
        "derived_from_rule": (
            "Sysmon Event Log EID 1: ParentImage -> Image. Parent/child "
            "process relationship as recorded by Sysmon at execution time."
        ),
    },
]


_XML_FIELD_RX = re.compile(r'Name="([^"]+)"[^>]*>([^<]*)<')


def _parse_event_data_fields(blob: Any) -> dict[str, str]:
    """Extract <Data Name=\"...\">value</Data> pairs from an Event Log row."""
    if not blob:
        return {}
    out: dict[str, str] = {}
    for m in _XML_FIELD_RX.finditer(str(blob)):
        out[m.group(1)] = m.group(2)
    return out


# ── Node identity ──────────────────────────────────────────────────────────

def _node_id(node_type: str, normalized_value: str, match_key: str) -> str:
    """Mode-scoped IDs so the same entity under different match_key modes
    can never silently share a node. Codex Round-7 fix."""
    return f"{node_type}:{match_key}:{normalized_value}"


def _normalize_entity(entity_type: str, raw: str, match_key: str) -> dict[str, Any]:
    """Return ``{normalized, rule, lossy, warning}`` for a raw entity value.

    ``match_key='raw'`` and ``match_key='strict'`` both stay in Tier 1
    (safe_*); identity is preserved. ``match_key='loose'`` invokes the
    matching Tier-2 helper and surfaces its warning so the caller can
    mirror it into the envelope.
    """
    if entity_type in ("user",):
        safe = _norm.safe_user_case(raw)
    elif entity_type in ("host",):
        safe = _norm.safe_domain(raw)
    elif entity_type in ("file", "process"):
        safe = _norm.safe_path_case(raw)
    elif entity_type == "hash":
        # Don't validate hash length here — the graph stores hashes of
        # multiple kinds (crypto SHA-1 from AmCache, Prefetch path
        # fingerprint, etc.). The edge type ('has_sha1' vs
        # 'has_prefetch_hash') carries the semantic distinction; the
        # node is just an opaque identifier.
        safe = _norm.safe_trim(raw).lower()
    elif entity_type == "service":
        safe = _norm.safe_service_name(raw)
    else:
        safe = _norm.safe_trim(raw)

    if match_key != "loose":
        return {"normalized": safe, "rule": "safe_display", "lossy": False, "warning": ""}

    # Tier-2 collapses for 'loose'
    if entity_type == "user":
        t2 = _norm.match_key_user_bare(safe)
    elif entity_type == "host":
        t2 = _norm.match_key_host_first_label(safe)
    elif entity_type in ("file", "process"):
        t2 = _norm.match_key_path_basename(safe)
    else:
        return {"normalized": safe, "rule": "safe_display", "lossy": False, "warning": ""}
    return {
        "normalized": t2["value"],
        "rule": t2["rule"],
        "lossy": bool(t2.get("collapsed")),
        "warning": t2.get("warning", ""),
    }


# ── Node / edge accumulators ───────────────────────────────────────────────

class _GraphBuilder:
    def __init__(self, match_key: str, limit_per_node_type: int):
        self.match_key = match_key
        self.limit = limit_per_node_type
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.warnings: list[str] = []
        self.truncation_notes: list[str] = []
        self.truncated_types: set[str] = set()

    def _touch_node(
        self, node_type: str, raw_value: str, source_hit_id: Any,
        case_id: str, label: str | None = None, timestamp: str = "",
        input_field: str = "",
    ) -> str | None:
        if not raw_value:
            return None
        verdict = _normalize_entity(node_type, raw_value, self.match_key)
        normalized = verdict["normalized"]
        if not normalized:
            return None
        nid = _node_id(node_type, normalized, self.match_key)

        n = self.nodes.get(nid)
        if n is None:
            # Per-type safety cap so big cases stay bounded. Codex Round-7:
            # truncation is a contract-visible incomplete signal, not just a
            # log line — envelope.graph_is_complete gets flipped to False.
            type_prefix = f"{node_type}:{self.match_key}:"
            same_type = sum(1 for k in self.nodes if k.startswith(type_prefix))
            if same_type >= self.limit:
                self.truncated_types.add(node_type)
                note = (
                    f"node_type={node_type} capped at {self.limit}; "
                    "further entities dropped. graph_is_complete=False."
                )
                if note not in self.truncation_notes:
                    self.truncation_notes.append(note)
                return None
            n = self.nodes[nid] = {
                "id": nid,
                "type": node_type,
                "label": label or normalized,
                "normalized_value": normalized,
                "match_key_mode": self.match_key,
                "collapsed_from": [],
                "first_seen": timestamp or "",
                "last_seen": timestamp or "",
                "hit_count": 0,
                "sample_hit_ids": [],
                "lossy_merge_warning": verdict["warning"] or "",
            }

        # Audit trail: every contributing raw value + rule + case + input
        # field + normalizer version. Codex Round-7: 'rule' alone is too
        # thin for replay; record version + field used so an audit can
        # reproduce byte-exactly.
        existing = {(e.get("raw"), e.get("source_hit_id")) for e in n["collapsed_from"]}
        if (raw_value, source_hit_id) not in existing:
            n["collapsed_from"].append({
                "raw": raw_value,
                "source_hit_id": source_hit_id,
                "case_id": case_id,
                "rule": verdict["rule"],
                "input_field": input_field,
                "normalizer_version": NORMALIZER_VERSION,
                "lossy": verdict["lossy"],
            })

        n["hit_count"] += 1
        if source_hit_id is not None and len(n["sample_hit_ids"]) < 10 and source_hit_id not in n["sample_hit_ids"]:
            n["sample_hit_ids"].append(source_hit_id)
        if timestamp:
            if not n["first_seen"] or timestamp < n["first_seen"]:
                n["first_seen"] = timestamp
            if not n["last_seen"] or timestamp > n["last_seen"]:
                n["last_seen"] = timestamp
        if verdict["warning"] and verdict["warning"] not in self.warnings:
            self.warnings.append(verdict["warning"])
        return nid

    def _touch_edge(
        self, edge_type: str, src: str | None, tgt: str | None,
        artifact_type: str, hit_id: Any, case_id: str, rule: str,
        timestamp: str = "",
    ) -> None:
        if not src or not tgt:
            return
        eid = f"{src}->{tgt}#{edge_type}"
        e = self.edges.get(eid)
        if e is None:
            # Edge inherits lossiness from its endpoint nodes so a caller
            # cannot miss that a merged identity influenced the edge.
            src_node = self.nodes.get(src, {})
            tgt_node = self.nodes.get(tgt, {})
            lossy_parts = []
            if src_node.get("lossy_merge_warning"):
                lossy_parts.append(f"source: {src_node['lossy_merge_warning']}")
            if tgt_node.get("lossy_merge_warning"):
                lossy_parts.append(f"target: {tgt_node['lossy_merge_warning']}")
            e = self.edges[eid] = {
                "id": eid, "type": edge_type, "source": src, "target": tgt,
                "derived_from": [], "first_seen": timestamp, "last_seen": timestamp,
                "hit_count": 0,
                "lossy_edge_warning": " | ".join(lossy_parts) if lossy_parts else "",
            }
        # Dedup identical derivations
        if not any(d.get("hit_id") == hit_id and d.get("case_id") == case_id for d in e["derived_from"]):
            e["derived_from"].append({
                "artifact_type": artifact_type, "hit_id": hit_id,
                "case_id": case_id, "rule": rule,
            })
        e["hit_count"] += 1
        if timestamp:
            if not e["first_seen"] or timestamp < e["first_seen"]:
                e["first_seen"] = timestamp
            if not e["last_seen"] or timestamp > e["last_seen"]:
                e["last_seen"] = timestamp


# ── Edge inference from connectors ─────────────────────────────────────────

def _edge_logon(b: _GraphBuilder, aq: Any, case_id: str) -> None:
    try:
        rows = aq.query_event_logs(event_ids=[4624], limit=0) or []
    except Exception:
        return
    for h in rows:
        fields = _parse_event_data_fields(h.get("Event Data", ""))
        user = fields.get("TargetUserName") or ""
        domain = fields.get("TargetDomainName") or ""
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"
        host = h.get("Computer", "") or fields.get("WorkstationName", "")
        ts = h.get("Created Date/Time - UTC (yyyy-mm-dd)", "")
        if not user or not host:
            continue
        src = b._touch_node("user", user, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Event Data/TargetUserName+TargetDomainName")
        tgt = b._touch_node("host", host, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Computer")
        b._touch_edge("logon", src, tgt, "Windows Event Logs (EID 4624)",
                      h.get("hit_id"), case_id, "eid_4624_logon", timestamp=ts)


def _edge_executed(b: _GraphBuilder, aq: Any, case_id: str) -> None:
    try:
        rows = aq.query_prefetch(limit=0) or []
    except Exception:
        return
    for h in rows:
        path = h.get("Application Path") or h.get("Application Name") or ""
        host = h.get("Computer", "") or ""
        ts = h.get("Last Run Date/Time - UTC (yyyy-mm-dd)", "") or h.get("Last Run Time", "")
        if not path:
            continue
        src = b._touch_node("file", path, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Application Path/Name")
        tgt = b._touch_node("host", host, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Computer") if host else None
        if src and tgt:
            b._touch_edge("executed", src, tgt, "Prefetch",
                          h.get("hit_id"), case_id, "prefetch_last_run", timestamp=ts)
        # Prefetch hash edge — SEPARATE edge type because this is a
        # path/volume fingerprint, not a cryptographic file hash.
        pf_hash = h.get("Prefetch Hash", "")
        if pf_hash:
            hash_node = b._touch_node("hash", pf_hash, h.get("hit_id"), case_id,
                                       timestamp=ts, input_field="Prefetch Hash")
            if src and hash_node:
                b._touch_edge("has_prefetch_hash", src, hash_node, "Prefetch",
                              h.get("hit_id"), case_id, "prefetch_hash_fingerprint", timestamp=ts)


def _edge_has_sha1(b: _GraphBuilder, aq: Any, case_id: str) -> None:
    try:
        rows = aq.query_amcache(limit=0) or []
    except Exception:
        return
    for h in rows:
        path = h.get("Full Path") or h.get("FullPath") or ""
        sha1 = h.get("SHA-1") or h.get("SHA1") or ""
        ts = h.get("File Key Last Write Timestamp", "") or h.get("File Key Last Write Time", "")
        if not path or not sha1:
            continue
        src = b._touch_node("file", path, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Full Path")
        tgt = b._touch_node("hash", sha1, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="SHA-1")
        if src and tgt:
            b._touch_edge("has_sha1", src, tgt, "AmCache File Entries",
                          h.get("hit_id"), case_id, "amcache_sha1", timestamp=ts)


def _edge_created_svc(b: _GraphBuilder, aq: Any, case_id: str) -> None:
    try:
        rows = aq.query_event_logs(event_ids=[7045], limit=0) or []
    except Exception:
        return
    for h in rows:
        fields = _parse_event_data_fields(h.get("Event Data", ""))
        user = fields.get("SubjectUserName") or fields.get("AccountName") or ""
        domain = fields.get("SubjectDomainName") or ""
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"
        svc = fields.get("ServiceName") or ""
        ts = h.get("Created Date/Time - UTC (yyyy-mm-dd)", "")
        if not svc:
            continue
        # Codex Round-7: never silently drop service installs; when
        # SubjectUserName is missing fall back to the explicit
        # UNKNOWN_PRINCIPAL marker so callers have to handle it.
        if not user:
            user = UNKNOWN_PRINCIPAL
            input_field = "Event Data/(SubjectUserName missing)"
        else:
            input_field = "Event Data/SubjectUserName"
        src = b._touch_node("user", user, h.get("hit_id"), case_id, timestamp=ts,
                            input_field=input_field)
        tgt = b._touch_node("service", svc, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Event Data/ServiceName")
        b._touch_edge("created_svc", src, tgt, "Windows Event Logs (EID 7045)",
                      h.get("hit_id"), case_id, "eid_7045_service_install", timestamp=ts)


def _edge_parent_of(b: _GraphBuilder, aq: Any, case_id: str) -> None:
    try:
        rows = aq.query_event_logs(event_ids=[1], limit=0) or []
    except Exception:
        return
    for h in rows:
        fields = _parse_event_data_fields(h.get("Event Data", ""))
        parent = fields.get("ParentImage") or ""
        child = fields.get("Image") or ""
        ts = h.get("Created Date/Time - UTC (yyyy-mm-dd)", "")
        if not parent or not child:
            continue
        src = b._touch_node("process", parent, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Event Data/ParentImage")
        tgt = b._touch_node("process", child, h.get("hit_id"), case_id, timestamp=ts,
                            input_field="Event Data/Image")
        b._touch_edge("parent_of", src, tgt, "Sysmon Event Logs (EID 1)",
                      h.get("hit_id"), case_id, "sysmon_eid_1_parent_child", timestamp=ts)


_EDGE_DISPATCH = {
    "logon": _edge_logon,
    "executed": _edge_executed,
    "has_prefetch_hash": _edge_executed,  # Prefetch scan handles both edges
    "has_sha1": _edge_has_sha1,
    "created_svc": _edge_created_svc,
    "parent_of": _edge_parent_of,
}


# ── Public entry point ────────────────────────────────────────────────────

def build_entity_graph(
    connectors: dict[str, Any] | None = None,
    *,
    axiom_cases: list[tuple[str, Any]] | None = None,
    entity_types: list[str] | None = None,
    edge_types: list[str] | None = None,
    match_key: str = "raw",
    limit_per_node_type: int = 200,
) -> dict[str, Any]:
    """Construct a typed graph over one or more AXIOM-style cases.

    Callers pass either a full ``connectors`` dict (axiom:* keys) or an
    explicit list of ``(case_id, connector)`` tuples (used by tests).
    """
    if axiom_cases is None:
        axiom_cases = []
        for name, c in (connectors or {}).items():
            if not name.startswith("axiom:"):
                continue
            if not getattr(c, "is_connected", lambda: False)():
                continue
            axiom_cases.append((name.replace("axiom:", ""), c))

    # Input validation — Codex Round-7b caught that unknown selector values
    # silently passed through as if valid. Reject unknown values with a clear
    # error so misuse surfaces immediately instead of producing wrong data.
    valid_match = {"raw", "strict", "loose"}
    if match_key not in valid_match:
        return {
            "ok": False,
            "error": f"match_key must be one of {sorted(valid_match)}, got {match_key!r}",
        }

    req_entities = set(entity_types) if entity_types else set(ENTITY_TYPES)
    bad_entities = req_entities - set(ENTITY_TYPES)
    if bad_entities:
        return {
            "ok": False,
            "error": f"Unknown entity_types: {sorted(bad_entities)}. "
                     f"Allowed: {sorted(ENTITY_TYPES)}",
        }
    req_edges = set(edge_types) if edge_types else set(EDGE_TYPES)
    bad_edges = req_edges - set(EDGE_TYPES)
    if bad_edges:
        return {
            "ok": False,
            "error": f"Unknown edge_types: {sorted(bad_edges)}. "
                     f"Allowed: {sorted(EDGE_TYPES)}",
        }

    wanted_edges = req_edges
    wanted_entities = req_entities

    b = _GraphBuilder(match_key=match_key, limit_per_node_type=limit_per_node_type)

    for case_id, c in axiom_cases:
        aq = getattr(c, "artifact_queries", c)
        # Deduplicate dispatch functions because multiple edge types can
        # share the same scan (executed + has_prefetch_hash both come from
        # Prefetch rows). Scanning twice would duplicate hit_count without
        # changing node set.
        seen_fns: set = set()
        for edge_name in wanted_edges:
            fn = _EDGE_DISPATCH.get(edge_name)
            if fn is None or fn in seen_fns:
                continue
            seen_fns.add(fn)
            try:
                fn(b, aq, case_id)
            except Exception as e:
                b.warnings.append(f"{case_id}: {edge_name} inference failed: {e}")

    # Apply entity_types AND edge_types filters to the final output.
    # Codex Round-7b caught that _edge_executed emits both 'executed' and
    # 'has_prefetch_hash' in a single scan — without filtering by edge type
    # here, a consumer asking for only one would still receive the other.
    filtered_nodes = {nid: n for nid, n in b.nodes.items() if n["type"] in wanted_entities}
    filtered_edges = [
        e for e in b.edges.values()
        if e["type"] in wanted_edges
        and e["source"] in filtered_nodes
        and e["target"] in filtered_nodes
    ]

    graph_is_complete = not b.truncated_types

    return {
        "ok": True,
        "case_count": len(axiom_cases),
        "match_key_mode": match_key,
        "normalizer_version": NORMALIZER_VERSION,
        "construction_rules_version": CONSTRUCTION_RULES_VERSION,
        "entity_types": sorted(wanted_entities),
        "edge_types": sorted(wanted_edges),
        "nodes": sorted(filtered_nodes.values(), key=lambda n: (n["type"], n["normalized_value"])),
        "edges": sorted(filtered_edges, key=lambda e: e["id"]),
        "construction_rules": [r for r in CONSTRUCTION_RULES if r["edge_type"] in wanted_edges],
        "warnings": b.warnings,
        "graph_is_complete": graph_is_complete,
        "truncated_node_types": sorted(b.truncated_types),
        "truncation_notes": b.truncation_notes,
        "notes": [
            "Every node carries 'collapsed_from' with raw values, input_field, "
            "normalizer_version, and rule so identity joins replay byte-exactly.",
            "Every edge carries 'derived_from' with artifact_type + hit_id + case_id. "
            "'construction_rules' publishes the exact artifact criteria each edge type uses.",
            "Node IDs include match_key_mode ('type:mode:normalized') so graphs built "
            "under different modes never share identity.",
            "has_prefetch_hash != has_sha1. Prefetch Hash is a volume/path fingerprint, "
            "NOT a cryptographic hash. Do not treat equality as file-content equality.",
            "Hash-type nodes (type:*:*) are stored as opaque identifiers with no length "
            "or format validation. Consumers must not assume the value is a syntactically "
            "validated cryptographic hash — the edge type ('has_sha1' vs "
            "'has_prefetch_hash') is the authoritative signal for what kind of hash it is.",
            "sample_hit_ids is a preview (max 10) for UI, NOT an authoritative list. "
            "Consult source artifacts for completeness.",
            "If graph_is_complete=False, at least one node_type hit its per-type cap "
            "and some entities were dropped. Treat the graph as a lower bound.",
            "match_key='loose' invokes Tier-2 normalization (user_bare / host_first_label "
            "/ path_basename). Collapse warnings land on BOTH envelope and affected "
            "nodes/edges.",
        ],
    }
