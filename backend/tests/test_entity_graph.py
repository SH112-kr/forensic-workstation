"""Unit tests for core.analysis.entity_graph.

Covers Codex Round-7 required edge cases:
  - has_prefetch_hash vs has_sha1 are separate edge types.
  - Node IDs are mode-scoped (same entity under raw vs loose never
    shares identity).
  - collapsed_from records normalizer_version + input_field for replay.
  - Truncation flips graph_is_complete to False and lists the capped type.
  - sample_hit_ids stays capped at 10.
  - EID 7045 without SubjectUserName emits <unknown> instead of dropping.
  - loose match_key surfaces warnings on BOTH envelope and per-node.
  - Byte-stable replay: same inputs -> same node/edge IDs.
"""

from __future__ import annotations

from core.analysis.entity_graph import (
    CONSTRUCTION_RULES,
    EDGE_TYPES,
    ENTITY_TYPES,
    NORMALIZER_VERSION,
    UNKNOWN_PRINCIPAL,
    build_entity_graph,
)


class _FakeAQ:
    def __init__(self, evtx_by_eid=None, prefetch=None, amcache=None):
        self._evtx = evtx_by_eid or {}
        self._prefetch = prefetch or []
        self._amcache = amcache or []

    def query_event_logs(self, event_ids=None, limit=0, provider=""):
        out = []
        for eid in event_ids or []:
            out.extend(self._evtx.get(eid, []))
        return out

    def query_prefetch(self, app_name_filter="", limit=0):
        return list(self._prefetch)

    def query_amcache(self, name_filter="", limit=0):
        return list(self._amcache)


def _mkhit(hid, event_data, computer="PC1", ts="2026-04-10T10:00:00"):
    return {
        "hit_id": hid,
        "Event Data": event_data,
        "Computer": computer,
        "Created Date/Time - UTC (yyyy-mm-dd)": ts,
    }


def test_logon_builds_user_host_edge():
    aq = _FakeAQ(evtx_by_eid={4624: [
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),
    ]})
    g = build_entity_graph(axiom_cases=[("a", aq)])
    assert g["ok"]
    user_node = next(n for n in g["nodes"] if n["type"] == "user")
    host_node = next(n for n in g["nodes"] if n["type"] == "host")
    # DOMAIN preserved under raw
    assert "contoso\\alice" in user_node["normalized_value"]
    logon = next(e for e in g["edges"] if e["type"] == "logon")
    assert logon["source"] == user_node["id"]
    assert logon["target"] == host_node["id"]
    # Audit: input_field + normalizer_version on every collapsed_from entry
    assert user_node["collapsed_from"][0]["normalizer_version"] == NORMALIZER_VERSION
    assert "TargetUserName" in user_node["collapsed_from"][0]["input_field"]


def test_has_prefetch_hash_and_has_sha1_are_distinct_edge_types():
    aq = _FakeAQ(
        prefetch=[{
            "hit_id": 10, "Application Name": "powershell.exe",
            "Application Path": "C:\\Windows\\System32\\powershell.exe",
            "Computer": "PC1", "Prefetch Hash": "ABCDEF01",
            "Last Run Date/Time - UTC (yyyy-mm-dd)": "2026-04-10T10:00:00",
        }],
        amcache=[{
            "hit_id": 20, "Full Path": "C:\\Windows\\System32\\powershell.exe",
            "SHA-1": "aabbccddeeff00112233445566778899aabbccdd",
            "File Key Last Write Timestamp": "2026-04-10T09:00:00",
        }],
    )
    g = build_entity_graph(axiom_cases=[("a", aq)])
    edge_types_seen = {e["type"] for e in g["edges"]}
    # Both edge types appear, never merged into a single 'has_hash'.
    assert "has_prefetch_hash" in edge_types_seen
    assert "has_sha1" in edge_types_seen
    assert "has_hash" not in edge_types_seen


def test_node_ids_are_mode_scoped():
    aq = _FakeAQ(evtx_by_eid={4624: [
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),
    ]})
    raw_g = build_entity_graph(axiom_cases=[("a", aq)], match_key="raw")
    loose_g = build_entity_graph(axiom_cases=[("a", aq)], match_key="loose")
    raw_user = next(n for n in raw_g["nodes"] if n["type"] == "user")
    loose_user = next(n for n in loose_g["nodes"] if n["type"] == "user")
    # Same underlying entity but IDs include the mode so merges can't cross.
    assert ":raw:" in raw_user["id"]
    assert ":loose:" in loose_user["id"]
    assert raw_user["id"] != loose_user["id"]


def test_loose_match_key_surfaces_warnings_on_envelope_and_node():
    aq = _FakeAQ(evtx_by_eid={4624: [
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),
    ]})
    g = build_entity_graph(axiom_cases=[("a", aq)], match_key="loose")
    user_node = next(n for n in g["nodes"] if n["type"] == "user")
    # Under loose, CONTOSO\Alice collapses to 'alice' and the warning is visible.
    assert user_node["lossy_merge_warning"]
    assert any("principals" in w.lower() or "collapse" in w.lower() for w in g["warnings"])


def test_eid_7045_without_subject_emits_unknown_principal():
    aq = _FakeAQ(evtx_by_eid={7045: [
        _mkhit(100, '<Data Name="ServiceName">MaliciousSvc</Data>'),  # no SubjectUserName
    ]})
    g = build_entity_graph(axiom_cases=[("a", aq)])
    # Service still exists as a node AND an edge was created (not silently dropped).
    svc_nodes = [n for n in g["nodes"] if n["type"] == "service"]
    assert len(svc_nodes) == 1
    edge = next((e for e in g["edges"] if e["type"] == "created_svc"), None)
    assert edge is not None
    src_node = next(n for n in g["nodes"] if n["id"] == edge["source"])
    assert UNKNOWN_PRINCIPAL in src_node["normalized_value"]


def test_truncation_flips_graph_is_complete():
    # Generate 250 distinct users to exceed limit_per_node_type=5
    events = []
    for i in range(250):
        events.append(_mkhit(
            i,
            f'<Data Name="TargetUserName">user{i}</Data>'
            f'<Data Name="TargetDomainName">DOM</Data>',
            computer=f"HOST{i % 3}",
        ))
    aq = _FakeAQ(evtx_by_eid={4624: events})
    g = build_entity_graph(axiom_cases=[("a", aq)], limit_per_node_type=5)
    assert g["graph_is_complete"] is False
    assert "user" in g["truncated_node_types"]
    assert any("capped" in t for t in g["truncation_notes"])


def test_sample_hit_ids_capped_at_10():
    events = [
        _mkhit(i,
               '<Data Name="TargetUserName">Alice</Data>'
               '<Data Name="TargetDomainName">CONTOSO</Data>')
        for i in range(20)
    ]
    aq = _FakeAQ(evtx_by_eid={4624: events})
    g = build_entity_graph(axiom_cases=[("a", aq)])
    user_node = next(n for n in g["nodes"] if n["type"] == "user")
    assert len(user_node["sample_hit_ids"]) <= 10


def test_replay_byte_stability():
    """Same input + construction_rules_version -> identical node/edge IDs."""
    aq = _FakeAQ(evtx_by_eid={4624: [
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),
    ]})
    g1 = build_entity_graph(axiom_cases=[("a", aq)])
    g2 = build_entity_graph(axiom_cases=[("a", aq)])
    assert [n["id"] for n in g1["nodes"]] == [n["id"] for n in g2["nodes"]]
    assert [e["id"] for e in g1["edges"]] == [e["id"] for e in g2["edges"]]
    assert g1["construction_rules_version"] == g2["construction_rules_version"]


def test_construction_rules_version_listed():
    g = build_entity_graph(axiom_cases=[])
    assert "construction_rules_version" in g
    # Every shipped edge type has a construction rule entry.
    rule_types = {r["edge_type"] for r in CONSTRUCTION_RULES}
    assert rule_types == set(EDGE_TYPES), f"Mismatch: {rule_types} vs {set(EDGE_TYPES)}"


def test_missing_parent_image_does_not_emit_edge():
    aq = _FakeAQ(evtx_by_eid={1: [
        _mkhit(1, '<Data Name="Image">C:\\foo.exe</Data>'),  # no ParentImage
    ]})
    g = build_entity_graph(axiom_cases=[("a", aq)])
    assert not any(e["type"] == "parent_of" for e in g["edges"])


def test_duplicate_hits_dont_duplicate_collapsed_from():
    aq = _FakeAQ(evtx_by_eid={4624: [
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),
        _mkhit(1, '<Data Name="TargetUserName">Alice</Data>'
                  '<Data Name="TargetDomainName">CONTOSO</Data>'),  # same hit_id + raw
    ]})
    g = build_entity_graph(axiom_cases=[("a", aq)])
    user_node = next(n for n in g["nodes"] if n["type"] == "user")
    # Dedup on (raw, source_hit_id)
    assert len(user_node["collapsed_from"]) == 1


def test_entity_types_shipped():
    assert set(ENTITY_TYPES) == {"user", "host", "file", "hash", "service", "process"}
