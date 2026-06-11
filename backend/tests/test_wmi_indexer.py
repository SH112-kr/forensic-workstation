"""Tests for the WMI subscription-persistence parser/indexer."""

from __future__ import annotations

from core.raw_index.artifact_indexer import (
    _wmi_sid_from_bytes,
    index_wmi_persistence,
    parse_wmi_persistence,
)
from core.raw_index.store import RawIndexStore


_UNINIT = object()


class _Prop:
    def __init__(self, value):
        self._v = value

    @property
    def value(self):
        if self._v is _UNINIT:
            raise RuntimeError("Property is not initialized")
        return self._v


class _Inst:
    def __init__(self, **props):
        self.properties = {k: _Prop(v) for k, v in props.items()}


class _Class:
    def __init__(self, instances):
        self.instances = instances


class _NS:
    def __init__(self, name, classes=None, children=None):
        self.name = name
        self._classes = classes or {}
        self.namespaces = children or []

    def class_(self, name):
        if name not in self._classes:
            raise KeyError(name)  # class not defined here — normal
        return self._classes[name]


def _tree():
    # root\subscription: benign default; root\evil: malicious CommandLine consumer
    subscription = _NS("subscription", classes={
        "__EventFilter": _Class([_Inst(Name="SCM Event Log Filter",
                                       Query="select * from MSFT_SCMEventLogEvent",
                                       QueryLanguage="WQL")]),
        "__FilterToConsumerBinding": _Class([_Inst(
            Filter='__EventFilter.Name="SCM Event Log Filter"',
            Consumer='NTEventLogEventConsumer.Name="SCM Event Log Consumer"')]),
    })
    evil = _NS("evil", classes={
        "CommandLineEventConsumer": _Class([_Inst(
            Name="Updater", CommandLineTemplate="powershell -enc ZQB2AGkAbAA=",
            ExecutablePath="C:\\Windows\\Temp\\x.exe")]),
    })
    return _NS("root", children=[subscription, evil])


def test_parse_wmi_extracts_filter_consumer_binding():
    records, gaps = parse_wmi_persistence(_tree())
    assert gaps == []
    kinds = sorted(r["kind"] for r in records)
    assert kinds == ["event_consumer", "event_filter", "filter_to_consumer_binding"]
    flt = next(r for r in records if r["kind"] == "event_filter")
    assert flt["query"] == "select * from MSFT_SCMEventLogEvent"


def test_parse_wmi_records_namespace_path_for_out_of_subscription_consumer():
    records, _ = parse_wmi_persistence(_tree())
    consumer = next(r for r in records if r["kind"] == "event_consumer")
    assert consumer["consumer_type"] == "CommandLineEventConsumer"
    # the malicious consumer is in root\evil, NOT root\subscription
    assert consumer["namespace"].endswith("evil")
    assert "powershell" in consumer["payload"]["CommandLineTemplate"]


def test_parse_wmi_namespace_cap_recorded_as_gap():
    deep = _NS("root", children=[_NS("a"), _NS("b"), _NS("c")])
    records, gaps = parse_wmi_persistence(deep, max_namespaces=2)
    assert any(g.get("reason") == "wmi_namespace_cap_reached" for g in gaps)


def test_parse_wmi_instance_cap_preserves_partial_and_gaps():
    from core.raw_index.artifact_indexer import _WMI_MAX_INSTANCES
    many = [_Inst(Name="f%d" % i, Query="q") for i in range(_WMI_MAX_INSTANCES + 5)]
    ns = _NS("root", classes={"__EventFilter": _Class(many)})
    records, gaps = parse_wmi_persistence(ns)
    # capped to the bound, and the cap is reported (no silent truncation)
    assert len(records) == _WMI_MAX_INSTANCES
    assert any(g.get("reason") == "wmi_instance_cap_reached" for g in gaps)


def test_parse_wmi_class_lookup_corruption_is_gap():
    class _CorruptNS(_NS):
        def class_(self, name):
            raise RuntimeError("UnmappedPageError-like corruption")

    records, gaps = parse_wmi_persistence(_CorruptNS("root"))
    assert any(g.get("reason") == "wmi_class_lookup_error" for g in gaps)


def test_parse_wmi_instance_enum_error_is_gap():
    class _BadClass:
        @property
        def instances(self):
            raise RuntimeError("corrupt instance")

    ns = _NS("root")
    ns._classes["__EventFilter"] = _BadClass()
    _records, gaps = parse_wmi_persistence(ns)
    assert any(g.get("reason") == "wmi_instance_enum_error" for g in gaps)


def test_wmi_sid_formatting():
    # [1,2,...,5, 32, ...,544] -> S-1-5-32-544 (Administrators)
    raw = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
    assert _wmi_sid_from_bytes(raw) == "S-1-5-32-544"


def _open(tmp_path):
    s = RawIndexStore(str(tmp_path / "wmi.sqlite"))
    s.open()
    return s


def test_index_wmi_missing_repo_is_not_evaluable(tmp_path):
    class _NoRepoImage:
        def extract_file(self, internal, local):
            return {"error": f"File not found in image: {internal}"}

    store = _open(tmp_path)
    try:
        result = index_wmi_persistence(_NoRepoImage(), store,
                                       started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert result["status"] == "not_evaluable"
    assert result["indexed_records"] == 0
    assert any(g.get("reason") == "wmi_repo_file_unavailable"
               for g in result["coverage_gaps"])
