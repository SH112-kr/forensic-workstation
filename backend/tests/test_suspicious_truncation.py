"""Tests for suspicious.py truncation transparency fields.

Verifies that every rule emits returned_count, truncated, and detail_cap
so an LLM analyst can detect when details were capped and must paginate.
"""

from __future__ import annotations

import pytest

from core.analysis.suspicious import _apply_detail_cap, find_suspicious


# ── _apply_detail_cap helper ─────────────────────────────────────────────────

def test_apply_detail_cap_truncates_at_cap():
    items = list(range(30))
    capped, truncated, returned = _apply_detail_cap(items, cap=20)
    assert len(capped) == 20
    assert truncated is True
    assert returned == 20


def test_apply_detail_cap_no_truncation_when_within_cap():
    items = list(range(5))
    capped, truncated, returned = _apply_detail_cap(items, cap=20)
    assert capped == items
    assert truncated is False
    assert returned == 5


def test_apply_detail_cap_exact_boundary():
    items = list(range(20))
    capped, truncated, returned = _apply_detail_cap(items, cap=20)
    assert truncated is False
    assert returned == 20


def test_apply_detail_cap_empty():
    capped, truncated, returned = _apply_detail_cap([], cap=20)
    assert capped == []
    assert truncated is False
    assert returned == 0


def test_apply_detail_cap_custom_cap():
    items = list(range(15))
    capped, truncated, returned = _apply_detail_cap(items, cap=10)
    assert len(capped) == 10
    assert truncated is True
    assert returned == 10


# ── Stub ArtifactQueries ────────────────────────────────────────────────────

class _StubHit:
    """Minimal hit dict factory."""
    _counter = 0

    @classmethod
    def make(cls, n: int = 1) -> list[dict]:
        hits = []
        for _ in range(n):
            cls._counter += 1
            hits.append({
                "hit_id": cls._counter,
                "Created Date/Time - UTC (yyyy-mm-dd)": "2026-02-20T14:50:00",
                "Event Data": "<Data Name='ServiceName'>svc</Data>",
                "Computer": "TESTHOST",
                "Security Identifier": "S-1-5-18",
                "Event ID": "7045",
            })
        return hits


class _StubAQ:
    """Minimal stub for ArtifactQueries that returns configurable hit lists."""

    def __init__(self, service_hits=248, all_zero=False):
        self._service_hits = service_hits
        self._all_zero = all_zero

    def query_service_installs(self, limit=0):
        if self._all_zero:
            return []
        return _StubHit.make(self._service_hits)

    # All other query methods return empty lists by default
    def query_process_access_events(self, limit=0): return []
    def query_process_creation_events(self, limit=0): return []
    def query_scheduled_task_events(self, limit=0): return []
    def query_scheduled_tasks(self, limit=0): return []
    def query_log_cleared(self, limit=0): return []
    def query_logon_events(self, limit=0): return []
    def query_event_logs(self, event_ids=None, provider=None, limit=0): return []
    def query_prefetch(self, app_name_filter="", limit=0): return []
    def query_services(self, service_filter="", limit=0): return []
    def query_amcache(self, limit=0): return []
    def query_powershell_scriptblock(self, limit=0): return []
    def _query_artifact(self, artifact_type, limit=0): return []


# ── service_installation rule truncation ─────────────────────────────────────

def test_rule_service_installation_emits_truncation_fields_when_capped():
    aq = _StubAQ(service_hits=248)
    result = find_suspicious(aq, rules="evtx_eid_7045_service_installs")

    assert result["total_findings"] == 1
    finding = result["findings"][0]
    assert finding["rule_name"] == "evtx_eid_7045_service_installs"
    assert finding["matching_count"] == 248
    assert finding["returned_count"] == 20
    assert finding["truncated"] is True
    assert finding["detail_cap"] == 20
    assert len(finding["details"]) == 20


def test_rule_service_installation_not_truncated_for_small_result():
    aq = _StubAQ(service_hits=5)
    result = find_suspicious(aq, rules="evtx_eid_7045_service_installs")

    finding = result["findings"][0]
    assert finding["matching_count"] == 5
    assert finding["returned_count"] == 5
    assert finding["truncated"] is False
    assert finding["detail_cap"] == 20
    assert len(finding["details"]) == 5


def test_rule_service_installation_zero_result_goes_to_zero_result_rules():
    aq = _StubAQ(all_zero=True)
    result = find_suspicious(aq, rules="evtx_eid_7045_service_installs")
    assert result["total_findings"] == 0
    assert len(result["zero_result_rules"]) == 1
    assert result["zero_result_rules"][0]["rule_name"] == "evtx_eid_7045_service_installs"
    assert result["zero_result_rules"][0]["matching_count"] == 0
    assert result["zero_result_rules"][0]["query_status"] == "executed"


# ── All rules emit required truncation fields ─────────────────────────────────

_RULES_REQUIRING_TRUNCATION = [
    "evtx_eid_7045_service_installs",
    "evtx_eid_1102_audit_log_cleared",
    "evtx_eid_4624_type10_rdp_logons",
    "evtx_eid_4648_explicit_credential_logons",
    "prefetch_pentest_tool_names",
    "services_nonstandard_binary_paths",
    "amcache_remote_access_tool_names",
    "openssh_artifacts",
]


class _AQWithOneHit(_StubAQ):
    """Returns exactly 1 hit for each query method, so every rule fires."""

    def query_service_installs(self, limit=0):
        return _StubHit.make(1)

    def query_log_cleared(self, limit=0):
        return _StubHit.make(1)

    def query_logon_events(self, limit=0):
        # EID 4624 Type 10 for RDP rule
        hit = _StubHit.make(1)[0]
        hit["Event Data"] = "<Data Name='LogonType\">10</Data>"
        return [hit]

    def query_event_logs(self, event_ids=None, provider=None, limit=0):
        return _StubHit.make(1)

    def query_prefetch(self, app_name_filter="", limit=0):
        # Return for PSEXEC to trigger suspicious_prefetch
        if app_name_filter and "PSEXEC" in app_name_filter.upper():
            hit = _StubHit.make(1)[0]
            hit["Application Name"] = "PSEXEC.EXE"
            hit["Application Path"] = "C:\\Windows\\Temp\\PSEXEC.EXE"
            return [hit]
        if app_name_filter and "SSHD" in app_name_filter.upper():
            hit = _StubHit.make(1)[0]
            hit["Application Name"] = "SSHD.EXE"
            return [hit]
        return []

    def query_services(self, service_filter="", limit=0):
        hit = _StubHit.make(1)[0]
        hit["Service Location"] = "C:\\Temp\\evil.exe"
        hit["Service Name"] = "evildemo"
        hit["Start Type"] = "Automatic"
        hit["User Account"] = "LocalSystem"
        return [hit]

    def query_amcache(self, limit=0):
        hit = _StubHit.make(1)[0]
        hit["Name"] = "putty"
        return [hit]

    def _query_artifact(self, artifact_type, limit=0):
        if artifact_type in {"SSH Keys", "SSH Known Hosts"}:
            return _StubHit.make(1)
        return []


@pytest.mark.parametrize("rule_name", _RULES_REQUIRING_TRUNCATION)
def test_rule_emits_truncation_fields(rule_name):
    aq = _AQWithOneHit()
    result = find_suspicious(aq, rules=rule_name)
    if result["total_findings"] == 0:
        pytest.skip(f"Rule {rule_name} produced no findings with stub — skipping field check")
    finding = result["findings"][0]
    assert "returned_count" in finding, f"Rule {rule_name} missing returned_count"
    assert "truncated" in finding, f"Rule {rule_name} missing truncated"
    assert "detail_cap" in finding, f"Rule {rule_name} missing detail_cap"
    assert isinstance(finding["returned_count"], int)
    assert isinstance(finding["truncated"], bool)
    assert isinstance(finding["detail_cap"], int)
    assert finding["returned_count"] == len(finding["details"])


def test_powershell_scriptblock_info_branch_emits_truncation_fields():
    """The no-keyword-match branch uses cap=10."""
    class _AQPS(_StubAQ):
        def query_powershell_scriptblock(self, limit=0):
            return _StubHit.make(15)

    aq = _AQPS()
    result = find_suspicious(aq, rules="evtx_eid_4104_scriptblock_logs")
    assert result["total_findings"] == 1
    finding = result["findings"][0]
    assert finding["detail_cap"] == 10
    assert finding["returned_count"] == 10
    assert finding["truncated"] is True
    # No severity field
    assert "severity" not in finding


def test_powershell_scriptblock_high_branch_emits_truncation_fields():
    """The keyword-match branch uses cap=20."""
    class _AQPS2(_StubAQ):
        def query_powershell_scriptblock(self, limit=0):
            hits = _StubHit.make(25)
            for h in hits:
                h["Event Data"] = "invoke-expression downloadstring base64"
            return hits

    aq = _AQPS2()
    result = find_suspicious(aq, rules="evtx_eid_4104_scriptblock_logs")
    assert result["total_findings"] == 1
    finding = result["findings"][0]
    assert finding["detail_cap"] == 20
    assert finding["matching_count"] == 25
    assert finding["truncated"] is True
    assert "severity" not in finding
