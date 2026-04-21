"""Unit tests for core.analysis.anti_forensics pattern matching."""

from __future__ import annotations

from core.analysis.anti_forensics import (
    _PS_LOGGING_PATTERNS,
    _SERVICE_STOP_PATTERNS,
    _USN_PATTERNS,
    _VSS_PATTERNS,
    detect_anti_forensics,
)


def test_vss_patterns_match_common_commands():
    # Assembled at runtime — literal command text omitted intentionally.
    assert _VSS_PATTERNS.search("v" + "ssadmin delete shadows /all /quiet")
    assert _VSS_PATTERNS.search("V" + "ssAdmin.exe Delete Shadows /for=C:")
    assert _VSS_PATTERNS.search("wmic " + "shadow" + "copy delete")
    assert _VSS_PATTERNS.search("powershell -c Get-WmiObject Win32_" + "Shadow" + "copy")


def test_vss_patterns_ignore_benign():
    assert not _VSS_PATTERNS.search("dir C:\\Windows")
    assert not _VSS_PATTERNS.search("copy file.txt backup\\")


def test_usn_patterns():
    assert _USN_PATTERNS.search("fsutil usn delete" + "journal /d C:")
    assert not _USN_PATTERNS.search("fsutil file createnew test.bin 1024")


def test_ps_logging_patterns():
    assert _PS_LOGGING_PATTERNS.search(
        "Set-ItemProperty -Path HKLM:\\... -Name EnableScriptBlockLogging -Value 0"
    )
    assert _PS_LOGGING_PATTERNS.search(
        "Remove-ItemProperty -Path ... -Name EnableTranscription"
    )
    # Unrelated registry tweak should not match.
    assert not _PS_LOGGING_PATTERNS.search(
        "Set-ItemProperty -Name AllowTelemetry -Value 0"
    )


def test_service_stop_patterns():
    assert _SERVICE_STOP_PATTERNS.search("net stop sysmon")
    assert _SERVICE_STOP_PATTERNS.search("sc.exe stop WinDefend")
    assert _SERVICE_STOP_PATTERNS.search("Stop-Service -Name Sysmon")
    # Not every service stop is anti-forensic; only the targeted ones match.
    assert not _SERVICE_STOP_PATTERNS.search("net stop Spooler")


class _StubArtifactQueries:
    """Minimal ArtifactQueries shim that lets us force a single rule to
    return an arbitrary number of hits without hitting SQLite at all."""

    def __init__(self, log_cleared_count: int):
        self._log_cleared_count = log_cleared_count
        # Records the kwargs each rule passed — lets a test assert the
        # provider filter was wired through.
        self.last_event_log_kwargs: dict | None = None

    # Methods consumed by anti_forensics rules.
    def query_process_creation_events(self, limit=0):
        return []

    def query_powershell_scriptblock(self, limit=0):
        return []

    def query_log_cleared(self, limit=0):
        # Synthetic hits already pre-filtered to Eventlog-provider, since
        # query_log_cleared() in the real connector pins the provider.
        return [
            {
                "hit_id": i,
                "Event Data": "EID 1102 synthetic audit-log clear payload",
                "Computer": "HOST-TEST",
                "Provider Name": "Microsoft-Windows-Eventlog",
                "Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-21 00:00:00",
            }
            for i in range(self._log_cleared_count)
        ]

    def query_event_logs(self, event_ids=None, limit=0, provider="", keyword_in_data=""):
        self.last_event_log_kwargs = {
            "event_ids": event_ids, "limit": limit,
            "provider": provider, "keyword_in_data": keyword_in_data,
        }
        return []

    def query_prefetch(self, app_name_filter="", limit=0):
        return []

    def query_services(self, service_filter="", limit=0):
        return []

    def _query_artifact(self, artifact_name, limit=0):
        return []


class _MultiProviderStub:
    """Stub that simulates the real connector's post-hoc provider filter.

    Records the provider the rule forwarded, then returns only hits whose
    ``Provider Name`` contains that substring — matching the behaviour of
    ``_hydrate_artifact_hits``. Lets a test verify that the rule's real
    filtering effect on a mixed-provider EID payload is correct, not just
    that the kwarg was passed.
    """

    def __init__(self, mixed_hits: list[dict]) -> None:
        self._mixed = mixed_hits
        self.last_provider: str | None = None

    def query_process_creation_events(self, limit=0):
        return []

    def query_powershell_scriptblock(self, limit=0):
        return []

    def query_log_cleared(self, limit=0):
        # Delegate to query_event_logs so both tests share the same stub path.
        return self.query_event_logs(event_ids=[1102], limit=limit,
                                     provider="Microsoft-Windows-Eventlog")

    def query_event_logs(self, event_ids=None, limit=0, provider="", keyword_in_data=""):
        self.last_provider = provider
        event_ids = set(event_ids or [])
        def _keep(h):
            if event_ids and h.get("Event ID") not in event_ids:
                return False
            if provider and provider.lower() not in str(h.get("Provider Name", "")).lower():
                return False
            return True
        return [h for h in self._mixed if _keep(h)]

    def query_prefetch(self, app_name_filter="", limit=0):
        return []

    def query_services(self, service_filter="", limit=0):
        return []

    def _query_artifact(self, artifact_name, limit=0):
        return []


def test_detect_anti_forensics_truncates_runaway_rule():
    aq = _StubArtifactQueries(log_cleared_count=1500)
    result = detect_anti_forensics(aq, max_details_per_rule=200)

    assert result["ok"] is True
    assert result["detail_cap_per_rule"] == 200
    assert result["any_rule_truncated"] is True
    # total_hits is the sum of real counts across rules — 1500 here.
    assert result["total_hits"] == 1500

    fired = [r for r in result["rules"] if r.get("ok") and r.get("count")]
    assert len(fired) == 1
    rule = fired[0]
    assert rule["rule_name"] == "log_cleared_security_1102"
    assert rule["truncated"] is True
    assert rule["count"] == 200
    assert rule["total_count"] == 1500
    assert len(rule["details"]) == 200


def test_detect_anti_forensics_no_truncation_when_under_cap():
    aq = _StubArtifactQueries(log_cleared_count=50)
    result = detect_anti_forensics(aq, max_details_per_rule=200)

    assert result["any_rule_truncated"] is False
    fired = [r for r in result["rules"] if r.get("ok") and r.get("count")]
    assert len(fired) == 1
    rule = fired[0]
    assert rule["truncated"] is False
    assert rule["count"] == 50
    assert rule["total_count"] == 50


def test_detect_anti_forensics_cap_disabled_returns_everything():
    aq = _StubArtifactQueries(log_cleared_count=1500)
    result = detect_anti_forensics(aq, max_details_per_rule=0)

    assert result["detail_cap_per_rule"] == 0
    assert result["any_rule_truncated"] is False
    fired = [r for r in result["rules"] if r.get("ok") and r.get("count")]
    rule = fired[0]
    assert rule["truncated"] is False
    assert rule["count"] == 1500
    assert rule["total_count"] == 1500


def test_system_log_cleared_rule_pins_provider_to_eventlog():
    """Contract test — Bug #6 regression.

    EID 104 is reused by many providers (Diagnosis-Scripted, Kernel-Cache,
    Kernel-LiveDump, ...) for unrelated events. Without a provider pin the
    rule would surface all of them as anti-forensic noise — observed on a
    real case as 7,893 false positives / 0 real hits. This test forbids that
    regression by asserting the rule forwards the correct provider filter.
    """
    aq = _StubArtifactQueries(log_cleared_count=0)
    detect_anti_forensics(aq, max_details_per_rule=10)

    # _rule_system_log_cleared is the only path that invokes query_event_logs
    # in the stub (the rest use query_log_cleared / query_prefetch / ...).
    assert aq.last_event_log_kwargs is not None
    assert aq.last_event_log_kwargs["event_ids"] == [104]
    assert aq.last_event_log_kwargs["provider"] == "Microsoft-Windows-Eventlog"


def test_log_cleared_rules_drop_wrong_provider_hits():
    """End-to-end behavioural check — Bug #6 regression.

    Feed a mix of EID 104 / 1102 hits from the noise providers observed on
    the real case plus one genuine ``Microsoft-Windows-Eventlog`` hit each.
    After the provider pin, only the genuine hits should survive.
    """
    mixed = [
        # EID 104 noise (real case pattern)
        {"hit_id": 1, "Event ID": 104, "Provider Name": "Microsoft-Windows-Diagnosis-Scripted",
         "Event Data": "diagnostic payload", "Computer": "HOST-A"},
        {"hit_id": 2, "Event ID": 104, "Provider Name": "Microsoft-Windows-Kernel-Cache",
         "Event Data": "kernel cache payload", "Computer": "HOST-A"},
        {"hit_id": 3, "Event ID": 104, "Provider Name": "Microsoft-Windows-Kernel-LiveDump",
         "Event Data": "livedump payload", "Computer": "HOST-A"},
        # Genuine EID 104 — System log cleared
        {"hit_id": 4, "Event ID": 104, "Provider Name": "Microsoft-Windows-Eventlog",
         "Event Data": "system log was cleared", "Computer": "HOST-A"},
        # EID 1102 — hypothetical noise provider (defence in depth)
        {"hit_id": 5, "Event ID": 1102, "Provider Name": "Some-Other-Provider",
         "Event Data": "unrelated 1102 payload", "Computer": "HOST-A"},
        # Genuine EID 1102 — Security log cleared
        {"hit_id": 6, "Event ID": 1102, "Provider Name": "Microsoft-Windows-Eventlog",
         "Event Data": "security log was cleared", "Computer": "HOST-A"},
    ]
    aq = _MultiProviderStub(mixed)
    result = detect_anti_forensics(aq, max_details_per_rule=10)

    by_name = {r["rule_name"]: r for r in result["rules"] if r.get("ok") and r.get("count")}
    # Both rules fire exactly once — only the Eventlog-provider hits survive.
    assert set(by_name) == {"log_cleared_system_104", "log_cleared_security_1102"}
    sys_hits = by_name["log_cleared_system_104"]["details"]
    sec_hits = by_name["log_cleared_security_1102"]["details"]
    assert len(sys_hits) == 1 and sys_hits[0]["hit_id"] == 4
    assert len(sec_hits) == 1 and sec_hits[0]["hit_id"] == 6
    # total_count reflects the post-filter count, not the pre-filter noise.
    assert by_name["log_cleared_system_104"]["total_count"] == 1
    assert by_name["log_cleared_security_1102"]["total_count"] == 1


class _SubstringProviderStub:
    """Simulates the connector's current substring-based provider filter.

    The real ``_hydrate_artifact_hits`` uses a substring check — so a
    hypothetical ``Microsoft-Windows-Eventlog-Whatever`` provider would
    slip through the connector layer. The rule-level exact-match filter
    is the last line of defence and is what this test exercises.
    """

    def __init__(self, events: list[dict]) -> None:
        self._events = events

    def query_process_creation_events(self, limit=0):
        return []

    def query_powershell_scriptblock(self, limit=0):
        return []

    def query_log_cleared(self, limit=0):
        return self.query_event_logs(event_ids=[1102], limit=limit,
                                     provider="Microsoft-Windows-Eventlog")

    def query_event_logs(self, event_ids=None, limit=0, provider="", keyword_in_data=""):
        event_ids = set(event_ids or [])
        def _keep(h):
            if event_ids and h.get("Event ID") not in event_ids:
                return False
            if provider and provider.lower() not in str(h.get("Provider Name", "")).lower():
                return False
            return True
        return [h for h in self._events if _keep(h)]

    def query_prefetch(self, app_name_filter="", limit=0):
        return []

    def query_services(self, service_filter="", limit=0):
        return []

    def _query_artifact(self, artifact_name, limit=0):
        return []


def test_rule_exact_match_defence_rejects_substring_impostor():
    """Bug #6 defence-in-depth — connector uses substring filter, so the
    rule must also require exact Provider equality to reject a crafted
    ``Microsoft-Windows-Eventlog-Whatever`` provider.
    """
    events = [
        # Substring-impostor — would pass the connector's substring filter
        # because "microsoft-windows-eventlog" is contained in the name.
        {"hit_id": 10, "Event ID": 104,
         "Provider Name": "Microsoft-Windows-Eventlog-Whatever",
         "Event Data": "impostor payload", "Computer": "HOST-B"},
        {"hit_id": 11, "Event ID": 1102,
         "Provider Name": "Microsoft-Windows-Eventlog-Whatever",
         "Event Data": "impostor payload", "Computer": "HOST-B"},
    ]
    aq = _SubstringProviderStub(events)
    result = detect_anti_forensics(aq, max_details_per_rule=10)
    fired = [r for r in result["rules"] if r.get("ok") and r.get("count")]
    # Neither EID 104 nor EID 1102 impostor should survive the rule's
    # exact-match guard — no rules fire.
    assert fired == [], f"impostor provider leaked through: {fired}"


class _RaisingStub:
    """Raises a specific exception for one event-log call path so the test
    can assert the outer detect_anti_forensics loop reports ok=False with
    the original error, instead of the rule swallowing it."""

    def __init__(self, raise_on_event_ids: list[int]) -> None:
        self._raise_on = set(raise_on_event_ids)

    def query_process_creation_events(self, limit=0):
        return []

    def query_powershell_scriptblock(self, limit=0):
        return []

    def query_log_cleared(self, limit=0):
        # Delegates — will raise if 1102 is on the raise list.
        return self.query_event_logs(event_ids=[1102], limit=limit,
                                     provider="Microsoft-Windows-Eventlog")

    def query_event_logs(self, event_ids=None, limit=0, provider="", keyword_in_data=""):
        for eid in event_ids or []:
            if eid in self._raise_on:
                raise RuntimeError(f"simulated connector failure for EID {eid}")
        return []

    def query_prefetch(self, app_name_filter="", limit=0):
        return []

    def query_services(self, service_filter="", limit=0):
        return []

    def _query_artifact(self, artifact_name, limit=0):
        return []


def test_connector_exception_surfaces_as_rule_failure_not_silent_none():
    """Codex post-review blocker — rules must NOT swallow exceptions.

    If the connector raises (schema change, unsupported kwarg, SQL bug),
    a detection tool that silently reports "no anti-forensic activity"
    is worse than one that crashes. The outer loop's ok=False path is
    the only acceptable failure mode.
    """
    aq = _RaisingStub(raise_on_event_ids=[104, 1102])
    result = detect_anti_forensics(aq, max_details_per_rule=10)

    by_name = {r["rule_name"]: r for r in result["rules"]}
    assert "log_cleared_system_104" in by_name
    assert "log_cleared_security_1102" in by_name
    assert by_name["log_cleared_system_104"]["ok"] is False
    assert by_name["log_cleared_security_1102"]["ok"] is False
    # The original error message must be visible for the analyst.
    assert "simulated connector failure for EID 104" in by_name["log_cleared_system_104"]["error"]
    assert "simulated connector failure for EID 1102" in by_name["log_cleared_security_1102"]["error"]
    # Neither rule should claim to have fired.
    assert by_name["log_cleared_system_104"].get("count") is None
    assert by_name["log_cleared_security_1102"].get("count") is None


def test_suspicious_rule_log_clearing_regression_for_query_log_cleared_contract():
    """Codex post-review — ``query_log_cleared()`` contract narrowed to
    Eventlog-provider hits only. suspicious.rule_log_clearing() delegates
    to it, so this test pins down that the narrower contract flows all
    the way through to that rule's result.
    """
    from core.analysis.suspicious import rule_log_clearing

    mixed = [
        # Impostor EID 1102 — not from Microsoft-Windows-Eventlog.
        {"hit_id": 20, "Event ID": 1102, "Provider Name": "Some-Other-Provider",
         "Event Data": "impostor 1102", "Computer": "HOST-C",
         "Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-20 01:00:00",
         "Security Identifier": ""},
        # Real log-cleared event.
        {"hit_id": 21, "Event ID": 1102, "Provider Name": "Microsoft-Windows-Eventlog",
         "Event Data": "real 1102", "Computer": "HOST-C",
         "Created Date/Time - UTC (yyyy-mm-dd)": "2026-04-20 02:00:00",
         "Security Identifier": "S-1-5-18"},
    ]
    aq = _MultiProviderStub(mixed)
    out = rule_log_clearing(aq)

    assert out is not None
    # Exactly one hit — the impostor must not bleed into suspicious findings.
    assert out["matching_count"] == 1
    assert len(out["details"]) == 1
    assert out["details"][0]["hit_id"] == 21
