"""Unit tests for core.analysis.baseline_diff."""

from __future__ import annotations

from core.analysis.baseline_diff import baseline_diff


class _FakeAQ:
    """Minimal ArtifactQueries stand-in for baseline_diff."""

    def __init__(self, services=None, tasks=None, startup=None, users=None):
        self._services = services or []
        self._tasks = tasks or []
        self._startup = startup or []
        self._users = users or []

    def query_services(self, limit=0):
        return [{"Service Name": s} for s in self._services]

    def query_scheduled_tasks(self, limit=0):
        return [{"Name": t} for t in self._tasks]

    def _query_artifact(self, name, limit=0):
        if name == "Startup Items":
            return [{"Path": s} for s in self._startup]
        if name == "User Accounts":
            return [{"Username": u} for u in self._users]
        return []


def test_diff_against_builtin_baseline():
    """Services in active case that aren't in the builtin list should surface."""
    active = _FakeAQ(services=["WinDefend", "EvilAgent", "MyCustomSvc"])
    r = baseline_diff(active)
    assert r["reference_source"] == "builtin_windows_baseline"
    # WinDefend is in the baseline; EvilAgent / MyCustomSvc should be flagged.
    new_services = r["categories"]["services"]["net_new"]
    assert "evilagent" in new_services
    assert "mycustomsvc" in new_services
    assert "windefend" not in new_services


def test_diff_against_reference_case():
    """A reference case removes its own entries from the net-new list."""
    active = _FakeAQ(services=["SharedSvc", "ActiveOnlySvc"])
    reference = _FakeAQ(services=["SharedSvc", "RefOnlySvc"])
    r = baseline_diff(active, reference_aq=reference)
    assert r["reference_source"] == "case_reference"
    new = r["categories"]["services"]["net_new"]
    assert "activeonlysvc" in new
    assert "sharedsvc" not in new
    assert "refonlysvc" not in new  # only in reference, not in active — skipped


def test_category_filter():
    active = _FakeAQ(
        services=["ExtraSvc"], tasks=["ExtraTask"],
        startup=["C:\\evil.exe"], users=["hacker"],
    )
    r = baseline_diff(active, categories=["services", "users"])
    assert set(r["categories"].keys()) == {"services", "users"}


def test_empty_active_case():
    active = _FakeAQ()
    r = baseline_diff(active)
    for cat in r["categories"].values():
        assert cat["active_count"] == 0
        assert cat["net_new_count"] == 0


def test_summary_total():
    active = _FakeAQ(services=["S1", "S2"], tasks=["T1"], users=["bob"])
    r = baseline_diff(active)
    # S1, S2, T1 not in builtin, plus bob. SYSTEM / Administrator etc are filtered.
    assert r["summary"]["total_net_new"] >= 3
