"""Tests for A-9 timestomp ($SI/$FN divergence) anti-forensics rule."""

from __future__ import annotations

from core.analysis.anti_forensics import _rule_timestomp, detect_anti_forensics


class _MftStub:
    """Minimal ArtifactQueries stub serving MFT rows + empty everything else."""

    def __init__(self, mft_rows):
        self._mft = mft_rows

    def _query_artifact(self, artifact_name, limit=0):
        if artifact_name in ("MFT Entries", "MFT"):
            return list(self._mft)
        return []

    # detect_anti_forensics touches these; keep them empty.
    def query_event_logs(self, event_ids=None, limit=0, provider="", keyword_in_data=""):
        return []

    def query_log_cleared(self, limit=0):
        return []

    def query_process_creation_events(self, limit=0):
        return []

    def query_powershell_scriptblock(self, limit=0):
        return []

    def query_prefetch(self, app_name_filter="", limit=0):
        return []

    def query_services(self, service_filter="", limit=0):
        return []


def test_backdating_si_before_fn_detected():
    rows = [{
        "hit_id": 1,
        "File Path": "\\Users\\Public\\win.exe",
        "SI Created": "2020-01-01 09:00:00",
        "FN Created": "2026-05-19 03:14:00",
    }]
    out = _rule_timestomp(_MftStub(rows))
    assert out is not None and len(out) == 1
    assert out[0]["rule"] == "timestomp_si_fn_divergence"
    assert "backdating" in out[0]["evidence"].lower()


def test_subsecond_zero_only_flagged_on_suspicious_path():
    suspicious = [{
        "hit_id": 2,
        "File Path": "\\Windows\\Temp\\a.exe",
        "SI Created": "2026-05-19 03:14:00",       # sub-second == 0
        "FN Created": "2026-05-19 03:14:00.512345",
    }]
    out = _rule_timestomp(_MftStub(suspicious))
    assert out and out[0]["evidence"].lower().count("subsecond") >= 0  # signal present

    benign = [{
        "hit_id": 3,
        "File Path": "\\Program Files\\App\\setup.exe",  # normal path
        "SI Created": "2026-05-19 03:14:00",
        "FN Created": "2026-05-19 03:14:00.512345",
    }]
    assert _rule_timestomp(_MftStub(benign)) is None


def test_no_mft_family_returns_none_not_empty():
    """Absence of the MFT substrate must read as 'not evaluated', not clean."""
    assert _rule_timestomp(_MftStub([])) is None


def test_mft_without_si_fn_columns_returns_none():
    rows = [{"hit_id": 4, "File Path": "\\x", "Created": "2026-05-19 03:14:00"}]
    assert _rule_timestomp(_MftStub(rows)) is None


def test_aligned_timestamps_do_not_fire():
    rows = [{
        "hit_id": 5,
        "File Path": "\\Users\\Public\\ok.exe",
        "SI Created": "2026-05-19 03:14:00.500000",
        "FN Created": "2026-05-19 03:14:00.500000",
    }]
    assert _rule_timestomp(_MftStub(rows)) is None


def test_timestomp_integrated_in_detect_anti_forensics():
    rows = [{
        "hit_id": 6,
        "File Path": "\\ProgramData\\evil.exe",
        "SI Created": "2019-01-01 00:00:00",
        "FN Created": "2026-05-19 03:14:00",
    }]
    env = detect_anti_forensics(_MftStub(rows))
    fired = {r["rule_name"] for r in env["rules"] if r.get("ok") and r.get("count")}
    assert "timestomp_si_fn_divergence" in fired
    # The note must frame it as weak, not a standalone verdict.
    assert any("weak" in n.lower() for n in env["notes"])
