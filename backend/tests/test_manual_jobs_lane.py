from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


def test_manual_jobs_status_reports_synchronous_lane_mode():
    from api import manual

    result = _run(manual.manual_jobs_status())

    assert result["analyst_only"] is True
    assert result["source"] == "manual_workbench_jobs"
    assert result["mode"] == "sync_direct"
    assert result["active_job_count"] == 0
    assert any("no background job queue" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_jobs_lane_has_stable_status_view():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/jobs/status" in src
    assert "Refresh jobs" in src
    assert "jobsLoading" in src
    assert "Current absorbed lanes run in synchronous direct mode" in src
    assert "Active jobs" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
