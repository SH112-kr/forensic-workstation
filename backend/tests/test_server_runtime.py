from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_bridge  # noqa: E402


def test_attach_runtime_warning_when_code_is_stale(monkeypatch):
    monkeypatch.setattr(
        mcp_bridge,
        "_runtime_status",
        lambda: {
            "pid": 1234,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stale_code_detected": True,
            "stale_files": ["backend/mcp_bridge.py"],
            "watched_files": ["backend/mcp_bridge.py"],
            "latest_code_mtime": datetime.now(timezone.utc).isoformat(),
        },
    )
    result = mcp_bridge._attach_runtime_warning({"status": "ok"}, tool_name="service_persistence_gate")
    assert result["status"] == "ok"
    assert result["server_runtime"]["pid"] == 1234
    assert result["server_runtime"]["stale_code_detected"] is True
    assert result["runtime_warnings"]
    assert result["runtime_status"]["severity"] == "critical"
    assert result["runtime_status"]["restart_required_before_relying_on_result"] is True
    assert result["analysis_blockers"]


def test_attach_runtime_warning_noop_when_fresh(monkeypatch):
    monkeypatch.setattr(
        mcp_bridge,
        "_runtime_status",
        lambda: {
            "pid": 1234,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stale_code_detected": False,
            "stale_files": [],
            "watched_files": [],
            "latest_code_mtime": "",
        },
    )
    result = mcp_bridge._attach_runtime_warning({"status": "ok"})
    assert result == {"status": "ok"}
