"""Unit tests for core.analysis.hunt_packs."""

from __future__ import annotations

import asyncio
import json

from core.analysis import hunt_packs as hp


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_builtin_packs_load():
    result = hp.list_packs()
    names = {p["name"] for p in result["packs"] if "name" in p}
    assert {"log_tamper_sweep", "persistence_sweep", "remote_access_sweep"} <= names


def test_substitute_replaces_placeholders():
    out = hp._substitute(
        {"rule_ids": "fw-evtx-001,{extra}", "severity_min": "{sev}"},
        {"extra": "fw-evtx-003", "sev": "medium"},
    )
    assert out == {"rule_ids": "fw-evtx-001,fw-evtx-003", "severity_min": "medium"}


def test_substitute_leaves_literals_alone():
    assert hp._substitute("plain string", {}) == "plain string"
    assert hp._substitute(42, {"x": "y"}) == 42


def test_run_pack_dispatches_each_step(tmp_path, monkeypatch):
    # Write a tiny local pack that calls two dummy tools.
    local = tmp_path / "local"
    local.mkdir()
    pack_path = local / "demo.json"
    pack_path.write_text(json.dumps({
        "name": "demo_pack",
        "description": "test",
        "steps": [
            {"tool": "tool_a", "args": {"x": "{name}"}},
            {"tool": "tool_b", "args": {"n": 3}},
        ],
    }))
    monkeypatch.setattr(hp, "_LOCAL_DIR", str(local))
    monkeypatch.setattr(hp, "_BUILTIN_DIR", str(tmp_path / "builtin"))
    (tmp_path / "builtin").mkdir()

    calls: list[tuple[str, dict]] = []

    def fake_dispatch(tool, args):
        calls.append((tool, args))
        return {"total_findings": 1}

    result = _run(hp.run_pack("demo_pack", params={"name": "alice"}, tool_dispatch=fake_dispatch))
    assert result["ok"] is True
    assert len(result["steps"]) == 2
    assert calls == [("tool_a", {"x": "alice"}), ("tool_b", {"n": 3})]
    assert all(s["status"] == "ok" for s in result["steps"])


def test_step_failure_does_not_abort_remaining(tmp_path, monkeypatch):
    local = tmp_path / "local"; local.mkdir()
    (tmp_path / "builtin").mkdir()
    monkeypatch.setattr(hp, "_LOCAL_DIR", str(local))
    monkeypatch.setattr(hp, "_BUILTIN_DIR", str(tmp_path / "builtin"))
    pack_path = local / "demo.json"
    pack_path.write_text(json.dumps({
        "name": "demo", "description": "",
        "steps": [
            {"tool": "tool_a", "args": {}},
            {"tool": "tool_broken", "args": {}},
            {"tool": "tool_c", "args": {}},
        ],
    }))

    def dispatch(tool, args):
        if tool == "tool_broken":
            raise RuntimeError("boom")
        return {"total": 1}

    result = _run(hp.run_pack("demo", tool_dispatch=dispatch))
    statuses = [s["status"] for s in result["steps"]]
    assert statuses == ["ok", "error", "ok"]
    assert "boom" in result["steps"][1]["error"]


def test_unknown_pack_returns_error():
    result = _run(hp.run_pack("nonexistent_pack", tool_dispatch=lambda t, a: {}))
    assert result["ok"] is False
    assert "not found" in result["error"].lower()
