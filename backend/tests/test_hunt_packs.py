"""Unit tests for core.analysis.hunt_packs."""

from __future__ import annotations

import asyncio
import json

from core.analysis import hunt_packs as hp


def _run(coro):
    return asyncio.run(coro)


def test_builtin_packs_load():
    result = hp.list_packs()
    names = {p["name"] for p in result["packs"] if "name" in p}
    assert {
        "entity_change_story_sweep",
        "log_tamper_sweep",
        "persistence_sweep",
        "remote_access_sweep",
    } <= names


def test_substitute_replaces_placeholders():
    out = hp._substitute(
        {"rule_ids": "fw-evtx-001,{extra}", "severity_min": "{sev}"},
        {"params": {"extra": "fw-evtx-003", "sev": "medium"}, "steps": {}},
    )
    assert out == {"rule_ids": "fw-evtx-001,fw-evtx-003", "severity_min": "medium"}


def test_substitute_leaves_literals_alone():
    assert hp._substitute("plain string", {"params": {}, "steps": {}}) == "plain string"
    assert hp._substitute(42, {"params": {"x": "y"}, "steps": {}}) == 42


def test_substitute_resolves_prior_step_results():
    out = hp._substitute(
        {
            "entity": "{steps.seed.result.recommended.entity_value}",
            "keywords": "{steps.seed.result.recommended.priority_seed_keywords_csv}",
        },
        {
            "params": {},
            "steps": {
                "seed": {
                    "result": {
                        "recommended": {
                            "entity_value": "bomgar-pec.exe",
                            "priority_seed_keywords_csv": "event_id:4648,event_id:7045",
                        }
                    }
                }
            },
        },
    )
    assert out == {
        "entity": "bomgar-pec.exe",
        "keywords": "event_id:4648,event_id:7045",
    }


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


def test_run_pack_passes_prior_step_results(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    (tmp_path / "builtin").mkdir()
    monkeypatch.setattr(hp, "_LOCAL_DIR", str(local))
    monkeypatch.setattr(hp, "_BUILTIN_DIR", str(tmp_path / "builtin"))
    (local / "demo.json").write_text(json.dumps({
        "name": "demo_refs",
        "description": "test",
        "steps": [
            {
                "id": "seed",
                "tool": "tool_a",
                "args": {},
            },
            {
                "tool": "tool_b",
                "args": {
                    "entity": "{steps.seed.result.recommended.entity_value}",
                    "keywords": "{steps.seed.result.recommended.priority_seed_keywords_csv}",
                },
            },
        ],
    }))

    calls: list[tuple[str, dict]] = []

    def fake_dispatch(tool, args):
        calls.append((tool, args))
        if tool == "tool_a":
            return {"recommended": {"entity_value": "bomgar-pec.exe", "priority_seed_keywords_csv": "event_id:4648"}}
        return {"ok": True}

    result = _run(hp.run_pack("demo_refs", tool_dispatch=fake_dispatch))
    assert result["ok"] is True
    assert calls == [
        ("tool_a", {}),
        ("tool_b", {"entity": "bomgar-pec.exe", "keywords": "event_id:4648"}),
    ]


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


def test_step_can_skip_when_resolved_arg_is_empty(tmp_path, monkeypatch):
    local = tmp_path / "local"; local.mkdir()
    (tmp_path / "builtin").mkdir()
    monkeypatch.setattr(hp, "_LOCAL_DIR", str(local))
    monkeypatch.setattr(hp, "_BUILTIN_DIR", str(tmp_path / "builtin"))
    pack_path = local / "demo.json"
    pack_path.write_text(json.dumps({
        "name": "demo_skip",
        "description": "",
        "steps": [
            {"tool": "tool_a", "args": {}},
            {"tool": "tool_b", "skip_if_empty_params": ["entity"], "args": {"entity": "{missing}"}},
            {"tool": "tool_c", "args": {}},
        ],
    }))

    calls: list[str] = []

    def dispatch(tool, args):
        calls.append(tool)
        return {"ok": True}

    result = _run(hp.run_pack("demo_skip", tool_dispatch=dispatch))
    statuses = [s["status"] for s in result["steps"]]
    assert statuses == ["ok", "skipped", "ok"]
    assert calls == ["tool_a", "tool_c"]


def test_unknown_pack_returns_error():
    result = _run(hp.run_pack("nonexistent_pack", tool_dispatch=lambda t, a: {}))
    assert result["ok"] is False
    assert "not found" in result["error"].lower()


def test_entity_change_story_sweep_does_not_auto_inject_recommended_entity():
    pack = hp._resolve_pack("entity_change_story_sweep")
    assert pack is not None
    serialized = json.dumps(pack, ensure_ascii=False)
    assert "recommended.entity_value" not in serialized
