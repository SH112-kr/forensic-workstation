from __future__ import annotations

import threading
import time


def _isolate_files(monkeypatch, tmp_path):
    from core.analysis import privacy_proxy

    monkeypatch.setattr(privacy_proxy, "_SETTINGS_FILE", str(tmp_path / "privacy.json"))
    monkeypatch.setattr(privacy_proxy, "_PENDING_FILE", str(tmp_path / "intercepts.json"))
    monkeypatch.setattr(privacy_proxy, "_AUDIT_FILE", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(privacy_proxy, "_ALIAS_FILE", str(tmp_path / "aliases.json"))
    monkeypatch.setattr(privacy_proxy, "_FILTER_LOG_FILE", str(tmp_path / "filter_events.json"))
    return privacy_proxy


def test_privacy_proxy_redacts_sensitive_payload_with_stable_tokens(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})

    payload = {
        "fields": {
            "User": "alice",
            "HostName": "DESKTOP-SECRET",
            "Path": r"C:\Users\alice\Downloads\loot.txt",
            "CommandLine": "curl http://example.test/a?token=abc password=hunter2",
            "IP": "203.0.113.5",
        }
    }

    projected = pp.apply_tool_privacy("get_hit_detail", {"hit_id": 1}, payload, channel="test")
    text = str(projected)

    assert "alice" not in text
    assert "DESKTOP-SECRET" not in text
    assert "hunter2" not in text
    assert "203.0.113.5" not in text
    assert "USER_HMAC_" in text
    assert "HOST_HMAC_" in text
    assert projected["_privacy"]["mode"] == "exclude"
    assert projected["_privacy"]["highlighted"] is True
    assert projected["_privacy"]["filter_event_id"]

    events = pp.list_filter_events()
    assert len(events) == 1
    assert events[0]["mode"] == "exclude"
    assert events[0]["status"] == "applied"
    assert events[0]["tool"] == "get_hit_detail"
    assert events[0]["match_count"] >= 1
    assert "alice" not in str(events[0]["matches"])
    assert "DESKTOP-SECRET" not in str(events[0]["matches"])


def test_privacy_proxy_redacts_non_user_windows_paths(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})

    payload = {
        "source_path": r"D:\incident\case42\server.E01",
        "system_path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    }

    projected = pp.apply_tool_privacy("get_summary", {}, payload, channel="test")
    text = str(projected)

    assert r"D:\incident\case42\server.E01" not in text
    assert r"C:\Windows\System32\winevt\Logs\Security.evtx" not in text
    assert "PATH_HMAC_" in text


def test_privacy_aliases_project_response_and_resolve_request(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})
    alias = pp.add_alias("홍길동", alias_type="PERSON")
    assert alias["alias"] == "PERSON_001"
    assert "raw_value" not in alias

    payload = {"path": r"C:\Users\홍길동\Downloads\a.exe", "user": "홍길동"}
    projected = pp.apply_tool_privacy("get_file_timestamps", {}, payload, channel="mcp")
    text = str(projected)

    assert "홍길동" not in text
    assert "PERSON_001" in text
    assert "USER_HMAC" not in text
    assert projected["_privacy"]["match_count"] == 0

    params = {"internal_path": r"C:\Users\PERSON_001\Downloads\a.exe", "user": "PERSON_001"}
    resolved = pp.resolve_aliases_in_payload(params)
    assert resolved["internal_path"] == r"C:\Users\홍길동\Downloads\a.exe"
    assert resolved["user"] == "홍길동"


def test_privacy_path_alias_can_be_used_as_safe_handle(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})
    pp.add_alias(r"C:\Users\홍길동\Downloads\a.exe", alias_type="PATH")

    projected = pp.apply_tool_privacy(
        "get_file_timestamps",
        {},
        {"internal_path": r"C:\Users\홍길동\Downloads\a.exe"},
        channel="mcp",
    )
    assert projected["internal_path"] == "PATH_001"
    assert projected["_privacy"]["match_count"] == 0
    assert pp.resolve_aliases_in_payload({"internal_path": "PATH_001"})["internal_path"] == r"C:\Users\홍길동\Downloads\a.exe"


def test_privacy_aliases_apply_even_in_include_mode(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "include", "intercept_sensitive_tools": True, "max_matches": 200})
    pp.add_alias("홍길동", alias_type="PERSON")

    projected = pp.apply_tool_privacy(
        "get_file_timestamps",
        {},
        {"path": r"C:\Users\홍길동\Downloads\a.exe", "user": "홍길동"},
        channel="mcp",
    )
    text = str(projected)

    assert "홍길동" not in text
    assert "PERSON_001" in text
    assert projected["_privacy"]["mode"] == "include"


def test_privacy_aliases_support_custom_prefix_and_updates(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})

    created = pp.add_alias("홍길동", alias_type="SUSPECT")
    assert created["alias"] == "SUSPECT_001"

    updated = pp.update_alias(created["id"], raw_value="김철수", alias_type="ACTOR", alias="lead")
    assert updated["alias"] == "ACTOR_LEAD"
    assert updated["alias_type"] == "ACTOR"
    assert "raw_value" not in updated

    projected = pp.apply_tool_privacy("search_artifacts", {}, {"user": "김철수"}, channel="mcp")
    assert "김철수" not in str(projected)
    assert projected["user"] == "ACTOR_LEAD"
    assert pp.resolve_aliases_in_payload({"user": "ACTOR_LEAD"})["user"] == "김철수"


def test_privacy_alias_raw_value_is_hidden_unless_requested(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "exclude", "intercept_sensitive_tools": True, "max_matches": 200})

    created = pp.add_alias("sensitive-person-name", alias_type="PERSON")

    listed = pp.list_aliases()
    public_item = pp.get_alias(created["id"])
    analyst_item = pp.get_alias(created["id"], include_raw=True)

    assert "raw_value" not in listed[0]
    assert "raw_value" not in public_item
    assert analyst_item["raw_value"] == "sensitive-person-name"


def test_privacy_proxy_intercept_creates_pending_payload(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True, "max_matches": 200})

    result = pp.apply_tool_privacy(
        "search_artifacts",
        {"keyword": "alice"},
        {"hits": [{"description": r"C:\Users\alice\AppData\Local\Temp\a.exe"}]},
        channel="mcp",
    )

    pending = result["privacy_intercept"]
    assert pending["status"] == "pending"
    assert pending["match_count"] >= 1
    assert "masked_preview" in pending

    items = pp.list_intercepts(include_payload=True)
    assert len(items) == 1
    assert items[0]["tool"] == "search_artifacts"
    assert items[0]["status"] == "pending"
    assert items[0]["payload_role"] == "response"
    assert items[0]["response_sensitive_summary"]["user_path"] == 1
    assert items[0]["payload"]["hits"][0]["description"].startswith(r"C:\Users\alice")
    assert all(not m["path"].startswith("$.result") for m in items[0]["matches"])

    listed = pp.list_intercepts()
    assert "payload" not in listed[0]
    assert "masked_payload" not in listed[0]
    assert "masked_preview" in listed[0]
    assert r"C:\Users\alice" not in str(listed[0].get("matches", []))

    events = pp.list_filter_events()
    assert len(events) == 1
    assert events[0]["mode"] == "intercept"
    assert events[0]["status"] == "pending"
    assert events[0]["intercept_id"] == items[0]["id"]
    assert r"C:\Users\alice" not in str(events[0]["matches"])

    resolved = pp.resolve_intercept(items[0]["id"], action="send_masked")
    assert resolved["decision"] == "send_masked"
    assert resolved["status"] == "resolved"
    assert pp.list_filter_events()[0]["status"] == "resolved"
    assert pp.list_filter_events()[0]["decision"] == "send_masked"


def test_privacy_proxy_does_not_intercept_clean_response_only_because_request_is_sensitive(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True, "max_matches": 200})

    projected = pp.apply_tool_privacy(
        "search_artifacts",
        {"keyword": r"C:\Users\alice\Downloads"},
        {"hits": [], "status": "ok"},
        channel="mcp",
    )

    assert "privacy_intercept" not in projected
    assert projected["hits"] == []
    assert projected["_privacy"]["mode"] == "intercept"
    assert projected["_privacy"]["match_count"] == 0
    assert pp.list_intercepts() == []


def test_privacy_proxy_replays_edited_payload_with_projection_metadata(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True, "max_matches": 200})
    result = pp.apply_tool_privacy(
        "get_summary",
        {},
        {"path": r"C:\Evidence\case.E01", "keep": "value"},
        channel="mcp",
    )
    intercept_id = result["privacy_intercept"]["intercept_id"]

    pending_replay = pp.replay_intercept(intercept_id)
    assert pending_replay["privacy_replay"]["status"] == "pending"

    edited = {"path": "PATH_REDACTED_BY_ANALYST", "keep": "value", "note": "edited"}
    pp.resolve_intercept(intercept_id, action="send_edited", edited_payload=edited)
    replayed = pp.replay_intercept(intercept_id)

    assert replayed["path"] == "PATH_REDACTED_BY_ANALYST"
    assert replayed["note"] == "edited"
    assert replayed["_privacy_replay"]["status"] == "replayed"
    assert replayed["_privacy_replay"]["decision"] == "send_edited"
    assert replayed["_privacy_replay"]["edited_payload_sha256"]
    assert replayed["_privacy_replay"]["analyst_projection"] is True
    assert any("edited" in note.lower() for note in replayed["analysis_limitations"])


def test_privacy_proxy_keeps_resolved_intercepts_when_new_pending_is_created(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True, "max_matches": 200})
    first = pp.apply_tool_privacy(
        "search_artifacts",
        {"keyword": "one"},
        {"path": r"C:\Evidence\one.E01"},
        channel="mcp",
    )["privacy_intercept"]["intercept_id"]
    pp.resolve_intercept(first, action="send_masked")

    second = pp.apply_tool_privacy(
        "get_summary",
        {},
        {"path": r"C:\Evidence\two.E01"},
        channel="mcp",
    )["privacy_intercept"]["intercept_id"]

    assert pp.get_intercept(first)["status"] == "resolved"
    assert pp.get_intercept(second)["status"] == "pending"
    assert pp.replay_intercept(first)["_privacy_replay"]["decision"] == "send_masked"


def test_privacy_proxy_can_block_until_analyst_sends_edited_payload(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({
        "mode": "intercept",
        "intercept_sensitive_tools": True,
        "intercept_blocking": True,
        "intercept_timeout_seconds": 5,
        "max_matches": 200,
    })

    result_box = {}

    def call_tool():
        result_box["result"] = pp.apply_tool_privacy(
            "search_artifacts",
            {"keyword": "alice"},
            {"hits": [{"path": r"C:\Users\alice\Downloads\secret.txt"}]},
            channel="mcp",
            wait_for_resolution=True,
        )

    worker = threading.Thread(target=call_tool)
    worker.start()

    intercept_id = ""
    for _ in range(50):
        items = pp.list_intercepts(include_payload=True)
        if items:
            intercept_id = items[0]["id"]
            break
        time.sleep(0.05)

    assert intercept_id
    assert worker.is_alive()

    edited = {"hits": [{"path": "PATH_REDACTED_BY_ANALYST", "note": "approved edit"}]}
    pp.resolve_intercept(intercept_id, action="send_edited", edited_payload=edited)
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert result_box["result"]["hits"][0]["path"] == "PATH_REDACTED_BY_ANALYST"
    assert result_box["result"]["_privacy_replay"]["decision"] == "send_edited"
    assert result_box["result"]["_privacy_replay"]["analyst_projection"] is True


def test_privacy_proxy_blocking_timeout_returns_replay_handle(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({
        "mode": "intercept",
        "intercept_sensitive_tools": True,
        "intercept_blocking": True,
        "intercept_timeout_seconds": 1,
        "max_matches": 200,
    })

    result = pp.apply_tool_privacy(
        "get_summary",
        {},
        {"path": r"C:\Evidence\case.E01"},
        channel="mcp",
        wait_for_resolution=True,
    )

    pending = result["privacy_intercept"]
    assert pending["status"] == "pending_timeout"
    assert pending["blocking"] is True
    assert pending["next_required_action"]["tool"] == "privacy_replay_intercept"


def test_privacy_proxy_get_intercept_hides_raw_payload_by_default(monkeypatch, tmp_path):
    pp = _isolate_files(monkeypatch, tmp_path)
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True, "max_matches": 200})
    result = pp.apply_tool_privacy(
        "server_runtime_info",
        {},
        {"path": r"C:\Users\alice\case.E01"},
        channel="mcp",
    )
    intercept_id = result["privacy_intercept"]["intercept_id"]

    public_item = pp.get_intercept(intercept_id, include_payload=False)
    assert "payload" not in public_item
    assert "edited_payload" not in public_item
    assert "masked_preview" in public_item

    analyst_item = pp.get_intercept(intercept_id, include_payload=True)
    assert analyst_item["payload"]["path"] == r"C:\Users\alice\case.E01"


def test_privacy_state_is_scoped_by_project_context(monkeypatch, tmp_path):
    from core.analysis import privacy_proxy as pp

    settings_default = str(tmp_path / ".privacy_policy.json")
    pending_default = str(tmp_path / ".privacy_intercepts.json")
    audit_default = str(tmp_path / ".privacy_audit.jsonl")
    alias_default = str(tmp_path / ".privacy_aliases.json")
    filter_default = str(tmp_path / ".privacy_filter_events.json")
    monkeypatch.setattr(pp, "_DEFAULT_SETTINGS_FILE", settings_default)
    monkeypatch.setattr(pp, "_DEFAULT_PENDING_FILE", pending_default)
    monkeypatch.setattr(pp, "_DEFAULT_AUDIT_FILE", audit_default)
    monkeypatch.setattr(pp, "_DEFAULT_ALIAS_FILE", alias_default)
    monkeypatch.setattr(pp, "_DEFAULT_FILTER_LOG_FILE", filter_default)
    monkeypatch.setattr(pp, "_SETTINGS_FILE", settings_default)
    monkeypatch.setattr(pp, "_PENDING_FILE", pending_default)
    monkeypatch.setattr(pp, "_AUDIT_FILE", audit_default)
    monkeypatch.setattr(pp, "_ALIAS_FILE", alias_default)
    monkeypatch.setattr(pp, "_FILTER_LOG_FILE", filter_default)
    monkeypatch.setattr(pp, "_PRIVACY_SCOPES_DIR", str(tmp_path / "scopes"))
    monkeypatch.setattr(pp, "_SCOPE_FILE", str(tmp_path / "scope.json"))

    scope_a = pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_a.fwproject"),
        project_name="Case A",
        evidence_paths=[str(tmp_path / "a.e01")],
    )
    pp.save_settings({"mode": "intercept", "intercept_sensitive_tools": True})
    pp.add_alias("case-a-secret", alias_type="PERSON")
    pp.create_intercept(tool="get_hit_detail", params={}, payload={"user": "case-a-secret"}, channel="test")

    scope_b = pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_b.fwproject"),
        project_name="Case B",
        evidence_paths=[str(tmp_path / "b.e01")],
    )
    assert scope_a["id"] != scope_b["id"]
    assert pp.list_aliases() == []
    assert pp.list_intercepts() == []
    assert pp.public_settings()["mode"] == "exclude"

    pp.add_alias("case-b-secret", alias_type="PERSON")
    assert [item["alias"] for item in pp.list_aliases()] == ["PERSON_001"]

    pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_a.fwproject"),
        project_name="Case A",
        evidence_paths=[str(tmp_path / "a.e01")],
    )
    assert [item["alias"] for item in pp.list_aliases()] == ["PERSON_001"]
    assert len(pp.list_intercepts()) == 1
    assert pp.public_settings()["mode"] == "intercept"


def test_legacy_masker_mapping_is_scoped_by_project_context(monkeypatch, tmp_path):
    from core.analysis import masker as masker_mod
    from core.analysis import privacy_proxy as pp

    monkeypatch.setattr(masker_mod, "_DEFAULT_MAPPING_FILE", str(tmp_path / "masking_map.json"))
    monkeypatch.setattr(pp, "_PRIVACY_SCOPES_DIR", str(tmp_path / "scopes"))
    monkeypatch.setattr(pp, "_SCOPE_FILE", str(tmp_path / "scope.json"))

    masker = masker_mod.DataMasker()
    masker.enable()

    pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_a.fwproject"),
        project_name="Case A",
        evidence_paths=[str(tmp_path / "a.e01")],
    )
    assert masker.mask({"ip": "203.0.113.10"})["ip"] == "IP_001"

    pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_b.fwproject"),
        project_name="Case B",
        evidence_paths=[str(tmp_path / "b.e01")],
    )
    assert masker.mask({"ip": "198.51.100.20"})["ip"] == "IP_001"
    assert "203.0.113.10" not in masker.get_mapping().values()

    pp.set_privacy_scope_context(
        project_path=str(tmp_path / "case_a.fwproject"),
        project_name="Case A",
        evidence_paths=[str(tmp_path / "a.e01")],
    )
    assert "203.0.113.10" in masker.get_mapping().values()
