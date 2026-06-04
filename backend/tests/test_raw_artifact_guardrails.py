from __future__ import annotations

import asyncio
import struct
from datetime import datetime, timezone

import mcp_bridge


def _run(coro):
    return asyncio.run(coro)


def _filetime(value: str) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def _prefetch_bytes(executable_name: str = "CMD.EXE") -> bytes:
    data = bytearray(0x180)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    data[0x10:0x10 + 60] = executable_name.encode("utf-16le").ljust(60, b"\x00")
    struct.pack_into("<Q", data, 0x80, _filetime("2026-02-11T08:00:07Z"))
    struct.pack_into("<I", data, 0xD0, 1)
    return bytes(data)


def _mock_selected_raw_image(monkeypatch):
    image_path = r"D:\case\selected.E01"
    monkeypatch.setattr(mcp_bridge, "_connectors", {})
    monkeypatch.setattr(
        mcp_bridge,
        "load_allowed_evidence",
        lambda: {"paths": [image_path], "source": "test"},
    )
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})
    monkeypatch.setattr(
        mcp_bridge,
        "resolve_image_evidence",
        lambda input_ref="": {"path": image_path, "source": "allowed_evidence"},
    )
    return image_path


def test_selected_raw_image_guidance_forces_active_image_alias(monkeypatch):
    image_path = _mock_selected_raw_image(monkeypatch)

    guidance = mcp_bridge._selected_evidence_guidance()

    assert guidance["evidence_mode"] == "raw_image_selected_unmounted"
    assert guidance["selected_evidence"]["selected_image"]["path"] == image_path
    assert guidance["next_required_action"]["tool"] == "mount_image"
    assert guidance["next_required_action"]["args"] == {"evidence_ref": "active_image"}
    assert guidance["enforcement"]["do_not_search_workspace_for_replacement_evidence"] is True


def test_get_summary_returns_selected_evidence_before_case_error(monkeypatch):
    _mock_selected_raw_image(monkeypatch)

    async def passthrough(_tool_name, _params, fn, timeout_seconds=0):
        return fn()

    monkeypatch.setattr(mcp_bridge, "_traced", passthrough)

    result = _run(mcp_bridge.get_summary())

    assert result["mode"] == "raw_image_selected_unmounted"
    assert result["parsed_case_loaded"] is False
    assert result["selected_evidence_guidance"]["next_required_action"]["tool"] == "mount_image"


def test_common_tool_errors_attach_selected_evidence_guidance(monkeypatch):
    _mock_selected_raw_image(monkeypatch)

    result = _run(mcp_bridge._traced(
        "unit",
        {},
        lambda: (_ for _ in ()).throw(RuntimeError("no parsed case")),
        timeout_seconds=1,
    ))

    assert result["error"] == "no parsed case"
    assert result["selected_evidence_guidance"]["next_required_action"]["args"] == {
        "evidence_ref": "active_image",
    }


def test_raw_guardrail_zero_result_warns_against_absence_claims():
    guardrail = mcp_bridge._raw_artifact_guardrails("prefetch", total=0)

    assert guardrail["evidence_role"] == "extraction_only"
    assert guardrail["strong_conclusion_allowed"] is False
    assert guardrail["absence_is_negative_evidence"] is False
    assert "zero_result_guidance" in guardrail


def test_query_prefetch_files_attaches_interpretation_guardrails(tmp_path, monkeypatch):
    pf = tmp_path / "CMD.EXE-12345678.pf"
    pf.write_bytes(_prefetch_bytes())
    monkeypatch.setattr(mcp_bridge, "_is_safe_local_analysis_path", lambda _path: True)

    result = _run(mcp_bridge.query_prefetch_files(
        prefetch_path=str(pf),
        keyword="does-not-match",
    ))

    assert result["ok"] is True
    assert result["total"] == 0
    guardrail = result["interpretation_guardrails"]
    assert guardrail["evidence_role"] == "extraction_only"
    assert "zero_result_guidance" in guardrail


def test_query_registry_hive_blocks_unbounded_keyword_search(monkeypatch):
    monkeypatch.setattr(
        mcp_bridge,
        "_materialize_local_artifact",
        lambda _path, _subdir: {
            "ok": True,
            "source": "local_file",
            "local_path": r"C:\workspace\SYSTEM",
        },
    )

    result = _run(mcp_bridge.query_registry_hive(
        hive_path=r"C:\workspace\SYSTEM",
        keyword="uploadmgr",
    ))

    assert result["ok"] is False
    assert "search_root" in result["error"]
    assert result["query_semantics"]["search_root_required"] is True
    guardrail = result["interpretation_guardrails"]
    assert guardrail["evidence_role"] == "extraction_only"
    assert guardrail["absence_is_negative_evidence"] is False


def test_materialized_local_artifact_carries_evidence_context(tmp_path, monkeypatch):
    sample = tmp_path / "sample.evtx"
    sample.write_bytes(b"data")
    monkeypatch.setattr(mcp_bridge, "_is_safe_local_analysis_path", lambda _path: True)

    result = mcp_bridge._materialize_local_artifact(str(sample), "unit")

    assert result["ok"] is True
    assert result["source"] == "local_file"
    assert result["evidence_context"]["result_source"] == "local_file"
    assert result["evidence_context"]["warnings"]


def test_initial_triage_pack_raw_image_fallback(monkeypatch):
    async def passthrough(_tool_name, _params, fn, timeout_seconds=0):
        return fn()

    monkeypatch.setattr(mcp_bridge, "_traced", passthrough)
    monkeypatch.setattr(mcp_bridge, "_get_axiom", lambda: (_ for _ in ()).throw(RuntimeError("no parsed case")))
    monkeypatch.setattr(
        mcp_bridge,
        "_raw_image_triage_gate",
        lambda system_hive_path="/c:/Windows/System32/config/SYSTEM": {
            "ok": True,
            "mode": "raw_image_gate",
            "coverage": {"gaps": []},
            "required_followups": [],
        },
    )

    result = _run(mcp_bridge.initial_triage_pack())

    assert result["mode"] == "raw_image_fallback_for_initial_triage"
    assert "parsed_case_error" in result
    assert result["analysis_blockers"]


def test_evidence_bound_export_path_includes_mounted_image_identity(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})
    monkeypatch.setattr(mcp_bridge, "load_allowed_evidence", lambda: {"paths": []})
    monkeypatch.setattr(mcp_bridge, "resolve_image_evidence", lambda _ref="": {})

    class _E01:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {"image_path": r"D:\case\hostA.E01"}

    monkeypatch.setitem(mcp_bridge._connectors, "e01", _E01())
    first = mcp_bridge._evidence_bound_export_path("unit", "/c:/Windows/System32/config/SYSTEM", "SYSTEM.hive")

    class _E01B(_E01):
        def get_metadata(self):
            return {"image_path": r"D:\case\hostB.E01"}

    monkeypatch.setitem(mcp_bridge._connectors, "e01", _E01B())
    second = mcp_bridge._evidence_bound_export_path("unit", "/c:/Windows/System32/config/SYSTEM", "SYSTEM.hive")

    assert first != second
    assert first.endswith(".hive")
    assert second.endswith(".hive")


def test_default_analysis_output_is_created_beside_selected_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_bridge, "load_active_case", lambda: {})
    monkeypatch.setattr(mcp_bridge, "load_allowed_evidence", lambda: {"paths": []})
    monkeypatch.setattr(mcp_bridge, "resolve_image_evidence", lambda _ref="": {})

    evidence_dir = tmp_path / "case"
    evidence_dir.mkdir()
    image_path = evidence_dir / "host.E01"
    image_path.write_bytes(b"evidence placeholder")

    class _E01:
        def is_connected(self):
            return True

        def get_metadata(self):
            return {"image_path": str(image_path)}

    monkeypatch.setitem(mcp_bridge._connectors, "e01", _E01())

    output_path = mcp_bridge._evidence_bound_export_path(
        "unit",
        "/c:/Windows/System32/config/SYSTEM",
        "SYSTEM.hive",
    )
    context = mcp_bridge._analysis_output_context(create=False)

    expected_root = evidence_dir / "forensic-workstation-output"
    assert context["root"] == str(expected_root)
    assert context["fallback_to_workspace"] is False
    assert str(expected_root / "unit") in output_path
    assert output_path.endswith(".hive")
