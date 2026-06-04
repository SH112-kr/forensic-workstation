from __future__ import annotations

import asyncio

import mcp_bridge


_TEST_EVENT_LOOP = asyncio.new_event_loop()
asyncio.set_event_loop(_TEST_EVENT_LOOP)


def _run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(_TEST_EVENT_LOOP)


async def _passthrough(_tool_name, _params, fn, timeout_seconds=0):
    return fn()


class _NoExtractE01:
    def is_connected(self):
        return True

    def get_metadata(self):
        return {"image_path": r"D:\case\host.E01", "hostname": "HOST", "volumes": []}

    def extract_file(self, *_args, **_kwargs):
        raise AssertionError("document content extraction should be blocked before connector access")

    def vss_extract_file(self, *_args, **_kwargs):
        raise AssertionError("VSS document content extraction should be blocked before connector access")

    def list_vss_snapshots(self, volume="/c:"):
        return {
            "ok": True,
            "snapshot_count": 1,
            "snapshots": [{
                "snapshot_id": "snap-1",
                "snapshot_index": 0,
                "snapshot_creation_time": "2026-03-08T23:11:00Z",
                "temporal_layer": "vss:0:snap-1",
                "volume": volume,
                "integrity_note": "VSS contents are historical layers.",
            }],
        }


class _RecordingE01(_NoExtractE01):
    def __init__(self):
        self.calls = []

    def extract_file(self, internal_path, output_path, *_args, **_kwargs):
        self.calls.append(("extract_file", internal_path, output_path))
        with open(output_path, "wb") as f:
            f.write(b"document fixture")
        return {
            "output_path": output_path,
            "size": 16,
            "sha256": "fixture-sha256",
            "warning": "STATIC ANALYSIS ONLY - do not execute this file",
        }

    def vss_extract_file(self, snapshot_id, internal_path, output_path, volume="/c:", *_args, **_kwargs):
        self.calls.append(("vss_extract_file", snapshot_id, internal_path, output_path, volume))
        with open(output_path, "wb") as f:
            f.write(b"vss document fixture")
        return {
            "output_path": output_path,
            "size": 20,
            "sha256": "vss-fixture-sha256",
            "snapshot_id": snapshot_id,
            "snapshot_index": 0,
            "snapshot_creation_time": "2026-03-08T23:11:00Z",
            "temporal_layer": f"vss:0:{snapshot_id}",
            "volume": volume,
            "integrity_note": "VSS contents are historical layers.",
            "warning": "STATIC ANALYSIS ONLY - do not execute this file",
        }


def test_document_content_path_detection_covers_common_document_formats():
    for path in (
        "/c:/Users/Alice/Desktop/report.docx",
        "/c:/Users/Alice/Desktop/report.hwp",
        "/c:/Users/Alice/Desktop/report.pdf",
        "/c:/Users/Alice/Desktop/notes.txt",
    ):
        assert mcp_bridge._is_document_content_path(path)

    assert not mcp_bridge._is_document_content_path("/c:/Windows/System32/config/SYSTEM")
    assert not mcp_bridge._is_document_content_path("/c:/Windows/System32/winevt/Logs/System.evtx")


def test_extract_file_blocks_document_content_before_connector(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": _NoExtractE01()})

    result = _run(mcp_bridge.extract_file("/c:/Users/Alice/Desktop/report.docx"))

    assert result["ok"] is False
    assert result["blocked_by_policy"] == "document_content_no_open"
    assert result["operation"] == "extract_file"
    assert result["approval_required"] is True


def test_vss_extract_file_blocks_document_content_before_connector(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": _NoExtractE01()})

    result = _run(mcp_bridge.vss_extract_file("snap-1", "/c:/Users/Alice/Desktop/report.pdf"))

    assert result["ok"] is False
    assert result["blocked_by_policy"] == "document_content_no_open"
    assert result["operation"] == "vss_extract_file"
    assert result["source"] == "vss_snapshot"
    assert result["approval_required"] is True


def test_inspect_pe_file_blocks_document_extension_without_approval(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)

    result = _run(mcp_bridge.inspect_pe_file("/c:/Windows/SysWOW64/test.txt"))

    assert result["ok"] is False
    assert result["blocked_by_policy"] == "document_content_no_open"
    assert result["operation"] == "inspect_pe_file"
    assert result["approval_required"] is True


def test_materialize_local_artifact_allows_document_extension_with_explicit_reason(monkeypatch, tmp_path):
    sample = tmp_path / "test.txt"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(mcp_bridge, "_is_safe_local_analysis_path", lambda _path: True)

    result = mcp_bridge._materialize_local_artifact(
        str(sample),
        "pe_inspect",
        document_access_approved=True,
        document_access_reason="masqueraded PE triage approved by analyst",
        document_access_operation="inspect_pe_file",
    )

    assert result["ok"] is True
    assert result["source"] == "local_file"
    assert result["document_access"]["operation"] == "inspect_pe_file"
    assert result["document_access"]["reason"] == "masqueraded PE triage approved by analyst"


def test_extract_file_still_blocks_document_content_without_reason(monkeypatch):
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": _NoExtractE01()})

    result = _run(mcp_bridge.extract_file(
        "/c:/Users/Alice/Desktop/report.txt",
        document_access_approved=True,
    ))

    assert result["ok"] is False
    assert result["blocked_by_policy"] == "document_content_no_open"
    assert result["approval_required"] is True


def test_extract_file_allows_document_content_with_explicit_reason(monkeypatch, tmp_path):
    fake = _RecordingE01()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": fake})

    result = _run(mcp_bridge.extract_file(
        "/c:/Users/Alice/Desktop/ransom_note.txt",
        output_dir=str(tmp_path),
        document_access_approved=True,
        document_access_reason="ransom note triage approved by analyst",
    ))

    assert result["output_path"].endswith("ransom_note.txt")
    assert result["document_access"]["approved"] is True
    assert result["document_access"]["reason"] == "ransom note triage approved by analyst"
    assert result["document_access"]["guardrails"]["permission_is_not_a_verdict"] is True
    assert result["guardrails"]["document_body_minimization_required"] is True
    assert fake.calls[0][0] == "extract_file"


def test_vss_extract_file_allows_document_content_with_explicit_reason(monkeypatch, tmp_path):
    fake = _RecordingE01()
    monkeypatch.setattr(mcp_bridge, "_traced", _passthrough)
    monkeypatch.setattr(mcp_bridge, "_connectors", {"e01": fake})
    monkeypatch.setattr(mcp_bridge, "_is_safe_local_analysis_path", lambda _path: True)

    result = _run(mcp_bridge.vss_extract_file(
        "snap-1",
        "/c:/Users/Alice/Desktop/ransom_note.txt",
        output_dir=str(tmp_path),
        document_access_approved=True,
        document_access_reason="historical ransom note triage approved by analyst",
    ))

    assert result["ok"] is True
    assert result["document_access"]["approved"] is True
    assert result["document_access"]["source"] == "vss_snapshot"
    assert result["document_access"]["guardrails"]["permission_is_not_a_verdict"] is True
    assert result["guardrails"]["document_body_minimization_required"] is True
    assert result["quarantine_manifest"]["ok"] is True
    assert fake.calls[0][0] == "vss_extract_file"
