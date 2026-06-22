from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from core.connectors.e01_image import E01ImageConnector


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


class _FakeHeader:
    def __init__(self, size: int):
        self.size = size


class _FakeAttr:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.data = data
        self.header = _FakeHeader(len(data))
        self.resident = True
        self.record = 42

    def open(self):
        from io import BytesIO

        return BytesIO(self.data)


class _FakeEntry:
    def attr(self):
        return {
            0x80: [
                _FakeAttr("", b"default"),
                _FakeAttr("Zone.Identifier", b"ZoneId=3\r\n"),
            ]
        }


class _FakePath:
    name = "dropper.exe"

    def exists(self):
        return True

    def is_dir(self):
        return False

    def get(self):
        return _FakeEntry()

    def __str__(self):
        return "/c:/Users/alice/Downloads/dropper.exe"


class _FakeFs:
    def path(self, _path: str):
        return _FakePath()


class _FakeTarget:
    fs = _FakeFs()


def test_e01_connector_lists_and_reads_named_ads_without_default_stream():
    conn = E01ImageConnector()
    conn._target = _FakeTarget()

    result = conn.list_alternate_data_streams(
        path="/c:/Users/alice/Downloads",
        keyword="Zone",
        recursive=False,
        limit=10,
    )
    info = conn.get_alternate_data_stream_info(
        "/c:/Users/alice/Downloads/dropper.exe",
        "Zone.Identifier",
    )
    data = conn.read_alternate_data_stream_content(
        "/c:/Users/alice/Downloads/dropper.exe",
        "Zone.Identifier",
        max_size=128,
    )

    assert result["ok"] is True
    assert result["returned"] == 1
    assert result["streams"][0]["stream_name"] == "Zone.Identifier"
    assert "dropper.exe:Zone.Identifier" in result["streams"][0]["ads_path"]
    assert info["size"] == len(b"ZoneId=3\r\n")
    assert data == b"ZoneId=3\r\n"


class _FakeManualE01:
    def get_alternate_data_stream_info(self, host_path: str, stream_name: str):
        return {
            "path": host_path,
            "host_path": host_path,
            "stream_name": stream_name,
            "ads_path": f"{host_path}:{stream_name}",
            "size": len(b"ZoneId=3\r\n"),
            "resident": True,
            "attribute_type": "$DATA",
        }

    def read_alternate_data_stream_content(self, host_path: str, stream_name: str, max_size: int = 1048576):
        assert host_path == "/c:/Users/alice/Downloads/dropper.exe"
        assert stream_name == "Zone.Identifier"
        return b"ZoneId=3\r\n"[:max_size]


class _FakeManualFileInfoE01:
    content = b"MZ" + b"\x00" * 126

    def get_file_info(self, internal_path: str):
        assert internal_path == "/c:/Users/alice/Downloads/dropper.exe"
        return {
            "path": internal_path,
            "exists": True,
            "is_dir": False,
            "size": len(self.content),
            "modified": "2026-03-08T23:11:00Z",
        }

    def read_file_content(self, internal_path: str, max_size: int = 1048576):
        assert internal_path == "/c:/Users/alice/Downloads/dropper.exe"
        return self.content[:max_size]


def test_manual_ads_info_hashes_stream_and_preserves_static_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (_FakeManualE01(), r"D:\cases\host.E01"))

    result = _run(manual.ads_info(manual.AdsInfoRequest(
        host_path="/c:/Users/alice/Downloads/dropper.exe",
        stream_name="Zone.Identifier",
        include_hash=True,
        include_pe=True,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "alternate_data_stream"
    assert result["ads_path"].endswith(":Zone.Identifier")
    assert result["hash_status"] == "complete"
    assert result["hashes"]["sha256"] == hashlib.sha256(b"ZoneId=3\r\n").hexdigest()
    assert result["pe_status"] == "not_pe"
    assert any("static analysis only" in note.lower() for note in result["coverage_notes"])
    assert any("does not prove execution" in note.lower() for note in result["coverage_notes"])


def test_manual_file_info_hashes_file_and_detects_pe_header(monkeypatch):
    from api import manual

    fake = _FakeManualFileInfoE01()
    monkeypatch.setattr(manual, "_get_manual_e01", lambda: (fake, r"D:\cases\host.E01"))

    result = _run(manual.file_info(manual.FileInfoRequest(
        internal_path="/c:/Users/alice/Downloads/dropper.exe",
        include_hash=True,
        include_pe=True,
    )))

    assert result["analyst_only"] is True
    assert result["source"] == "current_file"
    assert result["internal_path"].endswith("dropper.exe")
    assert result["hash_status"] == "complete"
    assert result["hashes"]["sha256"] == hashlib.sha256(fake.content).hexdigest()
    assert result["pe_status"] == "pe_header_detected"
    assert result["pe"]["is_pe"] is True
    assert any("static analysis only" in note.lower() for note in result["coverage_notes"])
    assert any("does not prove execution" in note.lower() for note in result["coverage_notes"])


def test_manual_workbench_ads_lane_has_stable_controls():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    src = component.read_text(encoding="utf-8")

    assert "/api/manual/ads/info" in src
    assert "/api/manual/files/info" in src
    assert "Inspect ADS" in src
    assert "Inspect file" in src
    assert "hostPath" in src
    assert "streamName" in src
    assert "fileInfoPath" in src
    assert "ADS inspection reads the named stream content" in src
    assert "File static triage reads captured file bytes" in src
    assert "gridTemplateColumns: 'minmax(220px, 1fr) 112px'" in src
    assert "overflowWrap: 'anywhere'" in src
    assert "minHeight: 0" in src
