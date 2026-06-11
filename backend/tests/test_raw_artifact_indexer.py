"""Tests for the raw-image EVTX/registry artifact indexers (D-4 / A-2 / A-3)."""

from __future__ import annotations

import os

from core.raw_index import artifact_indexer as ai
from core.raw_index.store import RawIndexStore


class _FakeImage:
    """Image stub: serves canned file bytes and directory listings."""

    def __init__(self, files: dict[str, bytes] | None = None,
                 dirs: dict[str, list[dict]] | None = None):
        self._files = files or {}
        self._dirs = dirs or {}

    def is_connected(self):
        return True

    def extract_file(self, internal_path: str, output_path: str) -> dict:
        if internal_path not in self._files:
            return {"error": f"not found: {internal_path}"}
        with open(output_path, "wb") as f:
            f.write(self._files[internal_path])
        return {"extracted": internal_path}

    def list_directory(self, path: str) -> list[dict]:
        if path not in self._dirs:
            raise FileNotFoundError(path)
        return self._dirs[path]


def _open_store(tmp_path):
    store = RawIndexStore(str(tmp_path / "sidecar.sqlite"))
    store.open()
    return store


# ── EVTX indexer ───────────────────────────────────────────────────────────

def _fake_parse_evtx(path, *, target_event_ids=None, limit=0, best_effort=False):
    return {
        "ok": True,
        "records": [
            {"event_id": 7045, "timestamp": "2026-05-19T03:14:05Z",
             "provider": "Service Control Manager", "channel": "System",
             "computer": "WS-01", "semantic": "service_install",
             "fields": {"ServiceName": "UpdaterSvc",
                        "ImagePath": "C:\\ProgramData\\updsvc.exe"}},
            {"event_id": 1102, "timestamp": "2026-05-19T22:47:12Z",
             "provider": "Microsoft-Windows-Eventlog", "channel": "Security",
             "computer": "WS-01", "semantic": "log_cleared", "fields": {}},
        ],
        "record_count": 2,
        "parser_failures": [],
    }


def test_smbclient_lateral_movement_channels_and_eids_targeted():
    """SmbClient lateral-movement coverage: the Security/Connectivity channels
    and EID 31001 (failed SMB auth to a remote share) must be in the target set."""
    assert "Microsoft-Windows-SmbClient%4Security.evtx" in ai.CORE_EVTX_CHANNELS
    assert "Microsoft-Windows-SmbClient%4Connectivity.evtx" in ai.CORE_EVTX_CHANNELS
    assert 31001 in ai.EVTX_TARGET_EVENT_IDS


def test_motw_files_per_dir_cap_covers_typical_downloads():
    # raised so a 1-2k-file Downloads folder is fully scanned for MOTW
    assert ai._MOTW_FILES_PER_DIR_CAP >= 2000


def test_evtx_indexer_indexes_records_and_reports_missing_channels(tmp_path):
    image = _FakeImage(files={
        "/c:/Windows/System32/winevt/Logs/Security.evtx": b"ElfFile\x00stub",
    })
    store = _open_store(tmp_path)
    try:
        result = ai.index_evtx_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z",
            parse_evtx=_fake_parse_evtx,
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "partial"  # other channels are gaps
    assert result["indexed_records"] == 2
    assert result["channels_indexed"] == ["Security.evtx"]
    missing = [g for g in result["coverage_gaps"]
               if g["reason"] == "evtx_channel_unavailable"]
    assert len(missing) == len(ai.CORE_EVTX_CHANNELS) - 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(keyword="7045", filters={}, limit=10)
    assert hits["total"] >= 1
    blob = " ".join(str(v) for h in hits["hits"] for v in h.values())
    assert "UpdaterSvc" in blob
    conn.disconnect()


def test_evtx_indexer_all_channels_missing_is_not_evaluable(tmp_path):
    store = _open_store(tmp_path)
    try:
        result = ai.index_evtx_artifacts(
            _FakeImage(), store, started_at="2026-06-10T00:00:00Z",
            parse_evtx=_fake_parse_evtx,
        )
    finally:
        store.close()
    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["indexed_records"] == 0


# ── Registry value parsers (pure functions, stub hive) ─────────────────────

class _Val:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Key:
    def __init__(self, name, subkeys=None, values=None):
        self.name = name
        self._subkeys = subkeys or []
        self._values = values or []

    def iter_subkeys(self):
        return iter(self._subkeys)

    def iter_values(self):
        return iter(self._values)


class _Hive:
    def __init__(self, keys: dict[str, _Key]):
        self._keys = keys

    def get_key(self, path):
        if path not in self._keys:
            raise KeyError(path)
        return self._keys[path]


def test_filetime_decoding():
    # 2026-05-19T03:14:00Z == epoch 1779160440
    epoch_ms = 1779160440000
    filetime = (epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000
    raw = filetime.to_bytes(8, "little") + b"\x00" * 16
    ms, display = ai._filetime_to_ms(raw)
    assert ms == epoch_ms
    assert display.startswith("2026-05-19T03:14")
    assert ai._filetime_to_ms(b"") is None
    assert ai._filetime_to_ms(b"\x00" * 8) is None


def test_parse_bam_entries_extracts_per_sid_executables():
    epoch_ms = 1779160440000
    raw = ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(8, "little")
    hive = _Hive({
        "\\ControlSet001\\Services\\bam\\State\\UserSettings": _Key(
            "UserSettings",
            subkeys=[_Key("S-1-5-21-1111", values=[
                _Val("\\Device\\HarddiskVolume3\\Users\\jh\\AppData\\evil.exe", raw),
                _Val("Version", b"\x01"),
                _Val("SequenceNumber", b"\x02"),
            ])],
        ),
    })
    entries = ai.parse_bam_entries(hive, [("ControlSet001", True)])
    assert len(entries) == 1
    assert entries[0]["user_sid"] == "S-1-5-21-1111"
    assert entries[0]["executable"].endswith("evil.exe")
    assert entries[0]["last_run"][0] == epoch_ms


def test_parse_usbstor_entries():
    hive = _Hive({
        "\\ControlSet001\\Enum\\USBSTOR": _Key(
            "USBSTOR",
            subkeys=[_Key("Disk&Ven_SanDisk&Prod_Ultra", subkeys=[
                _Key("4C5310...&0", values=[_Val("FriendlyName", "SanDisk Ultra USB Device")]),
            ])],
        ),
    })
    entries = ai.parse_usbstor_entries(hive, [("ControlSet001", True)])
    assert len(entries) == 1
    assert entries[0]["device"].startswith("Disk&Ven_SanDisk")
    assert entries[0]["friendly_name"] == "SanDisk Ultra USB Device"


def test_parse_run_keys():
    hive = _Hive({
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": _Key(
            "Run", values=[_Val("Updater", "C:\\ProgramData\\updsvc.exe -boot")],
        ),
    })
    entries = ai.parse_run_keys(hive, hive_label="NTUSER:jhlee")
    assert len(entries) == 1
    assert entries[0]["name"] == "Updater"
    assert "updsvc.exe" in entries[0]["command"]


# ── Registry indexer gap paths ─────────────────────────────────────────────

def test_registry_indexer_missing_hives_yields_gaps(tmp_path):
    store = _open_store(tmp_path)
    try:
        result = ai.index_registry_artifacts(
            _FakeImage(), store, started_at="2026-06-10T00:00:00Z",
        )
    finally:
        store.close()
    assert result["status"] == "not_evaluable"
    reasons = {g["reason"] for g in result["coverage_gaps"]}
    assert "system_hive_unavailable" in reasons
    assert "users_root_unavailable" in reasons


# ── New artifact types are registered on guardrail surfaces ────────────────

def test_bam_and_usb_have_evidence_strength_tiers():
    from core.analysis.evidence_strength import classify_artifact

    bam = classify_artifact("BAM Execution Entries")
    assert bam["tier"] == "strong"
    usb = classify_artifact("USB Devices")
    assert usb["tier"] == "moderate"


def test_bam_and_usb_have_rule_coverage_aliases():
    from core.analysis.rule_coverage import FAMILY_ALIASES

    assert "BAM Execution Entries" in FAMILY_ALIASES["BAM"]
    assert "USB Devices" in FAMILY_ALIASES["USB Devices"]


# ── Office TrustRecords (A-4) ──────────────────────────────────────────────

def test_parse_trust_records_detects_macro_enabled_document():
    epoch_ms = 1779160440000
    filetime = ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(8, "little")
    macro_data = filetime + b"\x00" * 12 + b"\xff\xff\xff\x7f"
    plain_data = filetime + b"\x00" * 16
    hive = _Hive({
        "\\Software\\Microsoft\\Office\\16.0\\Word"
        "\\Security\\Trusted Documents\\TrustRecords": _Key(
            "TrustRecords", values=[
                _Val("%USERPROFILE%/Downloads/invoice.docm", macro_data),
                _Val("%USERPROFILE%/Documents/report.docx", plain_data),
            ],
        ),
    })
    entries = ai.parse_trust_records(hive, hive_label="NTUSER:jhlee")
    assert len(entries) == 2
    by_doc = {e["document"]: e for e in entries}
    assert by_doc["%USERPROFILE%/Downloads/invoice.docm"]["macro_enabled"] is True
    assert by_doc["%USERPROFILE%/Documents/report.docx"]["macro_enabled"] is False
    assert by_doc["%USERPROFILE%/Downloads/invoice.docm"]["trusted_at"][0] == epoch_ms


def test_trust_records_registered_on_guardrail_surfaces():
    from core.analysis.evidence_strength import classify_artifact
    from core.analysis.rule_coverage import FAMILY_ALIASES

    assert classify_artifact("Office Trusted Documents")["tier"] == "strong"
    assert "TrustRecords" in FAMILY_ALIASES["Office Trusted Documents"]


# ── regipy hex-string REG_BINARY coercion (real-data bug) ──────────────────

def test_coerce_bytes_accepts_hex_string_and_bytes():
    # regipy returns REG_BINARY as a hex STRING, not bytes.
    epoch_ms = 1779160440000
    ft = ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(8, "little")
    raw = ft + b"\x00" * 16
    assert ai._coerce_bytes(raw) == raw
    assert ai._coerce_bytes(raw.hex()) == raw
    assert ai._coerce_bytes("not-hex-zz") is None
    assert ai._coerce_bytes(12345) is None
    assert ai._coerce_bytes(None) is None


def test_parse_bam_decodes_hex_string_value():
    """regipy hands BAM values as hex strings; last_run must still decode."""
    epoch_ms = 1779160440000
    ft = ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(8, "little")
    hex_value = (ft + b"\x00" * 16).hex()  # 24 bytes as hex string
    hive = _Hive({
        "\\ControlSet001\\Services\\bam\\State\\UserSettings": _Key(
            "UserSettings",
            subkeys=[_Key("S-1-5-21-9", values=[
                _Val("\\Device\\HarddiskVolume3\\evil.exe", hex_value),
            ])],
        ),
    })
    entries = ai.parse_bam_entries(hive, [("ControlSet001", True)])
    assert len(entries) == 1
    assert entries[0]["last_run"] is not None
    assert entries[0]["last_run"][0] == epoch_ms


def test_parse_trustrecords_decodes_hex_string_macro_flag():
    """TrustRecords macro-enable marker must be detected from hex-string data."""
    epoch_ms = 1779160440000
    ft = ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(8, "little")
    macro_hex = (ft + b"\x00" * 12 + b"\xff\xff\xff\x7f").hex()
    plain_hex = (ft + b"\x00" * 16).hex()
    hive = _Hive({
        "\\Software\\Microsoft\\Office\\16.0\\Excel"
        "\\Security\\Trusted Documents\\TrustRecords": _Key(
            "TrustRecords", values=[
                _Val("%USERPROFILE%/macro.xlsb", macro_hex),
                _Val("%USERPROFILE%/plain.xlsx", plain_hex),
            ],
        ),
    })
    recs = ai.parse_trust_records(hive, hive_label="NTUSER:t")
    by_doc = {r["document"]: r for r in recs}
    assert by_doc["%USERPROFILE%/macro.xlsb"]["macro_enabled"] is True
    assert by_doc["%USERPROFILE%/plain.xlsx"]["macro_enabled"] is False
    assert by_doc["%USERPROFILE%/macro.xlsb"]["trusted_at"][0] == epoch_ms
