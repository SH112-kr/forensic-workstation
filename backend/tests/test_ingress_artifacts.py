"""Tests for step-4 ingress artifacts: MOTW, Office MRU, MountPoints2,
setupapi.dev.log, and the two new initial-access detection rules."""

from __future__ import annotations

from core.raw_index import artifact_indexer as ai
from core.raw_index.store import RawIndexStore


# Reuse the stub shapes from the indexer test module.
from tests.test_raw_artifact_indexer import _FakeImage, _Hive, _Key, _Val


def _open_store(tmp_path):
    store = RawIndexStore(str(tmp_path / "sidecar.sqlite"))
    store.open()
    return store


# ── Zone.Identifier parsing + MOTW indexer ─────────────────────────────────

ZONE_CONTENT = (
    b"[ZoneTransfer]\r\nZoneId=3\r\n"
    b"ReferrerUrl=http://cdn.lkd-delivery.example/pkg/\r\n"
    b"HostUrl=http://cdn.lkd-delivery.example/pkg/updsvc.exe\r\n"
)


def test_parse_zone_identifier():
    fields = ai.parse_zone_identifier(ZONE_CONTENT)
    assert fields["ZoneId"] == "3"
    assert fields["HostUrl"].endswith("updsvc.exe")
    assert ai.parse_zone_identifier(b"") == {}
    assert ai.parse_zone_identifier(b"garbage no equals") == {}


class _AdsImage(_FakeImage):
    """FakeImage with ADS-aware read_file_content."""

    def __init__(self, files=None, dirs=None, ads=None, ads_raises=False):
        super().__init__(files=files, dirs=dirs)
        self._ads = ads or {}
        self._ads_raises = ads_raises

    def read_file_content(self, internal_path: str, max_size: int = 1048576) -> bytes:
        if self._ads_raises:
            raise OSError("ADS not supported")
        if internal_path in self._ads:
            return self._ads[internal_path]
        raise FileNotFoundError(internal_path)


def _motw_dirs():
    return {
        "/c:/Users": [
            {"name": "jhlee", "path": "/c:/Users/jhlee", "is_dir": True},
        ],
        "/c:/Users/jhlee/Downloads": [
            {"name": "updsvc.exe", "path": "/c:/Users/jhlee/Downloads/updsvc.exe",
             "is_dir": False, "created": "2026-05-19T02:56:00Z"},
            {"name": "notes.txt", "path": "/c:/Users/jhlee/Downloads/notes.txt",
             "is_dir": False},
        ],
    }


def test_motw_indexer_indexes_internet_origin_file(tmp_path):
    image = _AdsImage(
        dirs=_motw_dirs(),
        ads={"/c:/Users/jhlee/Downloads/updsvc.exe:Zone.Identifier": ZONE_CONTENT},
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_motw_artifacts(image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["ok"] is True
    assert result["indexed_records"] == 1
    assert result["files_checked"] == 2

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(keyword="updsvc", filters={}, limit=10)
    blob = " ".join(str(v) for h in hits["hits"] for v in h.values())
    assert "cdn.lkd-delivery.example" in blob
    conn.disconnect()


def test_motw_indexer_flags_unsupported_ads_as_gap(tmp_path):
    image = _AdsImage(dirs=_motw_dirs(), ads_raises=True)
    store = _open_store(tmp_path)
    try:
        result = ai.index_motw_artifacts(image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()
    assert result["indexed_records"] == 0
    reasons = {g["reason"] for g in result["coverage_gaps"]}
    assert "ads_read_unsupported" in reasons


# ── Office MRU / MountPoints2 / setupapi parsers ───────────────────────────

def test_parse_office_mru_decodes_filetime():
    epoch_ms = 1779160440000
    filetime = (epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000
    item = f"[F00000000][T{filetime:016X}][O00000000]*C:\\Docs\\invoice.docm"
    hive = _Hive({
        "\\Software\\Microsoft\\Office\\16.0\\Word\\File MRU": _Key(
            "File MRU", values=[_Val("Item 1", item)],
        ),
    })
    entries = ai.parse_office_mru(hive, hive_label="NTUSER:jhlee")
    assert len(entries) == 1
    assert entries[0]["document"].endswith("invoice.docm")
    assert entries[0]["last_opened"][0] == epoch_ms


def test_parse_mountpoints2_classifies_kinds():
    hive = _Hive({
        "\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Explorer\\MountPoints2": _Key(
            "MountPoints2",
            subkeys=[_Key("{guid-1234}"), _Key("##fileserver#share"), _Key("F")],
        ),
    })
    entries = ai.parse_mountpoints2(hive, hive_label="NTUSER:jhlee")
    kinds = {e["mount_point"]: e["kind"] for e in entries}
    assert kinds["{guid-1234}"] == "volume_guid"
    assert kinds["##fileserver#share"] == "network_share"
    assert kinds["F"] == "drive_letter"


SETUPAPI_TEXT = """\
>>>  [Device Install (Hardware initiated) - SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra#4C5310&0#]
>>>  Section start 2026/05/19 11:02:33.123
     dvi: ...
<<<  Section end 2026/05/19 11:02:35.000
>>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234]
>>>  Section start 2026/05/19 12:00:00.000
"""


def test_parse_setupapi_filters_usb_and_marks_local_time():
    entries = ai.parse_setupapi_device_installs(SETUPAPI_TEXT)
    assert len(entries) == 1
    assert "USBSTOR" in entries[0]["device_id"]
    assert entries[0]["first_install"][1].endswith("(local time)")


# ── New initial-access rules over a fixture connector ──────────────────────

def _ingress_fixture():
    from regression.fixtures.base import FixtureConnector, FixtureHit

    hits = [
        FixtureHit(
            hit_id=1,
            artifact_type="Office Trusted Documents",
            timestamp="2026-05-19T02:58:00Z",
            source_path="/c:/Users/jhlee/NTUSER.DAT",
            fields={"Document": "%USERPROFILE%/Downloads/invoice.docm",
                    "Application": "Word", "Macro Enabled": "True",
                    "User": "jhlee", "Trusted At": "2026-05-19T02:58:00Z"},
        ),
        FixtureHit(
            hit_id=2,
            artifact_type="Office Trusted Documents",
            timestamp="2026-05-10T09:00:00Z",
            source_path="/c:/Users/jhlee/NTUSER.DAT",
            fields={"Document": "%USERPROFILE%/Documents/report.docx",
                    "Application": "Word", "Macro Enabled": "False",
                    "User": "jhlee"},
        ),
        FixtureHit(
            hit_id=3,
            artifact_type="Mark of the Web (Zone.Identifier)",
            timestamp="2026-05-19T02:56:00Z",
            source_path="/c:/Users/jhlee/Downloads/updsvc.exe",
            fields={"File Path": "/c:/Users/jhlee/Downloads/updsvc.exe",
                    "Zone ID": "3",
                    "Host URL": "http://cdn.lkd-delivery.example/pkg/updsvc.exe",
                    "User": "jhlee"},
        ),
        FixtureHit(
            hit_id=4,
            artifact_type="Mark of the Web (Zone.Identifier)",
            timestamp="2026-05-18T10:00:00Z",
            source_path="/c:/Users/jhlee/Downloads/photo.jpg",
            fields={"File Path": "/c:/Users/jhlee/Downloads/photo.jpg",
                    "Zone ID": "3", "User": "jhlee"},
        ),
    ]
    metadata = {"case_name": "ingress_rule_test", "source_type": "fixture",
                "source_path": "fixture://ingress", "total_hits": len(hits),
                "artifact_type_count": 0, "evidence_sources": ["FIXTURE"],
                "evidence_locations": [], "date_range_start": "2026-05-01",
                "date_range_end": "2026-05-31"}
    return FixtureConnector(metadata=metadata, hits=hits)


def test_trustrecords_rule_fires_only_on_macro_enabled():
    from core.analysis.suspicious import find_suspicious

    conn = _ingress_fixture()
    result = find_suspicious(conn.artifact_queries,
                             rules="office_trustrecords_macro_enabled")
    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["matching_count"] == 1
    assert findings[0]["details"][0]["document"].endswith("invoice.docm")
    assert findings[0]["category"] == "initial_access"


def test_motw_rule_fires_only_on_risky_extensions():
    from core.analysis.suspicious import find_suspicious

    conn = _ingress_fixture()
    result = find_suspicious(conn.artifact_queries,
                             rules="motw_internet_origin_risky_file")
    findings = result["findings"]
    assert len(findings) == 1
    detail = findings[0]["details"][0]
    assert detail["file_path"].endswith("updsvc.exe")
    assert detail["host_url"].startswith("http://cdn.lkd-delivery.example")


def test_new_rules_zero_result_on_empty_fixture():
    from core.analysis.suspicious import find_suspicious
    from regression.fixtures import load

    conn = load("case_empty_or_malformed")
    result = find_suspicious(
        conn.artifact_queries,
        rules="office_trustrecords_macro_enabled,motw_internet_origin_risky_file",
    )
    assert result["findings"] == []
    assert len(result["zero_result_rules"]) == 2


def test_new_ingress_types_registered_on_guardrail_surfaces():
    from core.analysis.evidence_strength import classify_artifact
    from core.analysis.rule_coverage import FAMILY_ALIASES, RULE_REQUIREMENTS

    assert classify_artifact("Mark of the Web (Zone.Identifier)")["tier"] == "strong"
    assert classify_artifact("Office Recent Documents")["tier"] == "moderate"
    assert "Mark of the Web (Zone.Identifier)" in FAMILY_ALIASES["Mark of the Web"]
    assert "office_trustrecords_macro_enabled" in RULE_REQUIREMENTS
    assert "motw_internet_origin_risky_file" in RULE_REQUIREMENTS


def test_usb_devices_rows_trigger_usb_exfil_signal():
    from core.analysis.autonomous_assessment import _has_row

    rows = [{"artifact_type": "USB Devices",
             "Device": "Disk&Ven_SanDisk&Prod_Ultra",
             "Serial Number": "4C5310", "Source": "USBSTOR",
             "Friendly Name": "SanDisk Ultra USB Device"}]
    assert _has_row(
        rows,
        ("usb", "kingston", "removable", "datatraveler", "e:\\confidential",
         "usbstor", "mountpoints2"),
        artifact_terms=("event logs", "jump list", "shellbags", "lnk files",
                        "usb devices"),
        field_terms=("device description", "target path", "full path", "event data",
                     "serial number", "friendly name", "mount point"),
    ) is True


# ── A-6 outbound RDP MRU parser ────────────────────────────────────────────

def test_parse_rdp_client_mru_servers_layout():
    hive = _Hive({
        "\\Software\\Microsoft\\Terminal Server Client\\Servers": _Key(
            "Servers",
            subkeys=[_Key("dc01.corp.local",
                          values=[_Val("UsernameHint", "CORP\admin-jh")])],
        ),
    })
    entries = ai.parse_rdp_client_mru(hive, hive_label="NTUSER:jhlee")
    assert len(entries) == 1
    assert entries[0]["destination"] == "dc01.corp.local"
    assert entries[0]["username_hint"] == "CORP\admin-jh"


def test_parse_rdp_client_mru_default_layout():
    hive = _Hive({
        "\\Software\\Microsoft\\Terminal Server Client\\Default": _Key(
            "Default",
            values=[_Val("MRU0", "10.0.0.5"), _Val("MRU1", "fileserver")],
        ),
    })
    entries = ai.parse_rdp_client_mru(hive, hive_label="NTUSER:jhlee")
    dests = {e["destination"] for e in entries}
    assert "10.0.0.5" in dests
    assert "fileserver" in dests


def test_rdp_client_destinations_registered():
    from core.analysis.evidence_strength import classify_artifact
    from core.analysis.rule_coverage import FAMILY_ALIASES

    assert classify_artifact("RDP Client Destinations")["tier"] == "moderate"
    assert "Terminal Server Client" in FAMILY_ALIASES["RDP Client Destinations"]


# ── B-3 new EVTX rules ─────────────────────────────────────────────────────

def test_new_evtx_rules_present_and_well_formed():
    from core.analysis.evtx_rules import BUILTIN_RULES

    by_id = {r["id"]: r for r in BUILTIN_RULES}
    for rid in ("fw-evtx-025", "fw-evtx-031", "fw-evtx-034", "fw-evtx-035",
                "fw-evtx-036", "fw-evtx-037", "fw-evtx-039"):
        assert rid in by_id, f"missing {rid}"
        rule = by_id[rid]
        assert rule["event_ids"] and isinstance(rule["event_ids"], list)
        assert rule["mitre"]
        assert rule["severity"] in {"low", "medium", "high", "critical"}
    # IDs are unique
    ids = [r["id"] for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids))


def test_defender_rule_matches_detection_event():
    from core.analysis.evtx_rules import _rule_matches, BUILTIN_RULES

    rule = next(r for r in BUILTIN_RULES if r["id"] == "fw-evtx-034")
    row = {"Event Data": "Threat Win32/Emotet detected and quarantined",
           "Provider Name": "Microsoft-Windows-Windows Defender"}
    assert _rule_matches(rule, row) is True


def test_lateral_movement_sweep_pack_loads():
    from core.analysis import hunt_packs as hp

    names = {p["name"] for p in hp.list_packs()["packs"] if "name" in p}
    assert "lateral_movement_sweep" in names


def test_known_gaps_annotated_with_coverage():
    from core.analysis.suspicious import KNOWN_COVERAGE_GAPS

    # DCSync / Defender / BITS now point to their EVTX rule coverage
    assert "fw-evtx-031" in KNOWN_COVERAGE_GAPS["evtx_eid_4662_ad_object_access"]
    assert "fw-evtx-034" in KNOWN_COVERAGE_GAPS["defender_tamper_events"]
    assert "fw-evtx-036" in KNOWN_COVERAGE_GAPS["bits_job_persistence"]
