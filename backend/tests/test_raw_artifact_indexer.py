"""Tests for the raw-image EVTX/registry artifact indexers (D-4 / A-2 / A-3)."""

from __future__ import annotations

import codecs
import os
import sqlite3

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


def test_raw_evtx_parity_channels_and_rule_pack_eids_targeted():
    """Raw sidecar EVTX indexing must cover rule-pack channels/EIDs as leads.

    This does not mean every rule can be evaluated in raw-only mode yet. It
    ensures the sidecar does not silently skip the source rows needed for
    later raw rule parity and timeline traversal.
    """
    required_channels = {
        "Microsoft-Windows-Sysmon%4Operational.evtx",
        "Microsoft-Windows-WinRM%4Operational.evtx",
        "Microsoft-Windows-DNS-Client%4Operational.evtx",
        "Microsoft-Windows-WMI-Activity%4Operational.evtx",
        "Windows PowerShell.evtx",
    }
    assert required_channels.issubset(set(ai.CORE_EVTX_CHANNELS))

    required_event_ids = {
        # Sysmon execution/network/file/registry/injection/DNS coverage.
        1, 3, 8, 10, 11, 12, 13, 18, 22,
        # WinRM and WMI operational corroboration.
        91, 168, 6, 5857, 5858, 5859, 5860, 5861,
        # Classic PowerShell, service state, clock/audit/firewall tamper.
        400, 600, 7036, 7040, 4616, 4719, 4946, 4947, 4950,
        # Account/discovery/share access rules not covered by the old subset.
        4768, 4769, 4771, 4798, 4799, 5136, 5140, 5145,
        # TaskScheduler execution events.
        106, 129, 140, 141, 200, 201,
    }
    assert required_event_ids.issubset(ai.EVTX_TARGET_EVENT_IDS)


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


# ── Scheduled Task XML indexer ─────────────────────────────────────────────

_TASK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-05-19T03:14:00Z</Date>
    <Author>WS-01\\Administrator</Author>
    <Description>Updater task</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-05-19T03:20:00Z</StartBoundary>
      <Enabled>true</Enabled>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1111</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\ProgramData\\updsvc.exe</Command>
      <Arguments>-task</Arguments>
      <WorkingDirectory>C:\\ProgramData</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def test_parse_scheduled_task_xml_extracts_execution_context():
    parsed = ai.parse_scheduled_task_xml(
        _TASK_XML, task_path="/c:/Windows/System32/Tasks/Updater")

    assert parsed["task_name"] == "Updater"
    assert parsed["command"] == "C:\\ProgramData\\updsvc.exe"
    assert parsed["arguments"] == "-task"
    assert parsed["working_directory"] == "C:\\ProgramData"
    assert parsed["author"] == "WS-01\\Administrator"
    assert parsed["user_id"] == "S-1-5-21-1111"
    assert parsed["run_level"] == "HighestAvailable"
    assert parsed["enabled"] == "true"
    assert parsed["hidden"] == "false"
    assert parsed["trigger_types"] == "CalendarTrigger"
    assert parsed["registered_at"][1] == "2026-05-19T03:14:00Z"
    assert parsed["start_boundary"][1] == "2026-05-19T03:20:00Z"


def test_scheduled_task_indexer_recurses_task_tree_and_indexes_xml(tmp_path):
    root = "/c:/Windows/System32/Tasks"
    task_path = f"{root}/Microsoft/Windows/Updater"
    image = _FakeImage(
        files={task_path: _TASK_XML.encode("utf-8")},
        dirs={
            root: [{"name": "Microsoft", "path": f"{root}/Microsoft", "is_dir": True}],
            f"{root}/Microsoft": [
                {"name": "Windows", "path": f"{root}/Microsoft/Windows", "is_dir": True}
            ],
            f"{root}/Microsoft/Windows": [
                {"name": "Updater", "path": task_path, "is_dir": False}
            ],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_scheduled_task_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="updsvc", filters={"artifact_type": "Scheduled Tasks"}, limit=10)
    assert hits["total"] == 1
    blob = " ".join(str(v) for h in hits["hits"] for v in h.values())
    assert "C:\\ProgramData\\updsvc.exe" in blob
    assert "CalendarTrigger" in blob
    conn.disconnect()


def test_parse_taskcache_entries_maps_tree_guid_and_extracts_action_strings():
    guid = "{11111111-2222-3333-4444-555555555555}"
    actions = (
        "C:\\ProgramData\\updsvc.exe\x00-task\x00C:\\ProgramData\x00"
    ).encode("utf-16-le")
    hive = _Hive({
        "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree":
            _Key("Tree", subkeys=[
                _Key("Updater", values=[_Val("Id", guid), _Val("Index", 3)]),
            ]),
        f"\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{guid}":
            _Key(guid, values=[
                _Val("URI", "\\Updater"),
                _Val("Path", "\\Updater"),
                _Val("Actions", actions),
            ]),
    })

    entries, gaps = ai.parse_taskcache_entries(hive, hive_label="SOFTWARE")

    assert gaps == []
    assert len(entries) == 1
    entry = entries[0]
    assert entry["task_name"] == "Updater"
    assert entry["task_guid"] == guid
    assert entry["tree_path"] == "\\Updater"
    assert entry["uri"] == "\\Updater"
    assert entry["index"] == "3"
    assert "C:\\ProgramData\\updsvc.exe" in entry["action_strings"]
    assert "-task" in entry["action_strings"]


# ── PCA pca.db indexer ─────────────────────────────────────────────────────

def _write_pca_db(path, rows=None):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE AppLaunch("
            "Path TEXT, RunTime TEXT, ProgramId TEXT, ExitCode INTEGER)"
        )
        for row in rows or [
            ("C:\\Users\\Public\\dropper.exe", "2026-05-19T03:14:00Z", "abc", 0)
        ]:
            conn.execute(
                "INSERT INTO AppLaunch(Path, RunTime, ProgramId, ExitCode) "
                "VALUES (?, ?, ?, ?)",
                row,
            )
        conn.commit()
    finally:
        conn.close()


def test_parse_pca_db_extracts_path_and_timestamp(tmp_path):
    db_path = tmp_path / "pca.db"
    _write_pca_db(db_path)

    result = ai.parse_pca_db(str(db_path))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1
    entry = result["entries"][0]
    assert entry["source_table"] == "AppLaunch"
    assert entry["executable_path"] == "C:\\Users\\Public\\dropper.exe"
    assert entry["timestamp_field"] == "RunTime"
    assert entry["timestamp"][1] == "2026-05-19T03:14:00Z"
    assert entry["fields"]["ProgramId"] == "abc"


def test_pca_indexer_extracts_pca_db_into_raw_index(tmp_path):
    db_path = tmp_path / "pca.db"
    _write_pca_db(db_path)
    internal = "/c:/Windows/appcompat/pca/pca.db"
    image = _FakeImage(files={internal: db_path.read_bytes()})
    store = _open_store(tmp_path)
    try:
        result = ai.index_pca_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="dropper.exe",
        filters={"artifact_type": "PCA Program Compatibility Activity"},
        limit=10,
    )
    assert hits["total"] == 1
    blob = " ".join(str(v) for h in hits["hits"] for v in h.values())
    assert "C:\\Users\\Public\\dropper.exe" in blob
    assert "AppLaunch" in blob
    conn.disconnect()


# ── Windows Timeline ActivitiesCache.db indexer ────────────────────────────

def _write_activities_cache_db(path, rows=None):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE Activity("
            "AppId TEXT, DisplayText TEXT, StartTime TEXT, "
            "EndTime TEXT, Payload TEXT)"
        )
        for row in rows or [
            (
                "C:\\Windows\\System32\\notepad.exe",
                "notes.txt",
                "2026-05-19T03:14:00Z",
                "2026-05-19T03:20:00Z",
                '{"file":"C:\\\\Users\\\\Alice\\\\Desktop\\\\notes.txt"}',
            )
        ]:
            conn.execute(
                "INSERT INTO Activity(AppId, DisplayText, StartTime, EndTime, Payload) "
                "VALUES (?, ?, ?, ?, ?)",
                row,
            )
        conn.commit()
    finally:
        conn.close()


def test_parse_activities_cache_db_extracts_user_activity(tmp_path):
    db_path = tmp_path / "ActivitiesCache.db"
    _write_activities_cache_db(db_path)

    result = ai.parse_activities_cache_db(str(db_path))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1
    entry = result["entries"][0]
    assert entry["source_table"] == "Activity"
    assert entry["app_id"] == "C:\\Windows\\System32\\notepad.exe"
    assert entry["display_text"] == "notes.txt"
    assert entry["timestamp_field"] == "StartTime"
    assert entry["timestamp"][1] == "2026-05-19T03:14:00Z"
    assert "C:\\Users\\Alice\\Desktop\\notes.txt" in entry["path_hint"]


def test_activities_cache_indexer_discovers_user_profile_databases(tmp_path):
    db_path = tmp_path / "ActivitiesCache.db"
    _write_activities_cache_db(db_path)
    root = "/c:/Users"
    user = f"{root}/Alice"
    cdp = f"{user}/AppData/Local/ConnectedDevicesPlatform"
    account = f"{cdp}/L.Alice"
    internal = f"{account}/ActivitiesCache.db"
    image = _FakeImage(
        files={internal: db_path.read_bytes()},
        dirs={
            root: [{"name": "Alice", "path": user, "is_dir": True}],
            cdp: [{"name": "L.Alice", "path": account, "is_dir": True}],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_activities_cache_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="notes.txt",
        filters={"artifact_type": "Windows Timeline Activity"},
        limit=10,
    )
    assert hits["total"] == 1
    blob = " ".join(str(v) for h in hits["hits"] for v in h.values())
    assert "notepad.exe" in blob
    assert "Alice" in blob
    conn.disconnect()


# ── LNK / JumpList indexer ─────────────────────────────────────────────────

# ── Browser History / Downloads / Cache indexer ────────────────────────────

_CHROME_EPOCH_OFFSET_SECONDS = 11644473600


def _chrome_time_us(epoch_ms: int) -> int:
    return (epoch_ms // 1000 + _CHROME_EPOCH_OFFSET_SECONDS) * 1_000_000


def _write_chromium_history_db(path, *, epoch_ms: int = 1779160440000):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE urls("
            "id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)"
        )
        conn.execute(
            "CREATE TABLE visits("
            "id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, "
            "from_visit INTEGER, transition INTEGER)"
        )
        conn.execute(
            "CREATE TABLE downloads("
            "id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, "
            "start_time INTEGER, end_time INTEGER, received_bytes INTEGER, "
            "total_bytes INTEGER, state INTEGER, danger_type INTEGER, "
            "tab_url TEXT, referrer TEXT)"
        )
        conn.execute(
            "CREATE TABLE downloads_url_chains("
            "id INTEGER, chain_index INTEGER, url TEXT)"
        )
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, typed_count, "
            "last_visit_time) VALUES (1, ?, ?, 3, 1, ?)",
            (
                "https://example.test/payload",
                "payload page",
                _chrome_time_us(epoch_ms),
            ),
        )
        conn.execute(
            "INSERT INTO visits(id, url, visit_time, from_visit, transition) "
            "VALUES (10, 1, ?, 0, 805306368)",
            (_chrome_time_us(epoch_ms),),
        )
        conn.execute(
            "INSERT INTO downloads(id, target_path, current_path, start_time, "
            "end_time, received_bytes, total_bytes, state, danger_type, "
            "tab_url, referrer) VALUES (7, ?, ?, ?, ?, 4096, 4096, 1, 0, ?, ?)",
            (
                "C:\\Users\\Alice\\Downloads\\payload.exe",
                "C:\\Users\\Alice\\Downloads\\payload.exe.crdownload",
                _chrome_time_us(epoch_ms + 1000),
                _chrome_time_us(epoch_ms + 3000),
                "https://example.test/payload",
                "https://example.test/",
            ),
        )
        conn.execute(
            "INSERT INTO downloads_url_chains(id, chain_index, url) "
            "VALUES (7, 0, ?)",
            ("https://cdn.example.test/payload.exe",),
        )
        conn.commit()
    finally:
        conn.close()


def _firefox_time_us(epoch_ms: int) -> int:
    return epoch_ms * 1000


def _write_firefox_places_db(path, *, epoch_ms: int = 1779160440000):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE moz_places("
            "id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, "
            "typed INTEGER, last_visit_date INTEGER)"
        )
        conn.execute(
            "CREATE TABLE moz_historyvisits("
            "id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, "
            "from_visit INTEGER, visit_type INTEGER)"
        )
        conn.execute(
            "CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT)"
        )
        conn.execute(
            "CREATE TABLE moz_annos("
            "id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, "
            "content TEXT, dateAdded INTEGER, lastModified INTEGER)"
        )
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, typed, "
            "last_visit_date) VALUES (1, ?, ?, 2, 1, ?)",
            (
                "https://example.test/firefox",
                "Firefox landing",
                _firefox_time_us(epoch_ms),
            ),
        )
        conn.execute(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date, "
            "from_visit, visit_type) VALUES (11, 1, ?, 0, 1)",
            (_firefox_time_us(epoch_ms),),
        )
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, typed, "
            "last_visit_date) VALUES (2, ?, ?, 1, 0, ?)",
            (
                "https://cdn.example.test/ffpayload.exe",
                "download",
                _firefox_time_us(epoch_ms + 1000),
            ),
        )
        conn.execute(
            "INSERT INTO moz_anno_attributes(id, name) VALUES "
            "(1, 'downloads/destinationFileURI'), (2, 'downloads/metaData')"
        )
        conn.execute(
            "INSERT INTO moz_annos(id, place_id, anno_attribute_id, content, "
            "dateAdded, lastModified) VALUES (21, 2, 1, ?, ?, ?)",
            (
                "file:///C:/Users/Alice/Downloads/ffpayload.exe",
                _firefox_time_us(epoch_ms + 1000),
                _firefox_time_us(epoch_ms + 3000),
            ),
        )
        conn.execute(
            "INSERT INTO moz_annos(id, place_id, anno_attribute_id, content, "
            "dateAdded, lastModified) VALUES (22, 2, 2, ?, ?, ?)",
            (
                '{"endTime":1779160443000,"fileSize":4096,"state":1}',
                _firefox_time_us(epoch_ms + 1000),
                _firefox_time_us(epoch_ms + 3000),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_parse_chromium_history_db_extracts_visits_and_downloads(tmp_path):
    db_path = tmp_path / "History"
    _write_chromium_history_db(db_path)

    result = ai.parse_chromium_history_db(
        str(db_path), browser_name="Chrome", user="Alice")

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    by_type = {entry["artifact_type"]: entry for entry in result["entries"]}
    visit = by_type["Chrome Web Visits"]
    assert visit["url"] == "https://example.test/payload"
    assert visit["title"] == "payload page"
    assert visit["visit_time"][1] == "2026-05-19T03:14:00Z"
    download = by_type["Chrome Downloads"]
    assert download["url"] == "https://cdn.example.test/payload.exe"
    assert download["target_path"] == "C:\\Users\\Alice\\Downloads\\payload.exe"
    assert download["start_time"][1] == "2026-05-19T03:14:01Z"
    assert download["end_time"][1] == "2026-05-19T03:14:03Z"


def test_parse_firefox_places_db_extracts_visits_and_downloads(tmp_path):
    db_path = tmp_path / "places.sqlite"
    _write_firefox_places_db(db_path)

    result = ai.parse_firefox_places_db(
        str(db_path), user="Alice", profile="abcd.default-release")

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    by_type = {entry["artifact_type"]: entry for entry in result["entries"]}
    visit = by_type["Firefox Web Visits"]
    assert visit["url"] == "https://example.test/firefox"
    assert visit["title"] == "Firefox landing"
    assert visit["visit_time"][1] == "2026-05-19T03:14:00Z"
    download = by_type["Firefox Downloads"]
    assert download["url"] == "https://cdn.example.test/ffpayload.exe"
    assert download["target_path"] == "C:\\Users\\Alice\\Downloads\\ffpayload.exe"
    assert download["start_time"][1] == "2026-05-19T03:14:01Z"
    assert download["end_time"][1] == "2026-05-19T03:14:03Z"
    assert download["total_bytes"] == "4096"


def test_browser_indexer_discovers_chromium_history_and_cache_files(tmp_path):
    db_path = tmp_path / "History"
    _write_chromium_history_db(db_path)
    root = "/c:/Users"
    user = f"{root}/Alice"
    chrome_root = f"{user}/AppData/Local/Google/Chrome/User Data"
    profile = f"{chrome_root}/Default"
    history = f"{profile}/History"
    cache_root = f"{profile}/Cache/Cache_Data"
    cache_file = f"{cache_root}/f_000001"
    code_cache_root = f"{profile}/Code Cache/js"
    code_cache_file = f"{code_cache_root}/abcdef"
    image = _FakeImage(
        files={history: db_path.read_bytes()},
        dirs={
            root: [{"name": "Alice", "path": user, "is_dir": True}],
            chrome_root: [{"name": "Default", "path": profile, "is_dir": True}],
            cache_root: [{
                "name": "f_000001",
                "path": cache_file,
                "is_dir": False,
                "created": "2026-05-19T03:10:00Z",
                "modified": "2026-05-19T03:15:00Z",
            }],
            code_cache_root: [{
                "name": "abcdef",
                "path": code_cache_file,
                "is_dir": False,
                "modified": "2026-05-19T03:16:00Z",
            }],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_browser_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 4
    assert result["histories_seen"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    visits = conn.search(
        keyword="example.test", filters={"artifact_type": "Chrome Web Visits"})
    downloads = conn.search(
        keyword="payload.exe", filters={"artifact_type": "Chrome Downloads"})
    cache = conn.search(
        keyword="f_000001", filters={"artifact_type": "Browser Cache File"})
    code_cache = conn.search(
        keyword="abcdef", filters={"artifact_type": "Browser Code Cache File"})
    assert visits["total"] == 1
    assert downloads["total"] == 1
    assert downloads["hits"][0]["fields"]["Target Path"] == (
        "C:\\Users\\Alice\\Downloads\\payload.exe"
    )
    assert cache["total"] == 1
    assert cache["hits"][0]["timestamps"]["Modified"] == "2026-05-19T03:15:00Z"
    assert code_cache["total"] == 1
    conn.disconnect()


def test_browser_indexer_discovers_firefox_places_databases(tmp_path):
    db_path = tmp_path / "places.sqlite"
    _write_firefox_places_db(db_path)
    root = "/c:/Users"
    user = f"{root}/Alice"
    profiles_root = f"{user}/AppData/Roaming/Mozilla/Firefox/Profiles"
    profile = f"{profiles_root}/abcd.default-release"
    places = f"{profile}/places.sqlite"
    image = _FakeImage(
        files={places: db_path.read_bytes()},
        dirs={
            root: [{"name": "Alice", "path": user, "is_dir": True}],
            profiles_root: [{
                "name": "abcd.default-release",
                "path": profile,
                "is_dir": True,
            }],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_browser_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    assert result["histories_seen"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    visits = conn.search(
        keyword="example.test", filters={"artifact_type": "Firefox Web Visits"})
    downloads = conn.search(
        keyword="ffpayload.exe", filters={"artifact_type": "Firefox Downloads"})
    assert visits["total"] == 1
    assert downloads["total"] == 1
    assert downloads["hits"][0]["fields"]["Target Path"] == (
        "C:\\Users\\Alice\\Downloads\\ffpayload.exe"
    )
    conn.disconnect()


def _fake_lnk_bytes(target: str, *, mtime_ms: int = 1779160440000) -> bytes:
    raw = bytearray(b"\x00" * 0x4C)
    raw[0:4] = (0x4C).to_bytes(4, "little")
    filetime = ((mtime_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(
        8, "little")
    raw[0x2C:0x34] = filetime
    raw.extend(target.encode("utf-16-le") + b"\x00\x00")
    return bytes(raw)


def test_parse_lnk_bytes_extracts_path_and_header_time():
    raw = _fake_lnk_bytes("C:\\Users\\Alice\\Desktop\\invoice.docx")

    parsed = ai.parse_lnk_bytes(raw, source_path="/c:/Users/Alice/Recent/invoice.lnk")

    assert parsed["target_path"] == "C:\\Users\\Alice\\Desktop\\invoice.docx"
    assert "C:\\Users\\Alice\\Desktop\\invoice.docx" in parsed["string_candidates"]
    assert parsed["modified_time"][0] == 1779160440000


def test_lnk_jumplist_indexer_discovers_recent_lnk_and_destinations(tmp_path):
    root = "/c:/Users"
    user = f"{root}/Alice"
    recent = f"{user}/AppData/Roaming/Microsoft/Windows/Recent"
    automatic = f"{recent}/AutomaticDestinations"
    custom = f"{recent}/CustomDestinations"
    lnk_path = f"{recent}/invoice.lnk"
    jumplist_path = f"{automatic}/1111111111111111.automaticDestinations-ms"
    image = _FakeImage(
        files={
            lnk_path: _fake_lnk_bytes("C:\\Users\\Alice\\Desktop\\invoice.docx"),
            jumplist_path: (
                b"ole-stub" +
                "C:\\Users\\Alice\\Documents\\budget.xlsx".encode("utf-16-le")
            ),
        },
        dirs={
            root: [{"name": "Alice", "path": user, "is_dir": True}],
            recent: [
                {"name": "invoice.lnk", "path": lnk_path, "is_dir": False},
                {"name": "AutomaticDestinations", "path": automatic, "is_dir": True},
                {"name": "CustomDestinations", "path": custom, "is_dir": True},
            ],
            automatic: [
                {"name": "1111111111111111.automaticDestinations-ms",
                 "path": jumplist_path, "is_dir": False},
            ],
            custom: [],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_lnk_jumplist_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    lnk_hits = conn.search(
        keyword="invoice.docx", filters={"artifact_type": "LNK Files"}, limit=10)
    jump_hits = conn.search(
        keyword="budget.xlsx", filters={"artifact_type": "Jump Lists"}, limit=10)
    assert lnk_hits["total"] == 1
    assert jump_hits["total"] == 1
    conn.disconnect()


# ── SRUM SRUDB.dat indexer ────────────────────────────────────────────────

class _FakeEseTable:
    def __init__(self, records):
        self._records = records

    def records(self):
        return iter(self._records)


class _FakeSrumEseDb:
    def __init__(self):
        self._tables = {
            "SruDbIdMapTable": _FakeEseTable([
                {"IdIndex": 7, "IdBlob": "C:\\Tools\\agent.exe"},
                {"IdIndex": 8, "IdBlob": "C:\\Tools\\helper.exe"},
            ]),
            "{973F5D5C-1D90-4944-BE8E-24B94231A174}": _FakeEseTable([
                {
                    "TimeStamp": "2026-05-19T03:14:00Z",
                    "AppId": 7,
                    "UserId": "S-1-5-21-1111",
                    "BytesSent": 4096,
                    "BytesReceived": 8192,
                    "InterfaceLuid": 12,
                },
            ]),
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": _FakeEseTable([
                {
                    "TimeStamp": "2026-05-19T03:14:30Z",
                    "AppId": 7,
                    "UserId": "S-1-5-21-1111",
                    "ForegroundCycleTime": 120,
                    "BackgroundBytesRead": 64,
                    "BackgroundBytesWritten": 32,
                },
            ]),
        }

    def tables(self):
        return list(self._tables)

    def table(self, name):
        return self._tables[name]


class _FakeWebCacheEseDb:
    def __init__(self):
        self._tables = {
            "Containers": _FakeEseTable([
                {"ContainerId": 1, "Name": "History"},
                {"ContainerId": 2, "Name": "iedownload"},
                {"ContainerId": 3, "Name": "Content"},
            ]),
            "Container_1": _FakeEseTable([
                {
                    "Url": "https://example.test/legacy",
                    "Title": "Legacy landing",
                    "AccessedTime": "2026-05-19T03:14:00Z",
                },
            ]),
            "Container_2": _FakeEseTable([
                {
                    "Url": "https://cdn.example.test/legacy.exe",
                    "Filename": "C:\\Users\\Alice\\Downloads\\legacy.exe",
                    "ModifiedTime": "2026-05-19T03:14:03Z",
                },
            ]),
            "Container_3": _FakeEseTable([
                {
                    "Url": "https://static.example.test/app.js",
                    "Filename": "C:\\Users\\Alice\\AppData\\Local\\Microsoft"
                                "\\Windows\\INetCache\\IE\\ABC\\app.js",
                    "ModifiedTime": "2026-05-19T03:15:00Z",
                },
            ]),
        }

    def tables(self):
        return list(self._tables)

    def table(self, name):
        return self._tables[name]


def test_parse_webcache_esedb_extracts_history_download_and_cache_records():
    result = ai.parse_webcache_esedb(_FakeWebCacheEseDb())

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 3
    by_type = {entry["artifact_type"]: entry for entry in result["entries"]}
    history = by_type["IE/Edge WebCache History"]
    assert history["url"] == "https://example.test/legacy"
    assert history["timestamp"][1] == "2026-05-19T03:14:00Z"
    download = by_type["IE/Edge WebCache Downloads"]
    assert download["url"] == "https://cdn.example.test/legacy.exe"
    assert download["target_path"] == "C:\\Users\\Alice\\Downloads\\legacy.exe"
    assert download["timestamp"][1] == "2026-05-19T03:14:03Z"
    cache = by_type["IE/Edge WebCache Cache"]
    assert cache["target_path"].endswith("\\INetCache\\IE\\ABC\\app.js")


def test_browser_indexer_discovers_webcache_databases(tmp_path):
    root = "/c:/Users"
    user = f"{root}/Alice"
    webcache_root = f"{user}/AppData/Local/Microsoft/Windows/WebCache"
    webcache = f"{webcache_root}/WebCacheV01.dat"
    image = _FakeImage(
        files={webcache: b"ese-webcache"},
        dirs={
            root: [{"name": "Alice", "path": user, "is_dir": True}],
            webcache_root: [{
                "name": "WebCacheV01.dat",
                "path": webcache,
                "is_dir": False,
            }],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_browser_artifacts(
            image,
            store,
            started_at="2026-06-10T00:00:00Z",
            webcache_ese_factory=lambda _fh: _FakeWebCacheEseDb(),
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 3
    assert result["webcache_dbs_seen"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    downloads = conn.search(
        keyword="legacy.exe",
        filters={"artifact_type": "IE/Edge WebCache Downloads"},
    )
    assert downloads["total"] == 1
    assert downloads["hits"][0]["fields"]["Target Path"] == (
        "C:\\Users\\Alice\\Downloads\\legacy.exe"
    )
    conn.disconnect()


# ── Recycle Bin $I / $R indexer ─────────────────────────────────────────────

def _recycle_i_bytes(
    original_path: str,
    *,
    original_size: int = 4096,
    deleted_ms: int = 1779160440000,
    version: int = 1,
) -> bytes:
    filetime = ((deleted_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000)
    return (
        version.to_bytes(8, "little") +
        original_size.to_bytes(8, "little") +
        filetime.to_bytes(8, "little") +
        original_path.encode("utf-16-le") +
        b"\x00\x00"
    )


def test_parse_recycle_bin_i_metadata_extracts_original_path_and_delete_time():
    raw = _recycle_i_bytes("C:\\Users\\Alice\\Downloads\\invoice.docm")

    parsed = ai.parse_recycle_bin_i_file(
        raw, source_path="/c:/$Recycle.Bin/S-1-5-21-1/$IABC123")

    assert parsed["ok"] is True
    assert parsed["recycle_id"] == "ABC123"
    assert parsed["original_path"] == "C:\\Users\\Alice\\Downloads\\invoice.docm"
    assert parsed["original_size"] == 4096
    assert parsed["deleted_at"][1] == "2026-05-19T03:14:00Z"


def test_recycle_bin_indexer_links_i_metadata_to_r_payload(tmp_path):
    root = "/c:/$Recycle.Bin"
    sid_dir = f"{root}/S-1-5-21-1111"
    i_path = f"{sid_dir}/$IABC123"
    r_path = f"{sid_dir}/$RABC123"
    image = _FakeImage(
        files={
            i_path: _recycle_i_bytes(
                "C:\\Users\\Alice\\Downloads\\invoice.docm",
                original_size=8192,
            ),
        },
        dirs={
            root: [{"name": "S-1-5-21-1111", "path": sid_dir, "is_dir": True}],
            sid_dir: [
                {"name": "$IABC123", "path": i_path, "is_dir": False},
                {
                    "name": "$RABC123",
                    "path": r_path,
                    "is_dir": False,
                    "modified": "2026-05-19T03:15:00Z",
                },
            ],
        },
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_recycle_bin_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1
    assert result["metadata_files_seen"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="invoice.docm",
        filters={"artifact_type": "Recycle Bin Deleted Items"},
    )
    assert hits["total"] == 1
    hit = hits["hits"][0]
    assert hit["fields"]["Original Path"] == "C:\\Users\\Alice\\Downloads\\invoice.docm"
    assert hit["fields"]["Recycled Path"] == r_path
    assert hit["fields"]["Original Size"] == "8192"
    assert hit["fields"]["User SID"] == "S-1-5-21-1111"
    assert hit["timestamps"]["Deleted Time"] == "2026-05-19T03:14:00Z"
    assert hit["timestamps"]["Recycled Modified"] == "2026-05-19T03:15:00Z"
    conn.disconnect()


# ── NTFS USN Journal $J indexer ─────────────────────────────────────────────

def _usn_filetime_bytes(epoch_ms: int) -> bytes:
    return ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(
        8, "little")


def _usn_v2_record(
    filename: str,
    *,
    reason: int,
    timestamp_ms: int = 1779160440000,
    file_ref: int = 0x0001000000000042,
    parent_ref: int = 0x0001000000000030,
    usn: int = 123456,
    file_attributes: int = 0x20,
) -> bytes:
    name = filename.encode("utf-16-le")
    record_len = 60 + len(name)
    padded_len = record_len + ((8 - record_len % 8) % 8)
    raw = bytearray(b"\x00" * padded_len)
    raw[0:4] = record_len.to_bytes(4, "little")
    raw[4:6] = (2).to_bytes(2, "little")
    raw[6:8] = (0).to_bytes(2, "little")
    raw[8:16] = file_ref.to_bytes(8, "little")
    raw[16:24] = parent_ref.to_bytes(8, "little")
    raw[24:32] = usn.to_bytes(8, "little", signed=True)
    raw[32:40] = _usn_filetime_bytes(timestamp_ms)
    raw[40:44] = reason.to_bytes(4, "little")
    raw[52:56] = file_attributes.to_bytes(4, "little")
    raw[56:58] = len(name).to_bytes(2, "little")
    raw[58:60] = (60).to_bytes(2, "little")
    raw[60:60 + len(name)] = name
    return bytes(raw)


def test_parse_usn_journal_records_extracts_reason_flags_and_timestamps():
    raw = (
        b"\x00" * 32 +
        _usn_v2_record("invoice.docm", reason=0x00000200) +
        b"\x00" * 8 +
        _usn_v2_record("payload.exe", reason=0x00002000)
    )

    result = ai.parse_usn_journal_records(raw)

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    delete = result["entries"][0]
    rename = result["entries"][1]
    assert delete["file_name"] == "invoice.docm"
    assert "FILE_DELETE" in delete["reason_names"]
    assert delete["timestamp"][1] == "2026-05-19T03:14:00Z"
    assert rename["file_name"] == "payload.exe"
    assert "RENAME_NEW_NAME" in rename["reason_names"]


def test_enrich_usn_entries_with_mft_paths_reconstructs_parent_path():
    raw = _usn_v2_record(
        "invoice.docm",
        reason=0x00000200,
        file_ref=0x0001000000000042,
        parent_ref=0x0001000000000030,
    )
    parsed = ai.parse_usn_journal_records(raw)
    entries = parsed["entries"]

    result = ai.enrich_usn_entries_with_mft_paths(
        entries,
        {
            0x30: {"path": "/c:/Users/Alice/Downloads", "sequence": 1},
            0x42: {"path": "/c:/Users/Alice/Downloads/invoice.docm", "sequence": 1},
        },
    )

    enriched = result["entries"][0]
    assert enriched["parent_path_candidate"] == "/c:/Users/Alice/Downloads"
    assert enriched["path_candidate"] == "/c:/Users/Alice/Downloads/invoice.docm"
    assert enriched["path_reconstruction_method"] == "mft_parent_frn_map"
    assert enriched["path_reconstruction_confidence"] == "sequence_verified"
    assert enriched["parent_sequence_verified"] is True
    assert result["coverage_gaps"] == []


def test_enrich_usn_entries_with_mft_paths_marks_sequence_mismatch_as_candidate():
    raw = _usn_v2_record(
        "invoice.docm",
        reason=0x00000200,
        file_ref=0x0001000000000042,
        parent_ref=0x0002000000000030,
    )
    entries = ai.parse_usn_journal_records(raw)["entries"]

    result = ai.enrich_usn_entries_with_mft_paths(
        entries,
        {
            0x30: {"path": "/c:/Users/Alice/Downloads", "sequence": 1},
        },
    )

    enriched = result["entries"][0]
    assert enriched["path_candidate"] == "/c:/Users/Alice/Downloads/invoice.docm"
    assert enriched["path_reconstruction_confidence"] == "sequence_mismatch_candidate"
    assert enriched["parent_sequence_verified"] is False
    assert result["sequence_verified_paths"] == 0
    assert result["sequence_mismatch_paths"] == 1


def test_build_usn_rename_transitions_pairs_old_and_new_names():
    raw = (
        _usn_v2_record(
            "invoice.docm",
            reason=0x00001000,
            timestamp_ms=1779160440000,
            file_ref=0x0001000000000042,
            parent_ref=0x0001000000000030,
            usn=100,
        ) +
        _usn_v2_record(
            "report.docm",
            reason=0x00002000,
            timestamp_ms=1779160440500,
            file_ref=0x0001000000000042,
            parent_ref=0x0001000000000030,
            usn=101,
        ) +
        _usn_v2_record(
            "orphan.tmp",
            reason=0x00001000,
            timestamp_ms=1779160450000,
            file_ref=0x0001000000000077,
            parent_ref=0x0001000000000030,
            usn=200,
        )
    )
    entries = ai.enrich_usn_entries_with_mft_paths(
        ai.parse_usn_journal_records(raw)["entries"],
        {0x30: {"path": "/c:/Users/Alice/Documents", "sequence": 1}},
    )["entries"]

    result = ai.build_usn_rename_transitions(entries)

    assert result["transition_count"] == 1
    assert result["unpaired_old_count"] == 1
    transition = result["transitions"][0]
    assert transition["old_name"] == "invoice.docm"
    assert transition["new_name"] == "report.docm"
    assert transition["old_path_candidate"] == "/c:/Users/Alice/Documents/invoice.docm"
    assert transition["new_path_candidate"] == "/c:/Users/Alice/Documents/report.docm"
    assert transition["file_reference_number"] == str(0x0001000000000042)
    assert transition["usn_delta"] == 1
    assert transition["time_delta_ms"] == 500
    assert transition["pairing_method"] == "same_frn_usn_time_window"


def test_usn_journal_indexer_extracts_j_stream_into_sidecar(tmp_path):
    internal = "/c:/$Extend/$UsnJrnl:$J"
    image = _FakeImage(files={
        internal: _usn_v2_record("invoice.docm", reason=0x00000200),
    })
    store = _open_store(tmp_path)
    try:
        result = ai.index_usn_journal_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="invoice.docm",
        filters={"artifact_type": "USN Journal Entries"},
    )
    assert hits["total"] == 1
    hit = hits["hits"][0]
    assert hit["fields"]["Reason"] == "FILE_DELETE"
    assert hit["fields"]["File Name"] == "invoice.docm"
    assert hit["timestamps"]["Event Time"] == "2026-05-19T03:14:00Z"
    conn.disconnect()


def test_usn_journal_indexer_reconstructs_path_from_mft_sidecar(tmp_path):
    internal = "/c:/$Extend/$UsnJrnl:$J"
    image = _FakeImage(files={
        internal: _usn_v2_record(
            "invoice.docm",
            reason=0x00000200,
            file_ref=0x0001000000000042,
            parent_ref=0x0001000000000030,
        ),
    })
    store = _open_store(tmp_path)
    try:
        mft_run = store.start_parser_run(
            "mft_indexer", "/c:", started_at="2026-06-10T00:00:00Z")
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path="/c:/Users/Alice/Downloads",
            primary_path="/c:/Users/Alice/Downloads",
            description="File System Entry /c:/Users/Alice/Downloads",
            strings={
                "Name": "Downloads",
                "Path": "/c:/Users/Alice/Downloads",
                "MFT Segment": str(0x30),
                "MFT Sequence Number": "1",
                "Type": "Directory",
            },
            times={},
            parser_run_id=mft_run,
        )
        store.finish_parser_run(
            mft_run,
            status="completed",
            coverage_status="searched",
            finished_at="2026-06-10T00:00:00Z",
        )
        result = ai.index_usn_journal_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["path_reconstruction"]["method"] == "mft_parent_frn_map"
    assert result["path_reconstruction"]["reconstructed_paths"] == 1
    assert result["path_reconstruction"]["sequence_verified_paths"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="invoice.docm",
        filters={"artifact_type": "USN Journal Entries"},
    )
    assert hits["total"] == 1
    hit = hits["hits"][0]
    assert hit["fields"]["Path Candidate"] == "/c:/Users/Alice/Downloads/invoice.docm"
    assert hit["fields"]["Parent Path Candidate"] == "/c:/Users/Alice/Downloads"
    assert hit["fields"]["Path Reconstruction"] == "mft_parent_frn_map"
    assert hit["fields"]["Path Reconstruction Confidence"] == "sequence_verified"
    conn.disconnect()


def test_usn_journal_indexer_writes_rename_transition_artifacts(tmp_path):
    internal = "/c:/$Extend/$UsnJrnl:$J"
    image = _FakeImage(files={
        internal: (
            _usn_v2_record(
                "invoice.docm",
                reason=0x00001000,
                timestamp_ms=1779160440000,
                file_ref=0x0001000000000042,
                parent_ref=0x0001000000000030,
                usn=100,
            ) +
            _usn_v2_record(
                "report.docm",
                reason=0x00002000,
                timestamp_ms=1779160440500,
                file_ref=0x0001000000000042,
                parent_ref=0x0001000000000030,
                usn=101,
            )
        ),
    })
    store = _open_store(tmp_path)
    try:
        mft_run = store.start_parser_run(
            "mft_indexer", "/c:", started_at="2026-06-10T00:00:00Z")
        store.insert_artifact(
            artifact_type="File System Entry",
            source_ref="/c:",
            source_path="/c:/Users/Alice/Documents",
            primary_path="/c:/Users/Alice/Documents",
            description="File System Entry /c:/Users/Alice/Documents",
            strings={
                "Name": "Documents",
                "Path": "/c:/Users/Alice/Documents",
                "MFT Segment": str(0x30),
                "MFT Sequence Number": "1",
                "Type": "Directory",
            },
            times={},
            parser_run_id=mft_run,
        )
        store.finish_parser_run(
            mft_run,
            status="completed",
            coverage_status="searched",
            finished_at="2026-06-10T00:00:00Z",
        )
        result = ai.index_usn_journal_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["rename_transitions"]["transition_count"] == 1
    assert result["rename_transitions"]["unpaired_old_count"] == 0

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="report.docm",
        filters={"artifact_type": "USN Rename Transitions"},
    )
    assert hits["total"] == 1
    hit = hits["hits"][0]
    assert hit["fields"]["Old Name"] == "invoice.docm"
    assert hit["fields"]["New Name"] == "report.docm"
    assert hit["fields"]["Old Path Candidate"] == "/c:/Users/Alice/Documents/invoice.docm"
    assert hit["fields"]["New Path Candidate"] == "/c:/Users/Alice/Documents/report.docm"
    assert hit["fields"]["Pairing Method"] == "same_frn_usn_time_window"
    assert hit["timestamps"]["Old Name Time"] == "2026-05-19T03:14:00Z"
    assert hit["timestamps"]["New Name Time"] == "2026-05-19T03:14:00Z"
    conn.disconnect()


# ── NTFS $LogFile page-candidate indexer ───────────────────────────────────

def _logfile_page(signature: bytes, payload: bytes = b"", *, page_size: int = 4096) -> bytes:
    raw = signature + payload
    return raw + (b"\x00" * max(0, page_size - len(raw)))


def test_parse_logfile_records_extracts_rstr_and_rcrd_candidates():
    path = "C:\\Users\\Alice\\Downloads\\invoice.docm"
    raw = (
        _logfile_page(b"RSTR", b"NTFS\x00RestartArea\x00ClientTable\x00") +
        _logfile_page(
            b"RCRD",
            b"DeleteFile\x00" + path.encode("utf-16-le") + b"\x00\x00",
        )
    )

    result = ai.parse_logfile_records(raw)

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    restart, operation = result["entries"]
    assert restart["artifact_type"] == "NTFS LogFile Restart Areas"
    assert restart["page_signature"] == "RSTR"
    assert operation["artifact_type"] == "NTFS LogFile Operation Candidates"
    assert operation["page_signature"] == "RCRD"
    assert path in operation["candidate_paths"]
    assert "invoice.docm" in operation["candidate_names"]
    assert "DeleteFile" in operation["operation_hints"]
    assert operation["parser_scope"] == "page_candidate_no_replay"


def test_logfile_indexer_extracts_logfile_into_sidecar(tmp_path):
    internal = "/c:/$LogFile"
    path = "C:\\Users\\Alice\\Downloads\\invoice.docm"
    raw = _logfile_page(
        b"RCRD",
        b"DeleteFile\x00" + path.encode("utf-16-le") + b"\x00\x00",
    )
    image = _FakeImage(files={internal: raw})
    store = _open_store(tmp_path)
    try:
        result = ai.index_logfile_artifacts(
            image, store, started_at="2026-06-10T00:00:00Z")
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 1

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="invoice.docm",
        filters={"artifact_type": "NTFS LogFile Operation Candidates"},
    )
    assert hits["total"] == 1
    hit = hits["hits"][0]
    assert hit["fields"]["Page Signature"] == "RCRD"
    assert hit["fields"]["Candidate Paths"] == path
    assert hit["fields"]["Operation Hints"] == "DeleteFile"
    assert hit["fields"]["Parser Scope"] == "page_candidate_no_replay"
    conn.disconnect()


def test_parse_srum_esedb_extracts_network_and_app_records():
    result = ai.parse_srum_esedb(_FakeSrumEseDb())

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2
    network = [e for e in result["entries"]
               if e["artifact_type"] == "SRUM Network Usage"][0]
    app = [e for e in result["entries"]
           if e["artifact_type"] == "SRUM Application Resource Usage"][0]
    assert network["application_name"] == "C:\\Tools\\agent.exe"
    assert network["bytes_sent"] == 4096
    assert network["bytes_received"] == 8192
    assert network["timestamp"][1] == "2026-05-19T03:14:00Z"
    assert app["application_name"] == "C:\\Tools\\agent.exe"
    assert app["foreground_cycle_time"] == 120
    assert app["timestamp"][1] == "2026-05-19T03:14:30Z"


def test_parse_srum_esedb_reports_unknown_schema_as_not_evaluable():
    class _UnknownSrumDb:
        def __init__(self):
            self._tables = {
                "SruDbIdMapTable": _FakeEseTable([]),
                "{UNKNOWN-GUID}": _FakeEseTable([
                    {"TimeStamp": "2026-05-19T03:14:00Z", "Mystery": 1},
                ]),
            }

        def tables(self):
            return list(self._tables)

        def table(self, name):
            return self._tables[name]

    result = ai.parse_srum_esedb(_UnknownSrumDb())

    assert result["ok"] is False
    assert result["status"] == "not_evaluable"
    assert result["indexed_records"] == 0
    assert any(g["reason"] == "srum_supported_tables_absent"
               for g in result["coverage_gaps"])


def test_srum_indexer_extracts_srudb_into_raw_index(tmp_path):
    internal = "/c:/Windows/System32/sru/SRUDB.dat"
    image = _FakeImage(files={internal: b"ese-stub"})
    store = _open_store(tmp_path)
    try:
        result = ai.index_srum_artifacts(
            image,
            store,
            started_at="2026-06-10T00:00:00Z",
            ese_factory=lambda _fh: _FakeSrumEseDb(),
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["indexed_records"] == 2

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    network_hits = conn.search(
        keyword="agent.exe",
        filters={"artifact_type": "SRUM Network Usage"},
        limit=10,
    )
    app_hits = conn.search(
        keyword="agent.exe",
        filters={"artifact_type": "SRUM Application Resource Usage"},
        limit=10,
    )
    assert network_hits["total"] == 1
    assert network_hits["hits"][0]["fields"]["Bytes Sent"] == "4096"
    assert network_hits["hits"][0]["timestamps"]["Timestamp"] == (
        "2026-05-19T03:14:00Z"
    )
    assert app_hits["total"] == 1
    assert app_hits["hits"][0]["fields"]["Foreground Cycle Time"] == "120"
    conn.disconnect()


# ── Registry value parsers (pure functions, stub hive) ─────────────────────

class _Val:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Key:
    def __init__(self, name, subkeys=None, values=None, last_modified=None):
        self.name = name
        self._subkeys = subkeys or []
        self._values = values or []
        self.header = type("_Header", (), {"last_modified": last_modified})()

    def iter_subkeys(self):
        return iter(self._subkeys)

    def iter_values(self):
        return iter(self._values)

    def get_subkey(self, name):
        for subkey in self._subkeys:
            if subkey.name == name:
                return subkey
        raise KeyError(name)


class _Hive:
    def __init__(self, keys: dict[str, _Key]):
        self._keys = keys

    def get_key(self, path):
        if path not in self._keys:
            raise KeyError(path)
        return self._keys[path]


def _shellbag_value(name: str) -> bytes:
    return b"\x14\x00" + name.encode("utf-16-le") + b"\x00\x00"


def test_parse_shellbags_walks_bagmru_tree_and_extracts_folder_names():
    hive = _Hive({
        "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU": _Key(
            "BagMRU",
            values=[
                _Val("0", _shellbag_value("Finance")),
                _Val("NodeSlot", 42),
            ],
            subkeys=[
                _Key("0", values=[
                    _Val("1", _shellbag_value("Quarterly")),
                    _Val("NodeSlot", 43),
                ]),
            ],
        ),
    })

    entries, gaps = ai.parse_shellbags(
        hive, user="alice", hive_label="UsrClass:alice")

    assert gaps == []
    assert len(entries) == 2
    assert entries[0]["item_name"] == "Finance"
    assert entries[0]["path_hint"] == "Finance"
    assert entries[0]["node_slot"] == "42"
    assert entries[1]["item_name"] == "Quarterly"
    assert entries[1]["path_hint"] == "Finance\\Quarterly"
    assert entries[1]["user"] == "alice"


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


# ── AmCache / UserAssist / ShimCache raw parsers ───────────────────────────

def _filetime_bytes(epoch_ms: int) -> bytes:
    return ((epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000).to_bytes(
        8, "little")


def test_parse_userassist_entries_decodes_rot13_path_and_run_time():
    epoch_ms = 1779160440000
    raw = bytearray(b"\x00" * 72)
    raw[4:8] = (5).to_bytes(4, "little")
    raw[60:68] = _filetime_bytes(epoch_ms)
    decoded = "C:\\Users\\Alice\\AppData\\Local\\Temp\\evil.exe"
    hive = _Hive({
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist":
            _Key("UserAssist", subkeys=[
                _Key("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", subkeys=[
                    _Key("Count", values=[
                        _Val(codecs.encode(decoded, "rot_13"), bytes(raw)),
                    ]),
                ]),
            ]),
    })

    entries, gaps = ai.parse_userassist_entries(
        hive, user="Alice", hive_label="NTUSER:Alice")

    assert gaps == []
    assert len(entries) == 1
    entry = entries[0]
    assert entry["decoded_name"] == decoded
    assert entry["run_count"] == 5
    assert entry["last_run"][0] == epoch_ms


def test_parse_shimcache_entries_extracts_utf16_paths_from_appcompat_blob():
    path = "C:\\Windows\\Temp\\evil.exe"
    blob = b"\x00\x01" + path.encode("utf-16-le") + b"\x00\x00"
    hive = _Hive({
        "\\ControlSet001\\Control\\Session Manager\\AppCompatCache": _Key(
            "AppCompatCache",
            values=[_Val("AppCompatCache", blob)],
        ),
    })

    entries, gaps = ai.parse_shimcache_entries(
        hive, [("ControlSet001", True)])

    assert gaps == []
    assert len(entries) == 1
    assert entries[0]["path"] == path
    assert entries[0]["control_set"] == "ControlSet001"


def test_parse_amcache_hive_extracts_file_program_and_driver_entries():
    epoch_ms = 1779160440000
    hive = _Hive({
        "\\Root\\File": _Key("File", subkeys=[
            _Key("{volume}", subkeys=[
                _Key("0000", values=[
                    _Val("FullPath", "C:\\Tools\\agent.exe"),
                    _Val("ApplicationName", "agent.exe"),
                    _Val("SHA1", "0123456789abcdef"),
                    _Val("FileKeyLastWriteTimestamp", "2026-05-19T03:14:00Z"),
                    _Val("ProductName", "Agent"),
                ], last_modified=(epoch_ms + ai._FILETIME_EPOCH_OFFSET_MS) * 10000),
            ]),
        ]),
        "\\Root\\Programs": _Key("Programs", subkeys=[
            _Key("program-id", values=[
                _Val("Name", "Remote Tool"),
                _Val("Version", "1.2.3"),
                _Val("Publisher", "Vendor"),
                _Val("RootDirPath", "C:\\Program Files\\Remote Tool"),
                _Val("KeyLastWriteTimestamp", "2026-05-19T03:15:00Z"),
            ]),
        ]),
        "\\Root\\InventoryDriverBinary": _Key("InventoryDriverBinary", subkeys=[
            _Key("driver-id", values=[
                _Val("DriverName", "evil.sys"),
                _Val("DriverCompany", "Unknown"),
                _Val("DriverCheckSum", "deadbeef"),
                _Val("KeyLastWriteTimestamp", "2026-05-19T03:16:00Z"),
            ]),
        ]),
    })

    entries, gaps = ai.parse_amcache_hive(hive)

    assert gaps == []
    by_type = {e["artifact_type"]: e for e in entries}
    assert by_type["AmCache File Entries"]["path"] == "C:\\Tools\\agent.exe"
    assert by_type["AmCache File Entries"]["sha1"] == "0123456789abcdef"
    assert by_type["AmCache Program Entries"]["name"] == "Remote Tool"
    assert by_type["AmCache Driver Binaries"]["driver_name"] == "evil.sys"


def test_userassist_indexer_discovers_user_hives(tmp_path):
    raw = bytearray(b"\x00" * 72)
    raw[4:8] = (2).to_bytes(4, "little")
    decoded = "C:\\Tools\\agent.exe"
    hive = _Hive({
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist":
            _Key("UserAssist", subkeys=[
                _Key("{GUID}", subkeys=[
                    _Key("Count", values=[
                        _Val(codecs.encode(decoded, "rot_13"), bytes(raw)),
                    ]),
                ]),
            ]),
    })
    root = "/c:/Users"
    user = f"{root}/Alice"
    ntuser = f"{user}/NTUSER.DAT"
    image = _FakeImage(
        files={ntuser: b"hive"},
        dirs={root: [{"name": "Alice", "path": user, "is_dir": True}]},
    )
    store = _open_store(tmp_path)
    try:
        result = ai.index_userassist_artifacts(
            image,
            store,
            started_at="2026-06-10T00:00:00Z",
            hive_factory=lambda _path: hive,
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["indexed_records"] == 1
    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(keyword="agent.exe", filters={"artifact_type": "UserAssist"})
    assert hits["total"] == 1
    assert hits["hits"][0]["fields"]["Run Count"] == "2"
    conn.disconnect()


def test_shimcache_indexer_extracts_system_hive_blob(tmp_path):
    path = "C:\\Windows\\Temp\\evil.exe"
    hive = _Hive({
        "\\ControlSet001\\Control\\Session Manager\\AppCompatCache": _Key(
            "AppCompatCache",
            values=[_Val("AppCompatCache", path.encode("utf-16-le") + b"\x00\x00")],
        ),
    })
    image = _FakeImage(files={"/c:/Windows/System32/config/SYSTEM": b"hive"})
    store = _open_store(tmp_path)
    try:
        result = ai.index_shimcache_artifacts(
            image,
            store,
            started_at="2026-06-10T00:00:00Z",
            hive_factory=lambda _path: hive,
            control_sets_factory=lambda _hive: [("ControlSet001", True)],
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["indexed_records"] == 1
    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(keyword="evil.exe", filters={"artifact_type": "Shim Cache"})
    assert hits["total"] == 1
    conn.disconnect()


def test_amcache_indexer_extracts_hive_into_raw_index(tmp_path):
    hive = _Hive({
        "\\Root\\File": _Key("File", subkeys=[
            _Key("{volume}", subkeys=[
                _Key("0000", values=[
                    _Val("FullPath", "C:\\Tools\\agent.exe"),
                    _Val("ApplicationName", "agent.exe"),
                    _Val("SHA1", "0123456789abcdef"),
                ]),
            ]),
        ]),
    })
    image = _FakeImage(files={"/c:/Windows/AppCompat/Programs/Amcache.hve": b"hive"})
    store = _open_store(tmp_path)
    try:
        result = ai.index_amcache_artifacts(
            image,
            store,
            started_at="2026-06-10T00:00:00Z",
            hive_factory=lambda _path: hive,
        )
    finally:
        store.close()

    assert result["ok"] is True
    assert result["indexed_records"] == 1
    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "sidecar.sqlite"))
    hits = conn.search(
        keyword="agent.exe",
        filters={"artifact_type": "AmCache File Entries"},
    )
    assert hits["total"] == 1
    assert hits["hits"][0]["fields"]["SHA-1"] == "0123456789abcdef"
    conn.disconnect()


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

def test_raw_execution_context_families_have_evidence_strength_tiers():
    from core.analysis.evidence_strength import classify_artifact

    bam = classify_artifact("BAM Execution Entries")
    assert bam["tier"] == "strong"
    usb = classify_artifact("USB Devices")
    assert usb["tier"] == "moderate"
    pca = classify_artifact("PCA Program Compatibility Activity")
    assert pca["tier"] == "moderate"
    shellbags = classify_artifact("ShellBags")
    assert shellbags["tier"] == "moderate"
    timeline = classify_artifact("Windows Timeline Activity")
    assert timeline["tier"] == "moderate"
    lnk = classify_artifact("LNK Files")
    assert lnk["tier"] == "moderate"
    jumplist = classify_artifact("Jump Lists")
    assert jumplist["tier"] == "moderate"
    srum_network = classify_artifact("SRUM Network Usage")
    assert srum_network["tier"] == "confirmed"
    srum_app = classify_artifact("SRUM Application Resource Usage")
    assert srum_app["tier"] == "confirmed"
    amcache = classify_artifact("AmCache File Entries")
    assert amcache["tier"] == "moderate"
    userassist = classify_artifact("UserAssist")
    assert userassist["tier"] == "moderate"
    shimcache = classify_artifact("Shim Cache")
    assert shimcache["tier"] == "weak"
    browser = classify_artifact("Chrome Web Visits")
    assert browser["tier"] == "moderate"
    assert "Browser" in browser["reason"]
    firefox = classify_artifact("Firefox Downloads")
    assert firefox["tier"] == "moderate"
    assert "Browser" in firefox["reason"]
    webcache = classify_artifact("IE/Edge WebCache Downloads")
    assert webcache["tier"] == "moderate"
    assert "Browser" in webcache["reason"]
    recycle = classify_artifact("Recycle Bin Deleted Items")
    assert recycle["tier"] == "moderate"
    assert "Recycle Bin" in recycle["reason"]
    usn = classify_artifact("USN Journal Entries")
    assert usn["tier"] == "strong"
    assert "USN Journal" in usn["reason"]
    usn_rename = classify_artifact("USN Rename Transitions")
    assert usn_rename["tier"] == "strong"
    assert "USN Journal" in usn_rename["reason"]
    logfile = classify_artifact("NTFS LogFile Operation Candidates")
    assert logfile["tier"] == "strong"
    assert "$LogFile" in logfile["reason"]


def test_raw_execution_context_families_have_rule_coverage_aliases():
    from core.analysis.rule_coverage import FAMILY_ALIASES

    assert "BAM Execution Entries" in FAMILY_ALIASES["BAM"]
    assert "USB Devices" in FAMILY_ALIASES["USB Devices"]
    assert "PCA Program Compatibility Activity" in FAMILY_ALIASES["PCA"]
    assert "ShellBags" in FAMILY_ALIASES["ShellBags"]
    assert "Windows Timeline Activity" in FAMILY_ALIASES["Windows Timeline"]
    assert "LNK Files" in FAMILY_ALIASES["LNK Files"]
    assert "Jump Lists" in FAMILY_ALIASES["Jump Lists"]
    assert "SRUM Network Usage" in FAMILY_ALIASES["SRUM"]
    assert "SRUM Application Resource Usage" in FAMILY_ALIASES["SRUM"]
    assert "AmCache File Entries" in FAMILY_ALIASES["AmCache"]
    assert "UserAssist" in FAMILY_ALIASES["UserAssist"]
    assert "Shim Cache" in FAMILY_ALIASES["ShimCache"]
    assert "Chrome Web Visits" in FAMILY_ALIASES["Browser History"]
    assert "Firefox Web Visits" in FAMILY_ALIASES["Browser History"]
    assert "IE/Edge WebCache History" in FAMILY_ALIASES["Browser History"]
    assert "Chrome Downloads" in FAMILY_ALIASES["Browser Downloads"]
    assert "Firefox Downloads" in FAMILY_ALIASES["Browser Downloads"]
    assert "IE/Edge WebCache Downloads" in FAMILY_ALIASES["Browser Downloads"]
    assert "Browser Cache File" in FAMILY_ALIASES["Browser Cache"]
    assert "IE/Edge WebCache Cache" in FAMILY_ALIASES["Browser Cache"]
    assert "Recycle Bin Deleted Items" in FAMILY_ALIASES["Recycle Bin"]
    assert "USN Journal Entries" in FAMILY_ALIASES["USN Journal"]
    assert "USN Rename Transitions" in FAMILY_ALIASES["USN Journal"]
    assert "NTFS LogFile Operation Candidates" in FAMILY_ALIASES["NTFS LogFile"]


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
