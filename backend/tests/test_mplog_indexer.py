"""Tests for the Defender MPLog artifact parser/indexer."""

from __future__ import annotations

from core.raw_index.artifact_indexer import index_mplog_artifacts, parse_mplog
from core.raw_index.store import RawIndexStore


_SAMPLE = "\n".join([
    "2026-05-01T06:35:38.766 ProcessImageName: updater.exe, Pid: 1116, TotalTime: 10, Count: 2",
    "2026-05-02T07:00:00.000 ProcessImageName: updater.exe, Pid: 2228, TotalTime: 5, Count: 1",
    "2026-05-02T08:00:00.000 ProcessImageName: whale.exe, Pid: 3000, TotalTime: 9, Count: 1",
    "2026-05-02T18:01:47.475 Engine:Process 6588 will be fully monitored because of "
    "injection from C:\\Windows\\System32\\csrss.exe",
    "2026-05-03T09:00:00.000 Engine:Process 6700 will be fully monitored because of "
    "injection from C:\\Windows\\System32\\csrss.exe",
    "2026-05-04T00:01:18.353 [AutoPurge] Routine task started.",  # ignored noise
    "2026-05-04T01:00:00.000 Threat:0,0,0",                       # clean — ignored
    "2026-05-05T02:00:00.000 DetectionEvent something Threat:5,0,1",  # real detection
])


def test_parse_mplog_aggregates_processes():
    records, capped = parse_mplog(_SAMPLE)
    assert capped is False
    procs = {r["key"]: r for r in records if r["kind"] == "process_execution"}
    assert procs["updater.exe"]["count"] == 2
    assert procs["updater.exe"]["first"] == "2026-05-01T06:35:38.766"
    assert procs["updater.exe"]["last"] == "2026-05-02T07:00:00.000"
    assert "1116" in procs["updater.exe"]["pids"]
    assert "2228" in procs["updater.exe"]["pids"]
    assert "whale.exe" in procs


def test_parse_mplog_aggregates_injection_sources():
    records, _ = parse_mplog(_SAMPLE)
    inj = [r for r in records if r["kind"] == "injection_source"]
    assert len(inj) == 1
    assert inj[0]["key"].endswith("csrss.exe")
    assert inj[0]["count"] == 2


def test_parse_mplog_only_nonzero_threats_are_detections():
    records, _ = parse_mplog(_SAMPLE)
    dets = [r for r in records if r["kind"] == "threat_detection"]
    assert len(dets) == 1  # Threat:0,0,0 is ignored; Threat:5,0,1 is kept
    assert "Threat:5,0,1" in dets[0]["detail"]


def test_parse_mplog_threat_outranks_process_on_same_line():
    # a line carrying BOTH a process name and a non-zero Threat must be a
    # detection, not downgraded to process_execution
    text = ("2026-05-05T02:00:00.000 ProcessImageName: evil.exe, Pid: 9 "
            "DetectionEvent Threat:7,0,0")
    records, _ = parse_mplog(text)
    kinds = [r["kind"] for r in records]
    assert "threat_detection" in kinds
    assert "process_execution" not in kinds


def test_index_mplog_listing_entry_error_is_gap(tmp_path):
    class _ErrListImage:
        def list_directory(self, path):
            return [
                {"error": "unreadable entry"},
                {"name": "MPLog-1.log", "path": f"{path}/MPLog-1.log", "is_dir": False},
            ]

        def read_file_content(self, path, max_size=0):
            return b"\xff\xfe" + _SAMPLE.encode("utf-16-le")

    store = _open(tmp_path)
    try:
        result = index_mplog_artifacts(_ErrListImage(), store,
                                       started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert any(g.get("reason") == "mplog_listing_entry_error"
               for g in result["coverage_gaps"])
    assert result["files_parsed"] == 1  # the good file is still parsed


def test_parse_mplog_detections_emitted_first_and_survive_cap():
    text = _SAMPLE + "\n" + "\n".join(
        f"2026-05-06T00:00:0{i}.000 ProcessImageName: p{i}.exe, Pid: {i}" for i in range(9)
    )
    records, capped = parse_mplog(text, max_records=2)
    assert capped is True
    assert len(records) == 2
    assert records[0]["kind"] == "threat_detection"  # detection kept first


class _MplogImage:
    """Stub exposing list_directory + read_file_content for the indexer."""

    def __init__(self, files):
        self._files = files  # {name: bytes}

    def list_directory(self, path):
        return [
            {"name": name, "path": f"{path}/{name}", "is_dir": False}
            for name in self._files
        ]

    def read_file_content(self, path, max_size=0):
        name = path.rsplit("/", 1)[-1]
        return self._files[name]


def _open(tmp_path):
    s = RawIndexStore(str(tmp_path / "mplog.sqlite"))
    s.open()
    return s


def test_index_mplog_writes_activity_and_is_searchable(tmp_path):
    # real MPLog files are UTF-16-LE with a BOM; mirror that exactly
    image = _MplogImage({
        "MPLog-20260501-131318.log": b"\xff\xfe" + _SAMPLE.encode("utf-16-le"),
    })
    store = _open(tmp_path)
    try:
        result = index_mplog_artifacts(image, store, started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert result["ok"] is True
    assert result["files_parsed"] == 1
    assert result["indexed_records"] >= 4  # 2 procs + 1 injection + 1 detection

    from core.connectors.raw_image_index import RawImageIndexConnector
    conn = RawImageIndexConnector()
    conn.connect(str(tmp_path / "mplog.sqlite"))
    hit = conn.search(keyword="updater.exe", filters={}, limit=5)
    assert hit["total"] >= 1
    conn.disconnect()


def test_index_mplog_no_files_is_not_evaluable(tmp_path):
    image = _MplogImage({})  # directory present but no MPLog files
    store = _open(tmp_path)
    try:
        result = index_mplog_artifacts(image, store, started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert result["status"] == "not_evaluable"
    assert result["indexed_records"] == 0


def test_index_mplog_unreadable_dir_is_gap(tmp_path):
    class _Broken:
        def list_directory(self, path):
            raise OSError("unreadable")

    store = _open(tmp_path)
    try:
        result = index_mplog_artifacts(_Broken(), store, started_at="2026-06-11T00:00:00Z")
    finally:
        store.close()
    assert result["status"] == "not_evaluable"
    assert any(g.get("reason") == "mplog_dir_unavailable" for g in result["coverage_gaps"])
