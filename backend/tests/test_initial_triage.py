from __future__ import annotations

from datetime import datetime, timezone

from core.analysis.initial_triage import initial_triage


def _iso(ts: str) -> str:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timeline_entry(hit_id: int, ts: str, artifact_type: str, description: str) -> dict:
    return {
        "hit_id": hit_id,
        "timestamp": _iso(ts),
        "artifact_type": artifact_type,
        "description": description,
    }


def _search_hit(hit_id: int, ts: str, artifact_type: str, fields: dict[str, str]) -> dict:
    return {
        "hit_id": hit_id,
        "artifact_type": artifact_type,
        "timestamp": _iso(ts),
        "fields": fields,
    }


class _ArtifactQueryStub:
    def __init__(
        self,
        *,
        services: list[str] | None = None,
        scheduled_tasks: list[str] | None = None,
        startup_items: list[str] | None = None,
        users: list[str] | None = None,
    ) -> None:
        self._services = services or []
        self._scheduled_tasks = scheduled_tasks or []
        self._startup_items = startup_items or []
        self._users = users or []

    def query_services(self, limit: int = 0) -> list[dict]:
        return [{"Service Name": value} for value in self._services]

    def query_scheduled_tasks(self, limit: int = 0) -> list[dict]:
        return [{"Name": value} for value in self._scheduled_tasks]

    def _query_artifact(self, artifact_type: str, limit: int = 0) -> list[dict]:
        if artifact_type == "Startup Items":
            return [{"Path": value} for value in self._startup_items]
        if artifact_type == "User Accounts":
            return [{"Username": value} for value in self._users]
        return []


class _StubConnector:
    def __init__(
        self,
        *,
        metadata: dict,
        artifact_counts: list[dict],
        timeline_entries: list[dict],
        search_map: dict[tuple[str, str], list[dict]],
        artifact_queries: _ArtifactQueryStub,
    ) -> None:
        self._metadata = metadata
        self._artifact_counts = artifact_counts
        self._timeline_entries = sorted(timeline_entries, key=lambda item: item["timestamp"])
        self._search_map = search_map
        self.artifact_queries = artifact_queries

    def get_metadata(self) -> dict:
        return dict(self._metadata)

    def get_artifact_type_counts(self) -> list[dict]:
        return list(self._artifact_counts)

    def get_timeline(self, start_date: str = "", end_date: str = "", limit: int = 200, offset: int = 0) -> dict:
        def in_range(entry: dict) -> bool:
            ts = entry["timestamp"][:10]
            if start_date and ts < start_date:
                return False
            if end_date and ts > end_date:
                return False
            return True

        filtered = [entry for entry in self._timeline_entries if in_range(entry)]
        page = filtered[offset:offset + limit]
        return {
            "total_events": len(filtered),
            "returned": len(page),
            "entries": page,
        }

    def search(self, keyword: str = "", filters: dict | None = None, limit: int = 50, offset: int = 0) -> dict:
        filters = filters or {}
        artifact_type = str(filters.get("artifact_type", "") or "").lower()
        needle = str(keyword or "").lower()
        hits = list(self._search_map.get((artifact_type, needle), self._search_map.get((artifact_type, ""), [])))
        start_date = str(filters.get("start_date", "") or "")
        end_date = str(filters.get("end_date", "") or "")
        if start_date or end_date:
            scoped = []
            for hit in hits:
                day = str(hit.get("timestamp", ""))[:10]
                if start_date and day < start_date:
                    continue
                if end_date and day > end_date:
                    continue
                scoped.append(hit)
            hits = scoped
        page = hits[offset:offset + limit]
        return {
            "total": len(hits),
            "returned": len(page),
            "hits": page,
        }


def _baro_like_connector() -> _StubConnector:
    artifact_queries = _ArtifactQueryStub(
        services=["bomgar remote support", "spooler"],
        users=["S"],
    )
    metadata = {
        "date_range_start": "2026-01-08T04:54:00Z",
        "date_range_end": "2026-04-15T00:35:53Z",
    }
    artifact_counts = [
        {"artifact_type": "Windows Event Logs", "count": 5000},
        {"artifact_type": "Prefetch Files - Windows 8/10/11", "count": 35},
        {"artifact_type": "$LogFile Analysis", "count": 200},
        {"artifact_type": "UsnJrnl", "count": 150},
        {"artifact_type": "SRUM Network Usage", "count": 20},
        {"artifact_type": "Edge Downloads", "count": 2},
        {"artifact_type": "System Services", "count": 3},
        {"artifact_type": "Text Documents", "count": 10},
        {"artifact_type": "LNK Files", "count": 4},
    ]
    timeline_entries = [
        _timeline_entry(1, "2026-04-09T20:31:10Z", "System Services", "Bomgar remote support service active"),
        _timeline_entry(2, "2026-04-12T02:50:03Z", "Prefetch Files - Windows 8/10/11", "Application Name: BOMGAR-PEC.EXE"),
        _timeline_entry(3, "2026-04-12T02:50:04Z", "Windows Event Logs", "Event ID: 7045 Bomgar service installed"),
        _timeline_entry(4, "2026-04-12T02:50:39Z", "Prefetch Files - Windows 8/10/11", "Application Name: RUNDLL32.EXE"),
        _timeline_entry(5, "2026-04-12T02:51:32Z", "Prefetch Files - Windows 8/10/11", "Application Name: WEVTUTIL.EXE"),
        _timeline_entry(6, "2026-04-12T02:53:33Z", "Prefetch Files - Windows 8/10/11", "Application Name: CONSENT.EXE"),
        _timeline_entry(7, "2026-04-12T02:55:25Z", "Text Documents", "Filename: INC-README.txt"),
        _timeline_entry(8, "2026-04-12T02:55:26Z", "$LogFile Analysis", "Create INC-README.txt"),
        _timeline_entry(9, "2026-04-12T02:55:49Z", "LNK Files", r"Linked Path: C:\Users\S\Desktop\INC-README.txt"),
    ]
    search_map = {
        ("system services", ""): [
            _search_hit(101, "2026-04-09T20:31:10Z", "System Services", {"Service Name": "bomgar remote support"}),
        ],
        ("prefetch files - windows 8/10/11", ""): [
            _search_hit(102, "2026-04-12T02:50:03Z", "Prefetch Files - Windows 8/10/11", {"Application Name": "BOMGAR-PEC.EXE"}),
            _search_hit(103, "2026-04-12T02:51:32Z", "Prefetch Files - Windows 8/10/11", {"Application Name": "WEVTUTIL.EXE"}),
        ],
        ("edge downloads", ""): [
            _search_hit(104, "2026-01-08T15:36:54Z", "Edge Downloads", {"URL": "https://pra.example/bomgar"}),
        ],
        ("text documents", "readme"): [
            _search_hit(105, "2026-04-12T02:55:25Z", "Text Documents", {"Filename": "INC-README.txt"}),
        ],
        ("$logfile analysis", ""): [
            _search_hit(106, "2026-04-12T02:55:26Z", "$LogFile Analysis", {"Current File Name": "INC-README.txt"}),
        ],
        ("usnjrnl", ""): [
            _search_hit(107, "2026-04-12T02:55:28Z", "UsnJrnl", {"File Name": "INC-README.txt"}),
        ],
        ("lnk files", ""): [
            _search_hit(108, "2026-04-12T02:55:49Z", "LNK Files", {"Linked Path": r"C:\Users\S\Desktop\INC-README.txt"}),
        ],
    }
    return _StubConnector(
        metadata=metadata,
        artifact_counts=artifact_counts,
        timeline_entries=timeline_entries,
        search_map=search_map,
        artifact_queries=artifact_queries,
    )


def _persistence_only_connector(*, include_related_families: bool) -> _StubConnector:
    artifact_counts = [
        {"artifact_type": "System Services", "count": 1},
    ]
    if include_related_families:
        artifact_counts.extend([
            {"artifact_type": "Windows Event Logs", "count": 50},
            {"artifact_type": "Prefetch Files - Windows 8/10/11", "count": 12},
            {"artifact_type": "SRUM Network Usage", "count": 3},
            {"artifact_type": "Edge Downloads", "count": 1},
            {"artifact_type": "$LogFile Analysis", "count": 5},
        ])

    return _StubConnector(
        metadata={
            "date_range_start": "2026-04-01T00:00:00Z",
            "date_range_end": "2026-04-15T00:00:00Z",
        },
        artifact_counts=artifact_counts,
        timeline_entries=[
            _timeline_entry(301, "2026-04-12T10:00:00Z", "System Services", "Service installed: updater"),
        ],
        search_map={},
        artifact_queries=_ArtifactQueryStub(services=["updater"]),
    )


def _low_confidence_bridge_connector() -> _StubConnector:
    return _StubConnector(
        metadata={
            "date_range_start": "2026-04-01T00:00:00Z",
            "date_range_end": "2026-04-15T00:00:00Z",
        },
        artifact_counts=[
            {"artifact_type": "System Services", "count": 2},
            {"artifact_type": "Windows Event Logs", "count": 25},
        ],
        timeline_entries=[
            _timeline_entry(401, "2026-04-09T20:31:10Z", "System Services", "Bomgar remote support service active"),
            _timeline_entry(402, "2026-04-12T02:50:03Z", "System Services", "Bomgar remote support service reconnected"),
        ],
        search_map={},
        artifact_queries=_ArtifactQueryStub(services=["bomgar remote support"]),
    )


def _capped_confidence_connector() -> _StubConnector:
    return _StubConnector(
        metadata={
            "date_range_start": "2026-04-01T00:00:00Z",
            "date_range_end": "2026-04-15T00:00:00Z",
        },
        artifact_counts=[
            {"artifact_type": "Windows Event Logs", "count": 120},
            {"artifact_type": "Edge Downloads", "count": 2},
            {"artifact_type": "$LogFile Analysis", "count": 10},
            {"artifact_type": "Text Documents", "count": 3},
            {"artifact_type": "LNK Files", "count": 2},
        ],
        timeline_entries=[
            _timeline_entry(501, "2026-04-12T02:50:03Z", "Windows Event Logs", "Event ID: 7045 Bomgar service installed"),
            _timeline_entry(502, "2026-04-12T02:55:25Z", "Text Documents", "Filename: READ_ME.txt"),
            _timeline_entry(503, "2026-04-12T02:55:49Z", "LNK Files", r"Linked Path: C:\Users\S\Desktop\READ_ME.txt"),
        ],
        search_map={},
        artifact_queries=_ArtifactQueryStub(services=["bomgar remote support"]),
    )


def test_initial_triage_prefers_window_first_and_delays_baseline_diff():
    result = initial_triage(_baro_like_connector())

    assert result["ok"] is True
    for key in (
        "anchor_days",
        "precursor_context",
        "window_discovery",
        "selected_scope",
        "case_health",
        "coverage_gate",
        "artifact_bundles",
        "anchoring_warnings",
        "analyst_tunable_params_used",
        "notes",
        "lane_evidence_summary",
    ):
        assert key in result

    # No verdict fields
    assert "classification" not in result
    assert "lane_state_board" not in result

    assert result["selected_scope"]["mode"] == "recent_14d"
    assert result["selected_scope"]["start_date"] == "2026-04-02"
    assert result["selected_scope"]["end_date"] == "2026-04-15"
    assert result["window_discovery"]["top_windows"]
    assert any("remote_admin_tool_exec" in window["matched_signals"] for window in result["window_discovery"]["top_windows"])
    assert result["precursor_context"]["baseline_diff_deferred"] is True
    assert result["precursor_context"]["status"] == "bridged_precursor"
    assert any(item["value"] == "bomgar remote support" for item in result["precursor_context"]["bridged_precursors"])


def test_initial_triage_lane_evidence_summary_shape():
    result = initial_triage(_baro_like_connector())

    les = result["lane_evidence_summary"]
    for lane in ("ingress_access", "execution_impact", "persistence_cleanup"):
        assert lane in les
        assert "artifact_families_seen" in les[lane]
        assert "event_count" in les[lane]
        assert isinstance(les[lane]["artifact_families_seen"], list)
        assert isinstance(les[lane]["event_count"], int)

    # Baro case has execution artifacts → event_count > 0 for execution_impact
    assert les["execution_impact"]["event_count"] > 0


def test_initial_triage_lane_evidence_summary_reports_missing_families():
    result = initial_triage(_persistence_only_connector(include_related_families=False))

    les = result["lane_evidence_summary"]
    assert les["ingress_access"]["event_count"] == 0
    assert les["ingress_access"]["artifact_families_seen"] == []


def test_initial_triage_coverage_gate_capped_confidence():
    result = initial_triage(_capped_confidence_connector())

    capped = {entry["claim"] for entry in result["coverage_gate"]["capped_confidence_claims"]}
    assert "overall_case_confidence" in capped
    # No verdict fields
    assert "allow_strong_conclusion" not in result
    assert "lane_state_board" not in result


def test_initial_triage_bridge_requires_incident_central_multi_axis_window():
    result = initial_triage(_low_confidence_bridge_connector())

    assert result["window_discovery"]["top_windows"]
    assert result["window_discovery"]["top_windows"][0]["status"] == "candidate"
    assert result["precursor_context"]["bridge_tokens"] == ["bomgar"]
    assert result["precursor_context"]["status"] == "candidate_bridge"
    assert result["precursor_context"]["bridged_precursors"]


def test_initial_triage_blocks_claims_when_core_families_are_missing():
    connector = _baro_like_connector()
    connector._artifact_counts = [
        {"artifact_type": "Windows Event Logs", "count": 5000},
        {"artifact_type": "Prefetch Files - Windows 8/10/11", "count": 35},
        {"artifact_type": "Text Documents", "count": 10},
    ]

    result = initial_triage(connector)

    gate = result["coverage_gate"]
    assert gate["statuses"]["mft_logfile_usn"] == "missing"
    assert gate["statuses"]["srum"] == "missing"
    assert "mass_file_modification_gate" in gate["blocked_claims"]
    assert "srum_network_coverage_gate" in gate["blocked_claims"]


def test_initial_triage_keeps_static_delta_as_candidate_when_no_windows_exist():
    artifact_queries = _ArtifactQueryStub(services=["bomgar remote support"], users=["S"])
    connector = _StubConnector(
        metadata={
            "date_range_start": "2026-04-01T00:00:00Z",
            "date_range_end": "2026-04-15T00:00:00Z",
        },
        artifact_counts=[
            {"artifact_type": "System Services", "count": 1},
        ],
        timeline_entries=[],
        search_map={},
        artifact_queries=artifact_queries,
    )

    result = initial_triage(connector)

    assert "classification" not in result
    assert result["window_discovery"]["top_windows"] == []
    assert result["precursor_context"]["status"] == "candidate_only"
    assert result["precursor_context"]["baseline_diff"]["total_net_new"] >= 1
