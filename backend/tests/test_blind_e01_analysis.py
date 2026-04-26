from regression.blind_e01_analysis import (
    _actor_from_internal_path,
    _build_integrated_timeline,
    _chrome_time,
    _classify_service_install,
    _dedupe_internal_paths,
    _parse_teamviewer_connections,
)


def test_chrome_time_converts_webkit_microseconds():
    assert _chrome_time(13197589122240965) == "2019-03-20T20:58:42.240965Z"


def test_dedupe_internal_paths_collapses_documents_and_settings_alias():
    paths = [
        "/c:/Documents and Settings/Alice/AppData/Local/Google/Chrome/User Data/Default/History",
        "/c:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History",
    ]

    assert _dedupe_internal_paths(paths) == [paths[0]]


def test_parse_teamviewer_connections_incoming_rows():
    text = (
        "1222215886\tJHYDE-SP\t18-03-2019 18:34:18\t18-03-2019 18:36:43\t"
        "SelmaBouvier\tRemoteControl\t{GUID}\t\r\n"
    )

    rows = _parse_teamviewer_connections(text)

    assert rows == [
        {
            "teamviewer_id": "1222215886",
            "remote_host": "JHYDE-SP",
            "start_local": "18-03-2019 18:34:18",
            "end_local": "18-03-2019 18:36:43",
            "user": "SelmaBouvier",
            "mode": "RemoteControl",
            "session_guid": "{GUID}",
        }
    ]


def test_actor_from_internal_path_extracts_user_profile():
    assert _actor_from_internal_path("/c:/Users/SelmaBouvier/AppData/Local/Google/Chrome/User Data/Default/History") == "SelmaBouvier"


def test_build_integrated_timeline_keeps_prefetch_pending():
    timeline = _build_integrated_timeline(
        evtx={"interesting_events": []},
        browser={"parsed": []},
        remote_access={
            "parsed": [
                {
                    "internal_path": "/c:/Program Files/TeamViewer/Connections_incoming.txt",
                    "connections": [
                        {
                            "teamviewer_id": "1222215886",
                            "remote_host": "JHYDE-SP",
                            "start_local": "18-03-2019 18:34:18",
                            "end_local": "18-03-2019 18:36:43",
                            "user": "SelmaBouvier",
                            "mode": "RemoteControl",
                            "session_guid": "{GUID}",
                        }
                    ],
                }
            ]
        },
        prefetch={
            "notable_prefetch": [
                {
                    "source_path": "/c:/Windows/Prefetch/TEAMVIEWER_DESKTOP.EXE-ABC.pf",
                    "executable_name": "TEAMVIEWER_DESKTOP.EXE",
                    "run_count": 3,
                    "last_run_times_utc": ["2019-03-18T18:34:19Z"],
                    "evidence_state": "pending_corroboration",
                }
            ]
        },
    )

    assert timeline["summary"]["event_count"] == 3
    prefetch_events = [event for event in timeline["events"] if event["source_artifact"] == "prefetch"]
    assert prefetch_events[0]["corroboration_state"] == "pending_corroboration"
    assert timeline["chains"][0]["corroboration_state"] == "candidate_chain"


def test_service_install_classification_separates_platform_noise_from_followup():
    assert _classify_service_install({
        "ServiceName": "Microsoft Streaming Clock Proxy",
        "ImagePath": "\\SystemRoot\\system32\\drivers\\MSPCLOCK.sys",
        "ServiceType": "kernel mode driver",
    }) == "likely_system_driver"

    assert _classify_service_install({
        "ServiceName": "coreupdater",
        "ImagePath": "C:\\Windows\\System32\\coreupdater.exe",
        "ServiceType": "user mode service",
    }) == "system32_executable_service_needs_context"

    assert _classify_service_install({
        "ServiceName": "updater",
        "ImagePath": "C:\\Users\\Public\\updater.exe",
        "ServiceType": "user mode service",
    }) == "unusual_service_path"
