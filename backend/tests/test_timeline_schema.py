from core.analysis.timeline_schema import build_timeline_chains, make_timeline_event, sort_timeline_events, summarize_timeline


def test_timeline_event_keeps_confidence_and_corroboration():
    event = make_timeline_event(
        event_time="2019-03-18T18:34:19Z",
        event_time_type="prefetch_last_run",
        source_artifact="prefetch",
        sequence_role="execution",
        object="TEAMVIEWER_DESKTOP.EXE",
        confidence="strong",
        corroboration_state="pending_corroboration",
    )

    assert event["event_time_type"] == "prefetch_last_run"
    assert event["confidence"] == "strong"
    assert event["corroboration_state"] == "pending_corroboration"


def test_sort_timeline_events_orders_iso_and_local_times():
    later = make_timeline_event(
        event_time="2019-03-18T18:36:49Z",
        event_time_type="prefetch_last_run",
        source_artifact="prefetch",
        sequence_role="execution",
    )
    earlier = make_timeline_event(
        event_time="18-03-2019 18:34:18",
        event_time_type="teamviewer_session_start_local",
        source_artifact="remote_access_log",
        sequence_role="remote_access",
        timezone_note="local_or_unknown",
    )

    assert sort_timeline_events([later, earlier]) == [earlier, later]


def test_timeline_summary_and_candidate_chain_do_not_claim_causation():
    events = [
        make_timeline_event(
            event_time="2019-03-18T18:34:19Z",
            event_time_type="prefetch_last_run",
            source_artifact="prefetch",
            sequence_role="execution",
            object="TEAMVIEWER_DESKTOP.EXE",
            corroboration_state="pending_corroboration",
        ),
        make_timeline_event(
            event_time="18-03-2019 18:34:18",
            event_time_type="teamviewer_session_start_local",
            source_artifact="remote_access_log",
            sequence_role="remote_access",
            object="TeamViewer RemoteControl",
            timezone_note="local_or_unknown",
            corroboration_state="source_observed",
        ),
    ]

    summary = summarize_timeline(events)
    chains = build_timeline_chains(events, window_seconds=120)

    assert summary["sequence_role_counts"] == {"execution": 1, "remote_access": 1}
    assert chains[0]["corroboration_state"] == "candidate_chain"
    assert "not a final causal proof" in chains[0]["notes"]
