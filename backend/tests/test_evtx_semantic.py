from __future__ import annotations


def test_parse_event_xml_extracts_service_install_fields():
    from core.analysis.evtx_semantic import parse_event_xml

    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Service Control Manager"/>
        <EventID>7045</EventID>
        <TimeCreated SystemTime="2020-09-19T02:24:10.000Z"/>
        <Channel>System</Channel>
        <Computer>DC01</Computer>
      </System>
      <EventData>
        <Data Name="ServiceName">coreupdater</Data>
        <Data Name="ImagePath">C:\\Windows\\System32\\coreupdater.exe</Data>
        <Data Name="AccountName">LocalSystem</Data>
      </EventData>
    </Event>"""

    event = parse_event_xml(xml, source_file="System.evtx")

    assert event["event_id"] == 7045
    assert event["semantic"]["label"] == "service_install"
    assert event["fields"]["ServiceName"] == "coreupdater"
    assert event["fields"]["ImagePath"].endswith("coreupdater.exe")


def test_parse_event_xml_marks_type10_as_rdp_logon():
    from core.analysis.evtx_semantic import parse_event_xml

    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2020-09-19T02:21:00.000Z"/>
        <Channel>Security</Channel>
        <Computer>DC01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">Administrator</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="IpAddress">194.61.24.102</Data>
      </EventData>
    </Event>"""

    event = parse_event_xml(xml)

    assert event["semantic"]["label"] == "rdp_logon"
    assert event["semantic"]["lane"] == "ingress_access"
    assert event["fields"]["IpAddress"] == "194.61.24.102"


def test_summarize_semantic_events_counts_entities():
    from core.analysis.evtx_semantic import summarize_semantic_events

    summary = summarize_semantic_events([
        {
            "event_id": 4625,
            "semantic": {"label": "failed_logon"},
            "fields": {"TargetUserName": "Administrator", "IpAddress": "1.2.3.4"},
        },
        {
            "event_id": 4625,
            "semantic": {"label": "failed_logon"},
            "fields": {"TargetUserName": "Administrator", "IpAddress": "1.2.3.4"},
        },
    ])

    assert summary["semantic_counts"]["failed_logon"] == 2
    assert ("TargetUserName:Administrator", 2) in summary["top_entities"]
