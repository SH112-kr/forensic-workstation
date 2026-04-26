"""Validation adapter for selected OTRF Security-Datasets JSON logs."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any


DEFAULT_SCENARIOS = {
    "otrf_psh_disable_eventlog_service.zip": {
        "dataset": "OTRF/Security-Datasets psh_disable_eventlog_service_startuptype_modification",
        "expected_rules": ["eventlog_service_registry_tamper"],
        "expected_tactic": "Defense Evasion",
        "expected_technique": "T1562.002",
    }
}


class OtrfJsonArtifactQueries:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def query_event_logs(
        self,
        event_ids: list[int] | None = None,
        eids: list[int] | None = None,
        provider: str = "",
        keyword_in_data: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        wanted = event_ids if event_ids is not None else eids
        out = list(self.rows)
        if wanted:
            wanted_text = {str(x) for x in wanted}
            out = [r for r in out if str(r.get("Event ID", "")) in wanted_text]
        if provider:
            needle = provider.lower()
            out = [r for r in out if needle in str(r.get("Provider Name", "")).lower()]
        if keyword_in_data:
            needle = keyword_in_data.lower()
            out = [r for r in out if needle in str(r.get("Event Data", "")).lower()]
        return out[: limit or len(out)]

    def query_process_creation_events(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.query_event_logs(event_ids=[4688, 1], limit=limit)

    def query_log_cleared(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.query_event_logs(event_ids=[1102, 104], limit=limit)

    def query_powershell_scriptblock(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.query_event_logs(event_ids=[4104], limit=limit)

    def query_prefetch(self, app_name_filter: str = "", limit: int = 100) -> list[dict[str, Any]]:
        return []


def load_otrf_zip(path: str | Path, *, max_rows: int = 20000) -> list[dict[str, Any]]:
    """Load JSONL rows from a selected OTRF zip without extracting binaries."""
    path = Path(path)
    rows: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json") and not n.startswith("__MACOSX/")]
        for name in names:
            with zf.open(name) as f:
                for idx, line in enumerate(f, start=1):
                    if not line.strip():
                        continue
                    raw = json.loads(line)
                    rows.append(_to_event_row(idx, raw, dataset_file=name))
                    if max_rows and len(rows) >= max_rows:
                        return rows
    return rows


def validate_otrf_scenario(zip_path: str | Path) -> dict[str, Any]:
    from core.analysis.anti_forensics import detect_anti_forensics

    rows = load_otrf_zip(zip_path)
    aq = OtrfJsonArtifactQueries(rows)
    result = detect_anti_forensics(aq)
    fired = [r.get("rule_name") for r in result.get("rules", []) if r.get("ok") and r.get("count")]
    expected = DEFAULT_SCENARIOS[Path(zip_path).name]["expected_rules"]
    missing = [rule for rule in expected if rule not in fired]
    return {
        "ok": not missing,
        "dataset": DEFAULT_SCENARIOS[Path(zip_path).name]["dataset"],
        "rows": len(rows),
        "expected_rules": expected,
        "fired_rules": fired,
        "missing_rules": missing,
        "anti_forensics": result,
        "safety": {
            "download_type": "zipped JSON event logs",
            "executables_extracted": False,
            "malware_samples_downloaded": False,
        },
    }


def _to_event_row(idx: int, raw: dict[str, Any], *, dataset_file: str) -> dict[str, Any]:
    message = str(raw.get("Message", ""))
    event_data = " ".join(str(v) for v in (
        message,
        raw.get("CommandLine", ""),
        raw.get("ProcessName", ""),
        raw.get("Image", ""),
        raw.get("ScriptBlockText", ""),
        raw.get("ObjectName", ""),
        raw.get("TargetObject", ""),
    ) if v)
    return {
        "hit_id": idx,
        "artifact_type": "Windows Event Logs",
        "Event ID": raw.get("EventID", ""),
        "Provider Name": raw.get("ProviderName") or raw.get("SourceName", ""),
        "Channel": raw.get("Channel", ""),
        "Computer": raw.get("Hostname", ""),
        "Created Date/Time - UTC (yyyy-mm-dd)": raw.get("TimeCreated") or raw.get("@timestamp", ""),
        "Event Data": event_data,
        "Event Description Summary": dataset_file,
        "CommandLine": raw.get("CommandLine", ""),
        "ProcessCommandLine": raw.get("CommandLine", ""),
    }
