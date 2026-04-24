"""Deterministic date-window triage anchors.

This module surfaces high-value raw anchors for a specified period without
inventing a verdict. The goal is to help an analyst or LLM start from
services, suspicious file drops, execution traces, and download/browser
artifacts before moving into broader narrative generation.
"""

from __future__ import annotations

from typing import Any


_SYSTEM_PATH_TOKENS = (
    "\\windows\\system32\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\appdata\\",
    "\\temp\\",
)

_SECTION_SPECS: list[dict[str, Any]] = [
    {
        "section_id": "service_and_autorun",
        "label": "Services and autoruns",
        "why_it_matters": "New or modified services, tasks, and autoruns are decisive anchors for persistence and service-hosted payloads.",
        "queries": [
            {"artifact_type": "System Services"},
            {"artifact_type": "Windows Event Logs - Service Events"},
            {"artifact_type": "Scheduled Tasks"},
            {"artifact_type": "AutoRun Items"},
            {"artifact_type": "Startup Items"},
        ],
    },
    {
        "section_id": "suspicious_file_drops",
        "label": "Suspicious file drops",
        "why_it_matters": "Executable or masquerading files in System32, ProgramData, Public, AppData, or Temp often anchor post-exploit payload placement.",
        "queries": [
            {"artifact_type": "File Signature Mismatch (Document)", "path_filter": "system_like"},
            {"artifact_type": "File Signature Mismatch (Container)", "path_filter": "system_like"},
            {"artifact_type": "NTFS Timestamp Mismatch", "path_filter": "system_like"},
            {"artifact_type": "Shim Cache", "path_filter": "system_like"},
        ],
    },
    {
        "section_id": "execution_and_scripts",
        "label": "Execution and script traces",
        "why_it_matters": "Execution artifacts help confirm what actually ran in the window and which paths or scripts deserve immediate validation.",
        "queries": [
            {"artifact_type": "Prefetch Files - Windows 8/10/11"},
            {"artifact_type": "UserAssist"},
            {"artifact_type": "AmCache File Entries"},
            {"artifact_type": "PowerShell History"},
            {"artifact_type": "Windows Event Logs - Script Events"},
        ],
    },
    {
        "section_id": "browser_and_downloads",
        "label": "Browser and download anchors",
        "why_it_matters": "Downloads, browser content, and recent visit artifacts provide the earliest visible hints of watering-hole or user-driven delivery.",
        "queries": [
            {"artifact_type": "Edge Downloads"},
            {"artifact_type": "Edge/Internet Explorer 10-11 Downloads"},
            {"artifact_type": "Edge/Internet Explorer 10-11 Main History"},
            {"artifact_type": "Potential Browser Activity"},
        ],
    },
]


def _looks_system_like(text: Any) -> bool:
    lowered = str(text or "").replace("/", "\\").lower()
    return any(token in lowered for token in _SYSTEM_PATH_TOKENS)


def _sample_hit(hit: dict[str, Any]) -> dict[str, Any]:
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    snippets: list[str] = []
    for key in (
        "Service Name",
        "Display Name",
        "Hosted Service",
        "File Path",
        "Full Path",
        "Path",
        "Application Name",
        "Application Path",
        "URL",
        "Download Location",
        "Title",
        "CommandLine",
    ):
        value = fields.get(key) if fields else None
        if value:
            snippets.append(f"{key}={value}")
        if len(snippets) >= 2:
            break

    if not snippets:
        for key in ("source_path", "artifact_type"):
            value = hit.get(key)
            if value:
                snippets.append(f"{key}={value}")

    return {
        "hit_id": hit.get("hit_id"),
        "artifact_type": hit.get("artifact_type", ""),
        "timestamp": hit.get("timestamp", ""),
        "source_path": hit.get("source_path", ""),
        "snippet": " | ".join(snippets),
    }


def _passes_path_filter(hit: dict[str, Any], mode: str) -> bool:
    if mode != "system_like":
        return True
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    values = [hit.get("source_path", "")]
    values.extend(fields.values())
    return any(_looks_system_like(v) for v in values)


def _run_query(
    connector: Any,
    artifact_type: str,
    start_date: str,
    end_date: str,
    limit: int,
    path_filter: str = "",
) -> dict[str, Any]:
    try:
        result = connector.search(
            keyword="",
            filters={
                "artifact_type": artifact_type,
                "start_date": start_date,
                "end_date": end_date,
            },
            limit=limit,
            offset=0,
        )
    except Exception as exc:
        return {
            "artifact_type": artifact_type,
            "total_hits": 0,
            "returned_hits": 0,
            "hits": [],
            "error": str(exc),
        }

    raw_hits = result.get("hits") or []
    kept_hits = [h for h in raw_hits if _passes_path_filter(h, path_filter)]
    return {
        "artifact_type": artifact_type,
        "total_hits": int(result.get("total", len(kept_hits)) or 0),
        "returned_hits": len(kept_hits),
        "hits": [_sample_hit(h) for h in kept_hits[:limit]],
    }


def date_anchor_triage(
    connector: Any,
    *,
    start_date: str = "",
    end_date: str = "",
    limit_per_query: int = 10,
) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    for spec in _SECTION_SPECS:
        query_results = [
            _run_query(
                connector,
                q["artifact_type"],
                start_date,
                end_date,
                limit_per_query,
                path_filter=q.get("path_filter", ""),
            )
            for q in spec["queries"]
        ]
        sections.append({
            "section_id": spec["section_id"],
            "label": spec["label"],
            "why_it_matters": spec["why_it_matters"],
            "total_hits": sum(int(q.get("returned_hits", 0) or 0) for q in query_results),
            "queries": query_results,
        })

    return {
        "ok": True,
        "period": {"start": start_date, "end": end_date},
        "sections": sections,
        "notes": [
            "This is a deterministic triage helper. It surfaces raw anchors only and does not assign intent or case centrality.",
            "Use service and file-drop anchors first when a narrow date window is known, then expand into full timeline and surrounding raw evidence.",
        ],
    }
