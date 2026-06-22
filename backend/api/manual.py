"""Analyst-only manual workbench API.

This module starts with a small status contract. Heavier manual lanes should be
added as separate, tested slices so the workbench does not become another
monolithic endpoint surface.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import re
import tempfile
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.connectors.e01_image import E01ImageConnector
from state import resolve_image_evidence

router = APIRouter(prefix="/api/manual", tags=["manual"])

_MANUAL_E01: E01ImageConnector | None = None
_MANUAL_E01_PATH = ""


class AdsInfoRequest(BaseModel):
    host_path: str
    stream_name: str
    include_hash: bool = True
    hash_max_bytes: int = 32 * 1024 * 1024
    include_pe: bool = True
    pe_max_bytes: int = 64 * 1024 * 1024


class FileInfoRequest(BaseModel):
    internal_path: str
    include_hash: bool = True
    hash_max_bytes: int = 32 * 1024 * 1024
    include_pe: bool = True
    pe_max_bytes: int = 64 * 1024 * 1024


class FileBrowseRequest(BaseModel):
    path: str = "/c:/"
    limit: int = 300


class FileSearchRequest(BaseModel):
    path: str = "/c:/"
    pattern: str = "*"
    keyword: str = ""
    recursive: bool = True
    limit: int = 300


class VssFileSearchRequest(BaseModel):
    snapshot_id: str
    volume: str = "/c:"
    path: str = "/c:/"
    pattern: str = "*"
    keyword: str = ""
    recursive: bool = True
    limit: int = 300


class EvtxQueryRequest(BaseModel):
    evtx_path: str
    event_ids: str = ""
    keyword: str = ""
    start_date: str = ""
    end_date: str = ""
    limit: int = 200
    offset: int = 0
    parse_limit: int = 5000


class PrefetchQueryRequest(BaseModel):
    directory: str = "/c:/Windows/Prefetch"
    pattern: str = "*.pf"
    keyword: str = ""
    start_date: str = ""
    end_date: str = ""
    limit: int = 200
    offset: int = 0
    source_limit: int = 1000


class RegistryQueryRequest(BaseModel):
    hive_path: str = "/c:/Windows/System32/config/SYSTEM"
    key_path: str = ""
    keyword: str = ""
    search_root: str = ""
    limit: int = 100
    offset: int = 0
    max_scan_keys: int = 10000


def _manual_guardrails() -> list[str]:
    return [
        "Manual Workbench is analyst-facing only; results are not automatically ingested into LLM context.",
        "Manual findings are leads and context, not verdicts.",
        "Zero results are coverage observations, not evidence of absence.",
        "Extracted files must remain static-analysis only and must never be executed.",
    ]


def _ads_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "ADS inspection reads the named stream content from the evidence image for static analysis only.",
        "ADS metadata and content hashes do not prove execution, compromise, maliciousness, or benignness.",
    ]


def _vss_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "VSS snapshots are historical layers, not verified-clean baselines.",
        "Keep VSS evidence separate from current filesystem evidence unless a report explicitly compares both layers.",
    ]


def _files_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "Current filesystem file search is bounded by analyst-selected path, pattern, and limit.",
        "File presence and metadata do not prove execution, maliciousness, or benignness.",
    ]


def _registry_evtx_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "EVTX query parses offline event-log copies from the captured image; it does not query the live host.",
        "Registry state proves captured hive contents and configuration state, not execution or actor intent.",
        "Low or zero query results are coverage observations, not evidence of absence.",
    ]


def _execution_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "Execution source discovery lists parser inputs only; it does not parse or prove execution.",
        "AmCache, BAM/DAM, UserAssist, and ShimCache leads require corroboration before incident conclusions.",
    ]


def _browser_recent_guardrails() -> list[str]:
    return [
        *_manual_guardrails(),
        "Browser and Recent discovery lists sensitive user-activity source files only.",
        "History databases, LNK files, and JumpLists are context leads; corroborate with downloads, file timestamps, execution artifacts, and network evidence.",
    ]


def _get_manual_e01() -> tuple[E01ImageConnector, str]:
    global _MANUAL_E01, _MANUAL_E01_PATH

    resolved = resolve_image_evidence("")
    image_path = str(resolved.get("path") or "")
    if not image_path:
        raise HTTPException(status_code=400, detail="No selected E01/raw image is available for manual workbench.")

    if _MANUAL_E01 is not None and _MANUAL_E01_PATH == image_path:
        return _MANUAL_E01, image_path

    conn = E01ImageConnector()
    conn.connect(image_path)
    _MANUAL_E01 = conn
    _MANUAL_E01_PATH = image_path
    return conn, image_path


async def _run_manual_io(fn, *args):
    return await asyncio.to_thread(fn, *args)


@router.get("/status")
async def manual_status() -> dict:
    resolved = resolve_image_evidence("")
    selected_image = str(resolved.get("path") or "")
    selected_source = str(resolved.get("source") or "")

    guardrails = _manual_guardrails()
    if not selected_image:
        guardrails = [
            "No selected image is available for manual workbench lanes.",
            *guardrails,
        ]

    return {
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "selected_image": selected_image,
        "selected_image_source": selected_source,
        "connected": bool(selected_image),
        "guardrails": guardrails,
        "lanes": [
            "overview",
            "files",
            "vss",
            "ads_pe",
            "registry_evtx",
            "execution",
            "browser_recent",
            "jobs",
        ],
    }


@router.post("/ads/info")
async def ads_info(req: AdsInfoRequest) -> dict:
    return await _run_manual_io(_ads_info_sync, req)


@router.post("/files/info")
async def file_info(req: FileInfoRequest) -> dict:
    return await _run_manual_io(_file_info_sync, req)


@router.post("/files/browse")
async def browse_files(req: FileBrowseRequest) -> dict:
    return await _run_manual_io(_browse_files_sync, req)


@router.post("/files/search")
async def search_files(req: FileSearchRequest) -> dict:
    return await _run_manual_io(_search_files_sync, req)


@router.get("/evtx/files")
async def list_evtx_files(path: str = "/c:/Windows/System32/winevt/Logs", limit: int = 800) -> dict:
    return await _run_manual_io(_list_evtx_files_sync, path, limit)


@router.get("/registry/hives")
async def list_registry_hives() -> dict:
    return await _run_manual_io(_list_registry_hives_sync)


@router.post("/evtx/query")
async def query_evtx(req: EvtxQueryRequest) -> dict:
    return await _run_manual_io(_query_evtx_sync, req)


@router.post("/registry/query")
async def query_registry(req: RegistryQueryRequest) -> dict:
    return await _run_manual_io(_query_registry_sync, req)


@router.get("/execution/sources")
async def execution_sources(limit: int = 80) -> dict:
    return await _run_manual_io(_execution_sources_sync, limit)


@router.post("/prefetch/query")
async def query_prefetch(req: PrefetchQueryRequest) -> dict:
    return await _run_manual_io(_query_prefetch_sync, req)


@router.get("/browser-recent/sources")
async def browser_recent_sources(limit: int = 120) -> dict:
    return await _run_manual_io(_browser_recent_sources_sync, limit)


@router.get("/jobs/status")
async def manual_jobs_status() -> dict:
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "source": "manual_workbench_jobs",
        "mode": "sync_direct",
        "active_job_count": 0,
        "jobs": [],
        "coverage_notes": [
            "Current absorbed manual lanes run in synchronous direct mode with no background job queue.",
            "Long-running H project job queues can be added later behind this status surface.",
        ],
        "guardrails": _manual_guardrails(),
    }


@router.get("/vss/snapshots")
async def list_manual_vss_snapshots(volume: str = "/c:") -> dict:
    return await _run_manual_io(_list_manual_vss_snapshots_sync, volume)


@router.post("/vss/files/search")
async def search_vss_files(req: VssFileSearchRequest) -> dict:
    return await _run_manual_io(_search_vss_files_sync, req)


def _ads_info_sync(req: AdsInfoRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    host_path = req.host_path.strip()
    stream_name = req.stream_name.strip()
    if not host_path:
        raise HTTPException(status_code=400, detail="host_path is required.")
    if not stream_name:
        raise HTTPException(status_code=400, detail="stream_name is required.")

    info = e01.get_alternate_data_stream_info(host_path, stream_name)
    ads_path = info.get("ads_path") or f"{host_path}:{stream_name}"
    result: dict[str, Any] = {
        "ok": "error" not in info,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "alternate_data_stream",
        "host_path": host_path,
        "stream_name": stream_name,
        "ads_path": ads_path,
        "info": info,
        "hashes": {},
        "hash_status": "not_requested" if not req.include_hash else "pending",
        "pe": {},
        "pe_status": "not_requested" if not req.include_pe else "pending",
        "coverage_notes": [
            "ADS inspection reads the named stream content from the evidence image for static analysis only.",
            "ADS payload metadata does not prove execution; corroborate with Prefetch, SRUM, EVTX, AmCache/BAM, and timestamps.",
        ],
        "guardrails": _ads_guardrails(),
    }
    if "error" in info:
        result["hash_status"] = "not_evaluable" if req.include_hash else "not_requested"
        result["pe_status"] = "not_evaluable" if req.include_pe else "not_requested"
        return result

    size = int(info.get("size") if isinstance(info.get("size"), int) else -1)
    content_cache: bytes | None = None

    def read_content(max_size: int) -> bytes:
        nonlocal content_cache
        if content_cache is None or len(content_cache) < max_size:
            content_cache = e01.read_alternate_data_stream_content(host_path, stream_name, max_size=max_size)
        return content_cache[:max_size]

    if req.include_hash:
        hash_max = max(0, min(int(req.hash_max_bytes or 0), 512 * 1024 * 1024))
        if size < 0:
            result["hash_status"] = "skipped_unknown_size"
        elif size > hash_max:
            result["hash_status"] = "skipped_size_limit"
            result["hash_limit_bytes"] = hash_max
            result["coverage_notes"].append("Hashing was skipped because the ADS stream exceeds the requested manual hash limit.")
        else:
            data = read_content(size)
            result["hashes"] = {
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identifier, not security control
                "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identifier, not security control
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            result["hash_status"] = "complete" if len(data) == size else "partial_read"

    if req.include_pe:
        pe_max = max(0, min(int(req.pe_max_bytes or 0), 512 * 1024 * 1024))
        if size < 0:
            result["pe_status"] = "skipped_unknown_size"
        elif size > pe_max:
            result["pe_status"] = "skipped_size_limit"
            result["pe_limit_bytes"] = pe_max
            result["coverage_notes"].append("PE triage was skipped because the ADS stream exceeds the requested manual PE limit.")
        else:
            data = read_content(size)
            if data[:2] == b"MZ":
                result["pe_status"] = "pe_header_detected"
                result["pe"] = {
                    "is_pe": True,
                    "path": ads_path,
                    "source_kind": "ads_stream",
                    "header": "MZ",
                    "interpretation": "Header-only PE triage. Full static metadata is a later manual workbench slice.",
                }
            else:
                result["pe_status"] = "not_pe"
                result["pe"] = {
                    "is_pe": False,
                    "reason": "missing_mz_header",
                    "source_kind": "ads_stream",
                    "path": ads_path,
                }
            result["coverage_notes"].append("PE static triage is metadata/capability context only. It does not prove execution, load, maliciousness, or benignness.")

    return result


def _file_info_sync(req: FileInfoRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    internal_path = req.internal_path.strip()
    if not internal_path:
        raise HTTPException(status_code=400, detail="internal_path is required.")

    info = e01.get_file_info(internal_path)
    result: dict[str, Any] = {
        "ok": isinstance(info, dict) and "error" not in info,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "current_file",
        "internal_path": internal_path,
        "info": info,
        "hashes": {},
        "hash_status": "not_requested" if not req.include_hash else "pending",
        "pe": {},
        "pe_status": "not_requested" if not req.include_pe else "pending",
        "coverage_notes": [
            "File static triage reads captured file bytes for static analysis only.",
            "File hash, metadata, and PE header status do not prove execution, maliciousness, or benignness.",
        ],
        "guardrails": _files_guardrails(),
    }
    if not isinstance(info, dict) or "error" in info:
        result["hash_status"] = "not_evaluable" if req.include_hash else "not_requested"
        result["pe_status"] = "not_evaluable" if req.include_pe else "not_requested"
        return result

    size = int(info.get("size") if isinstance(info.get("size"), int) else -1)
    content_cache: bytes | None = None

    def read_content(max_size: int) -> bytes:
        nonlocal content_cache
        if content_cache is None or len(content_cache) < max_size:
            content_cache = e01.read_file_content(internal_path, max_size=max_size)
        return content_cache[:max_size]

    if req.include_hash:
        hash_max = max(0, min(int(req.hash_max_bytes or 0), 512 * 1024 * 1024))
        if size < 0:
            result["hash_status"] = "skipped_unknown_size"
        elif size > hash_max:
            result["hash_status"] = "skipped_size_limit"
            result["hash_limit_bytes"] = hash_max
            result["coverage_notes"].append("Hashing was skipped because the file exceeds the requested manual hash limit.")
        else:
            data = read_content(size)
            result["hashes"] = {
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identifier, not security control
                "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identifier, not security control
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            result["hash_status"] = "complete" if len(data) == size else "partial_read"

    if req.include_pe:
        pe_max = max(0, min(int(req.pe_max_bytes or 0), 512 * 1024 * 1024))
        if size < 0:
            result["pe_status"] = "skipped_unknown_size"
        elif size > pe_max:
            result["pe_status"] = "skipped_size_limit"
            result["pe_limit_bytes"] = pe_max
            result["coverage_notes"].append("PE triage was skipped because the file exceeds the requested manual PE limit.")
        else:
            data = read_content(size)
            if data[:2] == b"MZ":
                result["pe_status"] = "pe_header_detected"
                result["pe"] = {
                    "is_pe": True,
                    "path": internal_path,
                    "source_kind": "current_file",
                    "header": "MZ",
                    "interpretation": "Header-only PE triage. Full static metadata is a later manual workbench slice.",
                }
            else:
                result["pe_status"] = "not_pe"
                result["pe"] = {
                    "is_pe": False,
                    "reason": "missing_mz_header",
                    "source_kind": "current_file",
                    "path": internal_path,
                }
            result["coverage_notes"].append("PE static triage is metadata/capability context only. It does not prove execution, load, maliciousness, or benignness.")

    return result


def _normalize_vss_volume(volume: str) -> str:
    text = str(volume or "/c:").strip().replace("\\", "/")
    if not text:
        return "/c:"
    if not text.startswith("/"):
        text = f"/{text}"
    if len(text) == 2 and text[1] == ":":
        text = f"{text[0].lower()}:"
    return text.lower()


def _browse_files_sync(req: FileBrowseRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    root = (req.path or "/c:/").strip() or "/c:/"
    safe_limit = max(1, min(int(req.limit or 300), 2000))
    rows = _filter_manual_file_rows(e01.list_directory(root), pattern="*", keyword="", limit=safe_limit)
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "current_filesystem",
        "searched": {
            "path": root,
            "pattern": "*",
            "keyword": "",
            "recursive": False,
            "limit": safe_limit,
        },
        "returned": len(rows),
        "files": rows,
        "coverage_notes": [
            "Current filesystem browsing reads the captured image layer, not the live host.",
            "Low or zero entries are path/permission/parser observations, not evidence of absence across the whole image.",
        ],
        "guardrails": _files_guardrails(),
    }


def _search_files_sync(req: FileSearchRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    safe_limit = max(1, min(int(req.limit or 300), 2000))
    root = (req.path or "/c:/").strip() or "/c:/"
    pattern = (req.pattern or "*").strip() or "*"
    keyword = (req.keyword or "").strip()
    effective_pattern = f"*{keyword}*" if keyword and pattern == "*" else pattern

    if req.recursive:
        rows = e01.find_files(effective_pattern, path=root, limit=safe_limit)
        if keyword:
            rows = _filter_manual_file_rows(rows, pattern="*", keyword=keyword, limit=safe_limit)
    else:
        rows = _filter_manual_file_rows(
            e01.list_directory(root),
            pattern=effective_pattern,
            keyword=keyword,
            limit=safe_limit,
        )

    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "current_filesystem",
        "searched": {
            "path": root,
            "pattern": effective_pattern,
            "keyword": keyword,
            "recursive": bool(req.recursive),
            "limit": safe_limit,
        },
        "returned": len(rows),
        "files": rows,
        "coverage_notes": [
            "Current filesystem search is bounded by path, pattern, recursive mode, and limit.",
            "Low or zero matches are not evidence of absence for the whole image.",
            "File presence is context only; corroborate execution with Prefetch, SRUM, EVTX, AmCache/BAM, and timestamps.",
        ],
        "guardrails": _files_guardrails(),
    }


def _list_evtx_files_sync(path: str = "/c:/Windows/System32/winevt/Logs", limit: int = 800) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    root = (path or "/c:/Windows/System32/winevt/Logs").strip() or "/c:/Windows/System32/winevt/Logs"
    safe_limit = max(1, min(int(limit or 800), 2000))
    rows = e01.find_files("*.evtx", path=root, limit=safe_limit)
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "evtx_file_discovery",
        "searched": {
            "path": root,
            "pattern": "*.evtx",
            "limit": safe_limit,
        },
        "returned": len(rows),
        "files": rows,
        "coverage_notes": [
            "Event log file presence identifies candidate EVTX sources, not parsed event activity.",
            "Missing or unreadable EVTX files are coverage observations, not proof that events never occurred.",
        ],
        "guardrails": _registry_evtx_guardrails(),
    }


def _list_registry_hives_sync() -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    candidates = [
        ("SYSTEM", "/c:/Windows/System32/config/SYSTEM"),
        ("SOFTWARE", "/c:/Windows/System32/config/SOFTWARE"),
        ("SAM", "/c:/Windows/System32/config/SAM"),
        ("SECURITY", "/c:/Windows/System32/config/SECURITY"),
        ("DEFAULT", "/c:/Windows/System32/config/DEFAULT"),
        ("Amcache", "/c:/Windows/AppCompat/Programs/Amcache.hve"),
    ]
    hives: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    for name, path in candidates:
        info = e01.get_file_info(path)
        row = {"name": name, "path": path, "info": info}
        if isinstance(info, dict) and "error" not in info:
            row["size"] = info.get("size", -1)
            row["modified"] = info.get("modified", "")
            hives.append(row)
        else:
            missing.append({"name": name, "path": path, "error": str(info.get("error", "not found")) if isinstance(info, dict) else "not found"})
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "registry_hive_discovery",
        "returned": len(hives),
        "hives": hives,
        "missing": missing,
        "coverage_notes": [
            "Registry hive discovery identifies candidate configuration state sources.",
            "Registry state proves captured hive contents, not execution or actor intent.",
            "User hives under profile directories are not included in this core-hive discovery slice.",
        ],
        "guardrails": _registry_evtx_guardrails(),
    }


def _query_evtx_sync(req: EvtxQueryRequest) -> dict[str, Any]:
    path = (req.evtx_path or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="evtx_path is required.")
    safe_limit = max(0, min(int(req.limit or 0), 1000))
    safe_offset = max(0, int(req.offset or 0))
    safe_parse_limit = max(1, min(int(req.parse_limit or 5000), 50000))
    try:
        event_ids = _parse_manual_event_ids(req.event_ids)
    except ValueError as exc:
        return _manual_error_result(
            "evtx_query",
            str(exc),
            coverage_notes=_evtx_query_coverage_notes(),
            query_semantics={"event_ids": req.event_ids},
        )

    e01, image_path = _get_manual_e01()
    with tempfile.TemporaryDirectory(prefix="fw_manual_evtx_") as tmpdir:
        local_path, materialized = _materialize_manual_artifact(e01, path, tmpdir, "evtx")
        if not local_path or materialized.get("error"):
            return _manual_error_result(
                "evtx_query",
                str(materialized.get("error") or "Unable to materialize EVTX file."),
                image_path=image_path,
                input_source=str(materialized.get("source") or "mounted_image"),
                coverage_notes=_evtx_query_coverage_notes(),
            )

        target_ids = event_ids or set(range(0, 65536))
        parsed = _parse_manual_evtx_file(local_path, target_ids, safe_parse_limit)
        parser_failures = (parsed.get("parser_failures", []) or []) + (
            (parsed.get("recovery", {}) or {}).get("parser_failures", []) or []
        )
        if not parsed.get("ok"):
            return {
                "ok": False,
                "analyst_only": True,
                "llm_auto_ingest": False,
                "mcp_event_log": False,
                "auto_ioc_graph": False,
                "source": "evtx_query",
                "input_source": str(materialized.get("source") or "mounted_image"),
                "image_path": image_path,
                "evtx_path": path,
                "parsed_record_count": 0,
                "event_id_counts_in_sample": {},
                "parser_backend": parsed.get("parser_backend", ""),
                "parser_failures": parser_failures,
                "recovery": parsed.get("recovery", {}),
                "filtered": {
                    "total": 0,
                    "returned": 0,
                    "records": [],
                    "truncated": False,
                },
                "coverage_notes": [
                    *_evtx_query_coverage_notes(),
                    "The parser could not produce records from this offline EVTX sample; inspect parser_failures and recovery metadata before interpreting the result.",
                ],
                "guardrails": _registry_evtx_guardrails(),
            }

        filtered = _filter_manual_evtx_records(
            parsed.get("records", []) or [],
            event_ids=event_ids or None,
            keyword=req.keyword,
            start_date=req.start_date,
            end_date=req.end_date,
            limit=safe_limit,
            offset=safe_offset,
        )
        return {
            "ok": True,
            "analyst_only": True,
            "llm_auto_ingest": False,
            "mcp_event_log": False,
            "auto_ioc_graph": False,
            "source": "evtx_query",
            "input_source": str(materialized.get("source") or "mounted_image"),
            "image_path": image_path,
            "evtx_path": path,
            "local_cache_status": "temporary_static_analysis_copy_removed_after_parse",
            "parsed_record_count": int(parsed.get("record_count", 0) or 0),
            "event_id_counts_in_sample": parsed.get("event_id_counts", {}),
            "parser_backend": parsed.get("parser_backend", ""),
            "parser_failures": parser_failures,
            "recovery": parsed.get("recovery", {}),
            "parse_limit": safe_parse_limit,
            "filtered": filtered,
            "coverage_notes": _evtx_query_coverage_notes(),
            "guardrails": _registry_evtx_guardrails(),
        }


def _query_registry_sync(req: RegistryQueryRequest) -> dict[str, Any]:
    hive_path = (req.hive_path or "").strip()
    key_path = (req.key_path or "").strip()
    keyword = (req.keyword or "").strip()
    search_root = (req.search_root or "").strip()
    if not hive_path:
        raise HTTPException(status_code=400, detail="hive_path is required.")
    if keyword and not search_root and not key_path:
        return _manual_error_result(
            "registry_query",
            "keyword search requires search_root or key_path to avoid whole-hive scans and false confidence from timed-out scans",
            coverage_notes=_registry_query_coverage_notes(),
            query_semantics={
                "keyword": keyword,
                "search_root_required": True,
                "recommended_examples": [
                    r"\ControlSet001\Services",
                    r"\Microsoft\Windows\CurrentVersion\Run",
                ],
            },
        )
    if not key_path and not keyword:
        return _manual_error_result(
            "registry_query",
            "Provide key_path for direct extraction or keyword plus search_root for bounded search.",
            coverage_notes=_registry_query_coverage_notes(),
        )

    safe_limit = max(0, min(int(req.limit or 0), 1000))
    safe_offset = max(0, int(req.offset or 0))
    safe_max_scan = max(1, min(int(req.max_scan_keys or 10000), 250000))
    e01, image_path = _get_manual_e01()
    with tempfile.TemporaryDirectory(prefix="fw_manual_reg_") as tmpdir:
        local_hive, materialized = _materialize_manual_artifact(e01, hive_path, tmpdir, "registry")
        if not local_hive or materialized.get("error"):
            return _manual_error_result(
                "registry_query",
                str(materialized.get("error") or "Unable to materialize registry hive."),
                image_path=image_path,
                input_source=str(materialized.get("source") or "mounted_image"),
                coverage_notes=_registry_query_coverage_notes(),
            )

        connector = _registry_connector()
        metadata = connector.connect(local_hive)
        try:
            if key_path:
                resolved_key = _normalize_manual_registry_key_path(key_path, local_hive)
                result = connector.get_key(resolved_key)
                result.update({
                    "ok": "error" not in result,
                    "analyst_only": True,
                    "llm_auto_ingest": False,
                    "mcp_event_log": False,
                    "auto_ioc_graph": False,
                    "source": "registry_query",
                    "query_mode": "key",
                    "input_source": str(materialized.get("source") or "mounted_image"),
                    "image_path": image_path,
                    "hive_path": hive_path,
                    "resolved_key_path": resolved_key,
                    "hive_metadata": metadata,
                    "local_cache_status": "temporary_static_analysis_copy_removed_after_parse",
                    "coverage_notes": _registry_query_coverage_notes(),
                    "guardrails": _registry_evtx_guardrails(),
                })
                return result

            resolved_root = _normalize_manual_registry_key_path(search_root, local_hive)
            result = _search_manual_registry_subtree(
                local_hive,
                resolved_root,
                keyword,
                limit=safe_limit,
                offset=safe_offset,
                max_scan_keys=safe_max_scan,
            )
            result.update({
                "ok": "error" not in result,
                "analyst_only": True,
                "llm_auto_ingest": False,
                "mcp_event_log": False,
                "auto_ioc_graph": False,
                "source": "registry_query",
                "query_mode": "keyword",
                "input_source": str(materialized.get("source") or "mounted_image"),
                "image_path": image_path,
                "hive_path": hive_path,
                "hive_metadata": metadata,
                "local_cache_status": "temporary_static_analysis_copy_removed_after_parse",
                "query_semantics": {
                    "keyword": keyword,
                    "search_root": search_root,
                    "resolved_search_root": resolved_root,
                    "limit": safe_limit,
                    "offset": safe_offset,
                    "max_scan_keys": safe_max_scan,
                    "whole_hive_scan_allowed": False,
                },
                "coverage_notes": _registry_query_coverage_notes(),
                "guardrails": _registry_evtx_guardrails(),
            })
            return result
        finally:
            connector.disconnect()


def _query_prefetch_sync(req: PrefetchQueryRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    directory = (req.directory or "/c:/Windows/Prefetch").strip() or "/c:/Windows/Prefetch"
    pattern = (req.pattern or "*.pf").strip() or "*.pf"
    keyword = (req.keyword or "").strip().lower()
    safe_limit = max(0, min(int(req.limit or 0), 1000))
    safe_offset = max(0, int(req.offset or 0))
    source_limit = max(1, min(int(req.source_limit or 1000), 5000))

    found = _prefetch_candidate_files(e01, directory, pattern, source_limit)
    parsed: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for item in found:
        internal_path = str(item.get("path", "") or "")
        if not internal_path or item.get("is_dir"):
            continue
        try:
            parsed_item = _parse_manual_prefetch_bytes(
                e01.read_file_content(internal_path, max_size=4 * 1024 * 1024),
                source_path=internal_path,
            )
            if parsed_item.get("ok"):
                parsed.append(parsed_item)
            else:
                failures.append({"path": internal_path, "error": parsed_item.get("error", "parse_failed")})
        except Exception as exc:  # noqa: BLE001
            failures.append({"path": internal_path, "error": str(exc)})

    matched: list[dict[str, Any]] = []
    for item in parsed:
        latest = str(item.get("latest_run_time_utc", "") or "")
        day = latest[:10]
        if req.start_date and day and day < req.start_date:
            continue
        if req.end_date and day and day > req.end_date:
            continue
        if keyword:
            haystack = " ".join([
                str(item.get("executable_name", "")),
                str(item.get("source_path", "")),
                " ".join(str(path) for path in item.get("raw_referenced_paths", [])[:50]),
            ]).lower()
            if keyword not in haystack:
                continue
        matched.append(item)

    matched.sort(key=lambda item: str(item.get("latest_run_time_utc", "")), reverse=True)
    page = matched[safe_offset:safe_offset + safe_limit] if safe_limit else matched[safe_offset:]
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "source": "prefetch_query",
        "image_path": image_path,
        "searched": {
            "directory": directory,
            "pattern": pattern,
            "keyword": req.keyword,
            "source_path_count": len(found),
            "source_limit": source_limit,
        },
        "total": len(matched),
        "returned": len(page),
        "offset": safe_offset,
        "limit": safe_limit,
        "truncated": safe_offset + len(page) < len(matched),
        "entries": page,
        "parse_failures": failures[:50],
        "parse_failure_count": len(failures),
        "coverage_notes": _prefetch_query_coverage_notes(),
        "guardrails": _prefetch_guardrails(),
    }


def _execution_sources_sync(limit: int = 80) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    safe_limit = max(1, min(int(limit or 80), 500))
    sources: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []

    static_sources = [
        ("AmCache", "/c:/Windows/AppCompat/Programs/Amcache.hve", "amcache"),
        ("SYSTEM hive", "/c:/Windows/System32/config/SYSTEM", "bam_shimcache"),
    ]
    for label, path, kind in static_sources:
        info = e01.get_file_info(path)
        row = {"name": label, "path": path, "kind": kind, "info": info}
        if isinstance(info, dict) and "error" not in info:
            row["size"] = info.get("size", -1)
            row["modified"] = info.get("modified", "")
            sources.append(row)
        else:
            missing.append({"name": label, "path": path, "error": str(info.get("error", "not found")) if isinstance(info, dict) else "not found"})

    user_hives = e01.find_files("NTUSER.DAT", path="/c:/Users", limit=safe_limit)
    for hive in _filter_manual_file_rows(user_hives, pattern="*", keyword="", limit=safe_limit):
        path = str(hive.get("path") or "")
        sources.append({
            "name": "UserAssist user hive",
            "path": path,
            "kind": "userassist",
            "size": hive.get("size", -1),
            "info": hive,
        })

    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "execution_source_discovery",
        "returned": len(sources),
        "sources": sources,
        "missing": missing,
        "summary": {
            "amcache_present": any(item.get("kind") == "amcache" for item in sources),
            "system_hive_present": any(item.get("kind") == "bam_shimcache" for item in sources),
            "user_hive_count": sum(1 for item in sources if item.get("kind") == "userassist"),
        },
        "coverage_notes": [
            "Execution source discovery lists parser inputs for AmCache, BAM/DAM, ShimCache, and UserAssist.",
            "These sources are not standalone execution proof; parsing and corroboration with Prefetch, SRUM, EVTX, and timestamps are still required.",
            "Low or zero discovered sources can reflect OS version, profile discovery gaps, cleanup, or parser/image limitations.",
        ],
        "guardrails": _execution_guardrails(),
    }


def _browser_recent_sources_sync(limit: int = 120) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    safe_limit = max(1, min(int(limit or 120), 500))
    per_source_limit = max(1, safe_limit)
    sources: list[dict[str, Any]] = []

    for row in e01.find_files("History", path="/c:/Users", limit=per_source_limit):
        sources.append({
            "name": "Chromium History",
            "kind": "browser_history",
            **row,
        })
    for row in e01.find_files("places.sqlite", path="/c:/Users", limit=per_source_limit):
        sources.append({
            "name": "Firefox places.sqlite",
            "kind": "browser_history",
            **row,
        })
    for row in e01.find_files("*.lnk", path="/c:/Users", limit=per_source_limit):
        sources.append({
            "name": "Recent LNK",
            "kind": "recent_lnk",
            **row,
        })

    sources = sources[:safe_limit]
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "browser_recent_source_discovery",
        "returned": len(sources),
        "sources": sources,
        "summary": {
            "browser_history_count": sum(1 for item in sources if item.get("kind") == "browser_history"),
            "recent_lnk_count": sum(1 for item in sources if item.get("kind") == "recent_lnk"),
        },
        "coverage_notes": [
            "Browser and Recent discovery lists sensitive user-activity source files only; it does not parse URLs, downloads, shortcut targets, or document names.",
            "Browser history or Recent files do not prove download, execution, exfiltration, or actor intent without corroboration.",
            "Portable browsers, nonstandard profiles, private browsing, cleanup, and sync behavior can create discovery gaps.",
        ],
        "guardrails": _browser_recent_guardrails(),
    }


def _list_manual_vss_snapshots_sync(volume: str = "/c:") -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    safe_volume = _normalize_vss_volume(volume)
    catalog = e01.list_vss_snapshots(volume=safe_volume)
    snapshots = catalog.get("snapshots", []) if isinstance(catalog, dict) else []
    result = {
        "ok": bool(catalog.get("ok", False)) if isinstance(catalog, dict) else False,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "vss_snapshot_catalog",
        "volume": safe_volume,
        "snapshot_count": int(catalog.get("snapshot_count", len(snapshots))) if isinstance(catalog, dict) else 0,
        "snapshots": snapshots,
        "coverage_notes": [
            "VSS snapshots are historical filesystem layers, not the current filesystem.",
            "An empty or unreadable VSS catalog is a coverage gap, not evidence that historical data never existed.",
        ],
        "guardrails": _vss_guardrails(),
    }
    if isinstance(catalog, dict) and catalog.get("error"):
        result["error"] = catalog.get("error")
    return result


def _search_vss_files_sync(req: VssFileSearchRequest) -> dict[str, Any]:
    e01, image_path = _get_manual_e01()
    snapshot_id = req.snapshot_id.strip()
    if not snapshot_id:
        raise HTTPException(status_code=400, detail="snapshot_id is required.")

    safe_volume = _normalize_vss_volume(req.volume)
    root = (req.path or "/c:/").strip() or "/c:/"
    pattern = (req.pattern or "*").strip() or "*"
    keyword = (req.keyword or "").strip()
    safe_limit = max(1, min(int(req.limit or 300), 2000))
    coverage: dict[str, Any] = {}

    if req.recursive:
        if hasattr(e01, "vss_find_files_with_coverage"):
            search = e01.vss_find_files_with_coverage(
                snapshot_id,
                pattern,
                path=root,
                volume=safe_volume,
                limit=safe_limit,
            )
            rows = search.get("files", []) if isinstance(search, dict) else []
            coverage = search.get("coverage", {}) if isinstance(search, dict) else {}
        else:
            rows = e01.vss_find_files(snapshot_id, pattern, path=root, volume=safe_volume, limit=safe_limit)
    else:
        rows = e01.vss_list_directory(snapshot_id, path=root, volume=safe_volume)

    filtered = _filter_manual_file_rows(rows, pattern="*" if req.recursive else pattern, keyword=keyword, limit=safe_limit)
    return {
        "ok": True,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "image_path": image_path,
        "source": "vss_snapshot",
        "snapshot_id": snapshot_id,
        "volume": safe_volume,
        "searched": {
            "path": root,
            "pattern": pattern,
            "keyword": keyword,
            "recursive": bool(req.recursive),
            "limit": safe_limit,
        },
        "returned": len(filtered),
        "files": filtered,
        "coverage": coverage,
        "coverage_notes": [
            "VSS search reads a historical snapshot layer, not the current filesystem.",
            "File search is bounded by limit and may report skipped paths. Low or zero matches are not absence evidence.",
        ],
        "guardrails": _vss_guardrails(),
    }


def _manual_error_result(
    source: str,
    error: str,
    *,
    image_path: str = "",
    input_source: str = "",
    coverage_notes: list[str] | None = None,
    query_semantics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "analyst_only": True,
        "llm_auto_ingest": False,
        "mcp_event_log": False,
        "auto_ioc_graph": False,
        "source": source,
        "error": error,
        "image_path": image_path,
        "coverage_notes": coverage_notes or _manual_guardrails(),
        "guardrails": _registry_evtx_guardrails() if source in {"evtx_query", "registry_query"} else _manual_guardrails(),
    }
    if input_source:
        result["input_source"] = input_source
    if query_semantics is not None:
        result["query_semantics"] = query_semantics
    return result


def _evtx_query_coverage_notes() -> list[str]:
    return [
        "Offline EVTX query parses a temporary copy from the captured image; it does not query live host logs.",
        "Zero filtered records are not evidence of absence; check parser_failures, recovery metadata, event IDs, date filters, and source coverage.",
        "Event-log absence must be cross-checked with registry and filesystem artifacts before persistence conclusions.",
    ]


def _registry_query_coverage_notes() -> list[str]:
    return [
        "Registry state proves captured hive contents and configuration state; it does not prove execution or actor intent.",
        "Zero registry matches are not evidence of absence; check the selected hive, control set, search root, parser failures, and VSS layers.",
        "Keyword search is bounded to an analyst-selected search_root to avoid whole-hive scans and false confidence.",
    ]


def _prefetch_query_coverage_notes() -> list[str]:
    return [
        "Prefetch is execution evidence on systems where Prefetch is enabled, but it is not a standalone incident verdict.",
        "Referenced paths inside Prefetch are context and are not proof that every referenced file executed.",
        "Zero Prefetch matches may reflect disabled Prefetch, cleanup, compression parser failure, source limits, date filters, or keyword filters.",
    ]


def _prefetch_guardrails() -> list[str]:
    return [
        *_execution_guardrails(),
        *_prefetch_query_coverage_notes(),
    ]


def _parse_manual_event_ids(value: str) -> set[int]:
    ids: set[int] = set()
    for part in str(value or "").split(","):
        text = part.strip()
        if not text:
            continue
        try:
            event_id = int(text)
        except ValueError as exc:
            raise ValueError(f"Invalid event id: {text}") from exc
        if event_id < 0 or event_id > 65535:
            raise ValueError(f"Invalid event id outside 0-65535: {text}")
        ids.add(event_id)
    return ids


def _safe_manual_artifact_name(internal_path: str, fallback: str) -> str:
    name = str(internal_path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or fallback


def _materialize_manual_artifact(
    e01: E01ImageConnector,
    internal_path: str,
    tmpdir: str,
    kind: str,
) -> tuple[str, dict[str, Any]]:
    safe_name = _safe_manual_artifact_name(internal_path, f"{kind}.bin")
    local_path = os.path.join(tmpdir, safe_name)
    extraction = e01.extract_file(internal_path, local_path)
    metadata = {
        "source": "mounted_image",
        "internal_path": internal_path,
        "kind": kind,
        "local_cache_status": "temporary_static_analysis_copy",
        "extraction": extraction,
    }
    if isinstance(extraction, dict) and extraction.get("error"):
        metadata["error"] = extraction.get("error")
        return "", metadata
    return local_path, metadata


def _parse_manual_evtx_file(local_path: str, target_event_ids: set[int], parse_limit: int) -> dict[str, Any]:
    from core.analysis.evtx_semantic import parse_evtx_file

    return parse_evtx_file(
        local_path,
        target_event_ids=target_event_ids,
        limit=parse_limit,
        best_effort=True,
    )


def _filter_manual_evtx_records(
    records: list[dict[str, Any]],
    *,
    event_ids: set[int] | None,
    keyword: str,
    start_date: str,
    end_date: str,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    from core.analysis.evtx_semantic import filter_evtx_records

    return filter_evtx_records(
        records,
        event_ids=event_ids,
        keyword=keyword,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )


def _parse_manual_prefetch_bytes(data: bytes, *, source_path: str = "") -> dict[str, Any]:
    from core.analysis.prefetch_semantic import parse_prefetch_bytes

    return parse_prefetch_bytes(data, source_path=source_path)


def _prefetch_candidate_files(
    e01: E01ImageConnector,
    directory: str,
    pattern: str,
    source_limit: int,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(source_limit or 1000), 5000))
    pattern_lc = (pattern or "*.pf").lower()
    try:
        rows = e01.list_directory(directory)
        if rows and not all(row.get("error") for row in rows if isinstance(row, dict)):
            out: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict) or row.get("error") or row.get("is_dir"):
                    continue
                path = str(row.get("path", "") or "")
                name = str(row.get("name", "") or path.replace("\\", "/").rsplit("/", 1)[-1])
                if fnmatch.fnmatchcase(name.lower(), pattern_lc) or fnmatch.fnmatchcase(path.lower(), pattern_lc):
                    out.append(row)
                    if len(out) >= safe_limit:
                        break
            return out
    except Exception:
        pass
    return e01.find_files(pattern or "*.pf", path=directory or "/c:/Windows/Prefetch", limit=safe_limit)


def _registry_connector():
    from core.connectors.registry import RegistryConnector

    return RegistryConnector()


def _normalize_manual_registry_key_path(key_path: str, hive_path: str = "") -> str:
    key = str(key_path or "").strip().replace("/", "\\")
    if not key:
        return ""
    while "\\\\" in key:
        key = key.replace("\\\\", "\\")
    lower = key.lower()
    prefixes = [
        "computer\\hkey_local_machine\\system\\",
        "hkey_local_machine\\system\\",
        "hklm\\system\\",
        "computer\\hkey_local_machine\\software\\",
        "hkey_local_machine\\software\\",
        "hklm\\software\\",
        "hkey_current_user\\",
        "hkcu\\",
    ]
    for prefix in prefixes:
        if lower.startswith(prefix):
            key = key[len(prefix):]
            break
    key = "\\" + key.lstrip("\\")
    if "\\currentcontrolset\\" in key.lower() and hive_path:
        current = _manual_current_control_set_name(hive_path)
        if current:
            key = re.sub(
                r"\\CurrentControlSet\\",
                lambda _m: f"\\{current}\\",
                key,
                flags=re.IGNORECASE,
            )
    return key


def _manual_current_control_set_name(hive_path: str) -> str:
    try:
        from regipy.registry import RegistryHive

        hive = RegistryHive(hive_path)
        select = hive.get_key("\\Select")
        try:
            values = list(select.iter_values())
        except Exception:
            values = list(getattr(select, "values", []) or [])
        for value in values:
            if str(getattr(value, "name", "")).lower() == "current":
                return f"ControlSet{int(getattr(value, 'value', 0)):03d}"
    except Exception:
        return ""
    return ""


def _search_manual_registry_subtree(
    hive_path: str,
    root_key_path: str,
    keyword: str,
    *,
    limit: int = 100,
    offset: int = 0,
    max_scan_keys: int = 10000,
) -> dict[str, Any]:
    from core.connectors.registry import _iter_registry_values
    from regipy.registry import RegistryHive

    safe_limit = max(0, int(limit or 0))
    safe_offset = max(0, int(offset or 0))
    safe_max = max(1, int(max_scan_keys or 1))
    kw_lower = str(keyword or "").lower()
    if not kw_lower:
        return {"error": "keyword is required for registry subtree search"}

    hive = RegistryHive(hive_path)
    try:
        root = hive.get_key(root_key_path)
    except Exception as exc:
        return {"error": f"Search root not found or error: {exc}", "root_key_path": root_key_path}

    stack: list[tuple[Any, str]] = [(root, root_key_path)]
    visited = 0
    matched_total = 0
    entries: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    while stack and visited < safe_max:
        key, path = stack.pop()
        visited += 1

        values: list[dict[str, str]] = []
        matched_fields: list[str] = []
        if kw_lower in path.lower():
            matched_fields.append("path")
        try:
            raw_values = _iter_registry_values(key)
        except Exception as exc:
            raw_values = []
            failures.append({"path": path, "stage": "values", "error": str(exc)})
        for value in raw_values:
            name = str(getattr(value, "name", ""))
            value_type = str(getattr(value, "value_type", ""))
            value_text = str(getattr(value, "value", ""))[:500]
            if kw_lower in name.lower():
                matched_fields.append(f"value_name:{name}")
            if kw_lower in value_text.lower():
                matched_fields.append(f"value_data:{name}")
            values.append({"name": name, "type": value_type, "value": value_text})

        if matched_fields:
            matched_total += 1
            if matched_total > safe_offset and len(entries) < safe_limit:
                timestamp = ""
                try:
                    timestamp = str(key.header.last_modified)
                except Exception:
                    pass
                entries.append({
                    "path": path,
                    "timestamp": timestamp,
                    "values_count": len(values),
                    "values": values[:10],
                    "matched_fields": matched_fields[:20],
                })

        try:
            subkeys = list(key.iter_subkeys()) if hasattr(key, "iter_subkeys") else []
        except Exception as exc:
            subkeys = []
            failures.append({"path": path, "stage": "subkeys", "error": str(exc)})
        for subkey in reversed(subkeys):
            name = str(getattr(subkey, "name", ""))
            parent_path = path.rstrip("\\")
            child_path = f"{parent_path}\\{name}" if path != "\\" else f"\\{name}"
            stack.append((subkey, child_path))

    scan_truncated = bool(stack)
    result: dict[str, Any] = {
        "total": matched_total,
        "returned": len(entries),
        "entries": entries,
        "root_key_path": root_key_path,
        "visited_keys": visited,
        "max_scan_keys": safe_max,
        "scan_truncated": scan_truncated,
        "parse_failures": failures[:50],
        "parse_failure_count": len(failures),
    }
    if scan_truncated:
        result["coverage_warnings"] = [
            (
                "Registry subtree scan stopped at max_scan_keys before exhausting the root. "
                "Treat 0 or low matches as incomplete coverage, not absence of the key/value."
            )
        ]
    return result


def _filter_manual_file_rows(rows: Any, *, pattern: str, keyword: str, limit: int) -> list[dict[str, Any]]:
    pattern_lc = (pattern or "*").lower()
    keyword_lc = (keyword or "").lower()
    result: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path") or "")
        name = str(row.get("name") or path.rsplit("/", 1)[-1])
        if pattern_lc not in {"", "*"}:
            if not (
                fnmatch.fnmatchcase(name.lower(), pattern_lc)
                or fnmatch.fnmatchcase(path.lower(), pattern_lc)
            ):
                continue
        if keyword_lc and keyword_lc not in " ".join([path, name, str(row)]).lower():
            continue
        result.append(row)
        if len(result) >= limit:
            break
    return result
