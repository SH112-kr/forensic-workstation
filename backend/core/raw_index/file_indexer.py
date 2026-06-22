from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

from core.raw_index.store import RawIndexStore


def index_file_listing(
    image: Any,
    store: RawIndexStore,
    *,
    roots: list[str],
    started_at: str,
    workers: int = 0,
    progress: Any = None,
) -> dict[str, Any]:
    normalized_roots = list(
        dict.fromkeys(str(root).strip() for root in roots if str(root).strip())
    )
    # TB-safe path: stream the $MFT instead of walking directories. Falls back
    # to the legacy directory walk only when the image cannot stream the MFT
    # (e.g. test stubs, non-NTFS volumes).
    if hasattr(image, "iter_mft_records"):
        return index_mft_listing(
            image,
            store,
            roots=normalized_roots,
            started_at=started_at,
            workers=workers,
            progress=progress,
        )
    with store.batch():
        if not normalized_roots:
            return _empty_roots_result(store, started_at=started_at)
        return _index_file_listing(
            image,
            store,
            roots=normalized_roots,
            started_at=started_at,
        )


def _root_to_volume_ref(root: str) -> str:
    r = str(root).strip().lower().replace("\\", "/")
    if r.startswith("/") and len(r) >= 3 and r[2] == ":":
        return f"/{r[1]}:"
    if len(r) >= 2 and r[1] == ":":
        return f"/{r[0]}:"
    return "/c:"


def _epoch_ms_to_time(ms: Any) -> tuple[int, str] | None:
    if ms is None:
        return None
    try:
        ms_int = int(ms)
    except (TypeError, ValueError):
        return None
    if ms_int <= 0:
        return None
    display = datetime.fromtimestamp(ms_int / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return ms_int, display


def _open_mft_stream(image: Any, vref: str, *, max_records: int, workers: int):
    """Parallel shard stream when workers>1 and the image is a real E01;
    otherwise the serial in-process generator. Parallelism is skipped when a
    record cap is set (the cap is a serial test/triage concern)."""
    e01_path = str(getattr(image, "_path", "") or "")
    if workers and workers > 1 and e01_path and not max_records:
        last_segment = 0
        if hasattr(image, "mft_segment_count"):
            try:
                last_segment = int(image.mft_segment_count(vref))
            except Exception:
                last_segment = 0
        if last_segment > 0:
            from core.raw_index.mft_parallel import parallel_mft_record_stream

            return parallel_mft_record_stream(
                e01_path, vref, last_segment, workers
            )
    return image.iter_mft_records(vref, max_records=max_records)


def index_mft_listing(
    image: Any,
    store: RawIndexStore,
    *,
    roots: list[str],
    started_at: str,
    max_records: int = 0,
    workers: int = 0,
    progress: Any = None,
) -> dict[str, Any]:
    """Index a full file inventory by streaming each volume's $MFT.

    No-miss: every per-record parse failure, MFT-unavailable volume, and the
    record cap are recorded as coverage gaps. Deleted records (in_use=False)
    are indexed too — a forensic advantage over directory walking.

    ``workers>1`` shards the scan across worker processes (parse is the
    CPU-bound cost); the parent still inserts serially. ``progress`` is an
    optional callable invoked as ``progress(indexed_files, gap_count)`` every
    few thousand records so a background job can report live counts.
    """
    volume_refs = list(dict.fromkeys(_root_to_volume_ref(r) for r in roots)) or ["/c:"]
    run_id = store.start_parser_run("mft_indexer", ",".join(volume_refs), started_at=started_at)
    coverage_gaps: list[dict[str, Any]] = []
    indexed_files = 0
    capped = False

    with store.batch():
        for vref in volume_refs:
            try:
                stream = _open_mft_stream(
                    image, vref, max_records=max_records, workers=workers
                )
            except Exception as exc:  # noqa: BLE001
                coverage_gaps.append({
                    "path": vref, "status": "coverage_gap",
                    "reason": "mft_stream_unavailable", "error": str(exc),
                })
                continue
            for rec in stream:
                err = rec.get("error")
                if err:
                    reason = "mft_record_cap_reached" if rec.get("cap") else (
                        rec.get("reason") or "mft_record_error")
                    if rec.get("cap"):
                        capped = True
                    coverage_gaps.append({
                        "path": vref, "status": "coverage_gap",
                        "reason": err if err in ("no_ntfs_mft_for_volume",) else reason,
                        "error": str(err),
                        "segment": rec.get("segment"),
                    })
                    continue
                path = str(rec.get("path") or "")
                if not path:
                    continue
                times: dict[str, tuple[int, str]] = {}
                for label, key in (("Created", "created"), ("Modified", "modified"),
                                   ("Accessed", "accessed"), ("MFT Changed", "changed")):
                    parsed = _epoch_ms_to_time(rec.get(key))
                    if parsed is not None:
                        times[label] = parsed
                strings = {
                    "Name": str(rec.get("name") or path.rsplit("/", 1)[-1]),
                    "Path": path,
                    "Size": str(rec.get("size", "")),
                    "MFT Segment": str(rec.get("segment", "")),
                }
                if rec.get("sequence") not in (None, ""):
                    strings["MFT Sequence Number"] = str(rec.get("sequence"))
                if rec.get("is_dir"):
                    strings["Type"] = "Directory"
                if rec.get("in_use") is False:
                    strings["Deleted"] = "True"
                store.insert_artifact(
                    artifact_type="File System Entry",
                    source_ref=vref,
                    source_path=path,
                    primary_path=path,
                    description=f"File System Entry {path}",
                    strings=strings,
                    times=times,
                    parser_run_id=run_id,
                )
                indexed_files += 1
                if progress is not None and indexed_files % 5000 == 0:
                    try:
                        progress(indexed_files, len(coverage_gaps))
                    except Exception:
                        pass

    if progress is not None:
        try:
            progress(indexed_files, len(coverage_gaps))
        except Exception:
            pass

    if indexed_files:
        # Use the same "completed" parser status as the legacy walk so
        # store._coverage_summary (which treats only "completed"+"searched" as
        # healthy) does not flag a clean MFT run as a coverage gap. The MCP
        # layer maps "completed" -> external "indexed".
        status = "partial" if coverage_gaps else "completed"
        coverage_status = "coverage_gap" if coverage_gaps else "searched"
    else:
        # Nothing indexed: a pure-gap result is not_evaluable, not partial.
        status = "not_evaluable"
        coverage_status = "not_evaluable"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        error="; ".join(str(g.get("error", "")) for g in coverage_gaps)[:2000],
    )
    return {
        "ok": indexed_files > 0,
        "status": status,
        "indexed_files": indexed_files,
        "record_cap_reached": capped,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
        "indexer": "mft",
    }


def _empty_roots_result(
    store: RawIndexStore,
    *,
    started_at: str,
) -> dict[str, Any]:
    error = "no roots supplied"
    run_id = store.start_parser_run("file_indexer", "", started_at=started_at)
    store.finish_parser_run(
        run_id,
        status="not_evaluable",
        coverage_status="not_evaluable",
        finished_at=started_at,
        error=error,
    )
    return {
        "ok": False,
        "status": "not_evaluable",
        "indexed_files": 0,
        "coverage_gaps": [
            {
                "path": "",
                "status": "not_evaluable",
                "reason": "raw_file_index_no_roots",
                "error": error,
            }
        ],
        "parser_run_id": run_id,
    }


def _index_file_listing(
    image: Any,
    store: RawIndexStore,
    *,
    roots: list[str],
    started_at: str,
) -> dict[str, Any]:
    run_id = store.start_parser_run(
        "file_indexer",
        ",".join(roots),
        started_at=started_at,
    )
    queue = deque(roots)
    visited: set[str] = set()
    indexed_paths: set[str] = set()
    indexed_files = 0
    coverage_gaps: list[dict[str, str]] = []

    while queue:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        try:
            entries = image.list_directory(path)
        except Exception as exc:
            coverage_gaps.append({
                "path": path,
                "status": "coverage_gap",
                "error": str(exc),
            })
            continue
        for entry in entries:
            if entry.get("error"):
                coverage_gaps.append({
                    "path": path,
                    "status": "coverage_gap",
                    "error": str(entry.get("error")),
                })
                continue
            entry_path = str(entry.get("path", ""))
            if not entry_path:
                entry_name = str(entry.get("name") or "")
                coverage_gaps.append({
                    "path": path,
                    "status": "coverage_gap",
                    "reason": "raw_file_index_missing_entry_path",
                    "error": (
                        f"directory entry missing path: {entry_name}"
                        if entry_name
                        else "directory entry missing path"
                    ),
                })
                continue
            if "is_dir" not in entry:
                coverage_gaps.append({
                    "path": entry_path,
                    "status": "coverage_gap",
                    "reason": "raw_file_index_missing_entry_type",
                    "error": f"directory entry missing is_dir: {entry_path}",
                })
                continue
            if entry.get("is_dir"):
                queue.append(entry_path)
                continue
            if entry_path in indexed_paths:
                continue
            indexed_paths.add(entry_path)
            name = str(entry.get("name") or entry_path.rsplit("/", 1)[-1])
            size = str(entry.get("size", ""))
            store.insert_artifact(
                artifact_type="File System Entry",
                source_ref=path,
                source_path=entry_path,
                primary_path=entry_path,
                description=f"File System Entry {entry_path}",
                strings={
                    "Name": name,
                    "Path": entry_path,
                    "Size": size,
                },
                times=_entry_timestamps(entry),
                parser_run_id=run_id,
            )
            indexed_files += 1

    status = "partial" if coverage_gaps else "completed"
    coverage_status = "coverage_gap" if coverage_gaps else "searched"
    store.finish_parser_run(
        run_id,
        status=status,
        coverage_status=coverage_status,
        finished_at=started_at,
        # Cap the persisted error like the MFT path: an unbounded join of every
        # gap error here previously bloated a parser_runs.error row to ~2.5 MB,
        # which then blew up get_coverage() responses past the MCP token limit.
        error="; ".join(g["error"] for g in coverage_gaps)[:2000],
    )
    return {
        "ok": True,
        "status": status,
        "indexed_files": indexed_files,
        "coverage_gaps": coverage_gaps,
        "parser_run_id": run_id,
    }


def _entry_timestamps(entry: dict[str, Any]) -> dict[str, tuple[int, str]]:
    fields = {
        "Created": ("created", "creation_time", "birth_time"),
        "Modified": ("modified", "mtime", "modification_time", "last_modified"),
        "Accessed": ("accessed", "atime", "access_time", "last_accessed"),
    }
    timestamps: dict[str, tuple[int, str]] = {}
    for field_name, keys in fields.items():
        for key in keys:
            value = entry.get(key)
            parsed = _parse_timestamp(value)
            if parsed is not None:
                timestamps[field_name] = parsed
                break
    return timestamps


def _parse_timestamp(value: Any) -> tuple[int, str] | None:
    if value is None or value == "":
        return None
    display = str(value)
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(display.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000), display
    except Exception:
        return None
