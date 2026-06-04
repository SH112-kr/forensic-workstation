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
) -> dict[str, Any]:
    with store.batch():
        return _index_file_listing(
            image,
            store,
            roots=roots,
            started_at=started_at,
        )


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
                continue
            if entry.get("is_dir"):
                queue.append(entry_path)
                continue
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
        error="; ".join(g["error"] for g in coverage_gaps),
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
