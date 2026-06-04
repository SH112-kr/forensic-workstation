from __future__ import annotations

from collections import deque
from typing import Any

from core.raw_index.store import RawIndexStore


def index_file_listing(
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
                times={},
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
