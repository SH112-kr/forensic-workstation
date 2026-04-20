"""Post-filter timeline entries by user / process / host / path substrings.

Runs on top of whatever ``get_timeline`` returned — we never touch the
connector's SQL. Each filter is a plain substring, case-insensitive, matched
against the entry's description + artifact_type + (if present) fields. The
matcher is deliberately simple so analysts can predict its behaviour; anything
fancier belongs in a dedicated search tool, not in timeline slicing.
"""

from __future__ import annotations

from typing import Any


def _haystack(entry: dict[str, Any]) -> str:
    parts = [
        str(entry.get("description", "")),
        str(entry.get("artifact_type", "")),
    ]
    fields = entry.get("fields")
    if isinstance(fields, dict):
        for v in fields.values():
            if v is None:
                continue
            parts.append(str(v))
    return " ".join(parts).lower()


def _match(entry: dict[str, Any], substring: str) -> bool:
    if not substring:
        return True
    return substring.lower() in _haystack(entry)


def slice_entries(
    entries: list[dict[str, Any]],
    *,
    user: str = "",
    process: str = "",
    host: str = "",
    path: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter ``entries`` by substring AND across all provided dimensions.

    Returns ``(filtered_entries, meta)`` where ``meta`` lists which filters were
    active and how many entries each one removed. The meta block is useful in
    UI so the analyst can see, for example, that adding ``process="powershell"``
    dropped 80% of events.
    """
    total = len(entries)
    stages: list[dict[str, Any]] = []

    def _apply(label: str, value: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not value:
            return rows
        before = len(rows)
        filtered = [e for e in rows if _match(e, value)]
        stages.append({
            "dimension": label,
            "substring": value,
            "matched": len(filtered),
            "removed": before - len(filtered),
        })
        return filtered

    rows = entries
    rows = _apply("user", user, rows)
    rows = _apply("process", process, rows)
    rows = _apply("host", host, rows)
    rows = _apply("path", path, rows)

    return rows, {
        "input_total": total,
        "output_total": len(rows),
        "stages": stages,
        "active_filters": {
            k: v for k, v in {"user": user, "process": process, "host": host, "path": path}.items() if v
        },
    }
