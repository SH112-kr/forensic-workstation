"""Parse an analyst's session outputs into a structured record.

Two inputs:
  - verdict file: JSON with the final answer (from the ```json block).
  - session log (optional): Claude Code conversation JSONL. If supplied,
    we extract tool_use events for the tool diversity metric.

The parser is intentionally tolerant: unknown / malformed events do not
abort ingestion. Missing session log drops tool diversity to null.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_verdict(path: str | Path) -> dict:
    """Read the LLM final-answer JSON file."""
    p = Path(path)
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Verdict file must be a JSON object: {p}")
    return data


def extract_tool_calls(session_log: str | Path | None) -> list[dict]:
    """Extract tool_use events from a Claude Code JSONL session log.

    Format assumption (Claude Code stream-json / session log):
      {"type": "assistant", "message": {"content": [{"type": "tool_use",
         "name": "...", "input": {...}}, ...]}}

    Returns empty list when the file is missing or unreadable.
    """
    if not session_log:
        return []
    p = Path(session_log)
    if not p.exists():
        return []

    calls: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            _collect_tool_uses(event, calls)
    except Exception:
        return calls
    return calls


def _collect_tool_uses(event: Any, sink: list[dict]) -> None:
    """Walk a single event (dict / list / scalar) and append tool_use blocks."""
    if isinstance(event, dict):
        if event.get("type") == "tool_use" and event.get("name"):
            sink.append({
                "name": event.get("name", ""),
                "id": event.get("id"),
                "input": event.get("input", {}),
            })
        for value in event.values():
            _collect_tool_uses(value, sink)
    elif isinstance(event, list):
        for item in event:
            _collect_tool_uses(item, sink)


_TRUNCATED_MARKERS = (
    '"truncated": true',
    '"truncated":true',
    "'truncated': true",
)


def extract_truncation_events(session_log: str | Path | None) -> dict:
    """Count truncated tool results and paginated follow-up calls (M5 input).

    A *truncated result* is any tool_result whose text contains a
    ``truncated: true`` marker. A *paginated follow-up* is any tool_use
    whose input shows pagination intent: ``offset > 0``, ``fetch_all``
    truthy, or a non-empty ``rules`` filter (the find_suspicious
    re-query path mandated by the truncation hard gate).

    Returns ``{"truncated_results": int, "paginated_follow_ups": int}``;
    zeros when the log is missing or unreadable.
    """
    counts = {"truncated_results": 0, "paginated_follow_ups": 0}
    if not session_log:
        return counts
    p = Path(session_log)
    if not p.exists():
        return counts

    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            _collect_truncation(event, counts)
    except Exception:
        pass
    return counts


def _collect_truncation(event: Any, counts: dict) -> None:
    if isinstance(event, dict):
        if event.get("type") == "tool_result":
            if _contains_truncated_flag(event):
                counts["truncated_results"] += 1
            return  # truncation already assessed for this result subtree
        if event.get("type") == "tool_use":
            inp = event.get("input") or {}
            if isinstance(inp, dict) and _is_pagination_input(inp):
                counts["paginated_follow_ups"] += 1
        for value in event.values():
            _collect_truncation(value, counts)
    elif isinstance(event, list):
        for item in event:
            _collect_truncation(item, counts)


def _contains_truncated_flag(node: Any) -> bool:
    """True when the result subtree carries a truncated=true signal, either
    as an actual boolean key or inside serialized JSON text content."""
    if isinstance(node, dict):
        if node.get("truncated") is True:
            return True
        return any(_contains_truncated_flag(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_truncated_flag(item) for item in node)
    if isinstance(node, str):
        lowered = node.lower()
        return any(m in lowered for m in _TRUNCATED_MARKERS)
    return False


def _is_pagination_input(inp: dict) -> bool:
    try:
        if float(inp.get("offset") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    if inp.get("fetch_all"):
        return True
    if str(inp.get("rules") or "").strip():
        return True
    return False


def extract_final_text(session_log: str | Path | None) -> str:
    """Return the last assistant text block from the session log.

    Used only for the uncertainty-citation metric when the caller did not
    supply a separate final-text file. Empty string when log is missing
    or contains no text blocks.
    """
    if not session_log:
        return ""
    p = Path(session_log)
    if not p.exists():
        return ""

    last_text = ""
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            text = _latest_text_block(event)
            if text:
                last_text = text
    except Exception:
        return last_text
    return last_text


def _latest_text_block(event: Any) -> str:
    if isinstance(event, dict):
        if event.get("type") == "text" and isinstance(event.get("text"), str):
            return event["text"]
        for value in event.values():
            t = _latest_text_block(value)
            if t:
                return t
    elif isinstance(event, list):
        for item in reversed(event):
            t = _latest_text_block(item)
            if t:
                return t
    return ""
