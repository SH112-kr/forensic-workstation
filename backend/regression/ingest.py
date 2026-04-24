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
