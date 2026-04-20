"""Per-rule suppression list — exact id match only, no regex, no conditions.

The goal is to let analysts mute noisy detections in their environment without
creating an opaque rules-engine. Everything here is deliberately constrained:

- Match key is an exact ``rule_id`` string. No regex, no globs.
- Each entry carries ``reason`` + ``analyst`` + optional ``expires_at``.
- Suppressed findings are NEVER dropped silently: ``apply_suppressions()``
  moves them into a ``suppressed`` list with the matching entry attached so
  the analyst can audit what got filtered and why.
- No conditional logic, no auto-expiry of other rules, no cross-finding state.

If an entry has ``expires_at`` in the past, the engine treats it as inactive
and writes a note in the response. An explicit UI / CLI delete is still
required to remove it.

Storage: backend/state/suppressions.json (gitignored).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "state", "suppressions.json",
)


def _ensure_store() -> None:
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    if not os.path.exists(_STORE):
        with open(_STORE, "w", encoding="utf-8") as f:
            json.dump({"schema": "fw.suppressions.v1", "entries": []}, f)


def _load() -> dict[str, Any]:
    _ensure_store()
    try:
        with open(_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "entries" not in data:
            return {"schema": "fw.suppressions.v1", "entries": []}
        return data
    except Exception:
        return {"schema": "fw.suppressions.v1", "entries": []}


def _save(data: dict[str, Any]) -> None:
    _ensure_store()
    with open(_STORE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _is_expired(entry: dict[str, Any]) -> bool:
    exp = entry.get("expires_at")
    if not exp:
        return False
    try:
        # Accept ISO 8601 with or without trailing Z
        s = exp.replace("Z", "+00:00") if exp.endswith("Z") else exp
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception:
        return False


def list_suppressions() -> dict[str, Any]:
    data = _load()
    entries = data.get("entries", [])
    active = [e for e in entries if not _is_expired(e)]
    expired = [e for e in entries if _is_expired(e)]
    return {
        "ok": True,
        "count": len(entries),
        "active_count": len(active),
        "expired_count": len(expired),
        "entries": entries,
    }


def add_suppression(
    rule_id: str,
    reason: str,
    analyst: str = "",
    expires_at: str = "",
) -> dict[str, Any]:
    """Append a suppression entry. Replaces an existing entry with the same rule_id."""
    rid = (rule_id or "").strip()
    if not rid:
        return {"ok": False, "error": "rule_id is required"}
    if not reason.strip():
        return {"ok": False, "error": "reason is required (explain why this rule is suppressed)"}

    data = _load()
    entries = [e for e in data.get("entries", []) if e.get("rule_id") != rid]
    entry = {
        "rule_id": rid,
        "reason": reason.strip(),
        "analyst": analyst.strip(),
        "expires_at": expires_at.strip() or None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    entries.append(entry)
    data["entries"] = entries
    _save(data)
    return {"ok": True, "entry": entry, "total": len(entries)}


def remove_suppression(rule_id: str) -> dict[str, Any]:
    rid = (rule_id or "").strip()
    data = _load()
    before = len(data.get("entries", []))
    entries = [e for e in data.get("entries", []) if e.get("rule_id") != rid]
    removed = before - len(entries)
    data["entries"] = entries
    _save(data)
    return {"ok": True, "removed": removed, "remaining": len(entries)}


def apply_suppressions(payload: dict[str, Any]) -> dict[str, Any]:
    """Move suppressed findings from ``findings`` into ``suppressed``.

    Never silently drops: each suppressed finding keeps all its original fields
    and gains a ``suppression`` block containing the matching rule. Expired
    entries are treated as inactive and logged in ``suppression_notes``.
    """
    data = _load()
    active_by_id = {e["rule_id"]: e for e in data.get("entries", []) if not _is_expired(e)}
    expired_by_id = {e["rule_id"]: e for e in data.get("entries", []) if _is_expired(e)}

    findings = payload.get("findings", []) or []
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for f in findings:
        rid = f.get("rule_name", "")
        if rid in active_by_id:
            f_copy = dict(f)
            f_copy["suppression"] = active_by_id[rid]
            suppressed.append(f_copy)
        else:
            kept.append(f)

    notes: list[str] = []
    for rid, exp in expired_by_id.items():
        notes.append(
            f"Suppression for '{rid}' expired at {exp.get('expires_at')} — "
            "treated as inactive. Delete it explicitly to remove this note."
        )

    payload["findings"] = kept
    payload["suppressed"] = suppressed
    payload["suppression_summary"] = {
        "active_entries": len(active_by_id),
        "expired_entries": len(expired_by_id),
        "suppressed_in_this_run": len(suppressed),
    }
    if notes:
        payload["suppression_notes"] = notes
    return payload
