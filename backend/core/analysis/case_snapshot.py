"""Persist an investigation snapshot so an analyst can resume later.

v1 is deliberately small:

- Snapshot = { name, saved_at, case_ids, active_case_id, masking, notes,
               tagged_hits, filters }
- Storage  = backend/state/snapshots/<slug>.json
- Operations = save / list / load (load restores masking + active case,
               returns the saved filter block so the UI can replay it).

No Python execution, no conditional logic, no attempt to re-run tools:
loading a snapshot restores analyst context (tags, notes, filters, which
cases are the frame of reference) but never silently reruns detection. The
analyst stays in charge of rerunning queries.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any


_STATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "state", "snapshots",
)


def _ensure_dir() -> str:
    os.makedirs(_STATE_DIR, exist_ok=True)
    return _STATE_DIR


_SLUG = re.compile(r"[^a-z0-9._-]+", re.IGNORECASE)


def _slug(name: str) -> str:
    s = (name or "snapshot").strip().replace(" ", "_").lower()
    s = _SLUG.sub("-", s).strip("-")
    return s[:80] or "snapshot"


def _active_case_id(connectors: dict[str, Any]) -> str:
    active = connectors.get("axiom")
    if not active:
        return ""
    for k, c in connectors.items():
        if k.startswith("axiom:") and c is active:
            return k.replace("axiom:", "")
    return ""


def _iter_case_ids(connectors: dict[str, Any]) -> list[str]:
    return [k.replace("axiom:", "") for k, c in connectors.items()
            if k.startswith("axiom:") and getattr(c, "is_connected", lambda: False)()]


def save_snapshot(
    connectors: dict[str, Any],
    name: str,
    tagged_hits: list[int] | None = None,
    notes: str = "",
    filters: dict[str, Any] | None = None,
    masker_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist analyst context under ``name``. Overwrites same-slug snapshots."""
    _ensure_dir()
    payload = {
        "schema": "fw.case_snapshot.v1",
        "name": name or "snapshot",
        "slug": _slug(name),
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "case_ids": _iter_case_ids(connectors),
        "active_case_id": _active_case_id(connectors),
        "tagged_hits": sorted(set(int(h) for h in (tagged_hits or []) if h is not None)),
        "notes": notes or "",
        "filters": filters or {},
        "masker": masker_state or {},
    }
    path = os.path.join(_STATE_DIR, payload["slug"] + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return {"ok": True, "path": path, **payload}


def list_snapshots() -> dict[str, Any]:
    _ensure_dir()
    items: list[dict[str, Any]] = []
    for name in sorted(os.listdir(_STATE_DIR)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(_STATE_DIR, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            items.append({"slug": name[:-5], "error": str(e)})
            continue
        items.append({
            "slug": data.get("slug", name[:-5]),
            "name": data.get("name", ""),
            "saved_at": data.get("saved_at", ""),
            "case_ids": data.get("case_ids", []),
            "active_case_id": data.get("active_case_id", ""),
            "tagged_count": len(data.get("tagged_hits", [])),
        })
    return {"ok": True, "count": len(items), "snapshots": items}


def load_snapshot(slug: str) -> dict[str, Any]:
    """Read the snapshot. Never re-runs tools; caller decides what to act on."""
    _ensure_dir()
    path = os.path.join(_STATE_DIR, _slug(slug) + ".json")
    if not os.path.exists(path):
        return {"ok": False, "error": f"Snapshot not found: {slug}"}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["ok"] = True
    data["path"] = path
    return data


def delete_snapshot(slug: str) -> dict[str, Any]:
    _ensure_dir()
    path = os.path.join(_STATE_DIR, _slug(slug) + ".json")
    if not os.path.exists(path):
        return {"ok": False, "error": f"Snapshot not found: {slug}"}
    os.remove(path)
    return {"ok": True, "deleted": path}
