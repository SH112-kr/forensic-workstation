"""Compare the active case against a known-good baseline.

Returns the net-new services / scheduled tasks / startup entries / users that
exist in the active case but not in the reference. Use this to cut noise
during triage — "what's NEW on this host?".

Two reference modes:

1. ``builtin``  — ``backend/reference/windows_baseline.json``. Tiny curated
   list so out-of-the-box operation still works. Many legitimate third-party
   items will show up as new; treat with caution.

2. ``case:<case_id>``  — diff against another loaded case (e.g. a golden
   image imported as a KAPE case). Strongest signal.

v1 categories: services, scheduled_tasks, startup_items, users.
No heuristics — each result is a plain name present in the active case but
not in the reference. The analyst still has to triage.
"""

from __future__ import annotations

import json
import os
from typing import Any


_REFERENCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reference", "windows_baseline.json",
)

_CATEGORIES = ("services", "scheduled_tasks", "startup_items", "users")


def _load_builtin() -> dict[str, Any]:
    try:
        with open(_REFERENCE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _extract_from_case(aq: Any) -> dict[str, set[str]]:
    """Pull category name sets from a connector's artifact queries."""
    result: dict[str, set[str]] = {c: set() for c in _CATEGORIES}

    try:
        for svc in (aq.query_services(limit=0) or []):
            name = svc.get("Service Name") or svc.get("ServiceName") or ""
            if name:
                result["services"].add(_norm(name))
    except Exception:
        pass

    try:
        for tsk in (aq.query_scheduled_tasks(limit=0) or []):
            name = tsk.get("Name") or tsk.get("Task Name") or ""
            if name:
                result["scheduled_tasks"].add(_norm(name))
    except Exception:
        pass

    try:
        # Startup Items is available on many AXIOM cases via _query_artifact.
        for item in (aq._query_artifact("Startup Items", limit=0) or []):
            v = item.get("Path") or item.get("Name") or ""
            if v:
                result["startup_items"].add(_norm(v))
    except Exception:
        pass

    try:
        for u in (aq._query_artifact("User Accounts", limit=0) or []):
            v = u.get("Username") or u.get("Name") or ""
            if v:
                result["users"].add(_norm(v))
    except Exception:
        pass

    return result


def _reference_sets(ref: dict[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for cat in _CATEGORIES:
        out[cat] = {_norm(v) for v in (ref.get(cat) or []) if v}
    return out


def baseline_diff(
    active_aq: Any,
    reference_aq: Any | None = None,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    """Return the net-new names in ``active_aq`` vs a reference.

    Args:
        active_aq: ArtifactQueries of the case to inspect.
        reference_aq: Optional ArtifactQueries of a reference case. When
            ``None`` the built-in Windows baseline JSON is used.
        categories: Optional subset of ``_CATEGORIES``. Empty / None = all.

    Output includes lists of net-new names per category with counts, plus
    notes explaining which reference was used.
    """
    cats = [c for c in (categories or _CATEGORIES) if c in _CATEGORIES]
    if not cats:
        cats = list(_CATEGORIES)

    active_sets = _extract_from_case(active_aq)

    if reference_aq is not None:
        reference = _extract_from_case(reference_aq)
        source = "case_reference"
    else:
        reference = _reference_sets(_load_builtin())
        source = "builtin_windows_baseline"

    result: dict[str, Any] = {
        "ok": True,
        "reference_source": source,
        "categories": {},
        "notes": [
            "Each listed item exists in the active case but NOT in the reference.",
            "Absence from reference does not imply malice — legitimate third-party "
            "software will appear here. Triage with get_hit_detail / get_file_timestamps.",
        ],
    }

    if source == "builtin_windows_baseline":
        result["notes"].append(
            "Built-in baseline is a tiny curated list. For serious triage, diff against a "
            "golden-image reference case instead."
        )

    for cat in cats:
        active = active_sets.get(cat, set())
        ref = reference.get(cat, set())
        new_names = sorted(active - ref)
        result["categories"][cat] = {
            "active_count": len(active),
            "reference_count": len(ref),
            "net_new_count": len(new_names),
            "net_new": new_names[:200],
        }

    result["summary"] = {
        "total_net_new": sum(c["net_new_count"] for c in result["categories"].values()),
    }
    return result
