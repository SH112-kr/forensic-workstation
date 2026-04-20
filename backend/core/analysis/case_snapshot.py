"""Persist an investigation snapshot so an analyst can resume later.

v2 extends the original snapshot with named buckets so a single case can
carry multiple parallel hypothesis working sets without forcing one
snapshot per bucket. v1 snapshots still load — ``load_snapshot`` normalizes
to v2 shape in memory without rewriting the on-disk file, so old files
stay backward compatible and no caller has to sprinkle ``.get(..., {})``
at every read site (Codex Round-9b review).

v2 schema additions (additive, v1 files still valid):
  tagged_hits_by_bucket : {bucket_slug: [hit_ids]}
  bucket_hypotheses     : {bucket_slug: 'free-form analyst hypothesis'}
  schema_version        : 'fw.snapshot.v2'

Operations kept thin:
  save_snapshot / list_snapshots / load_snapshot / delete_snapshot   (v1)
  add_hits_to_bucket / remove_hits_from_bucket / get_bucket_hits     (v2)

Missing-bucket reads are a hard error — never silent empty — so typos
cannot masquerade as "no activity" in downstream tools.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION_V2 = "fw.snapshot.v2"


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
    tagged_hits_by_bucket: dict[str, list[int]] | None = None,
    bucket_hypotheses: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Persist analyst context under ``name``. Overwrites same-slug snapshots.

    v2 additions (optional — omitted = empty):
      tagged_hits_by_bucket   {bucket_slug: [hit_ids]}
      bucket_hypotheses       {bucket_slug: 'free-form hypothesis'}
    """
    _ensure_dir()
    buckets = {
        _slug(b): sorted({int(h) for h in hits if h is not None})
        for b, hits in (tagged_hits_by_bucket or {}).items()
    }
    hypotheses = {_slug(b): h for b, h in (bucket_hypotheses or {}).items() if h}
    payload = {
        "schema": SCHEMA_VERSION_V2,
        "name": name or "snapshot",
        "slug": _slug(name),
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "case_ids": _iter_case_ids(connectors),
        "active_case_id": _active_case_id(connectors),
        "tagged_hits": sorted(set(int(h) for h in (tagged_hits or []) if h is not None)),
        "notes": notes or "",
        "filters": filters or {},
        "masker": masker_state or {},
        "tagged_hits_by_bucket": buckets,
        "bucket_hypotheses": hypotheses,
    }
    path = os.path.join(_STATE_DIR, payload["slug"] + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return {"ok": True, "path": path, **payload}


def _normalize_loaded(data: dict[str, Any]) -> dict[str, Any]:
    """In-memory upgrade of v1 payloads to v2 shape.

    The on-disk file stays untouched so downgrade paths still work; this
    lives at the load boundary so every caller below gets a uniform shape
    without scattering ``.get(..., {})`` across call sites (Codex 9b fix).
    """
    data.setdefault("tagged_hits_by_bucket", {})
    data.setdefault("bucket_hypotheses", {})
    data.setdefault("bucket_display_names", {})
    data.setdefault("schema", "fw.case_snapshot.v1")
    data["schema_version_normalized"] = SCHEMA_VERSION_V2
    return data


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
    """Read the snapshot. Never re-runs tools; caller decides what to act on.

    v1 files are normalized to v2 shape in memory (the file on disk stays
    untouched) so every downstream caller can rely on
    ``tagged_hits_by_bucket`` / ``bucket_hypotheses`` existing as dicts.
    """
    _ensure_dir()
    path = os.path.join(_STATE_DIR, _slug(slug) + ".json")
    if not os.path.exists(path):
        return {"ok": False, "error": f"Snapshot not found: {slug}"}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    _normalize_loaded(data)
    data["ok"] = True
    data["path"] = path
    return data


# ── v2 bucket operations ──────────────────────────────────────────────────

class SnapshotNotFoundError(Exception):
    pass


class BucketNotFoundError(Exception):
    pass


def _read_snapshot_raw(slug: str) -> tuple[str, dict[str, Any]]:
    """Internal: load + normalize without the {'ok': True} wrapper."""
    r = load_snapshot(slug)
    if not r.get("ok"):
        raise SnapshotNotFoundError(r.get("error") or f"Snapshot not found: {slug}")
    path = r.pop("path")
    r.pop("ok")
    return path, r


def _write_snapshot_raw(path: str, payload: dict[str, Any]) -> None:
    payload["schema"] = SCHEMA_VERSION_V2
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def add_hits_to_bucket(
    snapshot_slug: str,
    bucket_name: str,
    hit_ids: list[int],
    hypothesis: str = "",
) -> dict[str, Any]:
    """Append hit_ids to a named bucket; dedup + sort. Creates the bucket
    on first call and records the hypothesis string if provided.

    Codex Round-9c: record the caller's first-seen display name under
    ``bucket_display_names`` so downstream callers can tell when two
    distinct bucket labels collapsed to the same slug (e.g. 'Payload Files'
    and 'payload files!' both → 'payload_files'). A mismatch on a later
    add returns a warning on the response, not a hard error — the merge
    is intentional (same slug = same bucket) but must be visible.
    """
    try:
        path, data = _read_snapshot_raw(snapshot_slug)
    except SnapshotNotFoundError as e:
        return {"ok": False, "error": str(e)}
    raw_name = (bucket_name or "").strip()
    b_slug = _slug(bucket_name)
    if not b_slug:
        return {"ok": False, "error": "bucket_name is empty after sanitization"}

    buckets = data.setdefault("tagged_hits_by_bucket", {})
    display_names = data.setdefault("bucket_display_names", {})

    collision_warning: str | None = None
    prior_display = display_names.get(b_slug)
    if prior_display is None:
        # First time we see this slug — record the original label.
        display_names[b_slug] = raw_name
    elif prior_display != raw_name:
        collision_warning = (
            f"bucket slug {b_slug!r} was previously created as "
            f"{prior_display!r}; this call used {raw_name!r}. Hits are merged "
            "into a single bucket; rename one label if the merge is unintentional."
        )

    current = set(int(h) for h in buckets.get(b_slug, []) if h is not None)
    current.update(int(h) for h in hit_ids if h is not None)
    buckets[b_slug] = sorted(current)
    if hypothesis.strip():
        data.setdefault("bucket_hypotheses", {})[b_slug] = hypothesis.strip()
    _write_snapshot_raw(path, data)

    out = {
        "ok": True,
        "snapshot_slug": data["slug"],
        "bucket": b_slug,
        "display_name": display_names[b_slug],
        "hit_count": len(buckets[b_slug]),
        "hypothesis": data.get("bucket_hypotheses", {}).get(b_slug, ""),
    }
    if collision_warning:
        out["collision_warning"] = collision_warning
    return out


def remove_hits_from_bucket(
    snapshot_slug: str,
    bucket_name: str,
    hit_ids: list[int],
) -> dict[str, Any]:
    """Remove hit_ids from a bucket. Hard-errors if the bucket doesn't exist."""
    try:
        path, data = _read_snapshot_raw(snapshot_slug)
    except SnapshotNotFoundError as e:
        return {"ok": False, "error": str(e)}
    b_slug = _slug(bucket_name)
    buckets = data.get("tagged_hits_by_bucket") or {}
    if b_slug not in buckets:
        return {"ok": False, "error": f"Bucket not found in snapshot '{data['slug']}': {bucket_name}"}
    to_drop = set(int(h) for h in hit_ids if h is not None)
    buckets[b_slug] = sorted(h for h in buckets[b_slug] if h not in to_drop)
    data["tagged_hits_by_bucket"] = buckets
    _write_snapshot_raw(path, data)
    return {
        "ok": True,
        "snapshot_slug": data["slug"],
        "bucket": b_slug,
        "hit_count": len(buckets[b_slug]),
    }


def get_bucket_hits(snapshot_slug: str, bucket_name: str) -> dict[str, Any]:
    """Read a bucket. Raises BucketNotFoundError at the helper level AND
    returns {ok: False, error} at the tool boundary so a typo in
    ``bucket_name`` cannot masquerade as 'no activity'."""
    try:
        _, data = _read_snapshot_raw(snapshot_slug)
    except SnapshotNotFoundError as e:
        return {"ok": False, "error": str(e)}
    b_slug = _slug(bucket_name)
    buckets = data.get("tagged_hits_by_bucket") or {}
    if b_slug not in buckets:
        return {
            "ok": False,
            "error": (
                f"Bucket not found in snapshot '{data['slug']}': {bucket_name!r}. "
                f"Known buckets: {sorted(buckets.keys())}"
            ),
        }
    return {
        "ok": True,
        "snapshot_slug": data["slug"],
        "bucket": b_slug,
        "hit_ids": list(buckets[b_slug]),
        "hit_count": len(buckets[b_slug]),
        "hypothesis": (data.get("bucket_hypotheses") or {}).get(b_slug, ""),
    }


def resolve_bucket_hit_ids(snapshot_slug: str, bucket_name: str) -> set[int]:
    """Strict resolver for downstream integrations.

    Returns the set of hit_ids for a bucket, raising ``BucketNotFoundError``
    / ``SnapshotNotFoundError`` with an explanatory message on any typo.
    Downstream tools (slice_timeline, build_entity_graph, generate_report)
    should use this so a missing bucket surfaces immediately rather than
    producing a silently-empty filter.
    """
    _, data = _read_snapshot_raw(snapshot_slug)
    b_slug = _slug(bucket_name)
    buckets = data.get("tagged_hits_by_bucket") or {}
    if b_slug not in buckets:
        known = sorted(buckets.keys())
        raise BucketNotFoundError(
            f"Bucket {bucket_name!r} not in snapshot '{data['slug']}'. "
            f"Known buckets: {known}"
        )
    return set(buckets[b_slug])


def delete_snapshot(slug: str) -> dict[str, Any]:
    _ensure_dir()
    path = os.path.join(_STATE_DIR, _slug(slug) + ".json")
    if not os.path.exists(path):
        return {"ok": False, "error": f"Snapshot not found: {slug}"}
    os.remove(path)
    return {"ok": True, "deleted": path}
