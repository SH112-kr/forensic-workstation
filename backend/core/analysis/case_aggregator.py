"""Cross-case aggregation helpers.

Everything here runs purely against connectors already resident in
``app_state``; no network calls and no mutation. All callers get the same
three guarantees spelled out in the roadmap:

1. **Provenance** — every result item carries ``case_id`` / ``source_type`` /
   ``source_path`` so downstream tools can route back to the per-case detail.
2. **Partial-failure contract** — a single case timeout or disconnect never
   fails the whole call. Callers inspect per-case ``ok``/``error`` status.
3. **Merged pagination stays deterministic** — callers that merge results
   fetch ``limit_per_case × pages_needed`` rows up front, then sort once
   globally, then slice. Nothing paginates across cases lazily.

This module is the substrate for ``compare_cases`` and later
``pivot_across_cases`` / ``search_across_cases`` / ``timeline_across_cases``.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Iterable


def iter_cases(connectors: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return ``(case_id, connector)`` for every connected case connector.

    A list rather than a generator so callers can iterate multiple times (e.g.
    once for metadata, once for counts) without reopening the connector dict.
    """
    cases: list[tuple[str, Any]] = []
    for name, c in connectors.items():
        if name.startswith("axiom:"):
            case_id = name.replace("axiom:", "", 1)
        elif name == "raw_index":
            case_id = "raw_index"
        else:
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        cases.append((case_id, c))
    return cases


def _case_provenance(case_id: str, connector: Any) -> dict[str, str]:
    """Pull the provenance block used on every result object."""
    try:
        meta = connector.get_metadata() or {}
    except Exception:
        meta = {}
    return {
        "case_id": case_id,
        "source_type": str(meta.get("source_type") or "").lower(),
        "source_path": meta.get("source_path", ""),
    }


def safe_collect(
    cases: Iterable[tuple[str, Any]],
    fn: Callable[[str, Any], Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run ``fn(case_id, connector)`` per case with partial-failure handling.

    Returns ``(results, warnings)``:
    - ``results`` — one entry per case with ``{case_id, ok, data?|error?}``
      plus provenance merged in so callers never have to re-derive it.
    - ``warnings`` — human-readable notes (e.g. "case X disconnected").
    """
    results: list[dict[str, Any]] = []
    warnings: list[str] = []

    for case_id, connector in cases:
        provenance = _case_provenance(case_id, connector)
        try:
            data = fn(case_id, connector)
        except Exception as e:  # noqa: BLE001 — translate any failure into envelope
            results.append({
                **provenance,
                "ok": False,
                "status": "not_evaluable",
                "error": str(e),
            })
            warnings.append(f"{case_id}: {e}")
            continue
        if isinstance(data, dict) and data.get("ok") is False:
            status = str(data.get("status") or "not_evaluable")
            error = str(data.get("error") or status)
            results.append({
                **provenance,
                "ok": False,
                "status": status,
                "error": error,
                "coverage": data.get("coverage"),
                "data": data,
            })
            warnings.append(f"{case_id}: {error}")
            continue
        results.append({**provenance, "ok": True, "data": data})

    return results, warnings


def aggregate_metadata(connectors: dict[str, Any]) -> dict[str, Any]:
    """Return metadata for every loaded case wrapped in the standard envelope."""
    cases = iter_cases(connectors)
    results, warnings = safe_collect(
        cases,
        lambda cid, c: c.get_metadata(),
    )
    return {
        "ok": True,
        "case_count": len(cases),
        "results": results,
        "warnings": warnings,
    }


def aggregate_artifact_counts(connectors: dict[str, Any]) -> dict[str, Any]:
    """Build a family × case matrix of hit counts across every loaded case.

    Returns::

        {
          ok: True,
          case_count: int,
          results: [per-case envelopes with raw type counts],
          matrix: {family_name: {case_id: count}},
          families: [sorted list of every family that appeared in any case],
          totals: {family_name: sum_of_counts_across_cases},
          warnings: [...],
        }
    """
    cases = iter_cases(connectors)
    def _run_counts(case_id: str, connector: Any) -> Any:
        counts = connector.get_artifact_type_counts() or []
        coverage_getter = getattr(connector, "get_coverage", None)
        if callable(coverage_getter):
            coverage = coverage_getter() or {}
            if isinstance(coverage, dict) and coverage.get("status") in {
                "not_evaluable",
                "coverage_gap",
            }:
                return {
                    "ok": False,
                    "status": coverage.get("status"),
                    "error": coverage.get("status"),
                    "coverage": coverage,
                    "artifact_type_counts": counts,
                }
        return counts

    results, warnings = safe_collect(cases, _run_counts)

    matrix: dict[str, dict[str, int]] = {}
    totals: dict[str, int] = {}
    for r in results:
        if not r.get("ok"):
            continue
        case_id = r["case_id"]
        for row in r.get("data", []) or []:
            fam = row.get("artifact_name") or row.get("artifact_type") or row.get("name")
            cnt = int(row.get("hit_count") or row.get("count") or 0)
            if not fam:
                continue
            matrix.setdefault(fam, {})[case_id] = matrix.get(fam, {}).get(case_id, 0) + cnt
            totals[fam] = totals.get(fam, 0) + cnt

    families = sorted(matrix.keys(), key=lambda f: (-totals.get(f, 0), f))
    result_status = _aggregate_status(results)

    return {
        "ok": result_status == "searched",
        **({"status": result_status} if result_status != "searched" else {}),
        "case_count": len(cases),
        "results": results,
        "matrix": matrix,
        "families": families,
        "totals": totals,
        "warnings": warnings,
    }


def compare_cases(connectors: dict[str, Any]) -> dict[str, Any]:
    """Return both metadata and artifact-count matrix in a single envelope."""
    meta = aggregate_metadata(connectors)
    counts = aggregate_artifact_counts(connectors)
    result_status = _aggregate_status(counts.get("results", []))
    return {
        "ok": result_status == "searched",
        **({"status": result_status} if result_status != "searched" else {}),
        "case_count": meta["case_count"],
        "metadata": meta["results"],
        "artifact_counts": {
            "matrix": counts["matrix"],
            "families": counts["families"],
            "totals": counts["totals"],
            "results": counts["results"],
        },
        "warnings": sorted(set(meta["warnings"] + counts["warnings"])),
    }


# ── Cross-case fan-out: search / timeline / hash / pivot ──

def _tag_hits_with_provenance(hits: list[dict[str, Any]], provenance: dict[str, str]) -> list[dict[str, Any]]:
    """Return a copy of each hit with the per-case provenance fields merged in.

    We never mutate the original hit so the connector's result stays untouched
    for other callers.
    """
    tagged = []
    for h in hits or []:
        tagged.append({**h, **provenance})
    return tagged


def _hit_sort_key(h: dict[str, Any]) -> tuple:
    """Deterministic sort key: earliest timestamp first, then case_id, then hit_id."""
    ts = h.get("timestamp") or ""
    # Empty-timestamp rows sort at the end, which is the right default when a
    # case carries hits without parsable dates.
    bucket = 1 if not ts else 0
    return (bucket, ts, str(h.get("case_id", "")), int(h.get("hit_id", 0) or 0))


def search_across_cases(
    connectors: dict[str, Any],
    keyword: str = "",
    artifact_type: str = "",
    start_date: str = "",
    end_date: str = "",
    limit_per_case: int = 100,
    global_limit: int = 200,
    global_offset: int = 0,
) -> dict[str, Any]:
    """Fan-out keyword/filter search across every loaded case.

    Per-case result envelopes carry ``ok``/``error`` so partial failures do not
    poison the merged view. The merged page is produced with:
    fetch ``limit_per_case`` per case → tag with provenance → sort globally →
    slice ``[global_offset : global_offset + global_limit]``.
    """
    cases = iter_cases(connectors)

    def _run(case_id: str, connector: Any) -> dict[str, Any]:
        return connector.search(
            keyword=keyword,
            filters={"artifact_type": artifact_type, "start_date": start_date, "end_date": end_date},
            limit=limit_per_case,
            offset=0,
        )

    per_case, warnings = safe_collect(cases, _run)

    merged: list[dict[str, Any]] = []
    per_case_totals: dict[str, int] = {}
    for env in per_case:
        if not env.get("ok"):
            continue
        provenance = {k: env[k] for k in ("case_id", "source_type", "source_path")}
        payload = env.get("data", {}) or {}
        hits = payload.get("hits", []) or []
        merged.extend(_tag_hits_with_provenance(hits, provenance))
        per_case_totals[env["case_id"]] = int(payload.get("total") or payload.get("total_estimated") or 0)

    merged.sort(key=_hit_sort_key)
    sliced = merged[global_offset : global_offset + global_limit]
    result_status = _aggregate_status(per_case)

    return {
        "ok": result_status == "searched",
        **({"status": result_status} if result_status != "searched" else {}),
        "query": {
            "keyword": keyword,
            "artifact_type": artifact_type,
            "start_date": start_date,
            "end_date": end_date,
        },
        "case_count": len(cases),
        "per_case": per_case,
        "per_case_totals": per_case_totals,
        "merged_total": len(merged),
        "global_offset": global_offset,
        "global_limit": global_limit,
        "returned": len(sliced),
        "hits": sliced,
        "warnings": warnings,
    }


def timeline_across_cases(
    connectors: dict[str, Any],
    start_date: str = "",
    end_date: str = "",
    artifact_types: list[str] | None = None,
    keywords: list[str] | None = None,
    limit_per_case: int = 200,
    global_limit: int = 500,
    global_offset: int = 0,
) -> dict[str, Any]:
    """Fan-out timeline construction across every loaded case.

    Same contract as ``search_across_cases`` — provenance on every event,
    per-case envelopes for partial failures, global-sort-then-slice paging.
    """
    cases = iter_cases(connectors)

    def _run(case_id: str, connector: Any) -> dict[str, Any]:
        if keywords:
            try:
                supports_keywords = (
                    "keywords"
                    in inspect.signature(connector.get_timeline).parameters
                )
            except (TypeError, ValueError):
                supports_keywords = False
            if not supports_keywords:
                return {
                    "ok": False,
                    "status": "not_evaluable",
                    "error": "timeline_keyword_filter_not_supported",
                    "coverage": {
                        "status": "not_evaluable",
                        "gaps": [{
                            "reason": "timeline_keyword_filter_not_supported",
                            "keywords": keywords,
                        }],
                    },
                }
            return connector.get_timeline(
                start_date=start_date,
                end_date=end_date,
                artifact_types=artifact_types,
                keywords=keywords,
                limit=limit_per_case,
                offset=0,
            )
        return connector.get_timeline(
            start_date=start_date,
            end_date=end_date,
            artifact_types=artifact_types,
            limit=limit_per_case,
            offset=0,
        )

    per_case, warnings = safe_collect(cases, _run)

    merged: list[dict[str, Any]] = []
    per_case_totals: dict[str, int] = {}
    for env in per_case:
        if not env.get("ok"):
            continue
        provenance = {k: env[k] for k in ("case_id", "source_type", "source_path")}
        payload = env.get("data", {}) or {}
        entries = payload.get("entries", []) or payload.get("events", []) or []
        merged.extend(_tag_hits_with_provenance(entries, provenance))
        per_case_totals[env["case_id"]] = int(
            payload.get("total_events")
            or payload.get("total")
            or len(entries)
        )

    merged.sort(key=_hit_sort_key)
    sliced = merged[global_offset : global_offset + global_limit]
    result_status = _aggregate_status(per_case)
    merged_total = sum(per_case_totals.values())

    return {
        "ok": result_status == "searched",
        **({"status": result_status} if result_status != "searched" else {}),
        "query": {
            "start_date": start_date,
            "end_date": end_date,
            "artifact_types": artifact_types or [],
            "keywords": keywords or [],
        },
        "case_count": len(cases),
        "per_case": per_case,
        "per_case_totals": per_case_totals,
        "merged_total": merged_total,
        "global_offset": global_offset,
        "global_limit": global_limit,
        "returned": len(sliced),
        "entries": sliced,
        "warnings": warnings,
    }


def hash_across_cases(
    connectors: dict[str, Any],
    hash_value: str,
    limit_per_case: int = 50,
) -> dict[str, Any]:
    """Look up a hash across every loaded case and return merged hits."""
    cases = iter_cases(connectors)

    def _run(case_id: str, connector: Any) -> dict[str, Any]:
        return connector.search_by_hash(hash_value, limit=limit_per_case, offset=0)

    per_case, warnings = safe_collect(cases, _run)

    merged: list[dict[str, Any]] = []
    for env in per_case:
        if not env.get("ok"):
            continue
        provenance = {k: env[k] for k in ("case_id", "source_type", "source_path")}
        payload = env.get("data", {}) or {}
        hits = payload.get("hits", []) or []
        merged.extend(_tag_hits_with_provenance(hits, provenance))

    merged.sort(key=_hit_sort_key)
    result_status = _aggregate_status(per_case)

    return {
        "ok": result_status == "searched",
        **({"status": result_status} if result_status != "searched" else {}),
        "query": {"hash": hash_value},
        "case_count": len(cases),
        "per_case": per_case,
        "total": len(merged),
        "hits": merged,
        "warnings": warnings,
    }


_ENTITY_TYPES = {"hash", "ip", "username", "filename", "path", "keyword"}


def pivot_across_cases(
    connectors: dict[str, Any],
    entity_type: str,
    entity_value: str,
    window_minutes: int = 60,
    limit_per_case: int = 100,
    match_key: str = "raw",
) -> dict[str, Any]:
    """Pivot on an entity (hash/ip/username/filename/path/keyword) across cases.

    Reuses ``hash_across_cases`` for hashes and ``search_across_cases`` for
    string entities. Returns per-case and merged views plus first/last-seen
    markers so an analyst can quickly see where the entity first surfaces and
    whether it crosses cases. ``window_minutes`` is accepted for future
    clustering — v1 returns raw merged hits without temporal clustering.

    Fully offline: only reads already-loaded connectors.
    """
    etype = (entity_type or "").strip().lower()
    evalue = (entity_value or "").strip()
    if etype not in _ENTITY_TYPES:
        return {
            "ok": False,
            "error": f"Unsupported entity_type {entity_type!r}; expected one of {sorted(_ENTITY_TYPES)}",
        }
    if not evalue:
        return {"ok": False, "error": "entity_value is empty"}

    if etype == "hash":
        base = hash_across_cases(connectors, evalue, limit_per_case=limit_per_case)
        merged = base.get("hits", []) or []
    else:
        base = search_across_cases(
            connectors,
            keyword=evalue,
            limit_per_case=limit_per_case,
            global_limit=limit_per_case * max(1, base_case_count(connectors)),
        )
        merged = base.get("hits", []) or []

    per_case_counts: dict[str, int] = {}
    first_seen: dict[str, Any] | None = None
    last_seen: dict[str, Any] | None = None
    for h in merged:
        cid = h.get("case_id", "")
        per_case_counts[cid] = per_case_counts.get(cid, 0) + 1
        ts = h.get("timestamp") or ""
        if ts:
            if first_seen is None or ts < first_seen.get("timestamp", ""):
                first_seen = {"case_id": cid, "timestamp": ts, "hit_id": h.get("hit_id")}
            if last_seen is None or ts > last_seen.get("timestamp", ""):
                last_seen = {"case_id": cid, "timestamp": ts, "hit_id": h.get("hit_id")}

    # Optional normalization — Codex Round-5 discipline: raw is the default,
    # 'strict' is safe Tier-1 (case/whitespace), 'loose' invokes Tier-2 with an
    # explicit warning both on the envelope AND on each affected hit so
    # misuse is visible at every scope.
    match_warnings: list[str] = []
    match_notes: dict[str, Any] = {"mode": match_key, "warnings": []}
    if match_key in ("strict", "loose"):
        from core.analysis import normalization as _norm
        t2_kind = None
        if match_key == "loose":
            if etype in ("username", "user"):
                t2_kind = "user_bare"
            elif etype in ("filename", "path"):
                t2_kind = "path_basename"
            elif etype in ("ip", "host", "hostname"):
                t2_kind = "host_first_label"
        for h in merged:
            raw_value = h.get("fields", {}).get("ImageFileName") if isinstance(h.get("fields"), dict) else None
            # Pick a best-effort field to normalize based on entity type.
            candidate = evalue
            normalized = _norm.safe_trim(candidate).lower()
            h["normalized_value"] = normalized
            h["normalized_rule"] = "safe_display"
            if t2_kind:
                verdict = _norm.apply_match_key(t2_kind, candidate)
                h["normalized_value"] = verdict["value"]
                h["normalized_rule"] = verdict["rule"]
                if verdict.get("warning"):
                    h["normalized_warning"] = verdict["warning"]
                    if verdict["warning"] not in match_warnings:
                        match_warnings.append(verdict["warning"])
        match_notes["warnings"] = match_warnings

    return {
        "ok": bool(base.get("ok", True)),
        **({"status": base["status"]} if base.get("status") else {}),
        "entity": {"type": etype, "value": evalue},
        "case_count": base.get("case_count", 0),
        "per_case": base.get("per_case", []),
        "per_case_counts": per_case_counts,
        "total": len(merged),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "hits": merged[: limit_per_case * 4],
        "warnings": list(base.get("warnings", [])) + match_warnings,
        "match_key": match_notes,
        "window_minutes": window_minutes,
    }


def base_case_count(connectors: dict[str, Any]) -> int:
    """Small utility so callers can size limits from the number of loaded cases."""
    return len(iter_cases(connectors))


def _aggregate_status(per_case: list[dict[str, Any]]) -> str:
    statuses = {
        str(env.get("status") or "")
        for env in per_case
        if env.get("ok") is False
    }
    if "not_evaluable" in statuses:
        return "not_evaluable"
    if "coverage_gap" in statuses:
        return "coverage_gap"
    return "searched"
