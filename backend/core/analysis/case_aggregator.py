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

from typing import Any, Callable, Iterable


def iter_cases(connectors: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return ``(case_id, connector)`` for every connected axiom:* case.

    A list rather than a generator so callers can iterate multiple times (e.g.
    once for metadata, once for counts) without reopening the connector dict.
    """
    cases: list[tuple[str, Any]] = []
    for name, c in connectors.items():
        if not name.startswith("axiom:"):
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        cases.append((name.replace("axiom:", ""), c))
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
            results.append({**provenance, "ok": False, "error": str(e)})
            warnings.append(f"{case_id}: {e}")
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
    results, warnings = safe_collect(
        cases,
        lambda cid, c: c.get_artifact_type_counts() or [],
    )

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

    return {
        "ok": True,
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
    return {
        "ok": True,
        "case_count": meta["case_count"],
        "metadata": meta["results"],
        "artifact_counts": {
            "matrix": counts["matrix"],
            "families": counts["families"],
            "totals": counts["totals"],
        },
        "warnings": sorted(set(meta["warnings"] + counts["warnings"])),
    }
