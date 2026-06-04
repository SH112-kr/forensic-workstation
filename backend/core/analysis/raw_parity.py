from __future__ import annotations

from typing import Any


def compare_search_parity(
    reference_connector: Any,
    raw_connector: Any,
    *,
    keyword: str,
    artifact_type: str = "",
    limit: int = 1000,
) -> dict[str, Any]:
    filters = {"artifact_type": artifact_type} if artifact_type else {}
    reference = _collect_complete_search(
        reference_connector,
        keyword=keyword,
        filters=filters,
        limit=limit,
    )
    reference_gap = _input_gap(reference, "reference")
    if reference_gap:
        reference_gap = dict(reference_gap)
        reference_gap["skipped_side"] = "raw"
        return _not_evaluable_result(
            keyword=keyword,
            artifact_type=artifact_type,
            reference=reference,
            raw=None,
            gap=reference_gap,
        )
    raw = _collect_complete_search(
        raw_connector,
        keyword=keyword,
        filters=filters,
        limit=limit,
    )
    gap = _input_gap(raw, "raw")
    if gap:
        return _not_evaluable_result(
            keyword=keyword,
            artifact_type=artifact_type,
            reference=reference,
            raw=raw,
            gap=gap,
        )

    reference_keys = {_stable_hit_key(hit) for hit in reference.get("hits", [])}
    raw_keys = {_stable_hit_key(hit) for hit in raw.get("hits", [])}
    missing = sorted(reference_keys - raw_keys)
    extra = sorted(raw_keys - reference_keys)
    return {
        "ok": True,
        "parity_status": "matched" if not missing else "gap_detected",
        "keyword": keyword,
        "artifact_type": artifact_type,
        "reference_total": _result_total(reference),
        "raw_total": _result_total(raw),
        "missing_in_raw": missing,
        "extra_in_raw": extra,
        "strong_conclusion_allowed": not missing,
        "notes": [
            "A raw parity gap means the raw index is not yet a drop-in replacement for this query.",
            "Do not remove the reference connector for this artifact family until parity gaps are resolved.",
        ],
    }


def _not_evaluable_result(
    *,
    keyword: str,
    artifact_type: str,
    reference: dict[str, Any],
    raw: dict[str, Any] | None,
    gap: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": False,
        "parity_status": "not_evaluable",
        "keyword": keyword,
        "artifact_type": artifact_type,
        "reference_total": _result_total(reference),
        "raw_total": _result_total(raw) if raw is not None else None,
        "missing_in_raw": [],
        "extra_in_raw": [],
        "strong_conclusion_allowed": False,
        "coverage_gap": gap,
        "notes": [
            "Parity cannot be evaluated from truncated, estimated, or coverage-gap input.",
        ],
    }


def _collect_complete_search(
    connector: Any,
    *,
    keyword: str,
    filters: dict[str, Any],
    limit: int,
) -> dict[str, Any]:
    safe_limit = max(1, int(limit))
    offset = 0
    collected_hits: list[dict[str, Any]] = []
    merged: dict[str, Any] | None = None
    total = 0
    while True:
        result = connector.search(
            keyword=keyword,
            filters=filters,
            limit=safe_limit,
            offset=offset,
        )
        if _blocking_input_gap(result):
            return result
        if merged is None:
            merged = dict(result)
            total = _result_total(result)
        page_hits = list(result.get("hits", []))
        returned = int(result.get("returned", len(page_hits)) or 0)
        if offset + returned > total:
            gap_result = dict(result)
            gap_result["pagination_gap"] = {
                "reason": "pagination_inconsistent",
                "offset": offset,
                "returned": returned,
                "total": total,
            }
            gap_result["truncated"] = True
            return gap_result
        collected_hits.extend(page_hits)
        if result.get("truncated") and returned < safe_limit:
            return result
        offset += returned
        if returned <= 0 or offset >= total or not result.get("truncated"):
            break
    if merged is None:
        return {"total": 0, "hits": [], "returned": 0, "truncated": False}
    merged["hits"] = collected_hits
    merged["returned"] = len(collected_hits)
    merged["truncated"] = total > len(collected_hits)
    return merged


def _input_gap(result: dict[str, Any], side: str) -> dict[str, Any] | None:
    blocking_gap = _blocking_input_gap(result)
    if blocking_gap:
        blocking_gap["side"] = side
        return blocking_gap
    total = _result_total(result)
    returned = int(result.get("returned", len(result.get("hits", []))) or 0)
    if result.get("truncated") or total > returned:
        return {
            "side": side,
            "reason": "truncated_input",
            "total": total,
            "returned": returned,
        }
    if result.get("total_is_estimated") is True:
        return {
            "side": side,
            "reason": "estimated_count",
            "total": total,
            "returned": returned,
        }
    coverage = result.get("coverage")
    if isinstance(coverage, dict) and coverage.get("status") in {
        "coverage_gap",
        "not_evaluable",
    }:
        return {
            "side": side,
            "reason": "coverage_gap",
            "coverage": coverage,
        }
    return None


def _blocking_input_gap(result: dict[str, Any]) -> dict[str, Any] | None:
    pagination_gap = result.get("pagination_gap")
    if isinstance(pagination_gap, dict):
        return dict(pagination_gap)
    total = _result_total(result)
    returned = int(result.get("returned", len(result.get("hits", []))) or 0)
    if result.get("total_is_estimated") is True:
        return {
            "reason": "estimated_count",
            "total": total,
            "returned": returned,
        }
    coverage = result.get("coverage")
    if isinstance(coverage, dict) and coverage.get("status") in {
        "coverage_gap",
        "not_evaluable",
    }:
        return {
            "reason": "coverage_gap",
            "coverage": coverage,
        }
    return None


def _result_total(result: dict[str, Any]) -> int:
    return int(result.get("total", len(result.get("hits", []))) or 0)


def _stable_hit_key(hit: dict[str, Any]) -> str:
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    for key in ("Path", "Full Path", "File Path", "URL", "Name"):
        if fields.get(key):
            return str(fields[key]).lower()
    return str(
        hit.get("location")
        or hit.get("source_path")
        or hit.get("path")
        or hit.get("hit_id", "")
    ).lower()
