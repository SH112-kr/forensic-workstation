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
    reference = reference_connector.search(
        keyword=keyword,
        filters=filters,
        limit=limit,
        offset=0,
    )
    raw = raw_connector.search(
        keyword=keyword,
        filters=filters,
        limit=limit,
        offset=0,
    )
    gap = _input_gap(reference, "reference") or _input_gap(raw, "raw")
    if gap:
        return {
            "ok": False,
            "parity_status": "not_evaluable",
            "keyword": keyword,
            "artifact_type": artifact_type,
            "reference_total": _result_total(reference),
            "raw_total": _result_total(raw),
            "missing_in_raw": [],
            "extra_in_raw": [],
            "strong_conclusion_allowed": False,
            "coverage_gap": gap,
            "notes": [
                "Parity cannot be evaluated from truncated, estimated, or coverage-gap input.",
            ],
        }

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


def _input_gap(result: dict[str, Any], side: str) -> dict[str, Any] | None:
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
