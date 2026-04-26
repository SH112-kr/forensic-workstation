"""Evidence quality and legal-defensibility scoring.

This is intentionally conservative. It does not certify evidence; it records
why a conclusion is strong or weak from a reproducibility and corroboration
perspective.
"""

from __future__ import annotations

from typing import Any


SOURCE_TIERS = {
    "e01": 1,
    "ex01": 1,
    "raw": 1,
    "dd": 1,
    "mfdb": 2,
    "axiom": 2,
    "kape": 3,
    "fixture": 4,
    "live": 5,
    "unknown": 9,
}


def build_evidence_quality_surface(
    connector: Any,
    detection_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    detection_payload = detection_payload or {}
    meta = _safe_metadata(connector)
    source_type = str(meta.get("source_type") or "unknown").lower()
    tier = _source_tier(source_type)

    warnings: list[dict[str, Any]] = []
    finding_scores: list[dict[str, Any]] = []
    for finding in detection_payload.get("findings", []) or []:
        supporting = finding.get("supporting_artifacts") or []
        source_count = len({s.get("artifact_type") for s in supporting if s.get("artifact_type")})
        absent = finding.get("absent_corroboration") or []
        single_source = source_count <= 1
        if single_source:
            warnings.append({
                "code": "SINGLE_SOURCE_UNVERIFIED",
                "rule_name": finding.get("rule_name", ""),
                "message": "Finding is supported by one artifact family or less.",
            })
        if absent:
            warnings.append({
                "code": "MISSING_CORROBORATION",
                "rule_name": finding.get("rule_name", ""),
                "message": f"{len(absent)} corroborating artifact families are absent or unavailable.",
            })
        finding_scores.append({
            "rule_name": finding.get("rule_name", ""),
            "source_family_count": source_count,
            "single_source": single_source,
            "missing_corroboration": len(absent),
            "defensibility": _defensibility_label(source_count, len(absent), tier),
        })

    return {
        "evidence_quality": {
            "source_type": source_type,
            "source_tier": tier,
            "source_path": meta.get("source_path", ""),
            "finding_scores": finding_scores,
            "warnings": warnings,
            "legal_defensibility_notes": [
                "Every final report claim should cite artifact_id/hit_id and parser/tool version where available.",
                "Single-source findings should remain hypotheses until corroborated by an independent artifact family.",
                "Source tier is an input-quality hint, not a substitute for corroboration.",
            ],
        }
    }


def _safe_metadata(connector: Any) -> dict[str, Any]:
    try:
        return connector.get_metadata() or {}
    except Exception:
        return {}


def _source_tier(source_type: str) -> int:
    for key, tier in SOURCE_TIERS.items():
        if key in source_type:
            return tier
    return SOURCE_TIERS["unknown"]


def _defensibility_label(source_count: int, missing_corroboration: int, source_tier: int) -> str:
    if source_count >= 2 and missing_corroboration == 0 and source_tier <= 3:
        return "strong"
    if source_count >= 2 and source_tier <= 4:
        return "moderate"
    if source_count == 1:
        return "weak_single_source"
    return "incomplete"
