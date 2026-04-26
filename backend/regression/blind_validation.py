"""Blind-first validation helpers for public DFIR scenarios.

The workflow is:
1. Register dataset metadata and evidence paths without loading answer keys.
2. Save the framework's analysis result as the blind result.
3. Reveal and compare against the answer key in a separate step.

This prevents development-time leakage from answer keys into the analysis path.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "fw.blind_validation.v1"


def write_blind_result(
    output_path: str | Path,
    *,
    dataset_id: str,
    evidence_paths: list[str],
    analysis_result: dict[str, Any],
    notes: list[str] | None = None,
) -> dict[str, Any]:
    record = {
        "schema_version": SCHEMA_VERSION,
        "phase": "blind_analysis",
        "dataset_id": dataset_id,
        "created_at": _now(),
        "evidence_paths": list(evidence_paths),
        "answer_key_loaded": False,
        "analysis_result": analysis_result,
        "notes": notes or [],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return record


def reveal_against_answer_key(
    blind_result_path: str | Path,
    answer_key: dict[str, Any],
    output_path: str | Path,
) -> dict[str, Any]:
    blind = json.loads(Path(blind_result_path).read_text(encoding="utf-8"))
    if blind.get("answer_key_loaded"):
        raise ValueError("Blind result already indicates an answer key was loaded")
    comparison = _compare(blind.get("analysis_result", {}), answer_key)
    record = {
        "schema_version": SCHEMA_VERSION,
        "phase": "revealed_comparison",
        "dataset_id": blind.get("dataset_id"),
        "created_at": _now(),
        "blind_result_path": str(blind_result_path),
        "answer_key_loaded_after_blind": True,
        "comparison": comparison,
        "answer_key_summary": _safe_answer_summary(answer_key),
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return record


def _compare(analysis: dict[str, Any], answer_key: dict[str, Any]) -> dict[str, Any]:
    expected = set(_norm_items(answer_key.get("expected_findings", [])))
    observed = set(_norm_items(analysis.get("findings", [])))
    if not observed:
        observed = set(_norm_items(analysis.get("stages", [])))
    if not observed and analysis.get("verdict"):
        observed = {_norm(analysis.get("verdict"))}
    matched = sorted(expected & observed)
    missed = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    return {
        "ok": not missed,
        "expected_count": len(expected),
        "observed_count": len(observed),
        "matched": matched,
        "missed": missed,
        "unexpected": unexpected,
    }


def _safe_answer_summary(answer_key: dict[str, Any]) -> dict[str, Any]:
    return {
        "expected_count": len(answer_key.get("expected_findings", []) or []),
        "source": answer_key.get("source", ""),
        "loaded_after_blind": True,
    }


def _norm_items(items: list[Any]) -> list[str]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            value = item.get("id") or item.get("name") or item.get("finding") or item.get("stage")
        else:
            value = item
        text = _norm(value)
        if text:
            out.append(text)
    return out


def _norm(value: Any) -> str:
    return str(value or "").lower().replace("_", " ").replace("-", " ").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
