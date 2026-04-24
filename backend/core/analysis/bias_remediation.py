"""Bias remediation helpers — feature flag and lane evidence summary surface."""

from __future__ import annotations

import os
import sys
from typing import Any


_DISABLE_ENV_VAR = "FW_BIAS_REMEDIATION_DISABLE"


def is_bias_remediation_enabled() -> bool:
    """Return True unless the remediation surface is explicitly disabled."""
    raw = str(os.environ.get(_DISABLE_ENV_VAR, "") or "").strip().lower()
    return raw not in {"1", "true", "yes", "on"}


def build_lane_evidence_summary_surface(
    connector: Any,
    *,
    triage_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the lane_evidence_summary from initial_triage or surface an error."""
    if not is_bias_remediation_enabled():
        return {}

    try:
        if triage_payload is None:
            triage_mod = (
                sys.modules.get("analysis.initial_triage")
                or sys.modules.get("core.analysis.initial_triage")
            )
            if triage_mod is None:
                from core.analysis import initial_triage as triage_mod
            triage_payload = triage_mod.initial_triage(connector, scope_mode="recent_14d")

        return {
            "lane_evidence_summary": (triage_payload or {}).get("lane_evidence_summary", {}) or {},
        }
    except Exception as e:
        return {"lane_evidence_summary": {"error": str(e)}}
