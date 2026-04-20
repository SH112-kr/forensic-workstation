"""Case health model — can the analyst trust the substrate of this investigation?

Runs a small deterministic suite of checks over every loaded case and
reports one envelope with:
  - overall_status:  blocked / degraded / healthy_with_notes / healthy
  - checks[]:        per-check record (severity, passed, detail, metrics)

Rolling rules (deterministic, transparent):
  - Any critical check failed          -> blocked
  - Else any high check failed         -> degraded
  - Else any medium/low check failed   -> healthy_with_notes
  - Else (all checks pass)             -> healthy

Every check is a pure function of connector metadata + artifact type
counts. No detection logic, no incident-specific heuristics. Numeric
thresholds are published on the response so the analyst can audit why a
check passed or failed. Check names are stable so downstream tooling can
pin behaviour by name.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# High-value families: a DFIR case that is completely empty of these is
# almost always a collection / parsing problem, not a truly quiet endpoint.
# Kept short and hand-curated; matched via substring (loose) because
# connector names carry sub-variants like "Prefetch Files - Windows 8/10/11".
HIGH_VALUE_FAMILIES = (
    "Windows Event Logs",
    "Prefetch",
    "AmCache",
    "System Services",
    "Scheduled Tasks",
)

# Thresholds — published on every response.
THRESHOLDS = {
    "evtx_thinness_min_rows": 100,
    "evtx_thinness_min_span_days": 7,
    "timezone_drift_tolerance_days": 365,
    "case_date_future_tolerance_days": 365,
}


def _iter_cases(connectors: dict[str, Any]) -> list[tuple[str, Any]]:
    out = []
    for name, c in (connectors or {}).items():
        if not name.startswith("axiom:"):
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        out.append((name.replace("axiom:", ""), c))
    return out


def _family_present(family: str, type_counts: dict[str, int]) -> bool:
    fam = family.lower()
    for name, cnt in type_counts.items():
        if cnt > 0 and fam in name.lower():
            return True
    return False


def _family_row_count(family: str, type_counts: dict[str, int]) -> int:
    fam = family.lower()
    return sum(cnt for name, cnt in type_counts.items() if fam in name.lower())


def _meta(c: Any) -> dict[str, Any]:
    try:
        return c.get_metadata() or {}
    except Exception:
        return {}


def _counts(c: Any) -> dict[str, int]:
    try:
        rows = c.get_artifact_type_counts() or []
    except Exception:
        return {}
    out: dict[str, int] = {}
    for r in rows:
        name = r.get("artifact_name") or r.get("artifact_type") or r.get("name")
        cnt = int(r.get("hit_count") or r.get("count") or 0)
        if name:
            out[name] = out.get(name, 0) + cnt
    return out


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        s2 = str(s).replace(" ", "T").split(".")[0].rstrip("Z")
        return datetime.fromisoformat(s2).replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ── Individual checks ──────────────────────────────────────────────────────

def check_case_loaded(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    passed = bool(cases)
    return {
        "check_name": "case_loaded",
        "severity": "critical",
        "passed": passed,
        "detail": f"{len(cases)} case(s) connected." if passed else "No cases are connected.",
        "metrics": {"connected_cases": len(cases)},
        "suggested_action": None if passed else "Open at least one case via open_case / open_multi.",
    }


def check_case_date_range(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    horizon = datetime.now(timezone.utc) + timedelta(days=THRESHOLDS["case_date_future_tolerance_days"])
    for cid, c in cases:
        m = _meta(c)
        start = _parse_iso(m.get("date_range_start", ""))
        end = _parse_iso(m.get("date_range_end", ""))
        if not start or not end:
            issues.append(f"{cid}: missing date_range metadata")
            continue
        if start > end:
            issues.append(f"{cid}: date_range_start > date_range_end")
        if end > horizon:
            issues.append(f"{cid}: date_range_end {end.isoformat()} is beyond now+1y — clock drift suspected")
    passed = not issues
    return {
        "check_name": "case_date_range",
        "severity": "medium",
        "passed": passed,
        "detail": "All cases have a sensible date range." if passed else "; ".join(issues),
        "metrics": {"case_count": len(cases), "issue_count": len(issues)},
        "suggested_action": None if passed else
            "Check the source evidence's system clock. A case with corrupted date "
            "bounds may produce wrong timeline positions.",
    }


def check_high_value_families_empty(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, int] = {}
    for _, c in cases:
        for name, cnt in _counts(c).items():
            merged[name] = merged.get(name, 0) + cnt
    missing = [fam for fam in HIGH_VALUE_FAMILIES if not _family_present(fam, merged)]
    passed = not missing
    return {
        "check_name": "high_value_families_empty",
        "severity": "high",
        "passed": passed,
        "detail": (
            "Every high-value family has at least one row across the loaded cases."
            if passed else
            f"Missing entirely: {', '.join(missing)}"
        ),
        "metrics": {"missing_families": missing, "watched_families": list(HIGH_VALUE_FAMILIES)},
        "suggested_action": None if passed else
            "Verify collection completeness. Zero rows across every loaded case for "
            "a high-value family usually indicates a parser miss or incomplete KAPE run.",
    }


def check_kape_module_failures(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    # Connector metadata does not carry kape_diagnostics directly; the web UI
    # attaches it on demand. We probe core.kape_log_parser.get_diagnostics
    # for KAPE-typed cases where possible.
    total_failed = 0
    dotnet_errors = 0
    details: list[str] = []
    for cid, c in cases:
        m = _meta(c)
        if str(m.get("source_type", "")).lower() != "kape":
            continue
        src = m.get("source_path", "")
        if not src or not os.path.exists(src):
            continue
        try:
            from core.kape_log_parser import get_diagnostics
            diag = get_diagnostics(src)
        except Exception:
            continue
        if "error" in diag:
            continue
        failed = [m for m in diag.get("modules", []) if m.get("status", "").startswith("failed")]
        recovered_tools = {m.get("module") for m in diag.get("modules", []) if m.get("status") == "recovered"}
        # Drop failed modules that later recovered.
        failed = [m for m in failed if m.get("module") not in recovered_tools]
        total_failed += len(failed)
        dotnet_errors += diag.get("summary", {}).get("dotnet_errors", 0)
        if failed:
            details.append(f"{cid}: {len(failed)} failed module(s)")
    passed = total_failed == 0
    return {
        "check_name": "kape_module_failures",
        "severity": "high",
        "passed": passed,
        "detail": (
            "No KAPE module failures detected."
            if passed else "; ".join(details) or f"{total_failed} module failure(s)."
        ),
        "metrics": {"failed_modules": total_failed, "dotnet_errors": dotnet_errors},
        "suggested_action": None if passed else
            "Inspect the case's kape_diagnostics. .NET runtimeconfig issues are often "
            "fixable; other failures may indicate a thin parse.",
    }


def check_evtx_row_thinness(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    thin: list[str] = []
    min_rows = THRESHOLDS["evtx_thinness_min_rows"]
    min_span = THRESHOLDS["evtx_thinness_min_span_days"]
    for cid, c in cases:
        counts = _counts(c)
        evtx = _family_row_count("Windows Event Logs", counts)
        if evtx == 0:
            continue  # covered by high_value_families_empty
        m = _meta(c)
        start = _parse_iso(m.get("date_range_start", ""))
        end = _parse_iso(m.get("date_range_end", ""))
        if start and end and (end - start).days >= min_span and evtx < min_rows:
            thin.append(f"{cid}: only {evtx} EVTX rows over {(end - start).days} days")
    passed = not thin
    return {
        "check_name": "evtx_row_thinness",
        "severity": "medium",
        "passed": passed,
        "detail": (
            f"EVTX row counts look reasonable for the case span (threshold: "
            f">={min_rows} rows over {min_span}+ days)."
            if passed else "; ".join(thin)
        ),
        "metrics": {"thin_cases": thin, "thresholds": {
            "min_rows": min_rows, "min_span_days": min_span,
        }},
        "suggested_action": None if passed else
            "Suspiciously low EVTX volume relative to the case window. Check for "
            "truncation, log clearing, or incomplete collection.",
    }


def check_duplicate_source_paths(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    by_path: dict[str, list[str]] = {}
    for cid, c in cases:
        src = _meta(c).get("source_path", "")
        if src:
            by_path.setdefault(src.lower(), []).append(cid)
    dupes = {p: ids for p, ids in by_path.items() if len(ids) > 1}
    passed = not dupes
    return {
        "check_name": "duplicate_source_paths",
        "severity": "medium",
        "passed": passed,
        "detail": (
            "No two loaded cases share a source_path."
            if passed else
            "; ".join(f"{len(ids)} cases point at {p}" for p, ids in dupes.items())
        ),
        "metrics": {"duplicate_groups": [list(ids) for ids in dupes.values()]},
        "suggested_action": None if passed else
            "Duplicate evidence paths usually mean the same case was opened twice "
            "under different labels. Close one to avoid double-counting.",
    }


def check_timezone_drift(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    tol = THRESHOLDS["timezone_drift_tolerance_days"]
    issues: list[str] = []
    for cid, c in cases:
        m = _meta(c)
        start = _parse_iso(m.get("date_range_start", ""))
        end = _parse_iso(m.get("date_range_end", ""))
        if not start or not end:
            continue
        # Implausibly wide span flags likely epoch/TZ parsing bugs.
        if (end - start).days > tol * 5:
            issues.append(f"{cid}: span {(end - start).days} days exceeds sanity")
    passed = not issues
    return {
        "check_name": "timezone_drift",
        "severity": "low",
        "passed": passed,
        "detail": (
            f"All cases span <= {tol*5} days." if passed else "; ".join(issues)
        ),
        "metrics": {"issue_count": len(issues), "tolerance_days": tol},
        "suggested_action": None if passed else
            "An implausibly wide date range suggests a parser treated an epoch-0 or "
            "future sentinel as real. Inspect the outliers with get_hit_detail.",
    }


def check_substrate_readable(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    """Codex Round-8: every other check silently treats unreadable metadata /
    artifact counts as empty. That produces false-healthy rollups. This
    check probes each case directly and reports every failure explicitly so
    a broken connector cannot hide behind 'no issues found'."""
    failed: list[dict[str, str]] = []
    for cid, c in cases:
        try:
            c.get_metadata()
        except Exception as e:  # noqa: BLE001 — translate to audit record
            failed.append({"case_id": cid, "op": "get_metadata", "error": str(e)[:200]})
        try:
            c.get_artifact_type_counts()
        except Exception as e:  # noqa: BLE001
            failed.append({"case_id": cid, "op": "get_artifact_type_counts", "error": str(e)[:200]})
    passed = not failed
    return {
        "check_name": "substrate_readable",
        "severity": "high",
        "passed": passed,
        "detail": (
            "All cases expose readable metadata and artifact counts."
            if passed else
            "; ".join(f"{f['case_id']}.{f['op']}: {f['error']}" for f in failed)
        ),
        "metrics": {"failed_probes": failed},
        "suggested_action": None if passed else
            "Reopen the failing case. Later checks depend on metadata / counts "
            "and will silently underreport otherwise.",
    }


def check_allowlist_integrity(cases: list[tuple[str, Any]], connectors: dict[str, Any]) -> dict[str, Any]:
    try:
        from state import load_allowed_evidence, normalize_path
    except Exception:
        return {
            "check_name": "allowlist_integrity", "severity": "info",
            "passed": True, "detail": "Allowlist helper not importable; skipping.",
            "metrics": {}, "suggested_action": None,
        }
    allowed = set(load_allowed_evidence().get("paths", []))
    missing: list[str] = []
    for cid, c in cases:
        p = _meta(c).get("source_path", "")
        if not p:
            continue
        if normalize_path(p) not in allowed:
            missing.append(f"{cid}: {p}")
    passed = not missing
    return {
        "check_name": "allowlist_integrity",
        "severity": "info",
        "passed": passed,
        "detail": "All case source paths are in the allowlist." if passed else "; ".join(missing),
        "metrics": {"missing_from_allowlist": missing},
        "suggested_action": None if passed else
            "Cases outside the allowlist should not normally happen. Re-open via "
            "open_case / open_multi to re-register.",
    }


# ── Runner ────────────────────────────────────────────────────────────────

CHECKS = (
    check_case_loaded,
    check_substrate_readable,  # Runs early so later checks can trust metadata.
    check_case_date_range,
    check_high_value_families_empty,
    check_kape_module_failures,
    check_evtx_row_thinness,
    check_duplicate_source_paths,
    check_timezone_drift,
    check_allowlist_integrity,
)


def _roll_up(results: list[dict[str, Any]]) -> str:
    # Codex Round-8 contract fix: 'info' failures are telemetry and must
    # never change overall_status. Only medium/low failures flip the
    # rollup to healthy_with_notes.
    failed = [r for r in results if not r["passed"]]
    if any(r["severity"] == "critical" for r in failed):
        return "blocked"
    if any(r["severity"] == "high" for r in failed):
        return "degraded"
    if any(r["severity"] in {"medium", "low"} for r in failed):
        return "healthy_with_notes"
    return "healthy"


def case_health(connectors: dict[str, Any]) -> dict[str, Any]:
    """Run every check in CHECKS order and return the envelope."""
    cases = _iter_cases(connectors)
    results = [chk(cases, connectors) for chk in CHECKS]
    return {
        "ok": True,
        "overall_status": _roll_up(results),
        "case_count": len(cases),
        "thresholds": dict(THRESHOLDS),
        "checks": results,
        "high_value_families": list(HIGH_VALUE_FAMILIES),
        "notes": [
            "Each check publishes its exact criteria and metrics. Rolling rule: "
            "critical fail -> blocked; high fail -> degraded; any other fail -> "
            "healthy_with_notes; no failures -> healthy.",
            "Thresholds (evtx_thinness_min_rows, etc.) are shipped verbatim in the "
            "response so an analyst can see what counted as 'thin' or 'drift'.",
        ],
    }
