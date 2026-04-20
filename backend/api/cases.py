"""Case management API — open/close cases, get summary."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _build_kape_diagnostics(diag: dict) -> dict:
    """Build deduplicated KAPE diagnostics summary from raw log parse."""
    # Deduplicate modules (same tool runs multiple times for VSS)
    seen_failed: dict[str, str] = {}
    for m in diag["modules"]:
        if m["status"].startswith("failed") and m["module"] not in seen_failed:
            seen_failed[m["module"]] = m["errors"][0][:100] if m["errors"] else "unknown"
    seen_recovered: set[str] = set()
    for m in diag["modules"]:
        if m["status"] == "recovered":
            seen_recovered.add(m["module"])
    # Remove from failed if recovered
    for tool in seen_recovered:
        seen_failed.pop(tool, None)

    return {
        "modules_total": diag["summary"]["total"],
        "modules_success": diag["summary"]["success"],
        "modules_failed": len(seen_failed),
        "modules_recovered": len(seen_recovered),
        "dotnet_errors": diag["summary"]["dotnet_errors"],
        "missing_modules": diag["missing_modules"],
        "failed_modules": [
            {"module": k, "reason": v} for k, v in seen_failed.items()
        ],
        "recovered_modules": sorted(seen_recovered),
        "recommendations": diag.get("recommendations", []),
    }


class OpenCaseRequest(BaseModel):
    path: str
    case_name: str = ""


class OpenMultiRequest(BaseModel):
    paths: list[str]


@router.post("/open")
async def open_case(req: OpenCaseRequest):
    from state import app_state
    try:
        # Additive — a quick-open must not erase evidence already registered
        # through the project flow.
        app_state.add_allowed_evidence([req.path], source="cases:open")
        result = app_state.open_axiom(req.path, req.case_name)

        # For KAPE sources, attach diagnostics (loaded vs missing artifacts)
        if result.get("source_type") == "kape":
            try:
                from core.kape_log_parser import get_diagnostics
                diag = get_diagnostics(req.path)
                if "error" not in diag:
                    result["kape_diagnostics"] = _build_kape_diagnostics(diag)
            except Exception:
                pass

        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/open-multi")
async def open_multi(req: OpenMultiRequest):
    """Open multiple case sources (MFDB + KAPE) simultaneously."""
    from state import app_state
    if not req.paths:
        raise HTTPException(status_code=400, detail="No paths provided")

    app_state.add_allowed_evidence(req.paths, source="cases:open_multi")

    results = []
    last_kape_diag = None
    for path in req.paths:
        path = path.strip()
        if not path:
            continue
        try:
            r = app_state.open_axiom(path)
            if r.get("source_type") == "kape":
                try:
                    from core.kape_log_parser import get_diagnostics
                    diag = get_diagnostics(path)
                    if "error" not in diag:
                        last_kape_diag = _build_kape_diagnostics(diag)
                        r["kape_diagnostics"] = last_kape_diag
                except Exception:
                    pass
            results.append({"status": "loaded", "path": path, **r})
        except Exception as e:
            results.append({"status": "error", "path": path, "error": str(e)})

    loaded = [r for r in results if r["status"] == "loaded"]
    if not loaded:
        raise HTTPException(status_code=400, detail="All sources failed to load")

    # Return combined info: use last loaded case as primary summary
    primary = loaded[-1]
    return {
        "status": "success",
        "cases_loaded": len(loaded),
        "results": results,
        "case_name": primary.get("case_name", ""),
        "total_hits": sum(r.get("total_hits", 0) for r in loaded),
        "source_type": "multi" if len(loaded) > 1 else primary.get("source_type"),
        "kape_diagnostics": last_kape_diag,
    }


@router.post("/close")
async def close_case():
    from state import app_state
    info = app_state.close_all_cases()
    return {"status": "closed", **info}


@router.get("/summary")
async def get_summary():
    from state import app_state
    try:
        result = app_state.get_axiom().get_metadata()

        if result.get("source_type") == "kape":
            try:
                from core.kape_log_parser import get_diagnostics
                diag = get_diagnostics(result.get("source_path", ""))
                if "error" not in diag:
                    result["kape_diagnostics"] = _build_kape_diagnostics(diag)
            except Exception:
                pass

        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/types")
async def get_artifact_types():
    from state import app_state
    try:
        types = app_state.get_axiom().get_artifact_type_counts()
        return {"artifact_types": types, "total_types": len(types)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PivotRequest(BaseModel):
    entity_type: str
    entity_value: str
    window_minutes: int = 60
    limit_per_case: int = 100


@router.post("/pivot")
async def post_pivot(req: PivotRequest):
    """Pivot on an entity across every loaded case.

    Offline: fans out to already-loaded connectors and merges hits with
    per-case provenance. No external lookup.
    """
    from state import app_state
    from core.analysis.case_aggregator import pivot_across_cases as _pivot
    axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
    return _pivot(axiom_conns, req.entity_type, req.entity_value, req.window_minutes, req.limit_per_case)


@router.get("/compare")
async def get_compare():
    """Return metadata + artifact-count matrix across every loaded case.

    Offline and partial-failure tolerant: a disconnected case shows up as
    ``ok: false`` in its envelope, the rest of the response is unaffected.
    """
    from state import app_state
    from core.analysis.case_aggregator import compare_cases as _compare
    axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
    return _compare(axiom_conns)


class SnapshotSaveRequest(BaseModel):
    name: str
    tagged_hit_ids: list[int] = []
    notes: str = ""
    filters: dict = {}


@router.post("/snapshot/save")
async def snapshot_save(req: SnapshotSaveRequest):
    from state import app_state
    from core.analysis.case_snapshot import save_snapshot
    return save_snapshot(
        app_state._connectors,
        name=req.name,
        tagged_hits=req.tagged_hit_ids,
        notes=req.notes,
        filters=req.filters,
    )


@router.get("/snapshot/list")
async def snapshot_list():
    from core.analysis.case_snapshot import list_snapshots
    return list_snapshots()


@router.get("/snapshot/{slug}")
async def snapshot_load(slug: str):
    from core.analysis.case_snapshot import load_snapshot
    return load_snapshot(slug)


@router.delete("/snapshot/{slug}")
async def snapshot_delete(slug: str):
    from core.analysis.case_snapshot import delete_snapshot
    return delete_snapshot(slug)


class ExplainZeroRequest(BaseModel):
    tool_name: str
    params: dict = {}


@router.post("/explain-zero")
async def post_explain_zero(req: ExplainZeroRequest):
    """Diagnose a zero-result response and return causes + follow-up queries.

    Offline: reads only the allowlisted connectors and case metadata.
    """
    from state import app_state
    from core.analysis.zero_results import explain_zero_results as _explain
    axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
    return _explain(axiom_conns, tool_name=req.tool_name, params=req.params)


@router.get("/coverage")
async def get_coverage(artifact_types: str = ""):
    """Report searchable vs structurally unavailable artifact families.

    Offline and deterministic: reads only from already-loaded connectors and a
    static AXIOM-vs-KAPE capability matrix. Never sends data outside.
    """
    from state import app_state
    from core.analysis.coverage import build_coverage_report
    requested = [a.strip() for a in artifact_types.split(",") if a.strip()] if artifact_types else None
    axiom_conns = {k: v for k, v in app_state._connectors.items() if k.startswith("axiom:")}
    return build_coverage_report(axiom_conns, artifact_types=requested)


@router.get("/list")
async def list_cases():
    from state import app_state
    return {
        "cases": app_state.list_cases(),
        "active_case_id": app_state.get_active_case_id(),
    }


@router.post("/switch")
async def switch_case(case_id: str):
    from state import app_state
    try:
        meta = app_state.switch_case(case_id)
        return {"status": "switched", **meta}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
async def get_status():
    from state import app_state
    return {"connectors": app_state.list_connected()}
