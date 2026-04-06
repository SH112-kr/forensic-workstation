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


@router.post("/open")
async def open_case(req: OpenCaseRequest):
    from state import app_state
    try:
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


@router.post("/close")
async def close_case():
    from state import app_state
    app_state.remove("axiom")
    return {"status": "closed"}


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


@router.get("/list")
async def list_cases():
    from state import app_state
    return {"cases": app_state.list_cases()}


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
