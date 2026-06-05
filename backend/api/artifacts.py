"""Artifact search & browsing API — AG Grid server-side support."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.raw_support import (
    active_raw_index_without_parsed_case,
    annotate_parsed_fallback,
    should_fallback_to_parsed_case,
)
from core.config import config

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


class SearchRequest(BaseModel):
    keyword: str = ""
    artifact_type: str = ""
    start_date: str = ""
    end_date: str = ""
    limit: int = 50
    offset: int = 0
    all_cases: bool = False


class GridRequest(BaseModel):
    """AG Grid server-side row model request."""
    startRow: int = 0
    endRow: int = 100
    filterModel: dict = {}
    sortModel: list = []


def _raw_unsupported_result(raw, reason: str) -> dict:
    coverage = (
        raw.get_coverage()
        if callable(getattr(raw, "get_coverage", None))
        else {"status": "searched", "gaps": []}
    )
    return {
        "ok": False,
        "status": "not_evaluable",
        "source_type": "raw_image_sidecar",
        "coverage_gap": {
            "status": "not_evaluable",
            "reason": reason,
        },
        "raw_index_coverage": coverage,
    }


@router.post("/search")
async def search_artifacts(req: SearchRequest):
    from state import app_state
    try:
        if req.all_cases:
            from core.analysis.case_aggregator import search_across_cases
            cap = min(req.limit, config.max_limit)
            # For now, surface the UI as a regular search payload: the
            # merged hits live on the same "hits" key, with per-case
            # provenance attached to each row, and the total reflects the
            # merged count so the grid paging stays consistent.
            result = search_across_cases(
                app_state._connectors,
                keyword=req.keyword,
                artifact_type=req.artifact_type,
                start_date=req.start_date,
                end_date=req.end_date,
                limit_per_case=cap,
                global_limit=cap,
                global_offset=req.offset,
            )
            return {
                "hits": result["hits"],
                "total_estimated": result["merged_total"],
                "total": result["merged_total"],
                "returned": result["returned"],
                "truncated": result["merged_total"] > req.offset + result["returned"],
                "per_case": result["per_case"],
                "warnings": result["warnings"],
                "all_cases": True,
            }

        raw = app_state.get("raw_index")
        if raw and raw.is_connected():
            raw_result = raw.search(
                keyword=req.keyword,
                filters={
                    "artifact_type": req.artifact_type,
                    "start_date": req.start_date,
                    "end_date": req.end_date,
                },
                limit=min(req.limit, config.max_limit),
                offset=req.offset,
            )
            if should_fallback_to_parsed_case(raw_result, app_state):
                parsed_result = app_state.get_axiom().search(
                    keyword=req.keyword,
                    filters={
                        "artifact_type": req.artifact_type,
                        "start_date": req.start_date,
                        "end_date": req.end_date,
                    },
                    limit=min(req.limit, config.max_limit),
                    offset=req.offset,
                )
                return annotate_parsed_fallback(parsed_result, raw_result)
            return raw_result

        return app_state.get_axiom().search(
            keyword=req.keyword,
            filters={
                "artifact_type": req.artifact_type,
                "start_date": req.start_date,
                "end_date": req.end_date,
            },
            limit=min(req.limit, config.max_limit),
            offset=req.offset,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/grid")
async def artifact_grid(req: GridRequest):
    """AG Grid server-side row model endpoint.

    Returns rows for the requested range + total row count.
    """
    from state import app_state
    try:
        raw = app_state.get("raw_index")
        connector = raw if raw and raw.is_connected() else app_state.get_axiom()

        # Extract filters from AG Grid filterModel
        keyword = ""
        artifact_type = ""
        for col, filter_def in req.filterModel.items():
            if col == "keyword" or col == "fields":
                keyword = filter_def.get("filter", "")
            elif col == "artifact_type":
                artifact_type = filter_def.get("filter", "")

        limit = req.endRow - req.startRow
        offset = req.startRow

        result = connector.search(
            keyword=keyword,
            filters={"artifact_type": artifact_type},
            limit=limit,
            offset=offset,
        )
        fallback_metadata: dict = {}
        if raw and raw.is_connected() and should_fallback_to_parsed_case(
            result,
            app_state,
        ):
            raw_result = result
            result = app_state.get_axiom().search(
                keyword=keyword,
                filters={"artifact_type": artifact_type},
                limit=limit,
                offset=offset,
            )
            fallback_metadata = {
                key: value
                for key, value in annotate_parsed_fallback(
                    result,
                    raw_result,
                ).items()
                if key in {"fallback_source", "raw_index_status", "raw_index_coverage"}
            }

        # AG Grid expects: { rowData: [...], rowCount: total }
        return {
            "rowData": result.get("hits", []),
            "rowCount": result.get("total", result.get("total_estimated", 0)),
            "count_accuracy": result.get("count_accuracy", ""),
            "total_is_estimated": result.get("total_is_estimated"),
            **fallback_metadata,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tagged")
async def get_tagged_hits(tag_name: str = ""):
    from state import app_state
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return _raw_unsupported_result(raw, "raw_tagged_hits_unsupported")
        return app_state.get_axiom().get_tagged_hits(tag_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/hash/{hash_value}")
async def search_by_hash(hash_value: str, limit: int = 50):
    from state import app_state
    try:
        raw = active_raw_index_without_parsed_case(app_state)
        if raw:
            return _raw_unsupported_result(raw, "raw_hash_search_unsupported")
        return app_state.get_axiom().search_by_hash(hash_value, limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/source/{path_pattern:path}")
async def search_by_source(path_pattern: str, limit: int = 50):
    from state import app_state
    try:
        raw = app_state.get("raw_index")
        if raw and raw.is_connected():
            return raw.search(keyword=path_pattern, filters={}, limit=limit, offset=0)
        return app_state.get_axiom().search_by_source(path_pattern, limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/detail/{hit_id}")
async def get_hit_detail(hit_id: int):
    from state import app_state
    try:
        raw = app_state.get("raw_index")
        if raw and raw.is_connected():
            return raw.get_hit_detail(hit_id)
        return app_state.get_axiom().get_hit_detail(hit_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
