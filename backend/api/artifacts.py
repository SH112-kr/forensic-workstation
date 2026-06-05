"""Artifact search & browsing API — AG Grid server-side support."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
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
            return raw.search(
                keyword=req.keyword,
                filters={
                    "artifact_type": req.artifact_type,
                    "start_date": req.start_date,
                    "end_date": req.end_date,
                },
                limit=min(req.limit, config.max_limit),
                offset=req.offset,
            )

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

        # AG Grid expects: { rowData: [...], rowCount: total }
        return {
            "rowData": result.get("hits", []),
            "rowCount": result.get("total", result.get("total_estimated", 0)),
            "count_accuracy": result.get("count_accuracy", ""),
            "total_is_estimated": result.get("total_is_estimated"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tagged")
async def get_tagged_hits(tag_name: str = ""):
    from state import app_state
    try:
        return app_state.get_axiom().get_tagged_hits(tag_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/hash/{hash_value}")
async def search_by_hash(hash_value: str, limit: int = 50):
    from state import app_state
    try:
        return app_state.get_axiom().search_by_hash(hash_value, limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/source/{path_pattern:path}")
async def search_by_source(path_pattern: str, limit: int = 50):
    from state import app_state
    try:
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
