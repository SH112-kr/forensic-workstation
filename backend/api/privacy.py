"""Privacy proxy API for LLM/MCP-bound analysis payloads."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.analysis.privacy_proxy import (
    add_alias,
    get_alias,
    get_intercept,
    list_filter_events,
    list_intercepts,
    list_aliases,
    replay_intercept,
    public_settings,
    remove_alias,
    resolve_intercept,
    save_settings,
    scan_payload,
    update_alias,
)


router = APIRouter(prefix="/api/privacy", tags=["privacy"])


class PrivacySettingsRequest(BaseModel):
    mode: str
    intercept_sensitive_tools: bool = True
    intercept_blocking: bool = True
    intercept_timeout_seconds: int = 600
    max_matches: int = 200


class PrivacyScanRequest(BaseModel):
    payload: Any


class PrivacyDecisionRequest(BaseModel):
    action: str
    edited_payload: Any = None


class PrivacyAliasRequest(BaseModel):
    raw_value: str
    alias_type: str = "CUSTOM"
    alias: str = ""


class PrivacyAliasUpdateRequest(BaseModel):
    raw_value: str | None = None
    alias_type: str | None = None
    alias: str | None = None


@router.get("")
async def get_privacy_settings():
    return public_settings()


@router.post("")
async def set_privacy_settings(req: PrivacySettingsRequest):
    return save_settings(req.model_dump())


@router.post("/scan")
async def post_privacy_scan(req: PrivacyScanRequest):
    return scan_payload(req.payload)


@router.get("/aliases")
async def get_privacy_aliases():
    return {"items": list_aliases(include_raw=False)}


@router.get("/aliases/{alias}")
async def get_privacy_alias(alias: str, include_raw: bool = False):
    try:
        return get_alias(alias, include_raw=include_raw)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/aliases")
async def post_privacy_alias(req: PrivacyAliasRequest):
    try:
        return add_alias(req.raw_value, alias_type=req.alias_type, alias=req.alias)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/aliases/{alias}")
async def put_privacy_alias(alias: str, req: PrivacyAliasUpdateRequest):
    try:
        return update_alias(alias, raw_value=req.raw_value, alias_type=req.alias_type, alias=req.alias)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/aliases/{alias}")
async def delete_privacy_alias(alias: str):
    try:
        return remove_alias(alias)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/intercepts")
async def get_privacy_intercepts(include_payload: bool = False):
    return {
        "items": list_intercepts(include_payload=include_payload),
        "settings": public_settings(),
    }


@router.get("/filters")
async def get_privacy_filter_events(limit: int = 200, include_matches: bool = True):
    return {"items": list_filter_events(limit=limit, include_matches=include_matches)}


@router.get("/intercepts/{intercept_id}")
async def get_privacy_intercept(intercept_id: str, include_payload: bool = False):
    item = get_intercept(intercept_id, include_payload=include_payload)
    if not item:
        raise HTTPException(status_code=404, detail=f"Privacy intercept not found: {intercept_id}")
    return item


@router.post("/intercepts/{intercept_id}/resolve")
async def post_privacy_decision(intercept_id: str, req: PrivacyDecisionRequest):
    try:
        return resolve_intercept(intercept_id, action=req.action, edited_payload=req.edited_payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/intercepts/{intercept_id}/replay")
async def get_privacy_replay(intercept_id: str):
    try:
        return replay_intercept(intercept_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
