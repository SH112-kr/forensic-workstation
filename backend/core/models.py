"""Shared Pydantic models for Forensic Orchestra MCP."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class CaseMetadata(BaseModel):
    case_name: str = ""
    case_number: str = ""
    created_on: str = ""
    source_path: str = ""
    total_hits: int = 0
    artifact_type_count: int = 0
    evidence_sources: list[str] = []
    evidence_locations: list[str] = []
    date_range_start: str = ""
    date_range_end: str = ""


class ArtifactHit(BaseModel):
    hit_id: int
    artifact_type: str = ""
    fields: dict[str, Any] = {}
    timestamps: dict[str, str] = {}
    location: str = ""
    source_path: str = ""
    hash_value: str = ""


class IOC(BaseModel):
    ioc_type: str
    value: str
    count: int = 0
    source_artifact_types: list[str] = []
    first_seen: str = ""
    last_seen: str = ""


class SuspiciousFind(BaseModel):
    rule_name: str
    severity: str
    description: str
    matching_count: int = 0
    details: list[dict[str, Any]] = []
    mitre_techniques: list[str] = []
