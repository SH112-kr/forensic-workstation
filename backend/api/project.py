"""Project management API — create, load, save forensic investigation projects.

A project bundles all evidence paths + case metadata so the analyst
(and Claude) can access everything without re-entering paths each session.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/project", tags=["project"])

_PROJECTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "projects",
)


# ── Models ──

class EvidenceItem(BaseModel):
    type: str  # axiom, kape, memory, disk_image, evtx, pcap, logs, yara_rules, other
    path: str
    label: str = ""
    loaded: bool = False


class ProjectInfo(BaseModel):
    name: str
    description: str = ""
    # Incident context
    incident_date: str = ""       # When was the incident discovered (ISO date)
    timezone: str = "Asia/Seoul"  # Target system timezone
    hostname: str = ""            # Target system hostname
    os_version: str = ""          # e.g. "Windows 10 22H2"
    ip_addresses: str = ""        # Comma-separated known IPs
    user_accounts: str = ""       # Comma-separated user accounts of interest
    # Known IOCs
    known_iocs: str = ""          # Comma-separated IPs, hashes, domains already identified
    # Evidence
    evidence: list[EvidenceItem] = []
    # Notes
    notes: str = ""


class ProjectFile(BaseModel):
    """Full project file format (.fwproject)."""
    version: str = "1.0"
    created: str = ""
    updated: str = ""
    info: ProjectInfo
    analysis_state: dict = {}  # saved analysis state (findings, timeline, etc.)


# ── Helpers ──

def _ensure_projects_dir():
    os.makedirs(_PROJECTS_DIR, exist_ok=True)


def _project_path(name: str) -> str:
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in name).strip()
    return os.path.join(_PROJECTS_DIR, f"{safe_name}.fwproject")


def _load_project(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_project(path: str, data: dict):
    data["updated"] = datetime.now(timezone.utc).isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ── API ──

@router.post("/create")
async def create_project(info: ProjectInfo):
    """Create a new project and optionally load evidence."""
    _ensure_projects_dir()
    path = _project_path(info.name)

    project = {
        "version": "1.0",
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
        "info": info.model_dump(),
        "analysis_state": {},
    }
    _save_project(path, project)

    # Auto-load evidence that exists
    load_results = await _load_evidence(info.evidence, info.timezone)

    return {
        "status": "created",
        "project_path": path,
        "project": project["info"],
        "load_results": load_results,
    }


class OpenProjectRequest(BaseModel):
    path: str = ""
    name: str = ""


@router.post("/open")
async def open_project(req: OpenProjectRequest):
    """Open an existing project by path or name."""
    path = req.path
    name = req.name
    if not path and name:
        path = _project_path(name)
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Project not found: {path or name}")

    project = _load_project(path)
    info = project.get("info", {})
    evidence = [EvidenceItem(**e) for e in info.get("evidence", [])]

    # Auto-load evidence
    load_results = await _load_evidence(evidence, info.get("timezone", ""))

    return {
        "status": "opened",
        "project_path": path,
        "project": info,
        "load_results": load_results,
    }


@router.get("/list")
async def list_projects():
    """List all saved projects."""
    _ensure_projects_dir()
    projects = []
    for f in sorted(os.listdir(_PROJECTS_DIR)):
        if not f.endswith(".fwproject"):
            continue
        try:
            data = _load_project(os.path.join(_PROJECTS_DIR, f))
            info = data.get("info", {})
            projects.append({
                "name": info.get("name", f),
                "description": info.get("description", ""),
                "hostname": info.get("hostname", ""),
                "incident_date": info.get("incident_date", ""),
                "evidence_count": len(info.get("evidence", [])),
                "created": data.get("created", ""),
                "updated": data.get("updated", ""),
                "path": os.path.join(_PROJECTS_DIR, f),
            })
        except Exception:
            pass
    return {"projects": projects}


@router.post("/save")
async def save_project(info: ProjectInfo, path: str = ""):
    """Update an existing project."""
    if not path:
        path = _project_path(info.name)
    if os.path.exists(path):
        project = _load_project(path)
    else:
        _ensure_projects_dir()
        project = {"version": "1.0", "created": datetime.now(timezone.utc).isoformat()}

    project["info"] = info.model_dump()
    _save_project(path, project)
    return {"status": "saved", "project_path": path}


@router.delete("/delete")
async def delete_project(path: str = "", name: str = ""):
    """Delete a project file."""
    if not path and name:
        path = _project_path(name)
    if path and os.path.exists(path):
        os.remove(path)
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Project not found")


@router.get("/evidence-types")
async def evidence_types():
    """Return supported evidence types with descriptions."""
    return {
        "types": [
            {"type": "axiom", "label": "AXIOM Case", "extensions": [".mfdb"], "description": "Magnet AXIOM case database"},
            {"type": "kape", "label": "KAPE Output", "extensions": [], "description": "KAPE parsed CSV directory", "is_dir": True},
            {"type": "memory", "label": "Memory Dump", "extensions": [".raw", ".vmem", ".dmp", ".mem"], "description": "RAM dump for Volatility analysis"},
            {"type": "disk_image", "label": "Disk Image", "extensions": [".e01", ".E01", ".ex01", ".vmdk", ".raw", ".dd"], "description": "Forensic disk image for file extraction"},
            {"type": "evtx", "label": "Event Logs", "extensions": [".evtx"], "description": "Windows event log files or directory", "is_dir_ok": True},
            {"type": "pcap", "label": "Network Capture", "extensions": [".pcap", ".pcapng"], "description": "Network packet capture"},
            {"type": "logs", "label": "Server Logs", "extensions": [".log", ".txt", ".zip"], "description": "Apache/IIS/syslog files", "is_dir_ok": True},
            {"type": "yara_rules", "label": "YARA Rules", "extensions": [".yar", ".yara"], "description": "YARA rule files for scanning", "is_dir_ok": True},
            {"type": "other", "label": "Other", "extensions": [], "description": "Any other evidence file"},
        ]
    }


class ScanEvidenceRequest(BaseModel):
    directory: str


@router.post("/scan-evidence")
async def scan_evidence(req: ScanEvidenceRequest):
    """Scan a directory for forensic evidence files and auto-detect types."""
    import glob as _glob

    base = req.directory
    if not os.path.isdir(base):
        raise HTTPException(status_code=400, detail=f"Directory not found: {base}")

    found: list[dict] = []

    # Extension → evidence type mapping
    ext_map = {
        ".mfdb": "axiom",
        ".raw": "memory", ".vmem": "memory", ".dmp": "memory", ".mem": "memory",
        ".e01": "disk_image", ".E01": "disk_image", ".ex01": "disk_image",
        ".vmdk": "disk_image", ".dd": "disk_image",
        ".evtx": "evtx",
        ".pcap": "pcap", ".pcapng": "pcap",
        ".yar": "yara_rules", ".yara": "yara_rules",
    }

    # Scan recursively (max 3 levels deep to avoid crawling huge trees)
    scanned_files = set()
    for depth in range(4):
        pattern = os.path.join(base, *["*"] * depth) if depth > 0 else os.path.join(base, "*")
        for filepath in _glob.glob(pattern):
            if filepath in scanned_files or os.path.isdir(filepath):
                continue
            scanned_files.add(filepath)

            _, ext = os.path.splitext(filepath)
            ext_lower = ext.lower()
            etype = ext_map.get(ext) or ext_map.get(ext_lower)
            if etype:
                # Determine size
                try:
                    size = os.path.getsize(filepath)
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1048576:
                        size_str = f"{size / 1024:.0f} KB"
                    elif size < 1073741824:
                        size_str = f"{size / 1048576:.1f} MB"
                    else:
                        size_str = f"{size / 1073741824:.1f} GB"
                except OSError:
                    size_str = ""

                # Auto-generate label
                label = os.path.basename(filepath)

                found.append({
                    "type": etype,
                    "path": filepath.replace("\\", "/"),
                    "label": label,
                    "size": size_str,
                    "loaded": False,
                })

    # Also detect KAPE output directories (contain parsed CSV subdirectories)
    kape_indicators = ["EventLogs", "ProgramExecution", "FileSystem", "Registry"]
    for depth in range(3):
        pattern = os.path.join(base, *["*"] * depth) if depth > 0 else base
        for dirpath in _glob.glob(pattern):
            if not os.path.isdir(dirpath):
                continue
            subdirs = set()
            try:
                subdirs = {d for d in os.listdir(dirpath) if os.path.isdir(os.path.join(dirpath, d))}
            except OSError:
                continue
            matches = subdirs & set(kape_indicators)
            if len(matches) >= 2:
                csv_count = sum(1 for f in _glob.glob(os.path.join(dirpath, "**", "*.csv"), recursive=True))
                if csv_count > 0:
                    found.append({
                        "type": "kape",
                        "path": dirpath.replace("\\", "/"),
                        "label": f"KAPE Output ({csv_count} CSVs)",
                        "size": f"{csv_count} files",
                        "loaded": False,
                    })

    # Sort: important types first
    type_order = {"axiom": 0, "kape": 1, "disk_image": 2, "memory": 3, "evtx": 4, "pcap": 5, "logs": 6, "yara_rules": 7, "other": 8}
    found.sort(key=lambda x: (type_order.get(x["type"], 9), x["path"]))

    return {
        "directory": base,
        "found": found,
        "total": len(found),
    }


# ── Evidence Loading ──

async def _load_evidence(evidence: list[EvidenceItem], timezone_str: str = "") -> list[dict]:
    """Try to load each evidence item into the appropriate connector."""
    from state import app_state
    results: list[dict] = []

    for ev in evidence:
        if not ev.path or not os.path.exists(ev.path):
            results.append({"type": ev.type, "path": ev.path, "status": "not_found"})
            continue

        try:
            if ev.type in ("axiom", "kape"):
                meta = app_state.open_axiom(ev.path, label=ev.label)
                results.append({"type": ev.type, "path": ev.path, "status": "loaded",
                                "total_hits": meta.get("total_hits", 0)})

            elif ev.type == "memory":
                from core.connectors.volatility_connector import VolatilityConnector
                vol = VolatilityConnector()
                meta = vol.connect(ev.path)
                app_state.set("volatility", vol)
                results.append({"type": ev.type, "path": ev.path, "status": "loaded"})

            elif ev.type == "disk_image":
                from core.connectors.e01_image import E01ImageConnector
                e01 = E01ImageConnector()
                meta = e01.connect(ev.path)
                app_state.set("e01", e01)
                results.append({"type": ev.type, "path": ev.path, "status": "loaded",
                                "hostname": meta.get("hostname", "")})

            elif ev.type == "evtx":
                # Just record path — Hayabusa will use it on demand
                results.append({"type": ev.type, "path": ev.path, "status": "registered"})

            elif ev.type == "pcap":
                results.append({"type": ev.type, "path": ev.path, "status": "registered"})

            elif ev.type == "logs":
                results.append({"type": ev.type, "path": ev.path, "status": "registered"})

            elif ev.type == "yara_rules":
                results.append({"type": ev.type, "path": ev.path, "status": "registered"})

            else:
                results.append({"type": ev.type, "path": ev.path, "status": "registered"})

        except Exception as e:
            results.append({"type": ev.type, "path": ev.path, "status": "error", "error": str(e)})

    # Set timezone if provided
    if timezone_str:
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(timezone_str)
            # Compute offset
            import datetime as dt
            offset = tz.utcoffset(dt.datetime.now())
            if offset:
                hours = offset.total_seconds() / 3600
                # Update MCP bridge timezone config
                import mcp_bridge
                if hasattr(mcp_bridge, '_tz_config'):
                    mcp_bridge._tz_config["local_tz_name"] = timezone_str
                    mcp_bridge._tz_config["local_tz_offset_hours"] = hours
        except Exception:
            pass

    return results
