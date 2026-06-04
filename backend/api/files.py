"""File browser API — browse local filesystem for forensic files."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from state import IMAGE_EXTENSIONS

router = APIRouter(prefix="/api/files", tags=["files"])

# Allowed extensions
FORENSIC_EXTENSIONS = {
    ".mfdb": "AXIOM Case",
    **{ext: "Disk Image" for ext in IMAGE_EXTENSIONS},
    ".raw": "Memory Dump",
    ".vmem": "Memory Dump",
    ".dmp": "Memory Dump",
    ".mem": "Memory Dump",
    ".exe": "Binary",
    ".dll": "Binary",
    ".sys": "Binary",
    ".evtx": "Event Log",
    ".pcap": "PCAP",
    ".pcapng": "PCAP",
    ".yar": "YARA Rules",
    ".yara": "YARA Rules",
    ".dat": "Registry Hive",
    ".hve": "Registry Hive",
}


class BrowseRequest(BaseModel):
    path: str = ""
    show_all: bool = False


@router.post("/browse")
async def browse_directory(req: BrowseRequest):
    """Browse a directory, showing forensic-relevant files."""
    path = req.path.strip()

    # Default: show drives on Windows
    if not path:
        drives = []
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append({
                    "name": f"{letter}:",
                    "path": drive,
                    "type": "drive",
                })
        return {"current": "", "items": drives}

    p = Path(path)
    if not p.exists():
        return {"current": path, "items": [], "error": "Path not found"}

    items = []

    # Parent directory
    parent = str(p.parent)
    if parent != path:
        items.append({"name": "..", "path": parent, "type": "directory"})

    try:
        for entry in sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                if entry.is_dir():
                    items.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": "directory",
                    })
                elif entry.is_file():
                    ext = entry.suffix.lower()
                    if req.show_all or ext in FORENSIC_EXTENSIONS:
                        size = entry.stat().st_size
                        items.append({
                            "name": entry.name,
                            "path": str(entry),
                            "type": "file",
                            "file_type": FORENSIC_EXTENSIONS.get(ext, "Other"),
                            "size": size,
                            "size_display": _format_size(size),
                            "extension": ext,
                        })
            except PermissionError:
                continue
    except PermissionError:
        return {"current": path, "items": items, "error": "Permission denied"}

    return {"current": str(p), "items": items}


def _format_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} TB"
