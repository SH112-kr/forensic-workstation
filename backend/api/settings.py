"""Settings API — tool path configuration and auto-detection."""

from __future__ import annotations

import glob
import os
import shutil
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/settings", tags=["settings"])

_ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

# Tools to detect: (env_key, display_name, executable_names, description)
TOOL_REGISTRY: list[dict] = [
    {
        "key": "FORENSIC_KAPE_PATH",
        "name": "KAPE",
        "executables": ["kape.exe"],
        "description": "KAPE artifact collector (kape.exe)",
        "required": False,
    },
    {
        "key": "FORENSIC_GHIDRA_INSTALL_DIR",
        "name": "Ghidra",
        "executables": ["ghidraRun.bat", "ghidraRun"],
        "description": "Ghidra reverse engineering framework (folder containing ghidraRun)",
        "is_dir": True,
        "required": False,
    },
    {
        "key": "FORENSIC_HAYABUSA_PATH",
        "name": "Hayabusa",
        "executables": ["hayabusa.exe", "hayabusa"],
        "description": "Hayabusa Windows event log analyzer",
        "required": False,
    },
    {
        "key": "FORENSIC_OTX_API_KEY",
        "name": "OTX API Key",
        "executables": [],
        "description": "AlienVault OTX threat intelligence API key",
        "is_api_key": True,
        "required": False,
    },
    {
        "key": "FORENSIC_ABUSEIPDB_API_KEY",
        "name": "AbuseIPDB API Key",
        "executables": [],
        "description": "AbuseIPDB threat intelligence API key",
        "is_api_key": True,
        "required": False,
    },
]


def _read_env() -> dict[str, str]:
    """Read .env file into a dict. Normalizes legacy keys to FORENSIC_ prefix."""
    env: dict[str, str] = {}
    if not os.path.exists(_ENV_FILE):
        return env

    # Map legacy keys → new keys
    legacy_map = {
        "GHIDRA_INSTALL_DIR": "FORENSIC_GHIDRA_INSTALL_DIR",
        "HAYABUSA_PATH": "FORENSIC_HAYABUSA_PATH",
        "KAPE_PATH": "FORENSIC_KAPE_PATH",
    }

    with open(_ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # Normalize legacy keys
                if key in legacy_map:
                    key = legacy_map[key]
                env[key] = value
    return env


def _write_env(env: dict[str, str]) -> None:
    """Write dict back to .env file, preserving comments."""
    lines: list[str] = []
    existing_keys: set[str] = set()

    # Read existing file to preserve comments and order
    if os.path.exists(_ENV_FILE):
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key = stripped.partition("=")[0].strip()
                    if key in env:
                        lines.append(f"{key}={env[key]}\n")
                        existing_keys.add(key)
                    # Skip keys not in new env (deleted)
                else:
                    lines.append(line if line.endswith("\n") else line + "\n")

    # Append new keys
    for key, value in env.items():
        if key not in existing_keys and value:
            lines.append(f"{key}={value}\n")

    with open(_ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _scan_directory(base_dir: str) -> dict[str, str]:
    """Scan a directory recursively for known tool executables."""
    found: dict[str, str] = {}
    if not os.path.isdir(base_dir):
        return found

    for tool in TOOL_REGISTRY:
        if tool.get("is_api_key"):
            continue
        for exe in tool["executables"]:
            # Search up to 4 levels deep
            for depth in range(5):
                pattern = os.path.join(base_dir, *["*"] * depth, exe)
                matches = glob.glob(pattern)
                if matches:
                    if tool.get("is_dir"):
                        # For Ghidra, return the directory containing the executable
                        found[tool["key"]] = os.path.dirname(matches[0])
                    else:
                        found[tool["key"]] = matches[0]
                    break
            if tool["key"] in found:
                break

    return found


def _check_tool_status(env: dict[str, str]) -> list[dict]:
    """Check status of each registered tool."""
    statuses = []
    for tool in TOOL_REGISTRY:
        key = tool["key"]
        value = env.get(key, "")
        status: dict[str, Any] = {
            "key": key,
            "name": tool["name"],
            "description": tool["description"],
            "required": tool.get("required", False),
            "is_api_key": tool.get("is_api_key", False),
            "path": value,
        }

        if tool.get("is_api_key"):
            status["status"] = "configured" if value else "not_configured"
            # Mask API key for display
            if value:
                status["display_value"] = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
            else:
                status["display_value"] = ""
        elif value:
            if tool.get("is_dir"):
                exists = os.path.isdir(value)
            else:
                exists = os.path.isfile(value)
            status["status"] = "ok" if exists else "path_not_found"
            # Get version info if possible
            if exists and not tool.get("is_dir"):
                status["file_size"] = os.path.getsize(value)
        else:
            # Try auto-detect from PATH
            for exe in tool.get("executables", []):
                auto = shutil.which(exe)
                if auto:
                    status["status"] = "auto_detected"
                    status["auto_path"] = auto
                    break
            else:
                status["status"] = "not_configured"

        statuses.append(status)
    return statuses


# ── API Endpoints ──

@router.get("")
async def get_settings():
    """Get current tool settings and status."""
    env = _read_env()
    return {
        "tools": _check_tool_status(env),
        "env_file": _ENV_FILE,
    }


class ScanRequest(BaseModel):
    directory: str


@router.post("/scan")
async def scan_tools(req: ScanRequest):
    """Scan a directory for forensic tools and return found paths."""
    found = _scan_directory(req.directory)
    return {
        "directory": req.directory,
        "found": [
            {"key": k, "name": next((t["name"] for t in TOOL_REGISTRY if t["key"] == k), k), "path": v}
            for k, v in found.items()
        ],
        "not_found": [
            t["name"] for t in TOOL_REGISTRY
            if not t.get("is_api_key") and t["key"] not in found
        ],
    }


class SaveSettingsRequest(BaseModel):
    settings: dict[str, str]


@router.post("/save")
async def save_settings(req: SaveSettingsRequest):
    """Save tool path settings to .env file."""
    env = _read_env()
    for key, value in req.settings.items():
        # Only allow known keys
        known_keys = {t["key"] for t in TOOL_REGISTRY}
        if key in known_keys:
            env[key] = value
    _write_env(env)

    # Reload config
    from core.config import config
    for key, value in req.settings.items():
        attr = key.replace("FORENSIC_", "").lower()
        if hasattr(config, attr):
            setattr(config, attr, value)

    return {"status": "saved", "tools": _check_tool_status(env)}


@router.post("/scan-and-save")
async def scan_and_save(req: ScanRequest):
    """Scan directory, find tools, and save to .env in one step."""
    found = _scan_directory(req.directory)
    if not found:
        return {"status": "no_tools_found", "directory": req.directory}

    env = _read_env()
    env.update(found)
    _write_env(env)

    # Reload config
    from core.config import config
    for key, value in found.items():
        attr = key.replace("FORENSIC_", "").lower()
        if hasattr(config, attr):
            setattr(config, attr, value)

    return {
        "status": "saved",
        "found": [
            {"key": k, "name": next((t["name"] for t in TOOL_REGISTRY if t["key"] == k), k), "path": v}
            for k, v in found.items()
        ],
        "tools": _check_tool_status(env),
    }


# ── KAPE Health Check ──

# EZ tools that require .NET runtimeconfig.json
_EZ_TOOLS = [
    "PECmd", "LECmd", "MFTECmd", "EvtxECmd", "SrumECmd",
    "AmcacheParser", "AppCompatCacheParser", "SBECmd", "RECmd",
    "RBCmd", "JLECmd", "WxTCmd", "SQLECmd", "SumECmd", "WxTCmd",
]


def _check_kape_health(kape_dir: str) -> list[dict]:
    """Check EZ tools for missing runtimeconfig.json and auto-fix."""
    bin_dir = os.path.join(kape_dir, "Modules", "bin")
    if not os.path.isdir(bin_dir):
        return []

    results: list[dict] = []
    for tool in _EZ_TOOLS:
        dll = os.path.join(bin_dir, f"{tool}.dll")
        if not os.path.isfile(dll):
            continue

        rc = os.path.join(bin_dir, f"{tool}.runtimeconfig.json")
        if os.path.isfile(rc):
            results.append({"tool": tool, "status": "ok", "detail": ""})
            continue

        # Search subdirectories for the runtimeconfig
        matches = glob.glob(os.path.join(bin_dir, "**", f"{tool}.runtimeconfig.json"), recursive=True)
        if matches:
            try:
                import shutil as _shutil
                _shutil.copy2(matches[0], rc)
                results.append({
                    "tool": tool, "status": "fixed",
                    "detail": f"Copied from {os.path.relpath(matches[0], bin_dir)}",
                })
            except OSError as e:
                results.append({"tool": tool, "status": "fix_failed", "detail": str(e)})
        else:
            results.append({
                "tool": tool, "status": "missing",
                "detail": "runtimeconfig.json not found anywhere",
            })

    return results


@router.post("/kape-health")
async def kape_health():
    """Check KAPE EZ tool health and auto-fix missing runtimeconfig.json files."""
    from core.config import find_kape

    kape = find_kape()
    if not kape or not os.path.isfile(kape):
        return {"error": "KAPE not found. Configure in Settings."}

    kape_dir = os.path.dirname(kape)
    tools = _check_kape_health(kape_dir)

    summary = {
        "ok": sum(1 for t in tools if t["status"] == "ok"),
        "fixed": sum(1 for t in tools if t["status"] == "fixed"),
        "missing": sum(1 for t in tools if t["status"] == "missing"),
        "fix_failed": sum(1 for t in tools if t["status"] == "fix_failed"),
    }

    return {
        "kape_dir": kape_dir,
        "bin_dir": os.path.join(kape_dir, "Modules", "bin"),
        "tools": tools,
        "summary": summary,
    }
