"""Parse KAPE ConsoleLog.txt to extract module execution results.

Surfaces silent module failures (missing runtimeconfig, crashed tools, etc.)
that would otherwise only be visible by manually reading the log file.
"""

from __future__ import annotations

import glob
import os
import re
from typing import Any


# Patterns for KAPE console log parsing
_RE_RUNNING = re.compile(r"Running (.+?\.exe):\s*(.*)")
_RE_FTL = re.compile(r"\[FTL\]\s*(.+)")
_RE_ERR = re.compile(r"\[ERR\]\s*(.+)")
_RE_PROCESSED = re.compile(r"Processed (\d[\d,]*)\s+(?:out of \d[\d,]* )?(?:records?|files?|entries)", re.IGNORECASE)
_RE_CSV_OUTPUT = re.compile(r"CSV (?:output|time line output) will be saved to (.+)")
_RE_HOSTPOLICY = re.compile(r"hostpolicy\.dll.*not found", re.IGNORECASE)
_RE_SELF_CONTAINED = re.compile(r"Failed to run as a self-contained app", re.IGNORECASE)
_RE_MODULE_FILE = re.compile(r"Cannot find module file (.+?)!", re.IGNORECASE)


def find_console_logs(base_dir: str) -> list[str]:
    """Find KAPE ConsoleLog files in a directory tree.

    Filters to main KAPE console logs (timestamp-prefixed), excluding
    tool-specific logs like SrumECmdConsoleLog.txt.
    """
    logs = []
    for search_dir in [base_dir, os.path.dirname(base_dir)]:
        logs.extend(glob.glob(os.path.join(search_dir, "*ConsoleLog*.txt")))
        logs.extend(glob.glob(os.path.join(search_dir, "**", "*ConsoleLog*.txt"), recursive=True))
    # Keep only KAPE main console logs (start with timestamp pattern)
    kape_logs = []
    for log in set(logs):
        basename = os.path.basename(log)
        if re.match(r"^\d{4}-\d{2}-\d{2}", basename):
            kape_logs.append(log)
    return sorted(kape_logs)


def parse_console_log(log_path: str) -> dict[str, Any]:
    """Parse a single KAPE ConsoleLog.txt file.

    Returns:
        {
            "log_path": str,
            "modules": [{"module": str, "status": str, "errors": [...], ...}],
            "missing_modules": [str],
            "summary": {"total": int, "success": int, "failed": int},
        }
    """
    if not os.path.isfile(log_path):
        return {"log_path": log_path, "error": "File not found"}

    with open(log_path, "r", encoding="utf-8-sig", errors="replace") as f:
        lines = f.readlines()

    modules: list[dict[str, Any]] = []
    missing_modules: list[str] = []
    current_module: dict[str, Any] | None = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Strip timestamp prefix: [2026-04-03 16:19:38.1234567 | INF]
        clean = re.sub(r"^\[[\d\-T :._]+\s*\|\s*\w+\]\s*", "", line)

        # Module file not found
        m = _RE_MODULE_FILE.search(clean)
        if m:
            missing_modules.append(m.group(1))
            continue

        # New module running
        m = _RE_RUNNING.search(clean)
        if m:
            # Save previous module
            if current_module:
                _finalize_module(current_module)
                modules.append(current_module)

            tool_path = m.group(1).strip()
            tool_name = os.path.basename(tool_path).replace(".exe", "")
            current_module = {
                "module": tool_name,
                "command": m.group(2).strip() if m.group(2) else "",
                "status": "running",
                "errors": [],
                "records": None,
                "csv_output": None,
            }
            continue

        if current_module is None:
            continue

        # hostpolicy.dll error (missing runtimeconfig)
        if _RE_HOSTPOLICY.search(clean) or _RE_SELF_CONTAINED.search(clean):
            current_module["errors"].append("Missing .NET runtimeconfig.json (hostpolicy.dll not found)")
            current_module["status"] = "failed_dotnet"
            continue

        # General error
        m = _RE_ERR.search(line)  # match on original line (has prefix)
        if m:
            err = m.group(1).strip()
            # Skip noisy "already processed" errors
            if "already processed" not in err:
                current_module["errors"].append(err[:200])
            continue

        # Fatal error
        m = _RE_FTL.search(line)
        if m:
            current_module["errors"].append(f"FATAL: {m.group(1).strip()[:200]}")
            current_module["status"] = "failed"
            continue

        # Records processed
        m = _RE_PROCESSED.search(clean)
        if m:
            current_module["records"] = int(m.group(1).replace(",", ""))
            continue

        # CSV output path
        m = _RE_CSV_OUTPUT.search(clean)
        if m:
            current_module["csv_output"] = m.group(1).strip()
            continue

    # Finalize last module
    if current_module:
        _finalize_module(current_module)
        modules.append(current_module)

    # Build summary
    success = sum(1 for m in modules if m["status"] == "success")
    failed = sum(1 for m in modules if m["status"].startswith("failed"))

    return {
        "log_path": log_path,
        "modules": modules,
        "missing_modules": missing_modules,
        "summary": {
            "total": len(modules),
            "success": success,
            "failed": failed,
            "dotnet_errors": sum(1 for m in modules if m["status"] == "failed_dotnet"),
        },
    }


def _finalize_module(mod: dict[str, Any]) -> None:
    """Set final status based on collected evidence."""
    if mod["status"] in ("failed", "failed_dotnet"):
        return
    if mod["errors"]:
        mod["status"] = "failed"
    else:
        # No errors → assume success (CSV output detection is best-effort)
        mod["status"] = "success"


def get_diagnostics(parsed_dir: str) -> dict[str, Any]:
    """Full diagnostics for a KAPE parsed output directory.

    Finds console logs, parses them, and cross-references with actual CSV output.
    """
    logs = find_console_logs(parsed_dir)
    if not logs:
        return {"error": "No KAPE ConsoleLog.txt found", "searched": parsed_dir}

    # Parse the most recent log (last in sorted order)
    log_result = parse_console_log(logs[-1])

    # Check what CSVs actually exist — cross-reference with log results
    existing_csvs = glob.glob(os.path.join(parsed_dir, "**", "*.csv"), recursive=True)
    csv_basenames = {os.path.basename(f).lower() for f in existing_csvs}

    # Map tool names to CSV filename patterns for recovery detection
    _TOOL_CSV_PATTERNS: dict[str, list[str]] = {
        "PECmd": ["pecmd"],
        "LECmd": ["lecmd"],
        "JLECmd": ["automaticdestinations", "customdestinations"],
        "SBECmd": ["usrclass", "ntuser"],
        "RBCmd": ["rbcmd"],
        "WxTCmd": ["activity"],
        "SrumECmd": ["srumecmd"],
        "SumECmd": ["sumecmd", "sumedb"],
        "AmcacheParser": ["amcache"],
        "AppCompatCacheParser": ["appcompatcache"],
        "MFTECmd": ["mftecmd"],
        "RECmd": ["recmd"],
        "SQLECmd": ["googlechrome", "chromiumbrowser", "firefox"],
    }

    for mod in log_result["modules"]:
        tool = mod["module"]

        # If log says failed but CSV output actually exists (e.g. manual re-run)
        if mod["status"].startswith("failed"):
            patterns = _TOOL_CSV_PATTERNS.get(tool, [tool.lower()])
            has_csv = any(
                any(pat in csv_name for pat in patterns)
                for csv_name in csv_basenames
            )
            if has_csv:
                mod["status"] = "recovered"
                mod["errors"] = [f"Failed in original KAPE run but CSV output exists (re-parsed)"]

        # If log says success but no CSV found
        if mod["status"] == "success" and mod["csv_output"]:
            csv_name = os.path.basename(mod["csv_output"]).lower()
            if csv_name not in csv_basenames:
                mod["status"] = "no_output"
                mod["errors"].append("Module reported success but CSV file not found")

    # Recalculate summary after recovery detection
    success = sum(1 for m in log_result["modules"] if m["status"] in ("success", "recovered"))
    failed = sum(1 for m in log_result["modules"] if m["status"].startswith("failed"))
    recovered = sum(1 for m in log_result["modules"] if m["status"] == "recovered")
    dotnet_errors = sum(1 for m in log_result["modules"] if m["status"] == "failed_dotnet")
    log_result["summary"] = {
        "total": len(log_result["modules"]),
        "success": success,
        "failed": failed,
        "recovered": recovered,
        "dotnet_errors": dotnet_errors,
    }

    # Check missing modules against actual CSV output
    # e.g. RECmd_Kroll was missing in KAPE run but we created the module and ran it manually
    _MISSING_MODULE_PATTERNS: dict[str, list[str]] = {
        "RECmd_Kroll": ["recmd", "kroll"],
    }
    resolved_missing = []
    for mm in log_result["missing_modules"]:
        patterns = _MISSING_MODULE_PATTERNS.get(mm, [mm.lower()])
        has_csv = any(
            any(pat in cn for pat in patterns) for cn in csv_basenames
        )
        if has_csv:
            resolved_missing.append(mm)
    for rm in resolved_missing:
        log_result["missing_modules"].remove(rm)

    # Also check: if data doesn't exist on this system (e.g. SUMDatabase on workstation)
    # and the tool has no CSV, mark as "no_data" instead of "failed"
    for mod in log_result["modules"]:
        if mod["status"] == "failed_dotnet" and mod["module"] == "SumECmd":
            # SUMDatabase only exists on Windows Server
            patterns = _TOOL_CSV_PATTERNS.get("SumECmd", [])
            has_csv = any(any(p in cn for p in patterns) for cn in csv_basenames)
            if not has_csv:
                mod["status"] = "no_data"
                mod["errors"] = ["SUMDatabase (Windows Server only) — not applicable to this system"]

    # Recalculate after no_data adjustment
    dotnet_errors = sum(1 for m in log_result["modules"] if m["status"] == "failed_dotnet")
    failed = sum(1 for m in log_result["modules"] if m["status"].startswith("failed"))
    log_result["summary"]["failed"] = failed
    log_result["summary"]["dotnet_errors"] = dotnet_errors

    # Actionable recommendations — only for genuinely failed modules
    recommendations: list[str] = []
    if dotnet_errors > 0:
        failed_tools = sorted({m["module"] for m in log_result["modules"] if m["status"] == "failed_dotnet"})
        recommendations.append(
            f"{dotnet_errors} modules failed due to missing .NET runtimeconfig.json ({', '.join(failed_tools)}). "
            "Run KAPE Health Check in Settings to auto-fix."
        )
    if log_result["missing_modules"]:
        recommendations.append(
            f"Missing module files: {', '.join(log_result['missing_modules'])}. "
            "Download from https://ericzimmerman.github.io/"
        )

    return {
        "console_logs_found": len(logs),
        "log_analyzed": logs[-1],
        "modules": log_result["modules"],
        "missing_modules": log_result["missing_modules"],
        "summary": log_result["summary"],
        "existing_csvs": len(existing_csvs),
        "recommendations": recommendations,
    }
