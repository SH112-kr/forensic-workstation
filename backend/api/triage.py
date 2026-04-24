"""Auto Triage API — web UI endpoint for the auto_triage pipeline."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/triage", tags=["triage"])

# Global triage state for progress tracking
_triage_state: dict[str, Any] = {
    "running": False,
    "phase": "",
    "progress": [],
    "result": None,
    "start_time": 0,
    "parsed_dir": "",
}


class TriageRequest(BaseModel):
    source_drive: str
    case_name: str = ""
    output_dir: str = ""
    vss: bool = True


def _count_parsed_files(parsed_dir: str) -> dict:
    """Count CSV files and total size in parsed directory."""
    if not os.path.isdir(parsed_dir):
        return {"files": 0, "size_mb": 0, "folders": {}}
    total_files = 0
    total_size = 0
    folders: dict[str, int] = {}
    for root, dirs, files in os.walk(parsed_dir):
        csv_files = [f for f in files if f.endswith(".csv")]
        if csv_files:
            folder_name = os.path.basename(root)
            folders[folder_name] = len(csv_files)
            total_files += len(csv_files)
            for f in csv_files:
                try:
                    total_size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    return {"files": total_files, "size_mb": round(total_size / 1048576, 1), "folders": folders}


def _run_triage_background(req: TriageRequest, out_dir: str, collected_dir: str, parsed_dir: str, cname: str):
    """Run triage in background thread."""
    global _triage_state
    from core.config import find_kape

    steps: list[dict] = []
    t_start = time.time()

    try:
        # ── Phase 1: KAPE ──
        _triage_state["phase"] = "kape_collecting"
        _triage_state["progress"].append({"time": time.time(), "msg": "Starting KAPE collection + parsing..."})

        drive = req.source_drive.rstrip(":\\/") + ":\\"
        kape = find_kape()
        if not kape or not os.path.isfile(kape):
            _triage_state["phase"] = "error"
            _triage_state["result"] = {"error": "KAPE not found. Configure in Settings."}
            _triage_state["running"] = False
            return

        cmd = [
            kape,
            "--tsource", drive,
            "--tdest", collected_dir,
            "--target", "ForensicWorkstation",
            "--mdest", parsed_dir,
            "--module", "ForensicWorkstation",
            "--msource", collected_dir,
        ]
        if req.vss:
            cmd += ["--vss", "--vd"]

        _triage_state["progress"].append({"time": time.time(), "msg": f"KAPE command: {os.path.basename(kape)} --target ForensicWorkstation --module ForensicWorkstation"})

        t1 = time.time()
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        # Read KAPE output line by line for progress
        last_running = ""
        for line in iter(proc.stdout.readline, ""):
            line = line.strip()
            if not line:
                continue
            # Track "Running <tool>" lines
            if line.startswith("Running "):
                tool_name = line.split(":")[0].replace("Running ", "").strip()
                if tool_name != last_running:
                    last_running = tool_name
                    _triage_state["phase"] = f"kape_parsing: {tool_name}"
                    _triage_state["progress"].append({"time": time.time(), "msg": f"Parsing: {tool_name}"})
            elif "Processed" in line or "records" in line.lower():
                _triage_state["progress"].append({"time": time.time(), "msg": line[:120]})
            elif "Error" in line or "error" in line:
                _triage_state["progress"].append({"time": time.time(), "msg": f"Warning: {line[:120]}"})

        proc.wait(timeout=7200)
        kape_duration = round(time.time() - t1, 1)
        steps.append({
            "step": "kape_complete",
            "duration_s": kape_duration,
            "return_code": proc.returncode,
        })
        _triage_state["progress"].append({"time": time.time(), "msg": f"KAPE complete ({kape_duration}s)"})

        # ── Phase 1.5: Console Log Diagnostics + SRUM Repair ──
        try:
            from core.kape_log_parser import get_diagnostics
            diag = get_diagnostics(parsed_dir)
            failed_mods = [m for m in diag.get("modules", []) if m["status"].startswith("failed")]
            if failed_mods:
                for fm in failed_mods[:5]:
                    err_msg = fm["errors"][0][:80] if fm["errors"] else "unknown error"
                    _triage_state["progress"].append({
                        "time": time.time(),
                        "msg": f"Module FAILED: {fm['module']} — {err_msg}",
                    })
            steps.append({"step": "log_diagnostics", "failed_modules": len(failed_mods)})
        except Exception:
            pass

        try:
            from core.srum_repair import find_srudb_in_collection, repair_and_parse_srum
            import glob as _glob
            srum_csvs = _glob.glob(os.path.join(parsed_dir, "**", "*SrumECmd*"), recursive=True)
            if not srum_csvs:
                srudbs = find_srudb_in_collection(collected_dir)
                if srudbs:
                    _triage_state["phase"] = "srum_repair"
                    _triage_state["progress"].append({"time": time.time(), "msg": "Repairing dirty SRUM database..."})
                    srum_out = os.path.join(parsed_dir, "SRUMDatabase")
                    srum_result = repair_and_parse_srum(srudbs[0], srum_out)
                    if srum_result.get("status") == "ok":
                        _triage_state["progress"].append({
                            "time": time.time(),
                            "msg": f"SRUM parsed: {srum_result.get('total_records', 0):,} records",
                        })
                    else:
                        _triage_state["progress"].append({
                            "time": time.time(),
                            "msg": f"SRUM repair: {srum_result.get('detail', 'failed')[:80]}",
                        })
                    steps.append({"step": "srum_repair", **srum_result})
        except Exception:
            pass

        # ── Phase 2: Open Case ──
        _triage_state["phase"] = "opening_case"
        _triage_state["progress"].append({"time": time.time(), "msg": "Loading parsed data..."})

        if not os.path.isdir(parsed_dir):
            _triage_state["phase"] = "error"
            _triage_state["result"] = {"error": f"Parsed directory not found: {parsed_dir}", "steps": steps}
            _triage_state["running"] = False
            return

        from state import app_state
        t2 = time.time()
        meta = app_state.open_axiom(parsed_dir, label=cname)
        steps.append({"step": "open_case", "duration_s": round(time.time() - t2, 1), "total_hits": meta.get("total_hits", 0)})
        _triage_state["progress"].append({"time": time.time(), "msg": f"Case loaded: {meta.get('total_hits', 0):,} artifacts"})

        axiom = app_state.get_axiom()

        _triage_state["phase"] = "initial_triage"
        _triage_state["progress"].append({"time": time.time(), "msg": "Running initial window-first triage..."})

        initial_triage_summary: dict[str, Any] = {}
        triage: dict[str, Any] | None = None
        t2b = time.time()
        try:
            from core.analysis.initial_triage import initial_triage

            triage = initial_triage(axiom, scope_mode="recent_14d")
            initial_triage_summary = {
                "incident_type": triage.get("classification", {}).get("incident_type", "unknown"),
                "operator_style": triage.get("classification", {}).get("operator_style", "unknown"),
                "top_window_count": len(triage.get("window_discovery", {}).get("top_windows", []) or []),
                "precursor_status": triage.get("precursor_context", {}).get("status", "historical_context"),
            }
            steps.append({
                "step": "initial_triage_pack",
                "duration_s": round(time.time() - t2b, 1),
                **initial_triage_summary,
            })
            _triage_state["progress"].append({
                "time": time.time(),
                "msg": (
                    "Initial triage: "
                    f"{initial_triage_summary.get('incident_type', 'unknown')} / "
                    f"{initial_triage_summary.get('operator_style', 'unknown')}"
                ),
            })
        except Exception as e:
            steps.append({"step": "initial_triage_pack", "error": str(e)})

        # ── Phase 3: Find Suspicious ──
        _triage_state["phase"] = "analyzing"
        _triage_state["progress"].append({"time": time.time(), "msg": "Running threat detection..."})

        findings: list = []
        t3 = time.time()
        try:
            from core.analysis.suspicious import find_suspicious
            sus = find_suspicious(axiom.artifact_queries)
            findings = sus.get("findings", [])
            steps.append({"step": "find_suspicious", "duration_s": round(time.time() - t3, 1), "total": len(findings)})
            _triage_state["progress"].append({"time": time.time(), "msg": f"Threat detection: {len(findings)} findings"})
        except Exception as e:
            steps.append({"step": "find_suspicious", "error": str(e)})

        # ── Phase 4: Extract IOCs ──
        _triage_state["progress"].append({"time": time.time(), "msg": "Extracting IOCs..."})
        ioc_list: list = []
        t4 = time.time()
        try:
            from core.analysis.ioc_extractor import extract_iocs
            iocs = extract_iocs(axiom)
            ioc_list = iocs.get("iocs", [])
            steps.append({"step": "extract_iocs", "duration_s": round(time.time() - t4, 1), "total": len(ioc_list)})
            _triage_state["progress"].append({"time": time.time(), "msg": f"IOCs extracted: {len(ioc_list)}"})
        except Exception as e:
            steps.append({"step": "extract_iocs", "error": str(e)})

        # ── Phase 5: Timeline ──
        _triage_state["progress"].append({"time": time.time(), "msg": "Building timeline..."})
        timeline_count = 0
        t5 = time.time()
        try:
            tl = axiom.get_timeline(limit=500)
            timeline_count = tl.get("total_events", 0)
            steps.append({"step": "build_timeline", "duration_s": round(time.time() - t5, 1), "total": timeline_count})
        except Exception as e:
            steps.append({"step": "build_timeline", "error": str(e)})

        # ── Phase 6: MITRE ──
        mitre_count = 0
        try:
            from core.analysis.mitre_mapper import get_attack_narrative
            mitre = get_attack_narrative(findings)
            mitre_count = len(mitre.get("techniques", []))
        except Exception:
            pass

        total_duration = round(time.time() - t_start, 1)
        _triage_state["progress"].append({"time": time.time(), "msg": f"Complete! Total: {total_duration}s"})

        _triage_state["phase"] = "complete"
        _triage_state["result"] = {
            "status": "complete",
            "case_name": meta.get("case_name", cname),
            "total_duration_s": total_duration,
            "output_dir": out_dir,
            "parsed_dir": parsed_dir,
            "total_hits": meta.get("total_hits", 0),
            "artifact_types": meta.get("artifact_types", {}),
            "summary": {
                "suspicious_findings": len(findings),
                "iocs_extracted": len(ioc_list),
                "timeline_events": timeline_count,
                "mitre_techniques": mitre_count,
            },
            "initial_triage": initial_triage_summary,
            "steps": steps,
        }

    except Exception as e:
        _triage_state["phase"] = "error"
        _triage_state["result"] = {"error": str(e), "steps": steps}
    finally:
        _triage_state["running"] = False


@router.post("/run")
async def run_triage(req: TriageRequest):
    """Start triage pipeline in background. Poll /api/triage/status for progress."""
    global _triage_state

    if _triage_state["running"]:
        return {"error": "Triage already running", "phase": _triage_state["phase"]}

    drive = req.source_drive.rstrip(":\\/") + ":\\"
    datestamp = datetime.now().strftime("%Y%m%d")
    cname = req.case_name or "case"
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_dir = os.path.dirname(backend_dir)

    if req.output_dir:
        out_dir = req.output_dir
    else:
        out_dir = os.path.join(project_dir, "export", f"{datestamp}_{cname}")

    collected_dir = os.path.join(out_dir, "collected")
    parsed_dir = os.path.join(out_dir, "parsed")

    # Reset state
    _triage_state = {
        "running": True,
        "phase": "starting",
        "progress": [{"time": time.time(), "msg": "Triage starting..."}],
        "result": None,
        "start_time": time.time(),
        "parsed_dir": parsed_dir,
    }

    # Run in background thread
    t = threading.Thread(
        target=_run_triage_background,
        args=(req, out_dir, collected_dir, parsed_dir, cname),
        daemon=True,
    )
    t.start()

    return {"status": "started", "output_dir": out_dir}


@router.get("/status")
async def triage_status():
    """Poll for triage progress."""
    elapsed = round(time.time() - _triage_state["start_time"], 1) if _triage_state["start_time"] else 0

    # Count parsed files for progress indicator
    parsed_stats = {}
    if _triage_state["parsed_dir"]:
        parsed_stats = _count_parsed_files(_triage_state["parsed_dir"])

    return {
        "running": _triage_state["running"],
        "phase": _triage_state["phase"],
        "elapsed_s": elapsed,
        "progress": _triage_state["progress"][-20:],  # last 20 messages
        "parsed_files": parsed_stats,
        "result": _triage_state["result"],
    }


@router.get("/kape-options")
async def kape_options():
    """List available KAPE targets and modules for the command builder."""
    from core.config import find_kape

    kape = find_kape()
    if not kape or not os.path.isfile(kape):
        return {"error": "KAPE not found. Configure in Settings."}

    kape_dir = os.path.dirname(kape)
    targets_dir = os.path.join(kape_dir, "Targets")
    modules_dir = os.path.join(kape_dir, "Modules")

    def _parse_kape_files(base_dir: str, ext: str) -> list[dict]:
        """Parse .tkape/.mkape files for name, description, and includes."""
        items: list[dict] = []
        if not os.path.isdir(base_dir):
            return items
        for root, dirs, files in os.walk(base_dir):
            rel = os.path.relpath(root, base_dir)
            category = rel if rel != "." else ""
            for f in sorted(files):
                if not f.endswith(ext):
                    continue
                name = f.replace(ext, "")
                desc = ""
                includes: list[str] = []
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if line.startswith("Description:"):
                                desc = line.replace("Description:", "").strip()
                            # Parse included targets/modules (Executable: or Path:)
                            if category == "Compound":
                                if line.startswith("Executable:") or line.startswith("Path:"):
                                    val = line.split(":", 1)[1].strip()
                                    val = val.replace(ext, "").replace(".tkape", "").replace(".mkape", "")
                                    if val:
                                        includes.append(val)
                except Exception:
                    pass
                item: dict = {
                    "name": name,
                    "category": category,
                    "description": desc,
                    "is_compound": category == "Compound",
                }
                if includes:
                    item["includes"] = includes
                items.append(item)
        return items

    targets = _parse_kape_files(targets_dir, ".tkape")
    modules = _parse_kape_files(modules_dir, ".mkape")

    project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    return {
        "kape_path": kape,
        "project_dir": project_dir.replace("\\", "/"),
        "targets": targets,
        "modules": modules,
    }


class KapeRunRequest(BaseModel):
    source: str
    target_dest: str
    targets: list[str] = []
    module_dest: str = ""
    module_source: str = ""
    modules: list[str] = []
    vss: bool = False
    vd: bool = False


@router.post("/kape-run")
async def kape_run(req: KapeRunRequest):
    """Run KAPE with custom targets/modules. Returns progress via /status."""
    global _triage_state
    from core.config import find_kape

    if _triage_state["running"]:
        return {"error": "A process is already running", "phase": _triage_state["phase"]}

    kape = find_kape()
    if not kape:
        return {"error": "KAPE not found"}

    source = req.source.rstrip(":\\/") + ":\\"

    cmd = [kape, "--tsource", source]

    if req.targets:
        cmd += ["--tdest", req.target_dest, "--target", ",".join(req.targets)]

    if req.modules:
        msource = req.module_source or req.target_dest
        cmd += ["--mdest", req.module_dest or req.target_dest, "--module", ",".join(req.modules), "--msource", msource]

    if req.vss:
        cmd.append("--vss")
    if req.vd:
        cmd.append("--vd")

    # Reset state
    _triage_state = {
        "running": True,
        "phase": "kape_custom",
        "progress": [{"time": time.time(), "msg": f"Command: {' '.join(os.path.basename(c) if i == 0 else c for i, c in enumerate(cmd))}"}],
        "result": None,
        "start_time": time.time(),
        "parsed_dir": req.module_dest or req.target_dest,
    }

    def _run():
        global _triage_state
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            last_tool = ""
            for line in iter(proc.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("Running "):
                    tool = line.split(":")[0].replace("Running ", "").strip()
                    if tool != last_tool:
                        last_tool = tool
                        _triage_state["phase"] = f"kape: {tool}"
                        _triage_state["progress"].append({"time": time.time(), "msg": f"Running: {tool}"})
                elif any(kw in line.lower() for kw in ["processed", "records", "completed", "found"]):
                    _triage_state["progress"].append({"time": time.time(), "msg": line[:150]})
                elif "error" in line.lower():
                    _triage_state["progress"].append({"time": time.time(), "msg": f"Error: {line[:150]}"})

            proc.wait(timeout=7200)
            duration = round(time.time() - _triage_state["start_time"], 1)
            _triage_state["phase"] = "complete"
            _triage_state["progress"].append({"time": time.time(), "msg": f"KAPE complete ({duration}s, exit code {proc.returncode})"})
            _triage_state["result"] = {"status": "complete", "duration_s": duration, "return_code": proc.returncode}
        except Exception as e:
            _triage_state["phase"] = "error"
            _triage_state["progress"].append({"time": time.time(), "msg": f"Error: {e}"})
            _triage_state["result"] = {"error": str(e)}
        finally:
            _triage_state["running"] = False

    threading.Thread(target=_run, daemon=True).start()

    return {"status": "started", "command": " ".join(cmd)}


@router.post("/stop")
async def stop_triage():
    """Stop running triage (best effort)."""
    global _triage_state
    _triage_state["running"] = False
    _triage_state["phase"] = "stopped"
    _triage_state["progress"].append({"time": time.time(), "msg": "Triage stopped by user"})
    return {"status": "stop_requested"}


@router.get("/lane-state")
async def get_lane_state():
    from state import app_state
    from core.analysis.bias_remediation import build_lane_evidence_summary_surface

    try:
        axiom = app_state.get_axiom()
        return build_lane_evidence_summary_surface(axiom)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/diagnostics")
async def triage_diagnostics(parsed_dir: str = ""):
    """Parse KAPE console logs and report module failures."""
    from core.kape_log_parser import get_diagnostics

    target = parsed_dir or _triage_state.get("parsed_dir", "")
    if not target:
        return {"error": "No parsed directory specified. Run triage first or provide parsed_dir."}
    return get_diagnostics(target)


class SrumRepairRequest(BaseModel):
    collected_dir: str
    output_dir: str


@router.post("/srum-repair")
async def srum_repair(req: SrumRepairRequest):
    """Find and repair dirty SRUM databases, then parse with SrumECmd."""
    from core.srum_repair import find_srudb_in_collection, repair_and_parse_srum

    srudbs = find_srudb_in_collection(req.collected_dir)
    if not srudbs:
        return {"status": "not_found", "detail": "No SRUDB.dat found in collected directory"}

    # Use the first (current volume, not VSS) SRUDB.dat
    result = repair_and_parse_srum(srudbs[0], req.output_dir)
    result["srudb_path"] = srudbs[0]
    result["total_srudbs_found"] = len(srudbs)
    return result
