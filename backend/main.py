"""Forensic Workstation — FastAPI backend.

Run: python backend/main.py
Open: http://localhost:8000
"""

from __future__ import annotations

import os
import sys

# Add backend directory to Python path for core imports
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_dir)

# Initialize core engine import paths
import core  # noqa: F401 — triggers core/__init__.py which adds core/ to sys.path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(
    title="Forensic Workstation",
    description="DFIR Investigation Platform",
    version="0.1.0",
)

# ── Global Exception Handler ──
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return user-friendly error messages with guidance instead of raw tracebacks."""
    msg = str(exc)
    guidance = ""
    if "not connected" in msg.lower() or "not loaded" in msg.lower():
        guidance = "Please open a case file first from the Dashboard."
    elif "permission denied" in msg.lower():
        guidance = "Check file permissions. Try running as administrator."
    elif "no such file" in msg.lower() or "not found" in msg.lower():
        guidance = "The specified file does not exist. Check the path."
    elif "pyhidra" in msg.lower() or "ghidra" in msg.lower():
        guidance = "Ghidra/pyhidra is not installed. See SETUP_GUIDE.md."
    elif "volatility" in msg.lower():
        guidance = "Volatility3 is not installed. Run: pip install volatility3"
    elif "yara" in msg.lower():
        guidance = "yara-python is not installed. Run: pip install yara-python"
    elif "regipy" in msg.lower():
        guidance = "regipy is not installed. Run: pip install regipy"
    elif "pyshark" in msg.lower():
        guidance = "pyshark is not installed. Run: pip install pyshark"

    return JSONResponse(status_code=400, content={
        "detail": msg,
        "guidance": guidance,
    })


# CORS for local development (React dev server on :5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Audit Logging Middleware ──
from audit import AuditMiddleware  # noqa: E402
app.add_middleware(AuditMiddleware)

# ── API Routes ──
from api.cases import router as cases_router
from api.artifacts import router as artifacts_router
from api.timeline import router as timeline_router
from api.detection import router as detection_router
from api.ioc import router as ioc_router
from api.files import router as files_router
from api.memory import router as memory_router
from api.binary import router as binary_router
from api.report import router as report_router
from api.copilot import router as copilot_router
from api.yara_api import router as yara_router
from api.registry import router as registry_router
from api.logs import router as logs_router
from api.network import router as network_router
from api.settings import router as settings_router
from api.triage import router as triage_router
from api.project import router as project_router
from api.privacy import router as privacy_router
from api.manual import router as manual_router

app.include_router(cases_router)
app.include_router(artifacts_router)
app.include_router(timeline_router)
app.include_router(detection_router)
app.include_router(ioc_router)
app.include_router(files_router)
app.include_router(memory_router)
app.include_router(binary_router)
app.include_router(report_router)
app.include_router(copilot_router)
app.include_router(yara_router)
app.include_router(registry_router)
app.include_router(logs_router)
app.include_router(network_router)
app.include_router(settings_router)
app.include_router(triage_router)
app.include_router(project_router)
app.include_router(privacy_router)
app.include_router(manual_router)


@app.get("/api/health")
async def health():
    from state import app_state
    return {
        "status": "ok",
        "connectors": app_state.list_connected(),
    }


@app.get("/api/health/dependencies")
async def health_dependencies():
    """Report analysis dependencies and the capabilities blocked when missing."""
    from core.dependencies import dependency_report
    return dependency_report()


@app.get("/api/audit")
async def get_audit_log(limit: int = 100):
    """Return the last N entries from the forensic audit log."""
    import json as _json
    from audit import AUDIT_FILE
    entries: list[dict] = []
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            line = line.strip()
            if line:
                entries.append(_json.loads(line))
    except FileNotFoundError:
        pass
    return {"entries": entries, "total": len(entries)}


# ── Serve React Frontend (production) ──
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve React SPA — all non-API routes return index.html."""
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))


def main():
    import uvicorn
    import webbrowser
    import socket

    base_port = int(os.environ.get("PORT", "8001"))

    # Find an available port, trying base_port through base_port+9
    port = base_port
    for try_port in range(base_port, base_port + 10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", try_port))
            port = try_port
            break
        except OSError:
            print(f"  Port {try_port} is in use, trying next...")
            continue
    else:
        print(f"  WARNING: Could not find a free port in range {base_port}-{base_port+9}, using {base_port}")
        port = base_port

    # Docker: bind 0.0.0.0, skip browser open
    is_docker = os.path.exists("/.dockerenv") or os.environ.get("DOCKER", "")
    host = "0.0.0.0" if is_docker else "127.0.0.1"

    print(f"\n  Forensic Workstation starting on http://localhost:{port}\n")

    if not is_docker:
        webbrowser.open(f"http://localhost:{port}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
