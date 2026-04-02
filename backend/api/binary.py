"""Ghidra binary analysis API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/binary", tags=["binary"])


class AnalyzeRequest(BaseModel):
    path: str
    ghidra_install_dir: str = ""


class DecompileRequest(BaseModel):
    address: str = ""
    name: str = ""


@router.post("/analyze")
async def analyze_binary(req: AnalyzeRequest):
    from state import app_state
    try:
        from core.connectors.ghidra import GhidraConnector
        existing = app_state.get("ghidra")
        if existing:
            existing.disconnect()
        c = GhidraConnector()
        if existing and existing._pyhidra_started:
            c._pyhidra_started = True
        meta = c.connect(req.path, ghidra_install_dir=req.ghidra_install_dir)
        app_state.set("ghidra", c)
        return {"status": "success", **meta}
    except ImportError:
        raise HTTPException(status_code=400, detail="pyhidra가 설치되지 않았습니다.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _ghidra():
    from state import app_state
    return app_state.get_ghidra()


@router.get("/functions")
async def list_functions(filter: str = "", limit: int = 200):
    try:
        funcs = _ghidra().list_functions(filter, limit)
        return {"total": len(funcs), "functions": funcs}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/imports")
async def list_imports():
    try:
        imports = _ghidra().list_imports()
        by_dll: dict[str, int] = {}
        for imp in imports:
            dll = imp.get("namespace", "?")
            by_dll[dll] = by_dll.get(dll, 0) + 1
        return {"total_imports": len(imports), "by_dll": by_dll, "imports": imports}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/suspicious")
async def find_suspicious_apis():
    try:
        return _ghidra().find_suspicious_apis()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/strings")
async def list_strings(min_length: int = 4, limit: int = 500):
    try:
        strings = _ghidra().list_strings(min_length, limit)
        return {"total": len(strings), "strings": strings}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decompile")
async def decompile_function(req: DecompileRequest):
    try:
        return _ghidra().decompile_function(req.address, req.name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
