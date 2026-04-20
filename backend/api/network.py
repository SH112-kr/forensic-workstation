"""PCAP network analysis API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/network", tags=["network"])


def _pyshark_available() -> bool:
    try:
        import pyshark  # noqa: F401
        return True
    except Exception:
        return False


class OpenPcapRequest(BaseModel):
    path: str


@router.get("/status")
async def status():
    """Report whether pyshark is installed and a PCAP is loaded.

    The UI calls this on mount so we can distinguish "dependency missing"
    from "no file loaded" and show the right guidance.
    """
    from state import app_state
    c = app_state.get("pcap")
    loaded = bool(c and getattr(c, "is_connected", lambda: False)())
    return {
        "pyshark_available": _pyshark_available(),
        "loaded": loaded,
        "metadata": c.get_metadata() if loaded else None,
        "install_hint": None if _pyshark_available() else (
            "pyshark is not installed. Run `pip install pyshark` and ensure "
            "Wireshark/tshark is on PATH."
        ),
    }


@router.post("/open")
async def open_pcap(req: OpenPcapRequest):
    from state import app_state
    if not _pyshark_available():
        raise HTTPException(
            status_code=400,
            detail="pyshark is not installed. Run `pip install pyshark` and ensure Wireshark/tshark is on PATH.",
        )
    try:
        app_state.add_allowed_evidence([req.path], source="network:open")
        from core.connectors.pcap import PcapConnector
        app_state.remove("pcap")
        c = PcapConnector()
        meta = c.connect(req.path)
        app_state.set("pcap", c)
        return meta
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _pcap():
    from state import app_state
    c = app_state.get("pcap")
    if not c or not c.is_connected():
        raise HTTPException(status_code=400, detail="PCAP 파일이 로드되지 않았습니다.")
    return c


@router.get("/conversations")
async def conversations(display_filter: str = "", limit: int = 100):
    try:
        return _pcap().get_conversations(display_filter, limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/dns")
async def dns_queries(limit: int = 200):
    try:
        results = _pcap().get_dns_queries(limit)
        return {"total": len(results), "dns_queries": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/http")
async def http_requests(limit: int = 200):
    try:
        results = _pcap().get_http_requests(limit)
        return {"total": len(results), "http_requests": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/iocs")
async def extract_iocs():
    try:
        return _pcap().extract_iocs()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
