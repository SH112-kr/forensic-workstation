"""Hayabusa EVTX log analysis connector (CLI-based)."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from connectors.base import BaseConnector


class HayabusaConnector(BaseConnector):
    """Windows EVTX log analysis using Hayabusa (Sigma-based detection)."""

    def __init__(self) -> None:
        self._evtx_path: str = ""
        self._hayabusa_path: str = "hayabusa"

    def connect(self, path: str, **kwargs: Any) -> dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"EVTX path not found: {path}")
        self._evtx_path = path
        self._hayabusa_path = kwargs.get("hayabusa_path", "hayabusa")
        return {"status": "success", "evtx_path": path}

    def disconnect(self) -> None:
        self._evtx_path = ""

    def is_connected(self) -> bool:
        return bool(self._evtx_path)

    def get_metadata(self) -> dict:
        return {"evtx_path": self._evtx_path}

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        return self.run_scan()

    def get_capabilities(self) -> list[str]:
        return ["scan", "search_events"]

    def run_scan(self, min_level: str = "medium", profile: str = "verbose") -> dict:
        """Run Hayabusa scan on EVTX files."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                self._hayabusa_path, "json-timeline",
                "-d" if os.path.isdir(self._evtx_path) else "-f",
                self._evtx_path,
                "-o", tmp_path,
                "--min-level", min_level,
                "-p", profile,
                "--no-wizard",
                "-q",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0 and not os.path.exists(tmp_path):
                return {"error": f"Hayabusa failed: {result.stderr[:500]}"}

            events = []
            if os.path.exists(tmp_path):
                with open(tmp_path, "r", encoding="utf-8-sig") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue

            # Sort by level severity
            level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
            events.sort(key=lambda x: level_order.get(x.get("Level", "").lower(), 5))

            return {
                "total_events": len(events),
                "events": events[:200],
                "truncated": len(events) > 200,
            }
        except FileNotFoundError:
            return {"error": f"Hayabusa를 찾을 수 없습니다. 경로 확인: {self._hayabusa_path}"}
        except subprocess.TimeoutExpired:
            return {"error": "Hayabusa 스캔 타임아웃 (5분 초과)"}
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def search_events(self, event_id: int = 0, keyword: str = "",
                      start_time: str = "", end_time: str = "") -> list[dict]:
        """Search EVTX events by criteria."""
        result = self.run_scan(min_level="informational")
        events = result.get("events", [])

        filtered = []
        for e in events:
            if event_id and e.get("EventID") != event_id:
                continue
            if keyword and keyword.lower() not in json.dumps(e).lower():
                continue
            if start_time and e.get("Timestamp", "") < start_time:
                continue
            if end_time and e.get("Timestamp", "") > end_time:
                continue
            filtered.append(e)
        return filtered
