"""Application state — manages connector instances across API requests."""

from __future__ import annotations

import os
import sqlite3
from typing import Any


class AppState:
    """Thread-safe state manager for forensic connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, Any] = {}

    def get(self, name: str) -> Any:
        return self._connectors.get(name)

    def set(self, name: str, connector: Any) -> None:
        self._connectors[name] = connector

    def remove(self, name: str) -> None:
        c = self._connectors.pop(name, None)
        if c and hasattr(c, "disconnect"):
            try:
                c.disconnect()
            except Exception:
                pass

    def get_axiom(self):
        from core.connectors.axiom_mfdb import AxiomMfdbConnector
        c = self.get("axiom")
        if not c or not c.is_connected():
            raise RuntimeError("케이스가 열려있지 않습니다. 먼저 케이스를 열어주세요.")
        return c

    def get_volatility(self):
        c = self.get("volatility")
        if not c or not c.is_connected():
            raise RuntimeError("메모리 덤프가 로드되지 않았습니다.")
        return c

    def get_ghidra(self):
        c = self.get("ghidra")
        if not c or not c.is_connected():
            raise RuntimeError("바이너리가 로드되지 않았습니다.")
        return c

    def open_axiom(self, path: str, label: str = "") -> dict:
        """Open an AXIOM case or KAPE output directory. Supports multiple simultaneous cases."""
        if os.path.isdir(path):
            from core.connectors.kape_csv import KapeCsvConnector
            c = KapeCsvConnector()
        else:
            from core.connectors.axiom_mfdb import AxiomMfdbConnector
            c = AxiomMfdbConnector()
        meta = c.connect(path)
        case_id = label or os.path.basename(os.path.dirname(path) if not os.path.isdir(path) else path)
        self._connectors[f"axiom:{case_id}"] = c
        # Keep backward compat: also set as primary
        self._connectors["axiom"] = c
        # Write shared state so MCP bridge can auto-connect
        self._write_active_case(path, case_id)
        return {"case_id": case_id, **meta}

    @staticmethod
    def _write_active_case(path: str, case_id: str) -> None:
        """Persist active case info for cross-process sharing (MCP bridge)."""
        import json
        state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".active_case.json")
        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump({"path": path, "case_id": case_id}, f)
        except Exception:
            pass

    def list_cases(self) -> list[dict]:
        """List all open AXIOM cases."""
        cases = []
        for name, c in self._connectors.items():
            if name.startswith("axiom:") and c.is_connected():
                cases.append({"case_id": name.replace("axiom:", ""), "metadata": c.get_metadata()})
        return cases

    def switch_case(self, case_id: str) -> dict:
        """Switch the active AXIOM case."""
        key = f"axiom:{case_id}"
        c = self._connectors.get(key)
        if not c or not c.is_connected():
            raise RuntimeError(f"Case '{case_id}' not found or not connected.")
        self._connectors["axiom"] = c
        return c.get_metadata()

    def list_connected(self) -> dict[str, bool]:
        return {name: c.is_connected() for name, c in self._connectors.items()}


# Singleton
app_state = AppState()
