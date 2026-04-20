"""Application state and evidence guardrails for forensic connectors."""

from __future__ import annotations

import json
import os
from typing import Any


_STATE_DIR = os.path.dirname(os.path.abspath(__file__))
_ACTIVE_CASE_FILE = os.path.join(_STATE_DIR, ".active_case.json")
_ALLOWED_EVIDENCE_FILE = os.path.join(_STATE_DIR, ".allowed_evidence.json")


def normalize_path(path: str) -> str:
    """Normalize a filesystem path for stable allowlist comparisons."""
    if not path:
        return ""
    return os.path.normcase(os.path.normpath(os.path.abspath(path.strip())))


def load_allowed_evidence() -> dict[str, Any]:
    """Read the persisted evidence allowlist for cross-process enforcement."""
    if not os.path.exists(_ALLOWED_EVIDENCE_FILE):
        return {"paths": [], "source": ""}
    try:
        with open(_ALLOWED_EVIDENCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"paths": [], "source": ""}

    paths = [normalize_path(p) for p in data.get("paths", []) if str(p).strip()]
    return {"paths": sorted(set(paths)), "source": data.get("source", "")}


def is_path_allowed(path: str) -> bool:
    """Return True when the path was explicitly selected by the user."""
    norm = normalize_path(path)
    allowed = set(load_allowed_evidence().get("paths", []))
    return bool(norm) and norm in allowed


def build_not_allowed_message(path: str) -> str:
    """Explain why a path is blocked by the evidence guardrail."""
    return (
        "Blocked by evidence guardrail. "
        f"Path was not explicitly selected by the user: {path}"
    )


class AppState:
    """Thread-safe state manager for forensic connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, Any] = {}
        self._allowed_evidence: set[str] = set(load_allowed_evidence().get("paths", []))
        # case_id -> original path, populated on open_axiom so _write_active_case
        # never has to re-derive paths from connector metadata.
        self._case_paths: dict[str, str] = {}

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

    def _persist_allowed(self, source: str) -> dict[str, Any]:
        payload = {"paths": sorted(self._allowed_evidence), "source": source}
        try:
            with open(_ALLOWED_EVIDENCE_FILE, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return payload

    def set_allowed_evidence(self, paths: list[str], source: str = "") -> dict[str, Any]:
        """Replace the allowlist with exactly these paths (project transition)."""
        self._allowed_evidence = {normalize_path(p) for p in paths if str(p).strip()}
        return self._persist_allowed(source)

    def add_allowed_evidence(self, paths: list[str], source: str = "") -> dict[str, Any]:
        """Append paths to the allowlist without clobbering prior entries."""
        # Reload from disk so a stale in-memory set doesn't drop entries another
        # process just added.
        self._allowed_evidence = set(load_allowed_evidence().get("paths", []))
        for p in paths:
            norm = normalize_path(p)
            if norm:
                self._allowed_evidence.add(norm)
        return self._persist_allowed(source)

    def remove_allowed_evidence(self, paths: list[str], source: str = "") -> dict[str, Any]:
        """Remove specific paths from the allowlist (e.g. on case close)."""
        self._allowed_evidence = set(load_allowed_evidence().get("paths", []))
        for p in paths:
            norm = normalize_path(p)
            if norm:
                self._allowed_evidence.discard(norm)
        return self._persist_allowed(source)

    def is_allowed_evidence(self, path: str) -> bool:
        norm = normalize_path(path)
        if not norm:
            return False
        if not self._allowed_evidence:
            self._allowed_evidence = set(load_allowed_evidence().get("paths", []))
        return norm in self._allowed_evidence

    def require_allowed_evidence(self, path: str) -> None:
        if not self.is_allowed_evidence(path):
            raise RuntimeError(build_not_allowed_message(path))

    def get_axiom(self):
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
        self.require_allowed_evidence(path)
        if os.path.isdir(path):
            from core.connectors.kape_csv import KapeCsvConnector
            c = KapeCsvConnector()
        else:
            from core.connectors.axiom_mfdb import AxiomMfdbConnector
            c = AxiomMfdbConnector()
        meta = c.connect(path)
        case_id = label or os.path.basename(os.path.dirname(path) if not os.path.isdir(path) else path)
        self._connectors[f"axiom:{case_id}"] = c
        self._connectors["axiom"] = c
        self._case_paths[case_id] = path
        self._write_active_case(path, case_id)
        return {"case_id": case_id, **meta}

    def _write_active_case(self, path: str, case_id: str) -> None:
        """Persist active case info for cross-process sharing (MCP bridge).

        Uses ``self._case_paths`` as the source of truth so the on-disk state
        stays populated even if a connector's metadata is missing or a case is
        temporarily disconnected.
        """
        try:
            cases = []
            for cid, p in self._case_paths.items():
                c = self._connectors.get(f"axiom:{cid}")
                if p and c and c.is_connected():
                    cases.append({"path": p, "case_id": cid})
            with open(_ACTIVE_CASE_FILE, "w", encoding="utf-8") as f:
                json.dump({"path": path, "case_id": case_id, "all_cases": cases}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def iter_axiom_cases(self):
        """Yield (case_id, connector) pairs for every connected axiom:* case.

        Cross-case aggregators (compare, pivot, fan-out search) iterate this
        helper instead of touching ``_connectors`` directly so the "skip the
        active alias" rule lives in one place.
        """
        for name, c in self._connectors.items():
            if name.startswith("axiom:") and c.is_connected():
                yield name.replace("axiom:", ""), c

    def get_active_case_id(self) -> str:
        """Return the case_id whose connector currently sits under the plain 'axiom' alias.

        Empty string when no case is active.
        """
        active = self._connectors.get("axiom")
        if not active:
            return ""
        for case_id, c in self.iter_axiom_cases():
            if c is active:
                return case_id
        return ""

    def list_cases(self) -> list[dict]:
        """List open cases with provenance already surfaced.

        Keeps the legacy ``metadata`` field so older callers keep working, but
        also pulls out ``source_type``, ``source_path``, ``case_name``, and
        ``total_hits`` at the top level so the UI does not have to drill into
        metadata on every render.
        """
        cases = []
        for case_id, c in self.iter_axiom_cases():
            meta = c.get_metadata()
            cases.append({
                "case_id": case_id,
                "source_type": meta.get("source_type", ""),
                "source_path": meta.get("source_path", ""),
                "case_name": meta.get("case_name", case_id),
                "total_hits": meta.get("total_hits", 0),
                "metadata": meta,
            })
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

    def close_all_cases(self) -> dict[str, Any]:
        """Disconnect every open AXIOM/KAPE case and clear evidence state."""
        closed_paths = list(self._case_paths.values())
        for name in [k for k in self._connectors if k.startswith("axiom")]:
            c = self._connectors.pop(name, None)
            if c and hasattr(c, "disconnect"):
                try:
                    c.disconnect()
                except Exception:
                    pass
        self._case_paths.clear()
        # Drop just the case paths from allowlist; leave other evidence intact.
        if closed_paths:
            self.remove_allowed_evidence(closed_paths, source="cases:close")
        try:
            if os.path.exists(_ACTIVE_CASE_FILE):
                os.remove(_ACTIVE_CASE_FILE)
        except Exception:
            pass
        return {"closed": len(closed_paths)}


app_state = AppState()
