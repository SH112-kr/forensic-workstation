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


def load_active_case() -> dict[str, Any]:
    """Read persisted active-case metadata for cross-process evidence resolution."""
    if not os.path.exists(_ACTIVE_CASE_FILE):
        return {}
    try:
        with open(_ACTIVE_CASE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any]:
        evidence_locations = [
            normalize_path(p) if os.path.isabs(str(p).strip()) else str(p).strip()
            for p in entry.get("evidence_locations", [])
            if str(p).strip()
        ]
        evidence_sources = [
            str(v).strip()
            for v in entry.get("evidence_sources", [])
            if str(v).strip()
        ]
        return {
            **entry,
            "path": normalize_path(entry.get("path", "")),
            "evidence_locations": sorted(set(evidence_locations)),
            "evidence_sources": evidence_sources,
        }

    data = _normalize_entry(data)
    data["all_cases"] = [
        _normalize_entry(entry)
        for entry in data.get("all_cases", [])
        if isinstance(entry, dict)
    ]
    return data


def _find_relative_evidence_path(case_path: str, evidence_name: str) -> str:
    """Resolve a basename-only evidence reference near the selected case tree.

    AXIOM sometimes stores only ``foo.E01`` instead of an absolute path. In
    that case, search a small set of ancestor directories around the already
    user-selected case path and accept the first UNIQUE match.
    """
    if not case_path or not evidence_name:
        return ""
    basename = os.path.basename(str(evidence_name).strip())
    if not basename or basename != str(evidence_name).strip():
        return ""

    roots: list[str] = []
    current = os.path.dirname(case_path)
    for _ in range(4):
        if not current or current in roots:
            break
        roots.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    for root in roots:
        matches: list[str] = []
        try:
            for dirpath, _, filenames in os.walk(root):
                if basename in filenames:
                    matches.append(normalize_path(os.path.join(dirpath, basename)))
                    if len(matches) > 1:
                        break
        except Exception:
            continue
        if len(matches) == 1:
            return matches[0]

    return ""


def resolve_active_case_evidence(path_or_ref: str = "") -> str:
    """Resolve an active-case evidence path from an empty input, path, or ref.

    Supported inputs:
    - ``""`` or ``"active_case"``: use the sole evidence file on the active case
    - full path: allowed if it exactly matches an active-case evidence location
    - basename / source evidence id: matched against active-case metadata
    """
    active = load_active_case()
    if not active:
        return ""

    refs = {str(path_or_ref or "").strip(), str(path_or_ref or "").strip().lower()}

    candidates: list[str] = []
    for entry in [active, *active.get("all_cases", [])]:
        for loc in entry.get("evidence_locations", []):
            if loc and loc not in candidates:
                candidates.append(loc)

    if not candidates:
        return ""

    raw = str(path_or_ref or "").strip()
    if raw in {"", "active_case"}:
        if len(candidates) != 1:
            return ""
        chosen = candidates[0]
        if os.path.isabs(chosen):
            return chosen
        for entry in [active, *active.get("all_cases", [])]:
            resolved = _find_relative_evidence_path(entry.get("path", ""), chosen)
            if resolved:
                return resolved
        return chosen

    normalized = normalize_path(raw)
    for loc in candidates:
        if normalized == loc:
            return loc

    for entry in [active, *active.get("all_cases", [])]:
        entry_locs = entry.get("evidence_locations", [])
        entry_sources = [str(v).strip().lower() for v in entry.get("evidence_sources", [])]
        for loc in entry_locs:
            basename = os.path.basename(loc).lower()
            if raw.lower() == basename or raw.lower() in entry_sources:
                return loc if os.path.isabs(loc) else (_find_relative_evidence_path(entry.get("path", ""), loc) or loc)

    return ""


def resolve_allowed_evidence(path_or_ref: str = "", extensions: tuple[str, ...] = ()) -> str:
    """Resolve a path strictly from the persisted user-selected allowlist.

    This is for evidence types that can be uploaded without an AXIOM/KAPE case
    wrapper, such as a standalone E01. It never searches the filesystem.
    """
    raw = str(path_or_ref or "").strip()
    allowed = load_allowed_evidence().get("paths", [])
    if extensions:
        extensions_lc = tuple(ext.lower() for ext in extensions)
        allowed = [p for p in allowed if str(p).lower().endswith(extensions_lc)]

    if raw in {"", "active_case"}:
        return allowed[0] if len(allowed) == 1 else ""

    normalized = normalize_path(raw)
    for path in allowed:
        if normalized == path:
            return path

    raw_lc = raw.lower()
    matches = [
        path for path in allowed
        if raw_lc == os.path.basename(path).lower()
    ]
    return matches[0] if len(matches) == 1 else ""


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
                    meta = c.get_metadata()
                    cases.append({
                        "path": p,
                        "case_id": cid,
                        "evidence_sources": meta.get("evidence_sources", []),
                        "evidence_locations": meta.get("evidence_locations", []),
                    })
            active_connector = self._connectors.get(f"axiom:{case_id}")
            active_meta = active_connector.get_metadata() if active_connector else {}
            with open(_ACTIVE_CASE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "path": path,
                    "case_id": case_id,
                    "evidence_sources": active_meta.get("evidence_sources", []),
                    "evidence_locations": active_meta.get("evidence_locations", []),
                    "all_cases": cases,
                }, f, ensure_ascii=False, indent=2)
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


# ── Regression harness: FW_FIXTURE preload ──
# When FW_FIXTURE is set, load a synthetic fixture as the active case so
# the MCP server / FastAPI backend both see it without any open_case call.
# Fully opt-in: env unset → this block is a no-op. Import is deferred so
# production deployments without backend/regression/ on sys.path still
# start cleanly.
try:
    from regression.preload import preload_fixture_if_requested as _preload_fixture
    _preload_fixture(app_state)
except ModuleNotFoundError:
    pass
except SystemExit:
    raise
except Exception as _preload_err:  # defensive: never crash production startup
    import sys as _sys
    print(f"[regression] preload skipped: {_preload_err}", file=_sys.stderr)
