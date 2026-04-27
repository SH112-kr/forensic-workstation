"""Registry hive analysis connector via regipy."""

from __future__ import annotations

import os
from typing import Any

from connectors.base import BaseConnector


class RegistryConnector(BaseConnector):
    """Windows registry hive analysis using regipy."""

    def __init__(self) -> None:
        self._hive = None
        self._path: str = ""
        self._hive_type: str = ""

    def connect(self, path: str, **kwargs: Any) -> dict:
        """Open a registry hive file.

        Args:
            path: Path to hive (NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY, etc.)
        """
        from regipy.registry import RegistryHive

        if not os.path.isfile(path):
            raise FileNotFoundError(f"Registry hive not found: {path}")

        self._hive = RegistryHive(path)
        self._path = path
        self._hive_type = self._detect_hive_type(path)

        return {
            "status": "success",
            "file": os.path.basename(path),
            "path": path,
            "hive_type": self._hive_type,
            "root_key": str(self._hive.root.name) if self._hive.root else "",
        }

    def disconnect(self) -> None:
        self._hive = None
        self._path = ""

    def is_connected(self) -> bool:
        return self._hive is not None

    def get_metadata(self) -> dict:
        return {"file": os.path.basename(self._path), "path": self._path, "hive_type": self._hive_type}

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        """Search registry keys and values by keyword."""
        results = []
        if not self._hive:
            return {"error": "No hive loaded."}

        kw_lower = keyword.lower() if keyword else ""
        count = 0
        for entry in self._hive.recurse_subkeys(as_json=True):
            if count >= offset + limit:
                break
            path = _entry_get(entry, "path", "")
            if kw_lower and kw_lower not in path.lower():
                # Also check values
                values = _entry_get(entry, "values", [])
                found = False
                for v in (values or []):
                    if kw_lower in str(v.get("name", "")).lower() or kw_lower in str(v.get("value", "")).lower():
                        found = True
                        break
                if not found:
                    continue
            count += 1
            if count > offset:
                results.append({
                    "path": path,
                    "timestamp": _entry_get(entry, "timestamp", ""),
                    "values_count": len(_entry_get(entry, "values", []) or []),
                    "values": (_entry_get(entry, "values", []) or [])[:10],
                })
        return {"total": count, "returned": len(results), "entries": results}

    def get_capabilities(self) -> list[str]:
        return ["search", "run_plugins", "get_key", "timeline"]

    def timeline(self, limit: int = 200) -> dict:
        """Return keys sorted by last-modified timestamp descending.

        Useful for isolating recent changes (persistence, service install, etc.)
        without guessing which specific keys to inspect first.
        """
        if not self._hive:
            return {"entries": [], "error": "No hive loaded."}
        entries: list[dict] = []
        for e in self._hive.recurse_subkeys(as_json=True):
            ts = _entry_get(e, "timestamp", "")
            if not ts:
                continue
            entries.append({
                "path": _entry_get(e, "path", ""),
                "timestamp": str(ts),
                "values_count": len(_entry_get(e, "values", []) or []),
            })
            if len(entries) >= 5000:
                break
        entries.sort(key=lambda x: x["timestamp"], reverse=True)
        return {"total": len(entries), "entries": entries[:limit]}

    def run_plugins(self) -> dict:
        """Run all applicable regipy plugins for this hive type."""
        from regipy.plugins.utils import run_relevant_plugins

        if not self._hive:
            return {"error": "No hive loaded."}

        plugin_results, errors = run_relevant_plugins(self._path, as_json=True)
        result = {}
        for plugin_name, entries in plugin_results.items():
            result[plugin_name] = entries[:50] if isinstance(entries, list) else entries
        return {
            "hive_type": self._hive_type,
            "plugins_run": len(plugin_results),
            "errors": [str(e) for e in errors] if errors else [],
            "results": result,
        }

    def get_key(self, path: str) -> dict:
        """Get a specific registry key and its values.

        Args:
            path: Registry key path (e.g. "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        """
        if not self._hive:
            return {"error": "No hive loaded."}
        try:
            key = self._hive.get_key(path)
            values = []
            for v in _iter_registry_values(key):
                values.append({
                    "name": v.name,
                    "type": str(v.value_type),
                    "value": str(v.value)[:500],
                })
            subkeys = [sk.name for sk in (key.iter_subkeys() if hasattr(key, 'iter_subkeys') else [])]
            return {
                "path": path,
                "timestamp": str(key.header.last_modified) if hasattr(key.header, 'last_modified') else "",
                "values": values,
                "subkeys": subkeys[:50],
            }
        except Exception as e:
            return {"error": f"Key not found or error: {e}"}

    @staticmethod
    def _detect_hive_type(path: str) -> str:
        name = os.path.basename(path).upper()
        if "NTUSER" in name:
            return "NTUSER.DAT"
        elif "SAM" in name:
            return "SAM"
        elif "SYSTEM" in name:
            return "SYSTEM"
        elif "SOFTWARE" in name:
            return "SOFTWARE"
        elif "SECURITY" in name:
            return "SECURITY"
        elif "USRCLASS" in name:
            return "UsrClass.dat"
        elif "AMCACHE" in name:
            return "Amcache.hve"
        return "Unknown"


def _iter_registry_values(key: Any) -> list[Any]:
    try:
        return list(key.iter_values())
    except Exception:
        pass
    try:
        return list(key.get_values())
    except Exception:
        pass
    try:
        return list(key.values or [])
    except Exception:
        return []


def _entry_get(entry: Any, name: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)
