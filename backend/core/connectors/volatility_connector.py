"""Volatility 3 connector for memory forensics."""

from __future__ import annotations

import os
from typing import Any

from connectors.base import BaseConnector


class VolatilityConnector(BaseConnector):
    """Memory dump analysis via Volatility 3 framework."""

    def __init__(self) -> None:
        self._path: str = ""
        self._context = None
        self._available_automagics = None
        self._base_config_path: str = "plugins"
        self._initialized: bool = False

    def connect(self, path: str, **kwargs: Any) -> dict:
        import volatility3.framework
        from volatility3.framework import contexts, automagic
        from volatility3 import plugins as vol_plugins

        if not os.path.isfile(path):
            raise FileNotFoundError(f"Memory dump not found: {path}")

        volatility3.framework.require_interface_version(2, 0, 0)
        volatility3.framework.import_files(vol_plugins, True)

        self._context = contexts.Context()
        self._context.config["automagic.LayerStacker.single_location"] = (
            "file:///" + os.path.abspath(path).replace("\\", "/")
        )
        self._available_automagics = automagic.available(self._context)
        self._path = path
        self._initialized = True

        return {
            "status": "success",
            "file": os.path.basename(path),
            "path": path,
            "size_mb": round(os.path.getsize(path) / (1024 * 1024), 1),
        }

    def disconnect(self) -> None:
        self._context = None
        self._available_automagics = None
        self._initialized = False

    def is_connected(self) -> bool:
        return self._initialized

    def get_metadata(self) -> dict:
        return {"file": os.path.basename(self._path), "path": self._path}

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        return {"error": "Use specific Volatility plugins (vol_pslist, vol_netscan, etc.)"}

    def get_capabilities(self) -> list[str]:
        return ["pslist", "pstree", "netscan", "malfind", "dlllist", "cmdline", "handles", "filescan", "svcscan"]

    def _run_plugin(self, plugin_class, extra_config: dict | None = None) -> list[dict]:
        """Run a Volatility plugin and return structured results."""
        from volatility3.framework import automagic
        from volatility3.framework import plugins as fw_plugins

        # 1. Choose automagics for this plugin
        chosen = automagic.choose_automagic(self._available_automagics, plugin_class)

        ctx = self._context
        if extra_config:
            for k, v in extra_config.items():
                ctx.config[k] = v

        # 2. Construct plugin (runs automagics internally)
        try:
            constructed = fw_plugins.construct_plugin(
                ctx, chosen, plugin_class,
                self._base_config_path, None, None,
            )
        except Exception as e:
            return [{"error": f"Plugin construction failed: {e}"}]

        if constructed is None:
            return [{"error": f"Failed to construct plugin {plugin_class.__name__}"}]

        # 3. Run plugin
        try:
            treegrid = constructed.run()
        except Exception as e:
            return [{"error": f"Plugin execution failed: {e}"}]

        # 4. Parse TreeGrid results
        results = []
        columns = [col.name for col in treegrid.columns]

        def visitor(node, _):
            row = {}
            for i, col_name in enumerate(columns):
                if i < len(node.values):
                    val = node.values[i]
                    if not isinstance(val, (str, int, float, bool, type(None))):
                        val = str(val)
                    row[col_name] = val
            results.append(row)

        treegrid.populate(visitor)
        return results

    def pslist(self) -> list[dict]:
        from volatility3.plugins.windows import pslist
        return self._run_plugin(pslist.PsList)

    def pstree(self) -> list[dict]:
        from volatility3.plugins.windows import pstree
        return self._run_plugin(pstree.PsTree)

    def netscan(self) -> list[dict]:
        from volatility3.plugins.windows import netscan
        return self._run_plugin(netscan.NetScan)

    def malfind(self) -> list[dict]:
        from volatility3.plugins.windows import malfind
        return self._run_plugin(malfind.Malfind)

    def dlllist(self, pid: int | None = None) -> list[dict]:
        from volatility3.plugins.windows import dlllist
        config = {}
        if pid is not None:
            config[f"{self._base_config_path}.DllList.pid"] = [pid]
        return self._run_plugin(dlllist.DllList, config)

    def cmdline(self) -> list[dict]:
        from volatility3.plugins.windows import cmdline
        return self._run_plugin(cmdline.CmdLine)

    def handles(self, pid: int | None = None) -> list[dict]:
        from volatility3.plugins.windows import handles
        config = {}
        if pid is not None:
            config[f"{self._base_config_path}.Handles.pid"] = [pid]
        return self._run_plugin(handles.Handles, config)

    def svcscan(self) -> list[dict]:
        from volatility3.plugins.windows import svcscan
        return self._run_plugin(svcscan.SvcScan)

    def filescan(self, pattern: str = "") -> list[dict]:
        from volatility3.plugins.windows import filescan
        results = self._run_plugin(filescan.FileScan)
        if pattern:
            p_lower = pattern.lower()
            results = [r for r in results if p_lower in str(r.get("Name", "")).lower()]
        return results

    def run_plugin(self, plugin_name: str, **kwargs) -> list[dict]:
        """Run any Volatility plugin by name."""
        import volatility3.framework
        plugin_list = volatility3.framework.list_plugins()
        for name, plugin_class in plugin_list.items():
            if plugin_name.lower() in name.lower():
                return self._run_plugin(plugin_class, kwargs if kwargs else None)
        available = sorted(plugin_list.keys())[:30]
        return [{"error": f"Plugin not found: {plugin_name}", "available_sample": available}]
