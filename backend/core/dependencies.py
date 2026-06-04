"""Runtime dependency diagnostics for analysis capabilities."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DependencySpec:
    key: str
    display_name: str
    kind: str
    required_for: str
    blocked_capabilities: list[str]
    install_hint: str
    required: bool = False
    import_names: tuple[str, ...] = ()
    binaries: tuple[str, ...] = ()


DEPENDENCIES: tuple[DependencySpec, ...] = (
    DependencySpec(
        key="regipy",
        display_name="regipy",
        kind="python",
        required=True,
        required_for="Offline Windows registry hive parsing",
        blocked_capabilities=[
            "SYSTEM/SOFTWARE/SAM hive parsing",
            "Service persistence registry review",
            "USB device registry review",
            "Timezone, account, and autorun registry pivots",
        ],
        install_hint="python -m pip install regipy",
        import_names=("regipy",),
    ),
    DependencySpec(
        key="volatility3",
        display_name="Volatility 3",
        kind="python",
        required=False,
        required_for="Memory dump analysis",
        blocked_capabilities=[
            "Process listing from memory",
            "Network connections from memory",
            "Injected-code and malfind style memory checks",
        ],
        install_hint="python -m pip install volatility3",
        import_names=("volatility3",),
    ),
    DependencySpec(
        key="yara-python",
        display_name="yara-python",
        kind="python",
        required=False,
        required_for="YARA file and directory scans",
        blocked_capabilities=["YARA rule loading", "YARA scans over extracted files"],
        install_hint="python -m pip install yara-python",
        import_names=("yara",),
    ),
    DependencySpec(
        key="pyshark",
        display_name="pyshark",
        kind="python",
        required=False,
        required_for="PCAP parsing through tshark",
        blocked_capabilities=["PCAP conversation, DNS, HTTP, and IOC extraction"],
        install_hint="python -m pip install pyshark",
        import_names=("pyshark",),
    ),
    DependencySpec(
        key="tshark",
        display_name="tshark",
        kind="binary",
        required=False,
        required_for="PCAP packet decoding used by pyshark",
        blocked_capabilities=["PCAP decoding even when pyshark is installed"],
        install_hint="Install Wireshark and ensure tshark is on PATH.",
        binaries=("tshark",),
    ),
    DependencySpec(
        key="pyhidra",
        display_name="pyhidra",
        kind="python",
        required=False,
        required_for="Ghidra-backed static binary analysis",
        blocked_capabilities=["Ghidra binary import", "Decompile, imports, strings, and suspicious API views"],
        install_hint="python -m pip install pyhidra",
        import_names=("pyhidra",),
    ),
    DependencySpec(
        key="dissect",
        display_name="dissect",
        kind="python",
        required=True,
        required_for="E01, VM, and raw disk image mounting and file extraction",
        blocked_capabilities=[
            "Mounted image browsing",
            "Raw-image EVTX, Prefetch, registry, and file extraction tools",
        ],
        install_hint="python -m pip install dissect",
        import_names=("dissect",),
    ),
)

_ALIASES = {
    "volatility": "volatility3",
    "volatility3": "volatility3",
    "yara": "yara-python",
    "yara-python": "yara-python",
    "regipy": "regipy",
    "pyshark": "pyshark",
    "tshark": "tshark",
    "pyhidra": "pyhidra",
    "ghidra": "pyhidra",
    "dissect": "dissect",
}


def _check_import(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _dependency_status(spec: DependencySpec) -> dict[str, Any]:
    missing_imports = [name for name in spec.import_names if not _check_import(name)]
    missing_binaries = [name for name in spec.binaries if shutil.which(name) is None]
    available = not missing_imports and not missing_binaries
    severity = "ok" if available else ("blocked" if spec.required else "degraded")
    return {
        "key": spec.key,
        "display_name": spec.display_name,
        "kind": spec.kind,
        "available": available,
        "required": spec.required,
        "severity": severity,
        "required_for": spec.required_for,
        "blocked_capabilities": list(spec.blocked_capabilities),
        "install_hint": "" if available else spec.install_hint,
        "missing_imports": missing_imports,
        "missing_binaries": missing_binaries,
    }


def dependency_report() -> dict[str, Any]:
    items = [_dependency_status(spec) for spec in DEPENDENCIES]
    missing_required = [item for item in items if item["required"] and not item["available"]]
    missing_optional = [item for item in items if not item["required"] and not item["available"]]
    if missing_required:
        overall = "blocked"
    elif missing_optional:
        overall = "degraded"
    else:
        overall = "ready"
    return {
        "overall_status": overall,
        "python_executable": sys.executable,
        "dependencies": items,
        "summary": {
            "total": len(items),
            "available": sum(1 for item in items if item["available"]),
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }


def diagnose_exception(exc: BaseException | str) -> dict[str, Any] | None:
    text = str(exc).lower()
    for token, key in _ALIASES.items():
        if token in text:
            item = next((d for d in dependency_report()["dependencies"] if d["key"] == key), None)
            if item and not item["available"]:
                return {
                    "type": "missing_dependency",
                    "dependency": item,
                    "user_message": (
                        f"{item['display_name']} is missing, so {item['required_for']} is not available."
                    ),
                    "recovery": item["install_hint"],
                }
    return None
