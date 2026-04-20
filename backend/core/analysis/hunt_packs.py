"""Saved hunt packs — named investigation recipes.

A hunt pack is a JSON file that lists a fixed sequence of MCP tool calls.
The engine here reads the pack, executes each step with a transparent
parameter substitution, and returns a single envelope with the tool name,
args, status, and summary of every step.

Deliberately constrained per the project's LLM-as-parameter-tuner rule:

- Steps call *existing* tool names only. The pack author picks which tools
  and what args; the engine never invents or conditionally skips anything.
- No loops, no branches, no analyst-authored Python. A pack is pure data.
- Params are substituted by ``{param_name}`` placeholder; anything else is
  literal. No arithmetic, no comparisons, no conditional string building.
- Each step runs in order; if one step fails the remaining steps still run
  with the failure captured in the envelope.
- Full audit log: every executed step records the resolved args and the
  summarized output so the analyst can justify the hunt after the fact.

Storage:
  backend/hunt_packs/builtin/*.json   -- shipped with the repo
  backend/hunt_packs/local/*.json     -- analyst-authored (gitignored)
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Callable


# Built-in pack directory (committed to the repo). Local packs live in
# ``backend/hunt_packs/local`` and are gitignored.
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BUILTIN_DIR = os.path.join(_BASE_DIR, "hunt_packs", "builtin")
_LOCAL_DIR = os.path.join(_BASE_DIR, "hunt_packs", "local")

# Substitute ``{param_name}`` placeholders only; everything else is literal.
_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _ensure_dirs() -> None:
    os.makedirs(_BUILTIN_DIR, exist_ok=True)
    os.makedirs(_LOCAL_DIR, exist_ok=True)


def _load_pack_file(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            pack = json.load(f)
    except Exception:
        return None
    # Minimal schema validation — reject anything that would surprise the
    # engine at execution time.
    if not isinstance(pack, dict):
        return None
    if not all(k in pack for k in ("name", "description", "steps")):
        return None
    if not isinstance(pack.get("steps"), list):
        return None
    for step in pack["steps"]:
        if not isinstance(step, dict) or "tool" not in step:
            return None
        if not isinstance(step.get("args", {}), dict):
            return None
    return pack


def list_packs() -> dict[str, Any]:
    _ensure_dirs()
    packs: list[dict[str, Any]] = []
    for scope, directory in (("builtin", _BUILTIN_DIR), ("local", _LOCAL_DIR)):
        for fn in sorted(os.listdir(directory)):
            if not fn.endswith(".json"):
                continue
            full = os.path.join(directory, fn)
            pack = _load_pack_file(full)
            if not pack:
                packs.append({"scope": scope, "file": fn, "error": "invalid pack file"})
                continue
            packs.append({
                "scope": scope,
                "file": fn,
                "name": pack.get("name"),
                "description": pack.get("description", ""),
                "params": list((pack.get("params_schema") or {}).keys()),
                "steps": [s.get("tool") for s in pack.get("steps", [])],
            })
    return {"ok": True, "count": len(packs), "packs": packs}


def _resolve_pack(name: str) -> dict[str, Any] | None:
    """Find a pack by name — local takes precedence over built-in."""
    _ensure_dirs()
    for directory in (_LOCAL_DIR, _BUILTIN_DIR):
        for fn in os.listdir(directory):
            if not fn.endswith(".json"):
                continue
            pack = _load_pack_file(os.path.join(directory, fn))
            if pack and pack.get("name") == name:
                return pack
    return None


def _substitute(value: Any, params: dict[str, Any]) -> Any:
    """Replace ``{name}`` placeholders in strings; deep-copy other types."""
    if isinstance(value, str):
        def _repl(m):
            key = m.group(1)
            return "" if key not in params else str(params[key])
        return _PARAM_RE.sub(_repl, value)
    if isinstance(value, list):
        return [_substitute(v, params) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, params) for k, v in value.items()}
    return value


def _summarize_output(result: Any) -> dict[str, Any]:
    """One-line summary of a tool output for the audit log."""
    if not isinstance(result, dict):
        return {"value": str(result)[:200]}
    # Try a handful of common "count" keys so the audit trail is compact.
    for key in ("total_findings", "rules_fired", "total_hits", "total", "count",
                "case_count", "rules_evaluated", "merged_total", "returned"):
        if key in result:
            return {key: result[key]}
    return {"keys": sorted(list(result.keys()))[:6]}


async def run_pack(
    name: str,
    params: dict[str, Any] | None = None,
    tool_dispatch: Callable[[str, dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Execute a pack by name.

    Args:
        name: Pack ``name`` as listed by ``list_packs``.
        params: Runtime parameter values substituted into step args.
        tool_dispatch: Callable ``(tool_name, args) -> result``. Injected by
            the MCP bridge so tests can pass a fake dispatcher.

    Returns an envelope listing every executed step, its resolved args, the
    result summary, and any error. Never raises; step failures are captured
    so subsequent steps still run.
    """
    params = params or {}
    pack = _resolve_pack(name)
    if not pack:
        return {"ok": False, "error": f"Pack not found: {name}"}

    if tool_dispatch is None:
        return {
            "ok": False,
            "error": "tool_dispatch must be provided by the MCP bridge",
        }

    run_id = f"hunt-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    steps_out: list[dict[str, Any]] = []
    for idx, step in enumerate(pack.get("steps", [])):
        tool = step.get("tool")
        raw_args = step.get("args", {}) or {}
        resolved_args = _substitute(raw_args, params)
        entry: dict[str, Any] = {
            "index": idx,
            "tool": tool,
            "resolved_args": resolved_args,
        }
        try:
            result = tool_dispatch(tool, resolved_args)
            if inspect.isawaitable(result):
                result = await result
            entry["status"] = "ok"
            entry["summary"] = _summarize_output(result)
        except Exception as e:  # noqa: BLE001 — pack failures are captured, never raised
            entry["status"] = "error"
            entry["error"] = str(e)
        steps_out.append(entry)

    return {
        "ok": True,
        "run_id": run_id,
        "pack_name": pack.get("name"),
        "pack_description": pack.get("description", ""),
        "params": params,
        "steps": steps_out,
        "notes": [
            "Hunt packs only call existing MCP tools; they do not run "
            "analyst-authored Python.",
            "Every step's resolved_args is preserved so the hunt is auditable.",
        ],
    }
