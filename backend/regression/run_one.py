"""Helper: run one fixture through `claude --print`, extract verdict, ingest.

Usage (from backend/ with FW_FIXTURE unset at process level):
    python -m regression.run_one <fixture_name> <run_idx>

Writes per-run artefacts under $TEMP/fw_baseline/ and appends the ingest
record to backend/regression/reports/runs.jsonl via the normal CLI.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python -m regression.run_one <fixture> <run_idx>", file=sys.stderr)
        return 2
    fixture, run_idx = argv[1], argv[2]

    base = Path(os.environ["TEMP"]) / "fw_baseline"
    base.mkdir(parents=True, exist_ok=True)
    log_path = base / f"{fixture}_run{run_idx}.jsonl"
    verdict_path = base / f"{fixture}_run{run_idx}_verdict.json"
    result_path = base / f"{fixture}_run{run_idx}_result.txt"
    prompt_path = base / "prompt.txt"

    if not prompt_path.exists():
        from regression.prompt import STANDARD_ANALYST_PROMPT
        prompt_path.write_text(STANDARD_ANALYST_PROMPT, encoding="utf-8")
    prompt = prompt_path.read_text(encoding="utf-8")

    env = {**os.environ, "FW_FIXTURE": fixture}
    # Claude Code ships a .cmd / .bat shim on Windows; subprocess needs
    # shell=True to resolve it. Pass the prompt via stdin to avoid any
    # command-line length / quoting trouble with long multi-line prompts.
    cmd = (
        "claude --print --output-format stream-json --verbose "
        "--permission-mode bypassPermissions --max-turns 35"
    )
    print(f"[run_one] {fixture} run {run_idx} starting...", flush=True)
    proc = subprocess.run(
        cmd,
        shell=True,
        input=prompt.encode("utf-8"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path.write_bytes(proc.stdout)

    # Parse events tolerantly
    events = []
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue

    result_event = next((e for e in events if e.get("type") == "result"), None)
    if not result_event:
        print(f"[run_one] NO result event. stderr/exit={proc.returncode}", file=sys.stderr)
        return 3

    text = result_event.get("result", "") or ""
    result_path.write_text(text, encoding="utf-8")

    match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not match:
        print("[run_one] No ```json block in final text.", file=sys.stderr)
        return 4

    try:
        verdict = json.loads(match.group(1))
    except Exception as e:
        print(f"[run_one] JSON parse fail: {e}", file=sys.stderr)
        return 5

    verdict_path.write_text(
        json.dumps(verdict, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(
        f"[run_one] {fixture} run {run_idx}: "
        f"verdict={verdict.get('verdict')} "
        f"confidence={verdict.get('confidence')} "
        f"turns={result_event.get('num_turns')} "
        f"cost=${result_event.get('total_cost_usd', 0):.3f}",
        flush=True,
    )

    # Ingest
    from regression import cli
    ingest_args = [
        "ingest",
        "--fixture", fixture,
        "--run", str(run_idx),
        "--verdict-file", str(verdict_path),
        "--session-log", str(log_path),
    ]
    return cli.main(ingest_args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
