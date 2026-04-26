"""Claude post-evaluation review helper.

The project uses this as a release/checkpoint step after local validation:
Codex runs tests and bias guards, then Claude critiques accuracy and bias risk
from the summarized evidence. The helper prefers npm's ``claude.cmd`` shim on
Windows to avoid PowerShell execution-policy failures.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any


REVIEW_PROMPT_TEMPLATE = """You are reviewing a DFIR automation change.

Goal: evaluate whether the completed improvement and validation introduced
accuracy regressions, overcall bias, undercall bias, privacy leakage, or unsafe
malware-handling behavior.

Return concise Korean feedback with:
1. pass/fail recommendation,
2. strongest accuracy concern,
3. strongest bias concern,
4. missing validation cases,
5. whether the change supports autonomous analysis without human intervention.

Validation summary JSON:
{summary}
"""


def run_claude_review(
    summary: dict[str, Any],
    *,
    output_path: str | Path | None = None,
    dry_run: bool = False,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    prompt = REVIEW_PROMPT_TEMPLATE.format(
        summary=json.dumps(_compact_summary(summary), ensure_ascii=False, indent=2, default=str)
    )
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "command": _claude_command() or "claude",
            "prompt": prompt,
        }

    command = _claude_command()
    if not command:
        return {
            "ok": False,
            "error": "Claude CLI not found. Install/authenticate Claude Code before review.",
        }

    proc = subprocess.run(
        [command, "--print", "--max-turns", "12"],
        input=prompt,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_seconds,
        check=False,
    )
    stdout = proc.stdout or ""
    result = {
        "ok": proc.returncode == 0 and bool(stdout.strip()),
        "command": command,
        "returncode": proc.returncode,
        "review": stdout.strip(),
    }
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["output_path"] = str(path)
    return result


def _claude_command() -> str:
    candidates = ["claude.cmd", "claude"] if platform.system().lower() == "windows" else ["claude"]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def _compact_summary(summary: dict[str, Any]) -> dict[str, Any]:
    external = summary.get("external") or {}
    bias_guard = summary.get("bias_guard") or {}
    synthetic = summary.get("synthetic") or bias_guard.get("synthetic") or {}
    bias_external = bias_guard.get("external") or {}
    external_checks = bias_external.get("checks") or []
    return {
        "ok": summary.get("ok"),
        "policy": summary.get("policy"),
        "check_count": summary.get("check_count"),
        "failed_count": summary.get("failed_count"),
        "failures": summary.get("failures", []),
        "residual_risks": summary.get("residual_risks", []),
        "schema_version": summary.get("schema_version"),
        "discussion_needed": summary.get("discussion_needed", []),
        "e01_probes": [
            {
                "case_id": probe.get("case_id"),
                "status": probe.get("status"),
                "benchmark_type": probe.get("benchmark_type"),
                "expected_scope": probe.get("expected_scope"),
                "scoring_included": probe.get("scoring_included"),
                "record_count": probe.get("record_count"),
                "artifact_type_counts": probe.get("artifact_type_counts", {}),
                "coverage": probe.get("coverage", {}),
                "issues": probe.get("issues", []),
            }
            for probe in summary.get("e01_probes", [])
        ],
        "tests": {
            "ok": (summary.get("tests") or {}).get("ok"),
            "returncode": (summary.get("tests") or {}).get("returncode"),
        },
        "safety_checks": summary.get("safety_checks", []),
        "clean_baseline": summary.get("clean_baseline", []),
        "clean_baseline_gaps": summary.get("clean_baseline_gaps", []),
        "synthetic": {
            "ok": synthetic.get("ok"),
            "case_count": synthetic.get("case_count"),
            "failed_checks": [
                check for check in synthetic.get("checks", [])
                if not check.get("ok")
            ],
        },
        "external": {
            "ok": external.get("ok"),
            "result_count": external.get("result_count"),
            "passed": external.get("passed"),
            "failed": external.get("failed"),
            "checks": [
                {
                    "name": check.get("name"),
                    "ok": check.get("ok"),
                    "bias_type": check.get("bias_type"),
                    "issues": check.get("issues", []),
                    "residual_risks": check.get("residual_risks", []),
                }
                for check in external_checks
            ],
            "datasets": [
                {
                    "dataset": item.get("dataset"),
                    "ok": item.get("ok"),
                    "result_count": _result_count(item),
                }
                for item in external.get("results", [])
            ],
        },
    }


def _result_count(item: dict[str, Any]) -> int | None:
    for key in ("result_count", "dataset_count", "scenario_count", "rows", "records_scanned"):
        value = item.get(key)
        if isinstance(value, int):
            return value
    results = item.get("results")
    if isinstance(results, list):
        return len(results)
    content_markers = item.get("content_marker_results")
    if isinstance(content_markers, list):
        return len(content_markers)
    return None
