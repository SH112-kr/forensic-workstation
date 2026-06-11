"""CSV + markdown reports for regression runs."""

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPORT_FIELDS = [
    "fixture",
    "run_idx",
    "verdict_correct",
    "is_fp",
    "total_calls",
    "unique_tools",
    "diversity_ratio",
    "top_tool_share",
    "uncertainty_total",
    "truncated_seen",
    "truncation_followed_up",
    "required_matched",
    "required_total",
    "prohibited_violations",
    "final_verdict",
    "prompt_version",
]


def aggregate(rows: list[dict]) -> dict[str, dict]:
    """Group runs by fixture and compute aggregate stats."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["fixture"]].append(row)

    summary: dict[str, dict] = {}
    for fixture, fixture_rows in groups.items():
        total_runs = len(fixture_rows)
        correct = sum(1 for r in fixture_rows if r.get("verdict_correct"))
        fp = sum(1 for r in fixture_rows if r.get("is_fp"))
        uncertainty = sum(int(r.get("uncertainty_total") or 0) for r in fixture_rows)
        diversity = [float(r.get("diversity_ratio") or 0) for r in fixture_rows]
        summary[fixture] = {
            "runs": total_runs,
            "verdict_correct_count": correct,
            "fp_count": fp,
            "avg_diversity": round(sum(diversity) / max(total_runs, 1), 3),
            "uncertainty_avg": round(uncertainty / max(total_runs, 1), 2),
            "verdicts": [r.get("final_verdict") for r in fixture_rows],
        }
    return summary


def write_csv(rows: list[dict], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = dict(row)
            viol = out.get("prohibited_violations")
            if isinstance(viol, list):
                out["prohibited_violations"] = ";".join(viol)
            writer.writerow(out)


def write_markdown(
    rows: list[dict],
    path: str | Path,
    prompt_version: str = "",
    generated_at: str | None = None,
) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    summary = aggregate(rows)
    stamp = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append(f"# Regression Report — {stamp}")
    lines.append("")
    lines.append(
        f"Prompt version: {prompt_version} | Total runs: {len(rows)} | "
        f"Fixtures: {len(summary)}"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Fixture | Runs | Verdict Correct | FP | Avg Diversity | Uncertainty Avg |")
    lines.append("|---|---|---|---|---|---|")
    for fixture, agg in sorted(summary.items()):
        lines.append(
            f"| {fixture} | {agg['runs']} | "
            f"{agg['verdict_correct_count']}/{agg['runs']} | "
            f"{agg['fp_count']}/{agg['runs']} | "
            f"{agg['avg_diversity']} | {agg['uncertainty_avg']} |"
        )
    lines.append("")
    lines.append("## Per-run detail")
    lines.append("")
    for row in rows:
        viol = row.get("prohibited_violations") or []
        if isinstance(viol, str):
            viol = [v for v in viol.split(";") if v]
        lines.append(
            f"### {row['fixture']} / run {row['run_idx']}"
        )
        lines.append("")
        lines.append(f"- verdict: **{row.get('final_verdict')}** "
                     f"(correct={row.get('verdict_correct')}, fp={row.get('is_fp')})")
        lines.append(f"- tools: {row.get('total_calls')} calls, "
                     f"{row.get('unique_tools')} unique, "
                     f"diversity={row.get('diversity_ratio')}, "
                     f"top_share={row.get('top_tool_share')}")
        lines.append(f"- uncertainty markers cited: {row.get('uncertainty_total')}")
        lines.append(f"- required phrases: "
                     f"{row.get('required_matched')}/{row.get('required_total')}")
        if viol:
            lines.append(f"- **prohibited phrases hit**: {', '.join(viol)}")
        lines.append("")

    lines.append("## Flags")
    lines.append("")
    flagged = False
    for row in rows:
        flags = []
        if row.get("is_fp"):
            flags.append("FALSE POSITIVE")
        if not row.get("verdict_correct"):
            flags.append("verdict mismatch")
        if row.get("truncation_followed_up") is False:
            flags.append("TRUNCATION IGNORED — concluded without pagination")
        viol = row.get("prohibited_violations") or []
        if isinstance(viol, str):
            viol = [v for v in viol.split(";") if v]
        if viol:
            flags.append(f"prohibited phrases: {', '.join(viol)}")
        if flags:
            flagged = True
            lines.append(
                f"- **{row['fixture']} run {row['run_idx']}** — {'; '.join(flags)}"
            )
    if not flagged:
        lines.append("- No flagged runs in this batch.")
    lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")


def records_path(base_dir: str | Path) -> Path:
    """JSONL store under ``base_dir`` where ingested runs accumulate."""
    return Path(base_dir) / "runs.jsonl"


def append_record(base_dir: str | Path, row: dict) -> None:
    p = records_path(base_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_records(base_dir: str | Path) -> list[dict]:
    p = records_path(base_dir)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out
