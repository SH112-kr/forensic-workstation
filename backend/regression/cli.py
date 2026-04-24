"""Argparse CLI for the manual regression harness.

Commands:
  list-fixtures      — print available fixture names
  show-prompt <name> — print the standard prompt (to paste into Claude)
  ingest ...         — parse a finished session into a run record
  finalize           — aggregate all ingested runs into CSV + markdown

Typical workflow:

    export FW_FIXTURE=case_ransomware_inc_like
    python backend/main.py                               # or MCP stdio
    # new terminal:
    python -m regression.cli show-prompt case_ransomware_inc_like
    # paste into Claude Code session, complete analysis, save verdict
    python -m regression.cli ingest \\
        --fixture case_ransomware_inc_like --run 1 \\
        --verdict-file run1.json --session-log session.jsonl
    # repeat...
    python -m regression.cli finalize
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def _cmd_list_fixtures(_args) -> int:
    from regression.fixtures import available

    for name in available():
        print(name)
    return 0


def _cmd_show_prompt(args) -> int:
    from regression.fixtures import available
    from regression.ground_truth import load as load_gt
    from regression import prompt

    name = args.fixture
    if name not in available():
        print(f"Unknown fixture: {name}. Available: {available()}", file=sys.stderr)
        return 2

    gt = load_gt(name)
    print(f"# Regression prompt for fixture: {name}")
    print(f"# Prompt version: {prompt.PROMPT_VERSION}")
    print(f"# Case description: {gt.get('case_description', '')}")
    print("#")
    print("# To run this session:")
    print(f"#   1. export FW_FIXTURE={name}")
    print("#   2. start the backend (python backend/main.py or MCP stdio)")
    print("#   3. open Claude Code; paste the prompt below")
    print("#")
    print("# ─────────────────────────────────────────────────────")
    print()
    print(prompt.STANDARD_ANALYST_PROMPT)
    return 0


def _cmd_ingest(args) -> int:
    from regression import ingest, metrics, prompt, report
    from regression.ground_truth import load as load_gt

    fixture = args.fixture
    try:
        gt = load_gt(fixture)
    except FileNotFoundError:
        print(f"No ground truth for fixture: {fixture}", file=sys.stderr)
        return 2

    verdict = ingest.load_verdict(args.verdict_file)
    tool_calls = ingest.extract_tool_calls(args.session_log) if args.session_log else []

    # Final text for uncertainty citation: prefer the session log's last
    # assistant text (richer context), fall back to serialised verdict.
    if args.session_log:
        final_text = ingest.extract_final_text(args.session_log) or ""
    else:
        final_text = ""
    if not final_text:
        final_text = "\n".join(
            f"{k}: {v}" for k, v in verdict.items() if isinstance(v, (str, list))
        )

    div = metrics.tool_diversity(tool_calls)
    uncertainty = metrics.uncertainty_cited(final_text)
    phrase_check = metrics.check_required_phrases(final_text, gt)

    row = {
        "fixture": fixture,
        "run_idx": int(args.run),
        "verdict_correct": metrics.verdict_correct(verdict, gt),
        "is_fp": metrics.is_false_positive(verdict, gt),
        "total_calls": div["total_calls"],
        "unique_tools": div["unique_tools"],
        "diversity_ratio": div["diversity_ratio"],
        "top_tool_share": div["top_tool_share"],
        "top_tool": div.get("top_tool"),
        "uncertainty_total": uncertainty["total_cited"],
        "uncertainty_markers": uncertainty,
        "required_matched": phrase_check["required_matched"],
        "required_total": phrase_check["required_total"],
        "required_missing": phrase_check["required_missing"],
        "prohibited_violations": phrase_check["prohibited_violations"],
        "final_verdict": verdict.get("verdict", ""),
        "final_confidence": verdict.get("confidence", ""),
        "prompt_version": prompt.PROMPT_VERSION,
        "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_calls": [c.get("name") for c in tool_calls],
    }
    report.append_record(REPORTS_DIR, row)
    print(_summarise(row))
    return 0


def _summarise(row: dict) -> str:
    return (
        f"[{row['fixture']} / run {row['run_idx']}] "
        f"verdict={row['final_verdict']} "
        f"correct={row['verdict_correct']} "
        f"fp={row['is_fp']} "
        f"tools={row['total_calls']} (unique {row['unique_tools']}) "
        f"uncertainty={row['uncertainty_total']}/3 "
        f"required={row['required_matched']}/{row['required_total']}"
    )


def _cmd_finalize(args) -> int:
    from regression import prompt, report

    rows = report.load_records(REPORTS_DIR)
    if not rows:
        print(
            f"No ingested runs yet under {REPORTS_DIR}. Run "
            "`regression.cli ingest` first.",
            file=sys.stderr,
        )
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    csv_path = REPORTS_DIR / f"run_{stamp}.csv"
    md_path = REPORTS_DIR / f"run_{stamp}.md"
    report.write_csv(rows, csv_path)
    report.write_markdown(rows, md_path, prompt_version=prompt.PROMPT_VERSION)
    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="regression.cli",
        description="LLM regression harness — manual edition",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list-fixtures", help="List available fixtures")

    show = sub.add_parser("show-prompt", help="Print the standard analyst prompt")
    show.add_argument("fixture")

    ing = sub.add_parser("ingest", help="Parse a finished session into a run record")
    ing.add_argument("--fixture", required=True)
    ing.add_argument("--run", required=True, type=int)
    ing.add_argument("--verdict-file", required=True)
    ing.add_argument("--session-log", default="")

    sub.add_parser("finalize", help="Aggregate ingested runs into CSV + markdown")

    return parser


def main(argv: list[str] | None = None) -> int:
    # Force UTF-8 stdout so em-dashes / box-drawing characters print
    # cleanly on Windows consoles that default to cp949.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list-fixtures":
        return _cmd_list_fixtures(args)
    if args.command == "show-prompt":
        return _cmd_show_prompt(args)
    if args.command == "ingest":
        return _cmd_ingest(args)
    if args.command == "finalize":
        return _cmd_finalize(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
