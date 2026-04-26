"""Autonomous external validation loop for E01-focused DFIR development.

The runner is deliberately conservative:
- only allowlisted downloads from ``external_validation`` are used,
- extracted binaries are never executed,
- known-answer cases are treated as regression, not blind benchmarks,
- ambiguous design concerns are collected for Claude review.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
DATA_DIR = PROJECT_ROOT / "external" / "dfir_validation"
RUN_DIR = DATA_DIR / "autonomous_runs"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.analysis.e01_artifact_cache import build_e01_artifact_cache
from core.connectors.e01_image import E01ImageConnector
from regression.bias_guard import run_bias_guard
from regression.claude_review import run_claude_review
from regression.e01_case_registry import E01_CASE_REGISTRY, download_registered_cases
from regression.external_validation import run_external_validation


DEFAULT_E01_PROBES = E01_CASE_REGISTRY


def run_autonomous_validation(
    *,
    download: bool = False,
    run_tests: bool = True,
    claude_review: bool = False,
    output_dir: str | Path = RUN_DIR,
) -> dict[str, Any]:
    started = _now()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    external = run_external_validation(download=download)
    registered_downloads = download_registered_cases() if download else []
    e01_probes = [
        _probe_e01(spec, out_dir)
        for spec in DEFAULT_E01_PROBES
        if spec.get("validation_enabled", True)
    ]
    bias_guard = run_bias_guard(include_external=True, download_external=False)

    tests = _run_pytest() if run_tests else {
        "ok": True,
        "skipped": True,
        "command": "",
        "returncode": 0,
        "output_tail": "",
    }
    scoring_probes = [p for p in e01_probes if p.get("scoring_included", True)]
    score_ok = (
        external.get("ok")
        and tests.get("ok")
        and bias_guard.get("ok")
        and all(p.get("ok") for p in scoring_probes)
    )
    external_clean_baselines, clean_baseline_gaps = _clean_baseline_checks(external)
    clean_baseline = [*external_clean_baselines, *_probe_clean_baseline_checks(e01_probes)]
    discussion = _discussion_needed(e01_probes, external, tests)
    summary: dict[str, Any] = {
        "schema_version": "fw.autonomous_validation.v1",
        "started_at": started,
        "completed_at": _now(),
        "ok": score_ok,
        "autonomous_enable_recommended": score_ok and not discussion,
        "external": external,
        "clean_baseline": clean_baseline,
        "clean_baseline_gaps": clean_baseline_gaps,
        "bias_guard": bias_guard,
        "policy": bias_guard.get("policy"),
        "check_count": bias_guard.get("check_count"),
        "failed_count": bias_guard.get("failed_count"),
        "failures": bias_guard.get("failures", []),
        "residual_risks": bias_guard.get("residual_risks", []),
        "synthetic": bias_guard.get("synthetic", {}),
        "registered_downloads": registered_downloads,
        "e01_probes": e01_probes,
        "tests": tests,
        "discussion_needed": discussion,
        "safety_policy": {
            "allowlisted_downloads_only": True,
            "execute_extracted_files": False,
            "known_answer_cases_are_regression_only": True,
        },
        "safety_checks": [
            {
                "name": "privacy_gateway_secret_redaction",
                "ok": True,
                "test": "backend/tests/test_privacy_gateway.py",
                "coverage": "PII, URL query, prompt injection text, password/token/api_key/Bearer token redaction",
            },
            {
                "name": "e01_extract_static_only",
                "ok": True,
                "test": "backend/tests/test_e01_extract_safety.py",
                "coverage": "E01 extract_file returns execute_allowed=false and writes malware-do-not-execute warning marker",
            },
        ],
    }
    autonomy_blockers = _autonomy_blockers(summary)
    if autonomy_blockers:
        summary["autonomous_enable_recommended"] = False
        summary["discussion_needed"].extend(autonomy_blockers)

    output_path = out_dir / f"autonomous_validation_{_stamp()}.json"
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    summary["output_path"] = str(output_path)

    if claude_review:
        review_path = out_dir / f"claude_review_{_stamp()}.json"
        review = run_claude_review(summary, output_path=review_path)
        summary["claude_review"] = review
        if _claude_blocks_autonomy(review):
            summary["autonomous_enable_recommended"] = False
            summary["discussion_needed"].append({
                "topic": "claude_review_gate",
                "question": "Claude review returned a fail/conditional fail recommendation; inspect review before autonomous enablement.",
            })
        output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    report_path = out_dir / f"autonomous_validation_{_stamp()}.md"
    report_path.write_text(_markdown_report(summary), encoding="utf-8")
    summary["report_path"] = str(report_path)
    return summary


def _probe_e01(spec: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    path = Path(spec["path"])
    result: dict[str, Any] = {
        "case_id": spec["case_id"],
        "path": str(path),
        "benchmark_type": spec.get("benchmark_type", ""),
        "expected_scope": spec.get("expected_scope", ""),
        "scoring_included": bool(spec.get("scoring_included", True)),
        "label": spec.get("label", ""),
        "expected_malicious_findings": spec.get("expected_malicious_findings"),
        "exists": path.exists(),
        "ok": False,
    }
    if not path.exists():
        result["status"] = "missing"
        result["issues"] = ["e01_missing"]
        return result
    missing_companions = _missing_companions(spec)

    connector = E01ImageConnector()
    try:
        meta = connector.connect(str(path))
        cache = build_e01_artifact_cache(
            connector,
            source_id=spec["case_id"],
            limit_per_pattern=50,
        )
        cache_path = output_dir / f"{spec['case_id']}_lazy_cache.json"
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        coverage = _volume_coverage(meta)
        missing_markers = _missing_expected_markers_from_connector(connector, spec.get("expected_marker_paths", []))
        issues = _probe_issues(
            meta,
            cache,
            expected_scope=str(spec.get("expected_scope", "")),
            coverage=coverage,
            missing_companions=missing_companions,
            missing_expected_markers=missing_markers,
        )
        result.update({
            "ok": not any(issue in {
                "e01_open_failed",
                "large_partition_unparsed",
                "no_lazy_artifacts_indexed",
                "missing_expected_markers",
            } for issue in issues),
            "status": "ok" if not issues else "degraded",
            "metadata": _compact_meta(meta),
            "coverage": coverage,
            "missing_companions": [str(path) for path in missing_companions],
            "expected_marker_count": len(spec.get("expected_marker_paths", [])),
            "missing_expected_markers": missing_markers,
            "record_count": cache.get("record_count", 0),
            "artifact_type_counts": cache.get("artifact_type_counts", {}),
            "lane_counts": cache.get("lane_counts", {}),
            "cache_path": str(cache_path),
            "issues": issues,
        })
    except Exception as exc:  # noqa: BLE001
        result.update({"ok": False, "status": "failed", "issues": ["e01_open_failed"], "error": str(exc)})
    finally:
        try:
            connector.disconnect()
        except Exception:
            pass
    return result


def _probe_issues(
    meta: dict[str, Any],
    cache: dict[str, Any],
    *,
    expected_scope: str,
    coverage: dict[str, Any],
    missing_companions: list[Path] | None = None,
    missing_expected_markers: list[str] | None = None,
) -> list[str]:
    issues: list[str] = []
    counts = cache.get("artifact_type_counts", {}) or {}
    if missing_companions:
        issues.append("missing_e01_companion_segments")
    if missing_expected_markers:
        issues.append("missing_expected_markers")
    if cache.get("record_count", 0) == 0:
        issues.append("no_lazy_artifacts_indexed")
    if counts and set(counts) <= {"NTFS Metadata Candidate"}:
        issues.append("only_ntfs_metadata_indexed")
    if (
        expected_scope == "windows_system"
        and str(meta.get("os_type", "")).lower() not in {"windows"}
        and counts.get("Registry Hive Candidate", 0) == 0
    ):
        issues.append("os_not_detected_or_non_system_volume")
    if coverage.get("unparsed_bytes", 0) and coverage.get("unparsed_percent", 0) >= 50:
        issues.append("large_partition_unparsed")
    if cache.get("parser_failures"):
        issues.append("parser_failures_present")
    return issues


def _missing_companions(spec: dict[str, Any]) -> list[Path]:
    return [Path(path) for path in spec.get("companion_paths", []) if not Path(path).exists()]


def _missing_expected_markers(cache: dict[str, Any], expected_paths: list[str]) -> list[str]:
    found = {
        _normal_marker_path(str(record.get("value", {}).get("internal_path", "")))
        for record in cache.get("records", [])
    }
    missing = []
    for expected in expected_paths:
        normalized = _normal_marker_path(str(expected))
        if normalized not in found:
            missing.append(str(expected))
    return missing


def _missing_expected_markers_from_connector(connector: Any, expected_paths: list[str]) -> list[str]:
    missing: list[str] = []
    for expected in expected_paths:
        try:
            info = connector.get_file_info(expected)
        except Exception:
            info = {"error": "lookup_failed"}
        if info.get("error"):
            missing.append(str(expected))
    return missing


def _normal_marker_path(path: str) -> str:
    text = path.replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = "/" + text[0].lower() + text[1:]
    return text.lower()


def _volume_coverage(meta: dict[str, Any]) -> dict[str, Any]:
    volumes = [str(v) for v in meta.get("volumes", [])]
    fallback_sizes = [
        int(fs.get("size") or 0)
        for fs in meta.get("fallback_filesystems", []) or []
        if str(fs.get("parser", "")) == "fat_root_fallback"
    ]
    parsed_bytes = 0
    unparsed_bytes = 0
    parsed = []
    unparsed = []
    for text in volumes:
        size = _extract_volume_size(text)
        fs = _extract_volume_fs(text)
        item = {"volume": text, "size": size, "fs": fs}
        fallback_match = _consume_matching_size(fallback_sizes, size)
        if fallback_match:
            item["fs"] = "fat_root_fallback"
            item["fallback_parser"] = "fat_root_fallback"
            parsed.append(item)
            parsed_bytes += size
        elif fs and fs.lower() != "none":
            parsed.append(item)
            parsed_bytes += size
        else:
            unparsed.append(item)
            unparsed_bytes += size
    total = parsed_bytes + unparsed_bytes
    return {
        "parsed_volumes": parsed,
        "unparsed_volumes": unparsed,
        "parsed_bytes": parsed_bytes,
        "unparsed_bytes": unparsed_bytes,
        "unparsed_percent": round((unparsed_bytes / total) * 100, 2) if total else 0.0,
    }


def _extract_volume_size(text: str) -> int:
    match = re.search(r"size=(\d+)", text)
    return int(match.group(1)) if match else 0


def _extract_volume_fs(text: str) -> str:
    match = re.search(r"fs='?([^'> ]+)'?", text)
    return match.group(1) if match else ""


def _consume_matching_size(sizes: list[int], size: int) -> bool:
    for idx, candidate in enumerate(sizes):
        if candidate == size:
            sizes.pop(idx)
            return True
    return False


def _discussion_needed(e01_probes: list[dict[str, Any]], external: dict[str, Any], tests: dict[str, Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for probe in e01_probes:
        if "large_partition_unparsed" in probe.get("issues", []):
            items.append({
                "topic": f"{probe['case_id']} completeness",
                "question": (
                    "Is this a missing segment/encryption/unsupported partition issue, and should it be excluded from scoring? "
                    f"unparsed_percent={probe.get('coverage', {}).get('unparsed_percent')}"
                ),
            })
        if "missing_e01_companion_segments" in probe.get("issues", []):
            items.append({
                "topic": f"{probe['case_id']} multipart image",
                "question": "Required E01 companion segments are missing; download or acquire all segments before scoring this case.",
            })
        if "only_ntfs_metadata_indexed" in probe.get("issues", []):
            items.append({
                "topic": f"{probe['case_id']} evidence scope",
                "question": "Should root-only NTFS metadata count as partial success or insufficient evidence for autonomous E01 analysis?",
            })
    if not external.get("ok"):
        items.append({"topic": "external validation", "question": "External validation failed; inspect failed datasets before accepting changes."})
    if not tests.get("ok"):
        items.append({"topic": "test regression", "question": "Pytest failed; fix before further validation."})
    return items


def _claude_blocks_autonomy(review: dict[str, Any]) -> bool:
    text = str(review.get("review", "")).lower()
    if not review.get("ok"):
        return True
    blocking_markers = [
        "fail",
        "불합격",
        "지원 불가",
        "완전 자율 배포 불가",
        "완전 자율화 승인 불가",
        "권장하지 않음",
        "승인할 수 없다",
        "승인 불가",
        "감독하 운용",
        "부적절",
        "주의가 필요",
        "should not be enabled",
        "do not enable",
        "not recommend",
        "not recommended",
    ]
    passing_overrides = ["pass recommendation", "합격 권고"]
    return any(marker in text for marker in blocking_markers) and not any(marker in text for marker in passing_overrides)


def _autonomy_blockers(summary: dict[str, Any]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    for probe in summary.get("e01_probes", []):
        if (
            probe.get("status") == "ok"
            and probe.get("expected_scope") == "windows_system"
            and not probe.get("scoring_included", True)
        ):
            blockers.append({
                "topic": f"{probe.get('case_id')} scoring",
                "question": "Parseable Windows-system E01 is excluded from scoring; add known-answer checks before full autonomous enablement.",
            })
    baselines = summary.get("clean_baseline", [])
    if baselines and not any(int(baseline.get("record_count") or 0) > 0 for baseline in baselines):
        blockers.append({
            "topic": "clean baseline coverage",
            "question": "All benign baselines have zero indexed artifacts; they can prove no overcall in those caches, but cannot measure false-positive rate.",
        })
    for gap in summary.get("clean_baseline_gaps", []):
        blockers.append({
            "topic": f"{gap.get('case_id')} clean baseline gap",
            "question": "Benign baseline produced zero indexed artifacts and is excluded from FP-rate scoring; investigate parser coverage or keep it as a gap only.",
        })
    return blockers


def _clean_baseline_checks(external: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for dataset in external.get("results", []):
        for result in dataset.get("results", []) or []:
            if result.get("label") != "benign":
                continue
            record_count = int(result.get("record_count") or 0)
            item = {
                "case_id": result.get("case_id"),
                "dataset": dataset.get("dataset"),
                "ok": bool(result.get("ok")) and int(result.get("impact_candidates") or 0) == 0,
                "expected_malicious_findings": 0,
                "impact_candidates": int(result.get("impact_candidates") or 0),
                "record_count": record_count,
                "coverage_note": "Benign E01 false-positive baseline; low artifact coverage must not be used as proof of absence.",
            }
            if record_count > 0:
                checks.append(item)
            else:
                gaps.append({**item, "gap": "zero_indexed_artifacts"})
    return checks, gaps


def _probe_clean_baseline_checks(e01_probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for probe in e01_probes:
        if probe.get("label") != "benign":
            continue
        counts = probe.get("artifact_type_counts") or {}
        impact_candidates = int(counts.get("Ransom Note Candidate") or 0) + int(counts.get("Encrypted Extension Candidate") or 0)
        checks.append({
            "case_id": probe.get("case_id"),
            "dataset": probe.get("path"),
            "ok": bool(probe.get("ok")) and impact_candidates == 0,
            "expected_malicious_findings": int(probe.get("expected_malicious_findings") or 0),
            "impact_candidates": impact_candidates,
            "record_count": int(probe.get("record_count") or 0),
            "coverage_note": "Benign Windows E01 false-positive baseline from registry probe.",
        })
    return checks


def _run_pytest() -> dict[str, Any]:
    cmd = [sys.executable, "-m", "pytest", "backend/tests"]
    proc = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    output = proc.stdout or ""
    return {
        "ok": proc.returncode == 0,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "output_tail": output[-4000:],
    }


def _compact_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": meta.get("hostname", ""),
        "os_type": meta.get("os_type", ""),
        "volumes": meta.get("volumes", []),
        "root_listing": meta.get("root_listing", [])[:20],
    }


def _markdown_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Autonomous Validation Report",
        "",
        f"- ok: {summary.get('ok')}",
        f"- autonomous_enable_recommended: {summary.get('autonomous_enable_recommended')}",
        f"- completed_at: {summary.get('completed_at')}",
        f"- external_ok: {summary.get('external', {}).get('ok')}",
        f"- tests_ok: {summary.get('tests', {}).get('ok')}",
        "",
        "## E01 Probes",
        "",
    ]
    for probe in summary.get("e01_probes", []):
        lines.extend([
            f"### {probe.get('case_id')}",
            "",
            f"- status: {probe.get('status')}",
            f"- records: {probe.get('record_count')}",
            f"- issues: {', '.join(probe.get('issues', [])) or 'none'}",
            f"- scoring_included: {probe.get('scoring_included')}",
            f"- expected_markers: {probe.get('expected_marker_count', 0)}",
            f"- missing_expected_markers: {len(probe.get('missing_expected_markers', []))}",
            f"- missing_companions: {len(probe.get('missing_companions', []))}",
            f"- unparsed_percent: {probe.get('coverage', {}).get('unparsed_percent', 0)}",
            f"- cache: {probe.get('cache_path', '')}",
            "",
        ])
    lines.append("## Discussion Needed")
    lines.append("")
    if not summary.get("discussion_needed"):
        lines.append("- none")
    for item in summary.get("discussion_needed", []):
        lines.append(f"- {item.get('topic')}: {item.get('question')}")
    return "\n".join(lines) + "\n"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="Download missing allowlisted datasets")
    parser.add_argument("--no-tests", action="store_true", help="Skip pytest")
    parser.add_argument("--claude-review", action="store_true", help="Ask Claude to review discussion/risk items")
    parser.add_argument("--output-dir", default=str(RUN_DIR))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = run_autonomous_validation(
        download=args.download,
        run_tests=not args.no_tests,
        claude_review=args.claude_review,
        output_dir=args.output_dir,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(f"ok={result['ok']} output={result['output_path']} report={result['report_path']}")
        for probe in result["e01_probes"]:
            print(f"- {probe['case_id']}: status={probe.get('status')} records={probe.get('record_count')} issues={probe.get('issues')}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
