import json
import re
from pathlib import Path

from core.analysis.prefetch_semantic import parse_prefetch_bytes
from regression.e01_case_registry import E01_CASE_REGISTRY


PROJECT_ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_CORE_STRINGS = [
    r"\bLoneWolf\b",
    r"\bSelmaBouvier\b",
    r"\bJHYDE[-_]SP\b",
    r"\bcoreupdater\b",
    r"\bricksanchez\b",
    r"\bjerrysmith\b",
    r"194\.61\.24\.102",
]

GENERIC_ALLOWED_TOKENS = {
    "windows",
    "desktop",
    "digital",
    "corpora",
    "redacted",
    "forensics",
    "hacking",
    "case",
    "image",
    "images",
    "magnet",
    "registry",
    "source",
    "system",
    "users",
    "downloads",
    "drive",
    "operation",
    "information",
}


def test_active_e01_validation_loop_is_windows_os_only():
    active = [case for case in E01_CASE_REGISTRY if case.get("validation_enabled", True)]

    assert active, "at least one active Windows E01 case is required"
    assert all(case.get("expected_scope") == "windows_system" for case in active)


def test_data_volume_e01_cases_are_not_active_or_scored():
    data_volume_cases = [
        case for case in E01_CASE_REGISTRY
        if case.get("expected_scope") == "data_volume"
    ]

    assert data_volume_cases, "policy test should cover at least one disabled data-volume case"
    for case in data_volume_cases:
        assert case.get("validation_enabled") is False
        assert case.get("scoring_included") is False


def test_core_analysis_has_no_case_specific_benchmark_strings():
    core_roots = [PROJECT_ROOT / "backend" / "core"]
    offenders = []
    forbidden = [*FORBIDDEN_CORE_STRINGS, *_registry_derived_forbidden_patterns()]
    for root in core_roots:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in forbidden:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{pattern}")

    assert offenders == []


def test_prefetch_semantic_guardrails_are_non_escalating():
    result = parse_prefetch_bytes(_minimal_prefetch(), source_path="CMD.EXE-123.pf")

    assert result["ok"] is True
    assert result["evidence_state"] == "pending_corroboration"
    assert result["guardrails"]["standalone_verdict_allowed"] is False
    assert result["guardrails"]["absence_is_negative_evidence"] is False
    assert result["guardrails"]["referenced_paths_are_execution_evidence"] is False


def test_blind_reports_do_not_claim_answer_material_used():
    blind_dir = PROJECT_ROOT / "external" / "dfir_validation" / "blind_runs"
    if not blind_dir.exists():
        return
    reports = list(blind_dir.glob("*_blind_analysis.json"))
    for path in reports:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("answer_material_used") is False
        safety = data.get("safety", {})
        assert safety.get("known_answer_material_loaded") is False


def test_blind_e01_analysis_does_not_import_case_registry_or_expected_markers():
    path = PROJECT_ROOT / "backend" / "regression" / "blind_e01_analysis.py"
    text = path.read_text(encoding="utf-8")

    assert "e01_case_registry" not in text
    assert "E01_CASE_REGISTRY" not in text
    assert "expected_marker_paths" not in text
    assert "Expected Scenario Path" not in text


def _minimal_prefetch() -> bytes:
    import struct

    data = bytearray(0xE0)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    data[0x10:0x10 + 60] = "CMD.EXE".encode("utf-16le").ljust(60, b"\x00")
    struct.pack_into("<I", data, 0xD0, 1)
    return bytes(data)


def _registry_derived_forbidden_patterns() -> list[str]:
    tokens = set()
    for case in E01_CASE_REGISTRY:
        tokens.update(_specific_tokens(str(case.get("case_id", ""))))
        tokens.update(_specific_tokens(str(case.get("source", ""))))
        for marker in case.get("expected_marker_paths", []) or []:
            tokens.update(_specific_tokens(Path(str(marker)).stem))
    return [rf"\b{re.escape(token)}\b" for token in sorted(tokens)]


def _specific_tokens(text: str) -> set[str]:
    found = set()
    for token in re.split(r"[^A-Za-z0-9]+", text):
        clean = token.strip()
        if len(clean) < 5:
            continue
        if clean.lower() in GENERIC_ALLOWED_TOKENS:
            continue
        if clean.isdigit():
            continue
        found.add(clean)
    return found
