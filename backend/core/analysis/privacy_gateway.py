"""LLM-safe artifact projection.

Raw evidence can contain PII, credentials, privileged paths, and prompt
injection text. This module produces a deterministic safe view for MCP/LLM
contexts while preserving artifact handles for later policy-controlled reveal.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


POLICY_VERSION = "privacy_gateway.v1"

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATH_RE = re.compile(r"([A-Za-z]:\\Users\\)([^\\/\s]+)", re.IGNORECASE)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
KR_RRN_RE = re.compile(r"\b\d{6}-[1-4]\d{6}\b")
PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|reveal\s+.*secret|system\s+prompt|developer\s+message)",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret)=([^\s&;]+)",
    re.IGNORECASE,
)
BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+\-/]+=*", re.IGNORECASE)


def build_llm_safe_artifacts(
    artifacts: list[dict[str, Any]],
    *,
    case_secret: str,
    allowed_fields: list[str] | None = None,
    max_text_len: int = 300,
) -> dict[str, Any]:
    """Return redacted artifacts suitable for LLM context."""
    allowed = set(allowed_fields or [
        "artifact_id",
        "artifact_type",
        "timestamp",
        "message",
        "value",
        "source_chain",
        "temporal_layer",
        "parser_status",
        "conflict_flags",
    ])
    safe = []
    blocked_fields = 0
    sensitive_count = 0
    injection_count = 0

    for artifact in artifacts:
        item: dict[str, Any] = {}
        sensitivity = set()
        for key, value in artifact.items():
            if key not in allowed:
                blocked_fields += 1
                continue
            redacted, labels, injection = _redact_value(value, case_secret=case_secret, max_text_len=max_text_len)
            if labels:
                sensitivity.update(labels)
            if injection:
                injection_count += 1
            item[key] = redacted
        item["sensitivity"] = sorted(sensitivity)
        item["raw_available"] = True
        sensitive_count += len(sensitivity)
        safe.append(item)

    return {
        "ok": True,
        "policy": POLICY_VERSION,
        "artifacts": safe,
        "summary": {
            "input_count": len(artifacts),
            "returned_count": len(safe),
            "blocked_fields": blocked_fields,
            "sensitive_label_count": sensitive_count,
            "prompt_injection_flags": injection_count,
        },
        "notes": [
            "LLM-safe artifacts keep handles and provenance but redact direct identifiers.",
            "Raw reveal must be handled by a separate policy-gated function, not by this projection.",
        ],
    }


def _redact_value(value: Any, *, case_secret: str, max_text_len: int) -> tuple[Any, set[str], bool]:
    if isinstance(value, dict):
        out = {}
        labels: set[str] = set()
        injection = False
        for k, v in value.items():
            rv, labs, inj = _redact_value(v, case_secret=case_secret, max_text_len=max_text_len)
            out[k] = rv
            labels.update(labs)
            injection = injection or inj
        return out, labels, injection
    if isinstance(value, list):
        out_list = []
        labels: set[str] = set()
        injection = False
        for v in value[:25]:
            rv, labs, inj = _redact_value(v, case_secret=case_secret, max_text_len=max_text_len)
            out_list.append(rv)
            labels.update(labs)
            injection = injection or inj
        if len(value) > 25:
            out_list.append(f"[truncated {len(value) - 25} items]")
        return out_list, labels, injection
    if not isinstance(value, str):
        return value, set(), False
    return _redact_text(value, case_secret=case_secret, max_text_len=max_text_len)


def _redact_text(text: str, *, case_secret: str, max_text_len: int) -> tuple[str, set[str], bool]:
    labels: set[str] = set()
    injection = bool(PROMPT_INJECTION_RE.search(text))
    if injection:
        labels.add("prompt_injection_text")

    def tok(label: str, raw: str) -> str:
        labels.add(label.lower())
        digest = hmac.new(case_secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        return f"{label.upper()}_HMAC_{digest}"

    text = EMAIL_RE.sub(lambda m: tok("email", m.group(0)), text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}={tok('secret', m.group(2))}", text)
    text = BEARER_TOKEN_RE.sub(lambda m: "Bearer " + tok("secret", m.group(0)), text)
    text = SSN_RE.sub(lambda m: tok("ssn", m.group(0)), text)
    text = KR_RRN_RE.sub(lambda m: tok("rrn", m.group(0)), text)
    text = IP_RE.sub(lambda m: tok("ip", m.group(0)), text)
    text = USER_PATH_RE.sub(lambda m: m.group(1) + tok("user", m.group(2)), text)
    text = _redact_url_queries(text, labels)
    if len(text) > max_text_len:
        text = text[:max_text_len] + "...[truncated]"
    return text, labels, injection


def _redact_url_queries(text: str, labels: set[str]) -> str:
    parts = text.split()
    changed = False
    for idx, part in enumerate(parts):
        if "://" not in part:
            continue
        try:
            parsed = urlsplit(part)
        except ValueError:
            continue
        if parsed.query:
            labels.add("url_query")
            parts[idx] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "[redacted-query]", parsed.fragment))
            changed = True
    return " ".join(parts) if changed else text
