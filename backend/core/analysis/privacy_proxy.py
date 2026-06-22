"""Privacy proxy for LLM/MCP-bound forensic payloads.

This module never edits evidence or connector state. It only projects tool
request/response payloads before they leave the analysis boundary.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from state import load_allowed_evidence, normalize_path


POLICY_VERSION = "privacy_proxy.v1"
VALID_MODES = {"exclude", "include", "intercept"}

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_SETTINGS_FILE = os.path.join(_BACKEND_DIR, ".privacy_policy.json")
_DEFAULT_PENDING_FILE = os.path.join(_BACKEND_DIR, ".privacy_intercepts.json")
_DEFAULT_AUDIT_FILE = os.path.join(_BACKEND_DIR, ".privacy_audit.jsonl")
_DEFAULT_ALIAS_FILE = os.path.join(_BACKEND_DIR, ".privacy_aliases.json")
_DEFAULT_FILTER_LOG_FILE = os.path.join(_BACKEND_DIR, ".privacy_filter_events.json")
_PRIVACY_SCOPES_DIR = os.path.join(_BACKEND_DIR, ".privacy_scopes")
_SCOPE_FILE = os.path.join(_BACKEND_DIR, ".privacy_scope.json")

_SETTINGS_FILE = _DEFAULT_SETTINGS_FILE
_PENDING_FILE = _DEFAULT_PENDING_FILE
_AUDIT_FILE = _DEFAULT_AUDIT_FILE
_ALIAS_FILE = _DEFAULT_ALIAS_FILE
_FILTER_LOG_FILE = _DEFAULT_FILTER_LOG_FILE

MAX_MATCHES_DEFAULT = 200
MAX_PENDING_ITEMS = 100
MAX_FILTER_EVENTS = 500
MAX_PREVIEW_CHARS = 60000
INTERCEPT_TIMEOUT_DEFAULT = 600
INTERCEPT_TIMEOUT_MAX = 3600
INTERCEPT_POLL_SECONDS = 0.25
DEFAULT_ALIAS_TYPES = {"PERSON", "USER", "HOST", "PATH", "IP", "EMAIL", "CUSTOM"}
ALIAS_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9]*_[0-9]{3}\b|\b[A-Z]+_HMAC_[a-f0-9]{12}\b")


FILTER_RULES: list[dict[str, str]] = [
    {
        "id": "secret_assignment",
        "label": "secret",
        "severity": "critical",
        "description": "password/token/api_key style assignment",
    },
    {
        "id": "bearer_token",
        "label": "secret",
        "severity": "critical",
        "description": "Bearer token",
    },
    {
        "id": "email",
        "label": "email",
        "severity": "high",
        "description": "email address",
    },
    {
        "id": "ipv4",
        "label": "ip",
        "severity": "medium",
        "description": "IPv4 address",
    },
    {
        "id": "windows_user_path",
        "label": "user_path",
        "severity": "high",
        "description": "Windows user profile path",
    },
    {
        "id": "windows_path",
        "label": "path",
        "severity": "medium",
        "description": "Windows filesystem path",
    },
    {
        "id": "url_query",
        "label": "url_query",
        "severity": "high",
        "description": "URL query string may carry tokens or case identifiers",
    },
    {
        "id": "ssn",
        "label": "ssn",
        "severity": "critical",
        "description": "US social security number pattern",
    },
    {
        "id": "kr_rrn",
        "label": "rrn",
        "severity": "critical",
        "description": "Korean resident registration number pattern",
    },
    {
        "id": "identity_field",
        "label": "identity",
        "severity": "medium",
        "description": "field name suggests host/user/account identity",
    },
]

_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "secret_assignment",
        "secret",
        "critical",
        re.compile(r"\b(password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret)=([^\s&;]+)", re.IGNORECASE),
    ),
    (
        "bearer_token",
        "secret",
        "critical",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+\-/]+=*", re.IGNORECASE),
    ),
    (
        "email",
        "email",
        "high",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "ipv4",
        "ip",
        "medium",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
    (
        "windows_user_path",
        "user_path",
        "high",
        re.compile(r"[A-Za-z]:\\Users\\[^\\/\s]+", re.IGNORECASE),
    ),
    (
        "windows_path",
        "path",
        "medium",
        re.compile(r"[A-Za-z]:\\(?:[^\\/\s:*?\"<>|]+\\)*[^\\/\s:*?\"<>|]*", re.IGNORECASE),
    ),
    (
        "url_query",
        "url_query",
        "high",
        re.compile(r"https?://[^\s?#]+[^\s#]*\?[^\s#]+", re.IGNORECASE),
    ),
    (
        "ssn",
        "ssn",
        "critical",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "kr_rrn",
        "rrn",
        "critical",
        re.compile(r"\b\d{6}-[1-4]\d{6}\b"),
    ),
]

_USER_PATH_RE = re.compile(r"([A-Za-z]:\\Users\\)([^\\/\s]+)", re.IGNORECASE)
_URL_QUERY_RE = re.compile(r"(https?://[^\s?#]+[^\s#]*\?)([^\s#]+)", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/\s:*?\"<>|]+\\)*[^\\/\s:*?\"<>|]*", re.IGNORECASE)


def set_privacy_scope_context(*, project_path: str = "", project_name: str = "", evidence_paths: list[str] | None = None) -> dict[str, Any]:
    """Persist the active privacy scope context for UI and MCP processes.

    Privacy state must not be global because Alias Vault entries and resolved
    intercepts may contain case-specific identifiers. The context file is small
    and deliberately derived only from analyst-selected project/evidence paths.
    """
    evidence = sorted({normalize_path(p) for p in (evidence_paths or []) if str(p).strip()})
    project = normalize_path(project_path) if project_path else ""
    payload = {
        "project_path": project,
        "project_name": str(project_name or "").strip(),
        "evidence_paths": evidence,
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(os.path.dirname(_SCOPE_FILE), exist_ok=True)
    with open(_SCOPE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return current_privacy_scope()


def current_privacy_scope() -> dict[str, Any]:
    material, label, source = _scope_material()
    if not material:
        return {
            "id": "global",
            "label": "Global privacy state",
            "source": "global",
            "scoped": False,
        }
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16]
    return {
        "id": f"scope_{digest}",
        "label": label,
        "source": source,
        "scoped": True,
    }


def current_privacy_scope_context() -> dict[str, Any]:
    """Return the persisted scope context without exposing mutable internals."""
    ctx = _read_scope_context()
    return copy.deepcopy(ctx) if isinstance(ctx, dict) else {}


def scoped_state_path(filename: str, *, global_path: str = "") -> str:
    """Return a project/evidence-scoped path for cross-process analysis state.

    This is intentionally generic so features adjacent to privacy (MCP event
    history, analyst-only graph notes) can share the same case boundary without
    reimplementing scope hashing.
    """
    scope = current_privacy_scope()
    if not scope.get("scoped"):
        return global_path or os.path.join(_BACKEND_DIR, filename)
    safe_name = os.path.basename(str(filename or "").lstrip("."))
    path = os.path.join(_PRIVACY_SCOPES_DIR, str(scope["id"]), safe_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def set_privacy_scope_for_evidence(*, evidence_paths: list[str] | None = None, project_name: str = "") -> dict[str, Any]:
    """Set an evidence-derived scope unless the current project already owns it.

    Direct MCP calls can open/mount evidence without going through the project
    UI. In that case we must avoid reusing a stale project's privacy state, but
    if the UI already selected a project containing this evidence, preserving
    the project scope keeps UI and MCP state aligned.
    """
    evidence = sorted({normalize_path(p) for p in (evidence_paths or []) if str(p).strip()})
    if not evidence:
        return current_privacy_scope()
    ctx = _read_scope_context()
    project_path = normalize_path(str(ctx.get("project_path") or "")) if ctx else ""
    ctx_evidence = {
        normalize_path(p)
        for p in (ctx.get("evidence_paths") or [])
        if str(p).strip()
    } if ctx else set()
    if project_path and set(evidence).issubset(ctx_evidence):
        return current_privacy_scope()
    return set_privacy_scope_context(project_name=project_name, evidence_paths=evidence)


def _scope_material() -> tuple[str, str, str]:
    ctx = _read_scope_context()
    project_path = normalize_path(str(ctx.get("project_path") or "")) if ctx else ""
    project_name = str(ctx.get("project_name") or "").strip()
    if project_path:
        label = project_name or os.path.splitext(os.path.basename(project_path))[0] or "Project"
        return f"project:{project_path}", label, "project"

    evidence_paths = [
        normalize_path(p)
        for p in (ctx.get("evidence_paths") or [])
        if str(p).strip()
    ] if ctx else []
    if not evidence_paths:
        allowed = load_allowed_evidence()
        evidence_paths = [normalize_path(p) for p in allowed.get("paths", []) if str(p).strip()]
    evidence_paths = sorted(set(evidence_paths))
    if evidence_paths:
        first = os.path.basename(evidence_paths[0])
        label = first if len(evidence_paths) == 1 else f"{first} + {len(evidence_paths) - 1}"
        return "evidence:" + "|".join(evidence_paths), label, "evidence"

    return "", "Global privacy state", "global"


def _read_scope_context() -> dict[str, Any]:
    if not os.path.exists(_SCOPE_FILE):
        return {}
    try:
        with open(_SCOPE_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _is_test_override(current: str, default: str) -> bool:
    return normalize_path(current) != normalize_path(default)


def _scope_file(default_file: str, current_file: str) -> str:
    if _is_test_override(current_file, default_file):
        return current_file
    scope = current_privacy_scope()
    if not scope.get("scoped"):
        return current_file
    path = os.path.join(_PRIVACY_SCOPES_DIR, str(scope["id"]), os.path.basename(default_file).lstrip("."))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def _settings_file() -> str:
    return _scope_file(_DEFAULT_SETTINGS_FILE, _SETTINGS_FILE)


def _pending_file() -> str:
    return _scope_file(_DEFAULT_PENDING_FILE, _PENDING_FILE)


def _audit_file() -> str:
    return _scope_file(_DEFAULT_AUDIT_FILE, _AUDIT_FILE)


def _alias_file() -> str:
    return _scope_file(_DEFAULT_ALIAS_FILE, _ALIAS_FILE)


def _filter_log_file() -> str:
    return _scope_file(_DEFAULT_FILTER_LOG_FILE, _FILTER_LOG_FILE)


def default_settings() -> dict[str, Any]:
    return {
        "policy": POLICY_VERSION,
        "mode": "exclude",
        "intercept_sensitive_tools": True,
        "intercept_blocking": True,
        "intercept_timeout_seconds": INTERCEPT_TIMEOUT_DEFAULT,
        "max_matches": MAX_MATCHES_DEFAULT,
        "case_secret": secrets.token_hex(16),
        "updated": datetime.now(timezone.utc).isoformat(),
    }


def get_settings() -> dict[str, Any]:
    settings = default_settings()
    settings_path = _settings_file()
    settings_exists = os.path.exists(settings_path)
    if settings_exists:
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                settings.update({k: v for k, v in loaded.items() if k in settings})
        except Exception:
            pass
    if settings.get("mode") not in VALID_MODES:
        settings["mode"] = "exclude"
    if not settings.get("case_secret"):
        settings["case_secret"] = secrets.token_hex(16)
        try:
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    elif not settings_exists:
        try:
            os.makedirs(os.path.dirname(settings_path), exist_ok=True)
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return settings


def public_settings() -> dict[str, Any]:
    settings = get_settings()
    return {
        "policy": settings["policy"],
        "mode": settings["mode"],
        "intercept_sensitive_tools": bool(settings.get("intercept_sensitive_tools", True)),
        "intercept_blocking": bool(settings.get("intercept_blocking", True)),
        "intercept_timeout_seconds": _intercept_timeout(settings),
        "max_matches": int(settings.get("max_matches") or MAX_MATCHES_DEFAULT),
        "updated": settings.get("updated", ""),
        "scope": current_privacy_scope(),
        "filter_rules": FILTER_RULES,
        "pending_count": len([i for i in list_intercepts() if i.get("status") == "pending"]),
        "filter_event_count": len(list_filter_events(limit=MAX_FILTER_EVENTS)),
    }


def save_settings(settings: dict[str, Any]) -> dict[str, Any]:
    settings_path = _settings_file()
    current = get_settings() if os.path.exists(settings_path) else default_settings()
    mode = str(settings.get("mode", current.get("mode", "exclude"))).strip().lower()
    if mode not in VALID_MODES:
        mode = "exclude"
    current.update({
        "policy": POLICY_VERSION,
        "mode": mode,
        "intercept_sensitive_tools": bool(settings.get(
            "intercept_sensitive_tools",
            current.get("intercept_sensitive_tools", True),
        )),
        "intercept_blocking": bool(settings.get(
            "intercept_blocking",
            current.get("intercept_blocking", True),
        )),
        "intercept_timeout_seconds": _intercept_timeout(settings, fallback=current.get("intercept_timeout_seconds")),
        "max_matches": max(1, min(int(settings.get("max_matches") or MAX_MATCHES_DEFAULT), 1000)),
        "updated": datetime.now(timezone.utc).isoformat(),
    })
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)
    _audit("settings_updated", {"mode": current["mode"]})
    return public_settings()


def _intercept_timeout(settings: dict[str, Any], *, fallback: Any = None) -> int:
    raw = settings.get("intercept_timeout_seconds")
    if raw is None:
        raw = fallback
    if raw is None:
        raw = os.environ.get("FW_PRIVACY_INTERCEPT_TIMEOUT", INTERCEPT_TIMEOUT_DEFAULT)
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        seconds = INTERCEPT_TIMEOUT_DEFAULT
    return max(1, min(seconds, INTERCEPT_TIMEOUT_MAX))


def _alias_type(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_]", "", str(value or "").upper()) or "CUSTOM"
    if label == "USER_PATH":
        label = "PATH"
    if len(label) > 32:
        raise ValueError("alias_type must be 32 characters or fewer")
    return label


def _alias_hmac(raw_value: str) -> str:
    secret = get_settings()["case_secret"]
    return hmac.new(secret.encode("utf-8"), raw_value.encode("utf-8"), hashlib.sha256).hexdigest()


def _read_alias_doc() -> dict[str, Any]:
    alias_path = _alias_file()
    if not os.path.exists(alias_path):
        return {"policy": POLICY_VERSION, "aliases": [], "counters": {}}
    try:
        with open(alias_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return {"policy": POLICY_VERSION, "aliases": [], "counters": {}}
    if isinstance(doc, list):
        return {"policy": POLICY_VERSION, "aliases": doc, "counters": {}}
    if not isinstance(doc, dict):
        return {"policy": POLICY_VERSION, "aliases": [], "counters": {}}
    doc.setdefault("policy", POLICY_VERSION)
    doc.setdefault("aliases", [])
    doc.setdefault("counters", {})
    if not isinstance(doc["aliases"], list):
        doc["aliases"] = []
    if not isinstance(doc["counters"], dict):
        doc["counters"] = {}
    return doc


def _write_alias_doc(doc: dict[str, Any]) -> None:
    alias_path = _alias_file()
    os.makedirs(os.path.dirname(alias_path), exist_ok=True)
    with open(alias_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, default=str)


def _next_alias(doc: dict[str, Any], alias_type: str) -> str:
    counters = doc.setdefault("counters", {})
    existing_numbers = []
    prefix = f"{alias_type}_"
    for item in doc.get("aliases", []):
        alias = str(item.get("alias", ""))
        if alias.startswith(prefix):
            try:
                existing_numbers.append(int(alias.rsplit("_", 1)[1]))
            except (IndexError, ValueError):
                pass
    current = int(counters.get(alias_type) or 0)
    next_number = max([current, *existing_numbers], default=0) + 1
    counters[alias_type] = next_number
    return f"{alias_type}_{next_number:03d}"


def list_aliases(*, include_raw: bool = False) -> list[dict[str, Any]]:
    """Return case-scoped alias rules. Raw values are hidden by default."""
    out = []
    for item in _read_alias_doc().get("aliases", []):
        if not isinstance(item, dict):
            continue
        clone = dict(item)
        if not include_raw:
            clone.pop("raw_value", None)
        out.append(clone)
    return out


def get_alias(alias_or_id: str, *, include_raw: bool = False) -> dict[str, Any]:
    """Return one alias rule. Raw value is available only for analyst edit flows."""
    alias_key = str(alias_or_id or "").strip()
    if not alias_key:
        raise KeyError("Alias not found")
    for item in _read_alias_doc().get("aliases", []):
        if not isinstance(item, dict):
            continue
        if item.get("alias") == alias_key or item.get("id") == alias_key:
            clone = dict(item)
            if not include_raw:
                clone.pop("raw_value", None)
            return clone
    raise KeyError(f"Alias not found: {alias_key}")


def add_alias(raw_value: str, alias_type: str = "CUSTOM", alias: str = "") -> dict[str, Any]:
    raw = str(raw_value or "").strip()
    if not raw:
        raise ValueError("raw_value is required")
    kind = _alias_type(alias_type)
    doc = _read_alias_doc()
    digest = _alias_hmac(raw)
    now = datetime.now(timezone.utc).isoformat()
    for item in doc.get("aliases", []):
        if item.get("raw_hmac") == digest:
            if alias and item.get("alias") != alias:
                alias_value = _normalize_alias(alias, kind)
                _ensure_alias_unique(doc, alias_value, skip_id=item.get("id", ""))
                item["alias"] = alias_value
                item["alias_type"] = kind
                item["updated"] = now
                _write_alias_doc(doc)
            clone = dict(item)
            clone.pop("raw_value", None)
            return clone
    alias_value = _normalize_alias(alias, kind) if alias else _next_alias(doc, kind)
    _ensure_alias_unique(doc, alias_value)
    item = {
        "id": f"pa_{digest[:12]}",
        "alias": alias_value,
        "alias_type": kind,
        "raw_value": raw,
        "raw_hmac": digest,
        "raw_length": len(raw),
        "created": now,
        "updated": now,
        "scope": current_privacy_scope(),
    }
    doc.setdefault("aliases", []).append(item)
    _write_alias_doc(doc)
    _audit("alias_added", {"id": item["id"], "alias": item["alias"], "alias_type": item["alias_type"]})
    clone = dict(item)
    clone.pop("raw_value", None)
    return clone


def update_alias(
    alias_or_id: str,
    *,
    raw_value: str | None = None,
    alias_type: str | None = None,
    alias: str | None = None,
) -> dict[str, Any]:
    alias_key = str(alias_or_id or "").strip()
    if not alias_key:
        raise KeyError("Alias not found")
    doc = _read_alias_doc()
    now = datetime.now(timezone.utc).isoformat()
    target = None
    for item in doc.get("aliases", []):
        if item.get("alias") == alias_key or item.get("id") == alias_key:
            target = item
            break
    if target is None:
        raise KeyError(f"Alias not found: {alias_key}")

    kind = _alias_type(alias_type or target.get("alias_type", "CUSTOM"))
    if raw_value is not None:
        raw = str(raw_value or "").strip()
        if not raw:
            raise ValueError("raw_value is empty")
        digest = _alias_hmac(raw)
        for item in doc.get("aliases", []):
            if item is not target and item.get("raw_hmac") == digest:
                raise ValueError("raw_value is already mapped to another alias")
        target["raw_value"] = raw
        target["raw_hmac"] = digest
        target["raw_length"] = len(raw)
        target["id"] = f"pa_{digest[:12]}"

    if alias is not None and str(alias).strip():
        alias_value = _normalize_alias(alias, kind)
    elif kind != target.get("alias_type"):
        alias_value = _next_alias(doc, kind)
    else:
        alias_value = str(target.get("alias", ""))
    _ensure_alias_unique(doc, alias_value, skip_id=target.get("id", ""))
    target["alias"] = alias_value
    target["alias_type"] = kind
    target["updated"] = now
    _write_alias_doc(doc)
    _audit("alias_updated", {"id": target["id"], "alias": target["alias"], "alias_type": target["alias_type"]})
    clone = dict(target)
    clone.pop("raw_value", None)
    return clone


def remove_alias(alias: str) -> dict[str, Any]:
    alias_value = str(alias or "").strip()
    doc = _read_alias_doc()
    kept = []
    removed = []
    for item in doc.get("aliases", []):
        if item.get("alias") == alias_value or item.get("id") == alias_value:
            removed.append(item)
        else:
            kept.append(item)
    if not removed:
        raise KeyError(f"Alias not found: {alias_value}")
    doc["aliases"] = kept
    _write_alias_doc(doc)
    _audit("alias_removed", {"alias": alias_value, "count": len(removed)})
    return {"status": "removed", "alias": alias_value, "count": len(removed)}


def _normalize_alias(alias: str, alias_type: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", str(alias or "").upper()).strip("_")
    if not value:
        raise ValueError("alias is empty after normalization")
    if not value.startswith(f"{alias_type}_"):
        value = f"{alias_type}_{value}"
    return value


def _ensure_alias_unique(doc: dict[str, Any], alias: str, *, skip_id: str = "") -> None:
    for item in doc.get("aliases", []):
        if skip_id and item.get("id") == skip_id:
            continue
        if item.get("alias") == alias:
            raise ValueError(f"alias already exists: {alias}")


def apply_aliases_to_payload(payload: Any) -> Any:
    entries = _alias_entries()
    if not entries:
        return copy.deepcopy(payload)
    return _replace_strings(payload, [(e["raw_value"], e["alias"]) for e in entries])


def resolve_aliases_in_payload(payload: Any) -> Any:
    entries = _alias_entries()
    if not entries:
        return copy.deepcopy(payload)
    return _replace_strings(payload, [(e["alias"], e["raw_value"]) for e in entries])


def _alias_entries() -> list[dict[str, Any]]:
    entries = [
        item for item in _read_alias_doc().get("aliases", [])
        if isinstance(item, dict) and item.get("raw_value") and item.get("alias")
    ]
    entries.sort(key=lambda x: max(len(str(x.get("raw_value", ""))), len(str(x.get("alias", "")))), reverse=True)
    return entries


def _replace_strings(value: Any, replacements: list[tuple[str, str]]) -> Any:
    def replace_text(text: str) -> str:
        out = text
        for src, dst in replacements:
            if src:
                out = out.replace(src, dst)
        return out

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return replace_text(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return copy.deepcopy(v)

    return walk(value)


def _has_known_alias_token(text: str) -> bool:
    if ALIAS_TOKEN_RE.search(text):
        return True
    return any(str(item.get("alias", "")) in text for item in _alias_entries())


def scan_payload(payload: Any, *, max_matches: int | None = None) -> dict[str, Any]:
    limit = max_matches or int(get_settings().get("max_matches") or MAX_MATCHES_DEFAULT)
    matches: list[dict[str, Any]] = []
    summary: dict[str, int] = {}

    for path, value in _walk_strings(payload):
        if len(matches) >= limit:
            break
        lowered_path = path.lower()
        if _identity_key_path(lowered_path) and value.strip() and not _has_known_alias_token(value):
            _add_match(
                matches,
                summary,
                path=path,
                rule_id="identity_field",
                label="identity",
                severity="medium",
                excerpt=_excerpt(value),
                span=[0, min(len(value), MAX_PREVIEW_CHARS)],
            )
            if len(matches) >= limit:
                break
        for rule_id, label, severity, pattern in _PATTERNS:
            for m in pattern.finditer(value):
                excerpt = m.group(0)
                if rule_id in {"windows_user_path", "windows_path"} and _has_known_alias_token(excerpt):
                    continue
                _add_match(
                    matches,
                    summary,
                    path=path,
                    rule_id=rule_id,
                    label=label,
                    severity=severity,
                    excerpt=_excerpt(excerpt),
                    span=[m.start(), m.end()],
                )
                if len(matches) >= limit:
                    break
            if len(matches) >= limit:
                break

    return {
        "has_sensitive": bool(matches),
        "matches": matches,
        "summary": summary,
        "truncated": len(matches) >= limit,
        "payload_sha256": payload_hash(payload),
    }


def list_filter_events(*, limit: int = 200, include_matches: bool = True) -> list[dict[str, Any]]:
    """Return case-scoped privacy filter/intercept events.

    Events are analyst-facing audit records. Match excerpts are public
    projections, not raw values, so this list can be shown in the UI without
    undoing the LLM-bound redaction policy.
    """
    path = _filter_log_file()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            items = json.load(f)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    out = []
    for item in items[: max(0, int(limit or 0))]:
        if not isinstance(item, dict):
            continue
        clone = dict(item)
        if not include_matches:
            clone.pop("matches", None)
        out.append(clone)
    return out


def _write_filter_events(items: list[dict[str, Any]]) -> None:
    path = _filter_log_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(items[:MAX_FILTER_EVENTS], f, ensure_ascii=False, indent=2, default=str)


def _public_match(match: dict[str, Any], *, case_secret: str) -> dict[str, Any]:
    clone = dict(match)
    raw_excerpt = str(clone.get("excerpt", ""))
    label = str(clone.get("label", "custom") or "custom").lower()
    projected = redact_payload(raw_excerpt, case_secret=case_secret)
    if projected == raw_excerpt and raw_excerpt:
        token_label = {
            "identity": "identity",
            "user_path": "path",
            "path": "path",
            "email": "email",
            "ip": "ip",
            "secret": "secret",
            "ssn": "ssn",
            "rrn": "rrn",
        }.get(label, "sensitive")
        digest = hmac.new(
            case_secret.encode("utf-8"),
            raw_excerpt.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()[:12]
        projected = f"{token_label.upper()}_HMAC_{digest}"
    clone["excerpt"] = str(projected)
    clone["excerpt_hmac"] = hmac.new(
        case_secret.encode("utf-8"),
        raw_excerpt.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()[:16] if raw_excerpt else ""
    return clone


def _public_matches(scan: dict[str, Any], *, case_secret: str) -> list[dict[str, Any]]:
    return [_public_match(m, case_secret=case_secret) for m in scan.get("matches", []) if isinstance(m, dict)]


def _record_filter_event(
    *,
    mode: str,
    tool: str,
    params: dict[str, Any],
    payload: Any,
    projected_payload: Any,
    channel: str,
    scan: dict[str, Any],
    status: str,
    intercept_id: str = "",
    decision: str = "",
) -> dict[str, Any]:
    settings = get_settings()
    now = datetime.now(timezone.utc).isoformat()
    item = {
        "id": f"pf_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}",
        "created": now,
        "updated": now,
        "status": status,
        "mode": mode,
        "tool": tool,
        "channel": channel,
        "payload_role": "response",
        "policy": POLICY_VERSION,
        "scope": current_privacy_scope(),
        "intercept_id": intercept_id,
        "decision": decision,
        "params_sha256": payload_hash(params),
        "payload_sha256": scan.get("payload_sha256") or payload_hash(payload),
        "projected_payload_sha256": payload_hash(projected_payload),
        "sensitive_summary": scan.get("summary", {}),
        "match_count": len(scan.get("matches", [])),
        "matches": _public_matches(scan, case_secret=settings["case_secret"]),
        "truncated": bool(scan.get("truncated")),
    }
    items = list_filter_events(limit=MAX_FILTER_EVENTS, include_matches=True)
    items.insert(0, item)
    _write_filter_events(items)
    _audit("filter_event_recorded", {
        "id": item["id"],
        "mode": mode,
        "tool": tool,
        "channel": channel,
        "status": status,
        "intercept_id": intercept_id,
        "sensitive_summary": item["sensitive_summary"],
    })
    return item


def _update_filter_event_for_intercept(intercept_id: str, *, status: str, decision: str = "") -> None:
    if not intercept_id:
        return
    items = list_filter_events(limit=MAX_FILTER_EVENTS, include_matches=True)
    changed = False
    for item in items:
        if item.get("intercept_id") != intercept_id:
            continue
        item["status"] = status
        item["updated"] = datetime.now(timezone.utc).isoformat()
        if decision:
            item["decision"] = decision
        changed = True
        break
    if changed:
        _write_filter_events(items)


def project_payload_for_event(payload: Any, *, tool: str = "", direction: str = "") -> Any:
    settings = get_settings()
    mode = settings.get("mode", "exclude")
    if mode == "include":
        return payload
    projected = redact_payload(apply_aliases_to_payload(payload), case_secret=settings["case_secret"])
    if isinstance(projected, dict):
        scan = scan_payload(payload, max_matches=settings.get("max_matches"))
        if scan["has_sensitive"]:
            projected = dict(projected)
            projected["_privacy"] = {
                "policy": POLICY_VERSION,
                "mode": mode,
                "direction": direction,
                "tool": tool,
                "sensitive_summary": scan["summary"],
                "highlighted": True,
            }
    return projected


def apply_tool_privacy(
    tool: str,
    params: dict[str, Any],
    result: Any,
    *,
    channel: str,
    wait_for_resolution: bool = False,
) -> Any:
    settings = get_settings()
    mode = settings.get("mode", "exclude")
    aliased_result = apply_aliases_to_payload(result)
    # The LLM receives the tool response, not the request params. Intercept
    # and editing therefore apply to RES only; request params are handled as
    # read-only context in logs/UI.
    scan = scan_payload(aliased_result, max_matches=settings.get("max_matches"))

    if mode == "include":
        return _attach_privacy_meta(aliased_result, mode=mode, channel=channel, tool=tool, scan=scan)

    if mode == "intercept" and settings.get("intercept_sensitive_tools", True) and scan["has_sensitive"]:
        item = create_intercept(tool=tool, params=params, payload=aliased_result, channel=channel, scan=scan)
        if wait_for_resolution and settings.get("intercept_blocking", True):
            resolved = wait_for_intercept_resolution(item["id"], timeout_seconds=_intercept_timeout(settings))
            if resolved is not None:
                return resolved
            _audit("intercept_wait_timeout", {
                "id": item["id"],
                "tool": tool,
                "channel": channel,
                "timeout_seconds": _intercept_timeout(settings),
            })
            return _pending_intercept_response(item, scan, status="pending_timeout")
        return _pending_intercept_response(item, scan, status="pending")

    redacted = redact_payload(aliased_result, case_secret=settings["case_secret"])
    filter_event = None
    if mode == "exclude" and scan["has_sensitive"]:
        filter_event = _record_filter_event(
            mode=mode,
            tool=tool,
            params=params,
            payload=aliased_result,
            projected_payload=redacted,
            channel=channel,
            scan=scan,
            status="applied",
        )
    return _attach_privacy_meta(
        redacted,
        mode=mode,
        channel=channel,
        tool=tool,
        scan=scan,
        filter_event_id=filter_event.get("id") if filter_event else "",
    )


def wait_for_intercept_resolution(intercept_id: str, *, timeout_seconds: int | None = None) -> dict[str, Any] | None:
    """Block the current tool response until the analyst resolves an intercept."""
    deadline = time.monotonic() + max(1, int(timeout_seconds or INTERCEPT_TIMEOUT_DEFAULT))
    while time.monotonic() < deadline:
        item = get_intercept(intercept_id)
        if item.get("status") == "resolved":
            return replay_intercept(intercept_id)
        if not item:
            return None
        time.sleep(INTERCEPT_POLL_SECONDS)
    return None


def _pending_intercept_response(item: dict[str, Any], scan: dict[str, Any], *, status: str) -> dict[str, Any]:
    timed_out = status == "pending_timeout"
    limitations = [
        "The original tool result was withheld because privacy intercept mode is enabled.",
        "Until an analyst approves or edits this payload, downstream LLM analysis lacks this evidence.",
    ]
    if timed_out:
        limitations.append(
            "The MCP tool call timed out waiting for analyst approval; replay is required to avoid omitting this evidence."
        )
    return {
        "privacy_intercept": {
            "status": status,
            "intercept_id": item["id"],
            "tool": item.get("tool", ""),
            "channel": item.get("channel", ""),
            "policy": POLICY_VERSION,
            "blocking": True,
            "sensitive_summary": scan["summary"],
            "match_count": len(scan["matches"]),
            "payload_sha256": scan["payload_sha256"],
            "masked_preview": item.get("masked_preview"),
            "analysis_limitations": limitations,
            "next_required_action": {
                "tool": "privacy_replay_intercept",
                "args": {"intercept_id": item["id"]},
                "when": "After the analyst resolves this intercept in the Web UI.",
            },
        }
    }


def redact_payload(payload: Any, *, case_secret: str | None = None) -> Any:
    secret = case_secret or get_settings()["case_secret"]
    payload = apply_aliases_to_payload(payload)

    def token(label: str, raw: str) -> str:
        digest = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        return f"{label.upper()}_HMAC_{digest}"

    def redact_text(text: str, path: str = "") -> str:
        if not text:
            return text

        lowered_path = path.lower()
        if _identity_key_path(lowered_path) and not re.search(r"[\\/]", text):
            if _has_known_alias_token(text):
                return text
            label = "host" if any(k in lowered_path for k in ("host", "computer")) else "user"
            return token(label, text)

        def secret_assignment_repl(m: re.Match[str]) -> str:
            return f"{m.group(1)}={token('secret', m.group(2))}"

        text = _PATTERNS[0][3].sub(secret_assignment_repl, text)
        text = _PATTERNS[1][3].sub(lambda m: "Bearer " + token("secret", m.group(0)), text)
        text = _PATTERNS[2][3].sub(lambda m: token("email", m.group(0)), text)
        text = _PATTERNS[3][3].sub(lambda m: token("ip", m.group(0)), text)
        text = _USER_PATH_RE.sub(
            lambda m: m.group(0) if _has_known_alias_token(m.group(2)) else m.group(1) + token("user", m.group(2)),
            text,
        )
        text = _URL_QUERY_RE.sub(lambda m: m.group(1) + "[redacted-query]", text)
        text = _PATTERNS[7][3].sub(lambda m: token("ssn", m.group(0)), text)
        text = _PATTERNS[8][3].sub(lambda m: token("rrn", m.group(0)), text)
        text = _WINDOWS_PATH_RE.sub(
            lambda m: m.group(0)
            if re.match(r"^[A-Za-z]:\\Users\\", m.group(0), re.IGNORECASE) or _has_known_alias_token(m.group(0))
            else token("path", m.group(0)),
            text,
        )
        return text

    def walk(value: Any, path: str = "$") -> Any:
        if isinstance(value, str):
            return redact_text(value, path)
        if isinstance(value, list):
            return [walk(v, f"{path}[{idx}]") for idx, v in enumerate(value)]
        if isinstance(value, dict):
            return {k: walk(v, f"{path}.{k}") for k, v in value.items()}
        return value

    return walk(copy.deepcopy(payload))


def create_intercept(
    *,
    tool: str,
    params: dict[str, Any],
    payload: Any,
    channel: str,
    scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    payload = apply_aliases_to_payload(payload)
    scan = scan or scan_payload(payload, max_matches=settings.get("max_matches"))
    now = datetime.now(timezone.utc).isoformat()
    item = {
        "id": f"pi_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}",
        "created": now,
        "updated": now,
        "status": "pending",
        "tool": tool,
        "channel": channel,
        "payload_role": "response",
        "policy": POLICY_VERSION,
        "scope": current_privacy_scope(),
        "params": params,
        "payload": payload,
        "payload_sha256": payload_hash(payload),
        "masked_payload": redact_payload(payload, case_secret=settings["case_secret"]),
        "masked_preview": _preview(redact_payload(payload, case_secret=settings["case_secret"])),
        "response_matches": scan["matches"],
        "response_sensitive_summary": scan["summary"],
        "matches": scan["matches"],
        "sensitive_summary": scan["summary"],
        "match_count": len(scan["matches"]),
        "truncated": scan["truncated"],
        "decision": "",
        "edited_payload": None,
        "analysis_limitations": [
            "Manual deletion or rewriting of sensitive fields can hide user, host, path, or IP evidence from downstream LLM analysis.",
            "Any approved edited payload must be treated as an analyst projection, not original evidence.",
        ],
    }
    filter_event = _record_filter_event(
        mode="intercept",
        tool=tool,
        params=params,
        payload=payload,
        projected_payload=item["masked_payload"],
        channel=channel,
        scan=scan,
        status="pending",
        intercept_id=item["id"],
    )
    item["filter_event_id"] = filter_event["id"]
    items = list_intercepts(include_payload=True)
    items.insert(0, item)
    _write_intercepts(items[:MAX_PENDING_ITEMS])
    _audit("intercept_created", {
        "id": item["id"],
        "tool": tool,
        "channel": channel,
        "sensitive_summary": item["sensitive_summary"],
    })
    return item


def list_intercepts(include_payload: bool = False) -> list[dict[str, Any]]:
    pending_path = _pending_file()
    if not os.path.exists(pending_path):
        return []
    try:
        with open(pending_path, "r", encoding="utf-8") as f:
            items = json.load(f)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    if include_payload:
        return items
    out = []
    for item in items:
        clone = dict(item)
        clone.pop("payload", None)
        clone.pop("masked_payload", None)
        clone.pop("edited_payload", None)
        settings = get_settings()
        if "matches" in clone:
            clone["matches"] = [_public_match(m, case_secret=settings["case_secret"]) for m in clone["matches"]]
        if "response_matches" in clone:
            clone["response_matches"] = [
                _public_match(m, case_secret=settings["case_secret"]) for m in clone["response_matches"]
            ]
        out.append(clone)
    return out


def get_intercept(intercept_id: str, *, include_payload: bool = True) -> dict[str, Any]:
    for item in list_intercepts(include_payload=include_payload):
        if item.get("id") == intercept_id:
            return item
    return {}


def resolve_intercept(intercept_id: str, *, action: str, edited_payload: Any = None) -> dict[str, Any]:
    allowed = {"send_masked", "send_raw", "send_edited", "block"}
    if action not in allowed:
        raise ValueError(f"Unsupported privacy action: {action}")
    items = list_intercepts(include_payload=True)
    resolved: dict[str, Any] = {}
    for item in items:
        if item.get("id") != intercept_id:
            continue
        item["status"] = "resolved"
        item["updated"] = datetime.now(timezone.utc).isoformat()
        item["decision"] = action
        if action == "send_edited":
            item["edited_payload"] = edited_payload
            item["edited_payload_sha256"] = payload_hash(edited_payload)
        resolved = item
        break
    if not resolved:
        raise KeyError(f"Privacy intercept not found: {intercept_id}")
    _write_intercepts(items)
    _update_filter_event_for_intercept(intercept_id, status="resolved", decision=action)
    _audit("intercept_resolved", {"id": intercept_id, "action": action, "tool": resolved.get("tool")})
    clone = dict(resolved)
    clone.pop("payload", None)
    clone.pop("edited_payload", None)
    return clone


def payload_for_decision(item: dict[str, Any]) -> Any:
    decision = item.get("decision")
    if decision == "send_masked":
        return item.get("masked_payload")
    if decision == "send_edited":
        return item.get("edited_payload")
    if decision == "send_raw":
        return item.get("payload")
    return {"privacy_intercept": {"status": "blocked", "intercept_id": item.get("id")}}


def replay_intercept(intercept_id: str) -> dict[str, Any]:
    """Return the analyst-approved payload for a resolved intercept.

    This is the MCP/API equivalent of forwarding an edited request in an
    intercepting proxy. It returns a clearly marked projection, not original
    evidence.
    """
    item = get_intercept(intercept_id)
    if not item:
        raise KeyError(f"Privacy intercept not found: {intercept_id}")

    status = item.get("status", "")
    if status != "resolved":
        return {
            "privacy_replay": {
                "status": status or "unknown",
                "intercept_id": intercept_id,
                "tool": item.get("tool", ""),
                "channel": item.get("channel", ""),
                "decision": item.get("decision", ""),
                "message": "Intercept has not been resolved by the analyst yet.",
            }
        }

    decision = item.get("decision", "")
    payload = payload_for_decision(item)
    meta = {
        "policy": POLICY_VERSION,
        "status": "replayed" if decision != "block" else "blocked",
        "intercept_id": intercept_id,
        "tool": item.get("tool", ""),
        "channel": item.get("channel", ""),
        "decision": decision,
        "original_payload_sha256": item.get("payload_sha256", ""),
        "edited_payload_sha256": item.get("edited_payload_sha256", ""),
        "replayed_payload_sha256": payload_hash(payload),
        "analyst_projection": decision in {"send_masked", "send_edited"},
        "replayed_at": datetime.now(timezone.utc).isoformat(),
    }
    limitations = [
        "This payload is an analyst-approved privacy projection, not original evidence.",
        "Use the original_payload_sha256 and intercept audit log when evidence provenance matters.",
    ]
    if decision == "send_edited":
        limitations.append("The analyst edited the payload; deleted or rewritten fields can bias downstream LLM analysis.")
    elif decision == "send_masked":
        limitations.append("Sensitive identifiers are tokenized; entity-level correlation is preserved only through stable tokens.")
    elif decision == "send_raw":
        limitations.append("The analyst approved raw sensitive payload replay for this intercept.")
    elif decision == "block":
        limitations.append("The analyst blocked this payload; downstream analysis lacks this evidence.")

    if isinstance(payload, dict):
        out = dict(payload)
        out["_privacy_replay"] = meta
        existing = list(out.get("analysis_limitations", []))
        for note in limitations:
            if note not in existing:
                existing.append(note)
        out["analysis_limitations"] = existing
        return out

    return {
        "payload": payload,
        "_privacy_replay": meta,
        "analysis_limitations": limitations,
    }


def payload_hash(payload: Any) -> str:
    try:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        raw = str(payload)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _attach_privacy_meta(
    result: Any,
    *,
    mode: str,
    channel: str,
    tool: str,
    scan: dict[str, Any],
    filter_event_id: str = "",
) -> Any:
    meta = {
        "policy": POLICY_VERSION,
        "mode": mode,
        "channel": channel,
        "tool": tool,
        "sensitive_summary": scan["summary"],
        "match_count": len(scan["matches"]),
        "highlighted": scan["has_sensitive"],
    }
    if filter_event_id:
        meta["filter_event_id"] = filter_event_id
    if isinstance(result, dict):
        out = dict(result)
        out["_privacy"] = meta
        if mode == "exclude" and scan["has_sensitive"]:
            limits = list(out.get("analysis_limitations", []))
            note = "Sensitive identifiers were tokenized before this payload crossed the LLM/MCP boundary."
            if note not in limits:
                limits.append(note)
            out["analysis_limitations"] = limits
        return out
    return {"payload": result, "_privacy": meta}


def _walk_strings(value: Any, path: str = "$"):
    if isinstance(value, str):
        yield path, value[:MAX_PREVIEW_CHARS]
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{idx}]")


def _identity_key_path(path: str) -> bool:
    parts = re.split(r"[\.\[\]]+", path.lower())
    keys = {p for p in parts if p}
    return bool(keys & {
        "user",
        "username",
        "user_name",
        "account",
        "account_name",
        "targetusername",
        "subjectusername",
        "host",
        "hostname",
        "computer",
        "computername",
    })


def _add_match(
    matches: list[dict[str, Any]],
    summary: dict[str, int],
    *,
    path: str,
    rule_id: str,
    label: str,
    severity: str,
    excerpt: str,
    span: list[int],
) -> None:
    matches.append({
        "path": path,
        "rule_id": rule_id,
        "label": label,
        "severity": severity,
        "excerpt": excerpt,
        "span": span,
    })
    summary[label] = summary.get(label, 0) + 1


def _excerpt(value: str, max_len: int = 160) -> str:
    compact = " ".join(str(value).split())
    return compact[:max_len] + ("..." if len(compact) > max_len else "")


def _preview(payload: Any) -> str:
    try:
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    except Exception:
        text = str(payload)
    return text[:MAX_PREVIEW_CHARS] + ("...[truncated]" if len(text) > MAX_PREVIEW_CHARS else "")


def _write_intercepts(items: list[dict[str, Any]]) -> None:
    pending_path = _pending_file()
    os.makedirs(os.path.dirname(pending_path), exist_ok=True)
    with open(pending_path, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2, default=str)


def _audit(event: str, data: dict[str, Any]) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "data": data,
    }
    try:
        entry["scope"] = current_privacy_scope()
        audit_path = _audit_file()
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass
