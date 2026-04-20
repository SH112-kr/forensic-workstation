"""Deterministic artifact normalization — two-tier split.

Codex Round-5 review pinned down that the biggest risk is silent identity
collapse: two distinct artifacts (different realms, different sub-domains,
different paths) normalizing to the same string and getting merged without
the analyst knowing.

The module solves that with an explicit two-tier split:

**Tier 1 — ``safe_*`` (always safe, identity-preserving)**
    Pure cosmetic normalization — whitespace, quotes, case where the
    underlying identifier is already case-insensitive (hashes, domains,
    Windows paths). NEVER drops DOMAIN\\, @realm, FQDN labels, or shortens
    paths. Safe to apply automatically.

**Tier 2 — ``match_key_*`` (opt-in only)**
    Aggressive canonicalization that CAN collapse distinct identities
    (DOMAIN stripping, FQDN first-label, path basename). Each returns a
    dict with an explicit ``warning`` string so the analyst sees what was
    lost. Never applied automatically — caller passes an explicit flag.

Command-line normalization is deliberately out of scope (shell parsing
varies, arguments can look like paths, removing quotes corrupts meaning).

NFKC / Unicode compatibility folding is deliberately NOT in Tier 1 —
compatibility forms can merge distinct strings (e.g. full-width digits and
ASCII digits). If NFKC is ever needed it must go in Tier 2 behind an
explicit opt-in.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any


# ── Tier 1 : safe_* ──────────────────────────────────────────────────────────

def safe_trim(s: Any) -> str:
    """Whitespace-only trim. No Unicode folding — compatibility equivalence is
    NOT identity preservation and can silently merge visibly-distinct strings."""
    if s is None:
        return ""
    return str(s).strip()


_QUOTE_CHARS = ("'", '"', "\u2018\u2019", "\u201c\u201d")


def safe_unquote(s: Any) -> str:
    out = safe_trim(s)
    if len(out) >= 2 and out[0] == out[-1] and out[0] in {'"', "'"}:
        return out[1:-1]
    return out


def safe_hash(s: Any) -> dict[str, Any]:
    """Validate + lowercase a hash. Returns ``{value, valid, kind}``.

    A caller that reads ``value`` without checking ``valid`` is a bug —
    invalid input keeps its raw value visible so the analyst can see why
    it was rejected, but ``valid=False`` prevents matching.
    """
    raw = safe_trim(s).lower()
    if not raw:
        return {"value": "", "valid": False, "kind": None}
    if re.fullmatch(r"[0-9a-f]{32}", raw):
        return {"value": raw, "valid": True, "kind": "md5"}
    if re.fullmatch(r"[0-9a-f]{40}", raw):
        return {"value": raw, "valid": True, "kind": "sha1"}
    if re.fullmatch(r"[0-9a-f]{64}", raw):
        return {"value": raw, "valid": True, "kind": "sha256"}
    return {"value": raw, "valid": False, "kind": None}


def safe_ipv4(s: Any) -> dict[str, Any]:
    raw = safe_trim(s)
    if not raw:
        return {"value": "", "valid": False}
    try:
        ip = ipaddress.IPv4Address(raw)
    except Exception:
        return {"value": raw, "valid": False}
    return {"value": str(ip), "valid": True}


def safe_domain(s: Any) -> str:
    """Lowercased, trailing dot stripped. FQDN labels preserved — we do NOT
    drop sub-domains because that collapses distinct zones."""
    out = safe_trim(s).lower()
    if out.endswith("."):
        out = out[:-1]
    return out


_WIN_PATH_RX = re.compile(r"^[a-zA-Z]:[\\/]|^\\\\|^//")


def safe_path_case(s: Any) -> str:
    """Normalize slashes and case ONLY when the input looks Windows-native.

    Windows paths are case-insensitive so lowering is safe. POSIX paths are
    case-sensitive so we leave them untouched. No shortname expansion —
    expansions are environment-dependent and routinely wrong.
    """
    raw = safe_unquote(s)
    if not raw:
        return ""
    if _WIN_PATH_RX.match(raw):
        unified = raw.replace("\\", "/")
        return unified.lower()
    return raw


def safe_user_case(s: Any) -> str:
    """Lowercase a user string while preserving DOMAIN\\ and @realm.

    'CONTOSO\\Alice' -> 'contoso\\alice' (both parts preserved).
    'alice@CORP.local' -> 'alice@corp.local'.
    Bare 'Alice' -> 'alice'.
    """
    return safe_trim(s).lower()


def safe_service_name(s: Any) -> str:
    return safe_trim(s).lower()


# ── Tier 2 : match_key_* (opt-in) ────────────────────────────────────────────

def match_key_user_bare(s: Any) -> dict[str, Any]:
    """Drop DOMAIN\\ and @realm. DANGEROUS: svc@a.local and svc@b.local
    collapse. Only use when cross-tenant collision is acceptable and the
    analyst knows it."""
    raw = safe_user_case(s)
    bare = raw
    if "\\" in bare:
        bare = bare.split("\\", 1)[1]
    if "@" in bare:
        bare = bare.split("@", 1)[0]
    collapsed = bare != raw
    return {
        "value": bare,
        "rule": "match_key_user_bare",
        "collapsed": collapsed,
        "warning": (
            "Distinct principals from different domains / realms collapse here. "
            "Do not use for attribution."
        ) if collapsed else "",
    }


def match_key_host_first_label(s: Any) -> dict[str, Any]:
    """First DNS label only. DANGEROUS: host1.prod and host1.dev collapse."""
    raw = safe_domain(s)
    label = raw.split(".", 1)[0] if raw else ""
    collapsed = bool(raw) and "." in raw
    return {
        "value": label,
        "rule": "match_key_host_first_label",
        "collapsed": collapsed,
        "warning": (
            "Distinct hosts in different DNS zones collapse here "
            "(e.g. db1.prod and db1.dev become db1)."
        ) if collapsed else "",
    }


def match_key_path_basename(s: Any) -> dict[str, Any]:
    """Basename only. DANGEROUS: distinct paths with same filename collapse."""
    raw = safe_path_case(s)
    base = os.path.basename(raw.replace("/", os.sep)) if raw else ""
    collapsed = bool(raw) and base != raw
    return {
        "value": base,
        "rule": "match_key_path_basename",
        "collapsed": collapsed,
        "warning": (
            "Distinct absolute paths collapse to the same basename here."
        ) if collapsed else "",
    }


# Registry of known Tier-2 keys — used to surface warnings on both the
# envelope AND each affected result (Codex Round-5b feedback).
MATCH_KEY_FUNCTIONS: dict[str, Any] = {
    "user_bare": match_key_user_bare,
    "host_first_label": match_key_host_first_label,
    "path_basename": match_key_path_basename,
}


def apply_match_key(kind: str, value: Any) -> dict[str, Any]:
    """Dispatch helper. Returns the Tier-2 dict with value + warning."""
    fn = MATCH_KEY_FUNCTIONS.get(kind)
    if fn is None:
        return {"value": safe_trim(value), "rule": "unknown", "collapsed": False, "warning": ""}
    return fn(value)
