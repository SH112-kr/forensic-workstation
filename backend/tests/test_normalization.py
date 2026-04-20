"""Unit tests for core.analysis.normalization.

Covers Codex Round-5 and 5b edge cases explicitly:
  - Tier-1 never collapses distinct identities (realm / zone / DOMAIN).
  - Tier-2 collapses are flagged with an explicit warning string.
  - Invalid data returns {valid: False} rather than empty string
    (no "missing" vs "invalid" ambiguity).
  - No NFKC folding in Tier 1 (Codex 5b fix).
"""

from __future__ import annotations

from core.analysis import normalization as n


# ── Tier-1 identity preservation ──────────────────────────────────────────

def test_safe_trim_is_ascii_only_no_nfkc():
    """Full-width digit '1' (U+FF11) must NOT fold to ASCII '1'."""
    full_width_one = "\uff11"
    assert n.safe_trim(full_width_one) == full_width_one
    assert n.safe_trim(full_width_one) != "1"


def test_safe_user_case_preserves_domain_and_upn():
    assert n.safe_user_case("CONTOSO\\Alice") == "contoso\\alice"
    assert n.safe_user_case("alice@CORP.local") == "alice@corp.local"
    # DOMAIN preserved
    assert "\\" in n.safe_user_case("DOM\\user")
    # Realm preserved
    assert "@" in n.safe_user_case("svc@tenant.local")


def test_safe_user_case_does_not_collapse_different_realms():
    """svc@a.local vs svc@b.local must stay distinct."""
    assert n.safe_user_case("svc@a.local") != n.safe_user_case("svc@b.local")


def test_safe_domain_keeps_fqdn_labels():
    """db1.prod vs db1.dev must not collapse."""
    assert n.safe_domain("db1.prod.internal") != n.safe_domain("db1.dev.internal")


def test_safe_path_case_lowercases_windows_only():
    """Windows paths are case-insensitive so lowering is safe; POSIX is not."""
    assert n.safe_path_case("C:\\Windows\\POWERshell.EXE") == "c:/windows/powershell.exe"
    # POSIX path preserved
    assert n.safe_path_case("/etc/PASSWD") == "/etc/PASSWD"


def test_safe_path_case_preserves_args_via_no_shortname_expansion():
    """No 8.3 shortname expansion; no command parsing."""
    cmdline = "C:\\PROGRA~1\\Tool\\run.exe -verbose --target=X"
    out = n.safe_path_case(cmdline)
    # PROGRA~1 preserved (we refuse to guess which of Program Files variants it is)
    assert "progra~1" in out
    # Arguments intact
    assert "-verbose" in out
    assert "--target=x" in out  # lowered


def test_safe_hash_validates_and_distinguishes_invalid():
    md5 = n.safe_hash("D41D8CD98F00B204E9800998ECF8427E")
    assert md5["valid"] is True
    assert md5["kind"] == "md5"
    assert md5["value"] == "d41d8cd98f00b204e9800998ecf8427e"

    # Invalid: value preserved but flagged
    bad = n.safe_hash("notahash")
    assert bad["valid"] is False
    assert bad["value"] == "notahash"  # NOT empty string

    # Empty input
    empty = n.safe_hash("")
    assert empty["valid"] is False
    assert empty["value"] == ""


def test_safe_ipv4_validates():
    ok = n.safe_ipv4("10.0.1.5")
    assert ok["valid"] is True
    bad = n.safe_ipv4("999.0.0.1")
    assert bad["valid"] is False
    assert bad["value"] == "999.0.0.1"  # preserved for analyst review


# ── Tier-2 opt-in with warnings ──────────────────────────────────────────

def test_match_key_user_bare_collapses_with_warning():
    r = n.match_key_user_bare("CONTOSO\\Alice")
    assert r["value"] == "alice"
    assert r["collapsed"] is True
    assert "Distinct principals" in r["warning"]

    # Bare input: no collapse, no warning
    bare = n.match_key_user_bare("alice")
    assert bare["value"] == "alice"
    assert bare["collapsed"] is False
    assert bare["warning"] == ""


def test_match_key_host_first_label_warns_on_fqdn():
    r = n.match_key_host_first_label("db1.prod.internal")
    assert r["value"] == "db1"
    assert r["collapsed"] is True
    assert "different DNS zones" in r["warning"]


def test_match_key_user_bare_collapses_cross_realm_identities():
    """Document the dangerous collapse so a future refactor cannot silently
    revert the safer Tier-1 behaviour."""
    a = n.match_key_user_bare("svc@a.local")
    b = n.match_key_user_bare("svc@b.local")
    assert a["value"] == b["value"]  # collapse is explicit
    assert a["warning"]  # but loudly flagged
    assert b["warning"]


def test_match_key_path_basename_warns_on_full_path():
    r = n.match_key_path_basename("C:\\Windows\\System32\\powershell.exe")
    assert r["value"] == "powershell.exe"
    assert r["collapsed"] is True
    assert "basename" in r["warning"]


def test_apply_match_key_unknown_kind_is_safe():
    r = n.apply_match_key("unknown_kind", "something")
    assert r["rule"] == "unknown"
    assert r["collapsed"] is False


# ── Idempotence ──────────────────────────────────────────────────────────

def test_safe_functions_are_idempotent():
    for fn, sample in [
        (n.safe_trim, "  hello  "),
        (n.safe_unquote, '"quoted"'),
        (n.safe_domain, "Example.Com."),
        (n.safe_path_case, "C:\\Windows"),
        (n.safe_user_case, "DOM\\User"),
        (n.safe_service_name, "  SvcName  "),
    ]:
        once = fn(sample)
        twice = fn(once)
        assert once == twice, f"{fn.__name__} not idempotent"
