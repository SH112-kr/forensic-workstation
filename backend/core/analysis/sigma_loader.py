"""Sigma YAML subset loader (B-1).

Converts a deliberately small subset of Sigma rules into the same dict shape
``evtx_rules.BUILTIN_RULES`` uses, so community/case-derived Windows EVTX
rules can be dropped into ``backend/hunt_packs/sigma/`` without code changes.

Scope is intentionally narrow — CLAUDE.md forbids overfitting and the engine
behind these rules only does EID + keyword-substring matching:

  - logsource.product must be "windows" (others are skipped with a reason).
  - detection.selection: EventID (int or list) plus ``<field>|contains``
    string/list values become OR keyword needles.
  - condition must be a bare "selection" (the single supported map name).

Anything else — ``|re``, ``|base64``, ``1 of``, ``all of``, ``not``,
multiple selection maps, numeric comparisons — is NOT silently approximated.
The rule is dropped and the unsupported feature is recorded so the analyst
sees exactly what coverage was declined rather than assuming it ran.

Every loaded rule carries ``provenance.origin`` so a Sigma hit is never
mistaken for a hand-curated builtin, and so it is treated as an evidence
hint (same per-rule cap, no severity-sort) by the engine.
"""

from __future__ import annotations

import os
from typing import Any


SUPPORTED_CONDITION = "selection"
_SEVERITY_FROM_LEVEL = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# detection field-name modifiers we can faithfully honour. Only plain
# equality and ``|contains`` map onto substring matching.
_SUPPORTED_MODIFIERS = {"", "contains"}


def _yaml_available() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def load_sigma_dir(directory: str) -> dict[str, Any]:
    """Load every ``*.yml`` / ``*.yaml`` Sigma rule under ``directory``.

    Returns ``{rules, skipped, unsupported_feature_counts, stats}``. Never
    raises on a single bad rule — that rule is skipped with a reason so the
    rest of the pack still loads.
    """
    if not _yaml_available():
        return {
            "rules": [],
            "skipped": [],
            "unsupported_feature_counts": {},
            "stats": {
                "ok": False,
                "reason": "pyyaml_not_installed",
                "detail": "PyYAML is required to parse Sigma rules. "
                          "pip install PyYAML>=6.0",
            },
        }
    if not directory or not os.path.isdir(directory):
        return {
            "rules": [],
            "skipped": [],
            "unsupported_feature_counts": {},
            "stats": {"ok": True, "files_seen": 0, "reason": "no_sigma_dir"},
        }

    import yaml

    rules: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    unsupported: dict[str, int] = {}
    files_seen = 0

    for name in sorted(os.listdir(directory)):
        if not name.lower().endswith((".yml", ".yaml")):
            continue
        files_seen += 1
        path = os.path.join(directory, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except Exception as exc:
            skipped.append({"file": name, "reason": "yaml_parse_error",
                            "detail": str(exc)})
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            converted = convert_sigma_rule(doc, source_file=name)
            if converted["ok"]:
                rules.append(converted["rule"])
            else:
                skipped.append({
                    "file": name,
                    "title": doc.get("title", ""),
                    "reason": converted["reason"],
                    "detail": converted.get("detail", ""),
                })
                feature = converted["reason"]
                unsupported[feature] = unsupported.get(feature, 0) + 1

    total = len(rules) + len(skipped)
    return {
        "rules": rules,
        "skipped": skipped,
        "unsupported_feature_counts": unsupported,
        "stats": {
            "ok": True,
            "files_seen": files_seen,
            "rules_loaded": len(rules),
            "rules_skipped": len(skipped),
            "unsupported_ratio": round(len(skipped) / total, 3) if total else 0.0,
        },
    }


def convert_sigma_rule(doc: dict[str, Any], *, source_file: str = "") -> dict[str, Any]:
    """Convert one parsed Sigma document into an evtx_rules-style dict.

    Returns ``{ok: True, rule}`` or ``{ok: False, reason, detail}``.
    """
    logsource = doc.get("logsource") or {}
    product = str(logsource.get("product", "")).lower()
    if product and product != "windows":
        return {"ok": False, "reason": "non_windows_logsource",
                "detail": f"product={product!r}"}

    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if not isinstance(condition, str) or condition.strip() != SUPPORTED_CONDITION:
        return {"ok": False, "reason": "unsupported_condition",
                "detail": f"condition={condition!r}; only "
                          f"'{SUPPORTED_CONDITION}' is supported"}

    selection = detection.get(SUPPORTED_CONDITION)
    if not isinstance(selection, dict):
        return {"ok": False, "reason": "unsupported_selection_shape",
                "detail": f"selection type={type(selection).__name__}"}

    event_ids: list[int] = []
    needles: list[str] = []
    for raw_key, raw_value in selection.items():
        field, _, modifier = str(raw_key).partition("|")
        field = field.strip()
        modifier = modifier.strip().lower()

        # A compound modifier like ``contains|all`` collapses to its first
        # token; anything we do not understand disqualifies the whole rule.
        primary_modifier = modifier.split("|")[0] if modifier else ""
        if primary_modifier not in _SUPPORTED_MODIFIERS:
            return {"ok": False, "reason": "unsupported_modifier",
                    "detail": f"{raw_key!r} uses |{modifier}"}
        if modifier and "|" in modifier:
            # e.g. ``|contains|all`` changes OR semantics — decline rather
            # than approximate.
            return {"ok": False, "reason": "unsupported_modifier",
                    "detail": f"{raw_key!r} uses compound modifier"}

        if field.lower() in ("eventid", "event_id"):
            for v in _as_list(raw_value):
                try:
                    event_ids.append(int(v))
                except (TypeError, ValueError):
                    return {"ok": False, "reason": "non_integer_eventid",
                            "detail": f"{raw_key}={v!r}"}
            continue

        # Non-EID fields become keyword needles (substring OR).
        for v in _as_list(raw_value):
            if isinstance(v, (int, float)):
                # numeric equality on a non-EID field is not substring-able
                return {"ok": False, "reason": "numeric_field_match",
                        "detail": f"{raw_key}={v!r}"}
            text = str(v).strip()
            if text:
                needles.append(text.lower())

    if not event_ids:
        return {"ok": False, "reason": "no_event_id",
                "detail": "selection has no EventID; this engine is EID-anchored"}

    level = str(doc.get("level", "medium")).lower()
    severity = _SEVERITY_FROM_LEVEL.get(level, "medium")
    mitre = _extract_mitre(doc.get("tags") or [])
    rule_id = str(doc.get("id") or doc.get("title") or f"sigma-{source_file}")

    return {
        "ok": True,
        "rule": {
            "id": f"sigma:{rule_id}",
            "title": str(doc.get("title", rule_id)),
            "severity": severity,
            "event_ids": sorted(set(event_ids)),
            "any": needles,
            "mitre": mitre,
            "tags": [str(t) for t in (doc.get("tags") or [])],
            "provenance": {
                "origin": "sigma-community",
                "source_file": source_file,
                "sigma_id": str(doc.get("id", "")),
                "evidence_hint_only": True,
            },
        },
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _extract_mitre(tags: list[Any]) -> list[str]:
    """Map ``attack.t1059.001`` style tags to ``T1059.001``."""
    out: list[str] = []
    for tag in tags:
        text = str(tag).lower()
        if text.startswith("attack.t"):
            technique = text.split(".", 1)[1]  # t1059.001
            out.append(technique.upper())
    return out
