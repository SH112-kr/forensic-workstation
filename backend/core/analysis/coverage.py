"""Coverage explainer — report which artifact families are searchable vs structurally unavailable.

Purely offline, transparent, no network calls. Every classification decision is
accompanied by an explicit reason string so the analyst can audit why a family
is flagged as unavailable.

Status vocabulary:
- ``searched``                 : loaded in at least one case and has records.
- ``available_not_loaded``     : supported by the current case format but no
                                 records were parsed (possibly data genuinely
                                 absent, possibly parser miss).
- ``structurally_unavailable`` : the loaded case format cannot expose this
                                 family at all (e.g. MFDB-only carving artifact
                                 on a KAPE-only case).

This matrix is intentionally small and hand-curated. If you add new KAPE tools
or AXIOM-only families, update ``AXIOM_ONLY_FAMILIES`` or
``KAPE_SUPPORTED_SAMPLE`` below; the contents are exposed verbatim in the tool
output so stale data never passes silently.
"""

from __future__ import annotations

from typing import Any


# Artifact families that only MFDB (AXIOM) exposes because they rely on deep
# semantic/carving analysis EZ tools do not reproduce. Keep this list short and
# cite the reason — never claim "no activity" when a family lives here and the
# case is KAPE-only.
AXIOM_ONLY_FAMILIES: list[dict[str, str]] = [
    {
        "family": "Webmail & Web History (carved)",
        "reason": "AXIOM carves from browser cache/DB and WebKit; KAPE only captures live browser files.",
    },
    {
        "family": "Chat Applications",
        "reason": "AXIOM parses KakaoTalk / Telegram / Signal / WeChat DBs; KAPE does not include chat parsers.",
    },
    {
        "family": "Mobile Backups",
        "reason": "iOS / Android backups require AXIOM Mobile; KAPE is disk-triage only.",
    },
    {
        "family": "Document Content",
        "reason": "Content and metadata extraction of HWP / PDF / Office files is AXIOM-specific.",
    },
    {
        "family": "Carved Pictures / Video / Audio",
        "reason": "AXIOM does file-signature carving from unallocated space; KAPE does not.",
    },
    {
        "family": "Identifiers (people / devices)",
        "reason": "AXIOM extracts identifiers across artifacts; KAPE does not aggregate this way.",
    },
    {
        "family": "Passwords and Tokens (carved)",
        "reason": "AXIOM carves credentials from memory / pagefile / browser stores.",
    },
    {
        "family": "AXIOM Tags / Bookmarks",
        "reason": "Analyst tagging lives inside the AXIOM case DB.",
    },
    {
        "family": "SSH known_hosts / keys",
        "reason": "AXIOM parses .ssh artifacts directly; not produced by standard KAPE modules.",
    },
]


def _iter_case_connectors(connectors: dict[str, Any]):
    for name, c in connectors.items():
        if name.startswith("axiom:"):
            case_id = name.replace("axiom:", "", 1)
        elif name == "raw_index":
            case_id = "raw_index"
        else:
            continue
        if not getattr(c, "is_connected", lambda: False)():
            continue
        yield name, case_id, c


def _infer_source_mix(connectors: dict[str, Any]) -> dict[str, Any]:
    """Classify the currently-loaded case set by connector source type."""
    kinds: list[str] = []
    case_names: list[str] = []
    for name, case_id, c in _iter_case_connectors(connectors):
        try:
            meta = c.get_metadata()
        except Exception:
            continue
        src = str(meta.get("source_type") or "").lower()
        if not src and name == "raw_index":
            src = "raw_image_sidecar"
        elif not src:
            # Fallback: AxiomMfdbConnector stores .mfdb, KapeCsvConnector uses a dir
            src = "mfdb" if str(meta.get("source_path", "")).lower().endswith(".mfdb") else "kape"
        kinds.append(src)
        case_names.append(case_id)

    if not kinds:
        return {
            "case_format": "none",
            "kinds": [],
            "cases": [],
            "has_mfdb": False,
            "has_kape": False,
            "has_raw_index": False,
        }

    has_mfdb = any(k.startswith("mfdb") or k.startswith("axiom") for k in kinds)
    has_kape = any(k.startswith("kape") for k in kinds)
    has_raw = any(k == "raw_image_sidecar" for k in kinds)

    if sum(1 for flag in (has_mfdb, has_kape, has_raw) if flag) > 1:
        fmt = "mixed"
    elif has_mfdb:
        fmt = "mfdb"
    elif has_kape:
        fmt = "kape"
    elif has_raw:
        fmt = "raw_image_sidecar"
    else:
        fmt = "unknown"

    return {
        "case_format": fmt,
        "kinds": sorted(set(kinds)),
        "cases": case_names,
        "has_mfdb": has_mfdb,
        "has_kape": has_kape,
        "has_raw_index": has_raw,
    }


def _collect_loaded_types(connectors: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Aggregate artifact-type counts across every connected case.

    Returns a mapping artifact_name -> { record_count, cases: [case_id] }. If a
    connector exposes ``get_artifact_type_counts`` that returns a list of dicts,
    the counts are summed per name; empty or unreadable connectors are skipped.
    """
    aggregated: dict[str, dict[str, Any]] = {}
    for _name, case_id, c in _iter_case_connectors(connectors):
        try:
            rows = c.get_artifact_type_counts()
        except Exception:
            continue
        for row in rows or []:
            art = row.get("artifact_name") or row.get("artifact_type") or row.get("name")
            cnt = row.get("hit_count") or row.get("count") or 0
            if not art:
                continue
            entry = aggregated.setdefault(art, {"record_count": 0, "cases": []})
            entry["record_count"] += int(cnt or 0)
            if case_id not in entry["cases"]:
                entry["cases"].append(case_id)
    return aggregated


def build_coverage_report(
    connectors: dict[str, Any],
    artifact_types: list[str] | None = None,
) -> dict[str, Any]:
    """Build a coverage report over the connectors currently held in app_state.

    Args:
        connectors: The ``axiom:*`` entries from ``AppState._connectors`` (a
            plain dict is fine; we never mutate it).
        artifact_types: Optional narrowing — only report on these families. When
            omitted, every loaded family plus every AXIOM-only family is listed.

    The report contains (a) a ``case_context`` block identifying the case mix,
    (b) a ``coverage`` array with one entry per artifact family, (c) a summary,
    and (d) ``notes`` warning about non-diagnostic zero-hit reads.
    """
    case_ctx = _infer_source_mix(connectors)
    loaded = _collect_loaded_types(connectors)

    families_to_report: list[str]
    if artifact_types:
        families_to_report = list(dict.fromkeys([a for a in artifact_types if a]))
    elif case_ctx["case_format"] == "none":
        families_to_report = []
    else:
        families_to_report = sorted(loaded.keys())
        # Only append AXIOM-only families when they'd be non-trivially classified
        # (i.e. KAPE-only case sees them as structurally unavailable; mixed/mfdb
        # cases would show them as searched or available_not_loaded depending on
        # records). A raw-only sidecar should not inherit AXIOM-only phantom
        # families unless an analyst explicitly asks for one.
        if case_ctx["has_mfdb"] or case_ctx["has_kape"]:
            for fam in AXIOM_ONLY_FAMILIES:
                families_to_report.append(fam["family"])
        families_to_report = list(dict.fromkeys(families_to_report))

    axiom_only_names = {f["family"] for f in AXIOM_ONLY_FAMILIES}
    axiom_only_reason = {f["family"]: f["reason"] for f in AXIOM_ONLY_FAMILIES}

    coverage: list[dict[str, Any]] = []
    count_searched = 0
    count_unloaded = 0
    count_structural = 0
    count_not_evaluable = 0

    for fam in families_to_report:
        info = loaded.get(fam)
        if info and info["record_count"] > 0:
            coverage.append({
                "artifact_type": fam,
                "status": "searched",
                "record_count": info["record_count"],
                "cases": info["cases"],
                "reason": None,
            })
            count_searched += 1
            continue

        if (
            case_ctx["has_raw_index"]
            and not case_ctx["has_mfdb"]
            and not case_ctx["has_kape"]
        ):
            coverage.append({
                "artifact_type": fam,
                "status": "not_evaluable",
                "record_count": 0,
                "cases": [],
                "reason": "raw_artifact_family_not_indexed",
                "detail": (
                    "The active raw sidecar has not indexed this artifact family. "
                    "Do not treat this as zero activity."
                ),
            })
            count_not_evaluable += 1
            continue

        if fam in axiom_only_names and case_ctx["has_kape"] and not case_ctx["has_mfdb"]:
            # Only flag structural unavailability when we actually have a
            # KAPE-only case loaded. Without any case we cannot judge the
            # structure.
            coverage.append({
                "artifact_type": fam,
                "status": "structurally_unavailable",
                "record_count": 0,
                "cases": [],
                "reason": axiom_only_reason[fam],
            })
            count_structural += 1
            continue

        # Supported by format but no records — could be genuinely absent or a
        # parser gap. Do not claim "no activity" here.
        coverage.append({
            "artifact_type": fam,
            "status": "available_not_loaded",
            "record_count": 0,
            "cases": [],
            "reason": (
                "No records in the loaded case(s). This could mean the activity "
                "did not occur, or the relevant source was not parsed. Verify the "
                "raw evidence before concluding 'no activity'."
            ),
        })
        count_unloaded += 1

    notes: list[str] = []
    if case_ctx["case_format"] == "kape":
        notes.append(
            "Case is KAPE-only. Zero-hit searches against AXIOM-only families are "
            "non-diagnostic — load the MFDB if one is available for this incident."
        )
    if case_ctx["case_format"] == "none":
        notes.append("No cases are currently loaded; nothing to search.")
    if count_structural:
        notes.append(
            f"{count_structural} family/families are structurally unavailable under "
            f"the current case format; do not treat their absence as evidence."
        )
    if count_not_evaluable:
        notes.append(
            "The active raw sidecar has not indexed at least one requested "
            "artifact family; do not treat that as zero activity."
        )

    result_status = "not_evaluable" if count_not_evaluable else ""

    return {
        "ok": result_status != "not_evaluable",
        **({"status": result_status} if result_status else {}),
        "tool": "coverage_explainer",
        "case_context": case_ctx,
        "coverage": coverage,
        "summary": {
            "total_reported": len(coverage),
            "searched": count_searched,
            "available_not_loaded": count_unloaded,
            "structurally_unavailable": count_structural,
            "not_evaluable": count_not_evaluable,
            "axiom_only_family_count": len(AXIOM_ONLY_FAMILIES),
        },
        "notes": notes,
    }
