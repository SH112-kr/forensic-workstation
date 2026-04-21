"""Observe behavioural change for a single entity between two periods.

Composition tool (T1 in the Codex roadmap) — orchestrates the shared
``correlate_keywords`` helper twice (baseline + incident) and reports
structural differences: dormant gaps, volume shifts, newly-seen
co-occurrences, net-new or went-silent entities. Every reported claim
carries ``derived_from`` pointers so the analyst can jump to the raw
evidence behind each statement.

Scope (deliberately narrow):
  - NO new detection primitives — no malice attribution, no threshold-
    based anomaly flags. The framing is "observed change" so a caller
    that confuses change with anomaly reads the output and catches
    itself.
  - Pure composition over ``correlate_keywords``. If that helper's
    shape changes, this module breaks at import time, not silently.
  - Deterministic — identical input always produces identical output
    order (claims sorted by (kind, keyword); top_windows by
    (-event_count, start)).

Output contract (stable for callers):
  {
    "ok": bool,
    "entity": {"value": str, "seed_keywords": [str, ...]},
    "periods": {"baseline": {...}, "incident": {...}},
    "baseline": {"total_events": N, "co_occurrence_windows": N,
                 "last_event_ts": str|None, "per_keyword_totals": {kw: N}},
    "incident": {"total_events": N, "co_occurrence_windows": N,
                 "first_event_ts": str|None, "per_keyword_totals": {kw: N},
                 "top_windows": [{start, keywords_present, event_count}, ...]},
    "delta": {
      "dormant_gap_seconds": float|None,
      "dormant_gap_reason": "computed|baseline_empty|incident_empty|both_empty",
      "new_cooccurring_keywords": [str, ...],
      "volume_ratio_per_keyword": {kw: {"baseline": N, "incident": N,
                                        "ratio": float|None,
                                        "ratio_note": str}},
      "co_occurrence_growth": {"baseline": N, "incident": N,
                               "ratio": float|None},
    },
    "claims": [{"kind": str, "claim": str,
                "derived_from": [{"period": str, "hit_id": int|None,
                                  "keyword": str, "timestamp": str}]}],
    "truncation_warnings": [str, ...],
    "notes": [str, ...],
  }
"""

from __future__ import annotations

from typing import Any


# Output caps so huge cases can't blow past the MCP response ceiling.
# Codex pre-review #4: behavioural delta on a long-running attack could
# emit hundreds of "observed change" claims of the same kind — unhelpful
# for a human reader.
_TOP_WINDOWS_CAP = 20
_CLAIMS_PER_KIND_CAP = 50

# Claim taxonomy — framed as "observed change" (Codex pre-review #1):
# these are structural differences, not anomaly verdicts. The analyst
# interprets.
_KIND_NO_ACTIVITY = "no_activity_in_either_period"
_KIND_NET_NEW = "entity_net_new_in_incident"
_KIND_WENT_SILENT = "entity_went_silent_in_incident"
_KIND_DORMANT_THEN_ACTIVE = "entity_dormant_then_active"
_KIND_VOLUME_CHANGE = "observed_volume_change"
_KIND_COOCCURRENCE_CHANGE = "observed_cooccurrence_change"


def _normalize_seed_keywords(
    entity_value: str,
    seed_keywords: list[str] | str | None,
) -> list[str]:
    """Return a deduplicated, order-preserving keyword list.

    Always includes ``entity_value`` as the first keyword. Additional seeds
    are appended in input order, skipping duplicates (case-sensitive on the
    keyword itself since the underlying search is case-insensitive — duping
    "Bomgar" + "bomgar" is pointless work).
    """
    seeds: list[str] = []
    seen: set[str] = set()
    for raw in [entity_value] + _as_list(seed_keywords):
        if not raw:
            continue
        s = str(raw).strip()
        if not s or s in seen:
            continue
        seeds.append(s)
        seen.add(s)
    return seeds


def _as_list(value: list[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    # Comma-separated string fallback — MCP tools pass strings.
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _period_totals(per_keyword: dict[str, Any]) -> dict[str, int]:
    """Pull the ``total_hits`` number out of every per-keyword entry.

    Pinned to ``total_hits`` (true count from axiom.search.total) rather
    than ``returned_hits`` (what the limit let through) so the ratio math
    does not quietly drift when a keyword truncates — Codex pre-review #4.
    """
    return {kw: int(v.get("total_hits", 0)) for kw, v in per_keyword.items()}


def _extreme_event(events: list[dict[str, Any]], newest: bool) -> dict[str, Any] | None:
    """Return the newest-or-oldest event or ``None`` when the list is empty."""
    if not events:
        return None
    return max(events, key=lambda e: e.get("timestamp_ms", 0)) if newest \
        else min(events, key=lambda e: e.get("timestamp_ms", 0))


def _truncation_warnings(
    period: str,
    per_keyword: dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    for kw, v in per_keyword.items():
        if v.get("truncated"):
            warnings.append(
                f"{period}: keyword '{kw}' returned {v.get('returned_hits')} of "
                f"{v.get('total_hits')} hits — delta counts use the true total "
                f"but top_windows / first/last events only reflect the returned sample."
            )
    return warnings


def _volume_ratios(
    baseline_totals: dict[str, int],
    incident_totals: dict[str, int],
) -> dict[str, dict[str, Any]]:
    """Per-keyword baseline-vs-incident ratio with truncation-safe semantics.

    ``ratio`` is computed on ``total_hits``. Division-by-zero and
    zero-over-zero get explicit sentinels in ``ratio_note`` so the caller
    can render "∞" vs "same as baseline" without inspecting the numbers.
    """
    result: dict[str, dict[str, Any]] = {}
    all_kws = sorted(set(baseline_totals) | set(incident_totals))
    for kw in all_kws:
        b = baseline_totals.get(kw, 0)
        i = incident_totals.get(kw, 0)
        if b == 0 and i == 0:
            ratio: float | None = None
            note = "no_activity_in_either_period"
        elif b == 0:
            ratio = None
            note = "baseline_zero_entity_net_new"
        elif i == 0:
            ratio = 0.0
            note = "incident_zero_entity_went_silent"
        else:
            ratio = i / b
            note = "computed"
        result[kw] = {"baseline": b, "incident": i, "ratio": ratio, "ratio_note": note}
    return result


def _dormant_gap(
    last_baseline_event: dict[str, Any] | None,
    first_incident_event: dict[str, Any] | None,
) -> tuple[float | None, str]:
    """``(gap_seconds, reason)`` — Codex pre-review #2.

    ``None`` is ambiguous, so always return a reason string even when the
    gap is a real number. Consumers that only read ``gap_seconds`` and
    ignore ``reason`` cannot mistake "not computable" for "no gap".
    """
    if not last_baseline_event and not first_incident_event:
        return None, "both_empty"
    if not last_baseline_event:
        return None, "baseline_empty"
    if not first_incident_event:
        return None, "incident_empty"
    delta_ms = first_incident_event["timestamp_ms"] - last_baseline_event["timestamp_ms"]
    return delta_ms / 1000.0, "computed"


def _claim(kind: str, claim: str, derived_from: list[dict[str, Any]]) -> dict[str, Any]:
    return {"kind": kind, "claim": claim, "derived_from": derived_from}


def _cap_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cap claims to ``_CLAIMS_PER_KIND_CAP`` per ``kind`` and stable-sort.

    Sort key is (keyword, timestamp, claim text) so ties on pointer content
    resolve deterministically on the human-readable claim string — the only
    remaining source of run-to-run ordering drift.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for c in claims:
        grouped.setdefault(c["kind"], []).append(c)
    trimmed: list[dict[str, Any]] = []
    for kind in sorted(grouped):
        group = grouped[kind]
        group.sort(key=lambda c: (
            c["derived_from"][0].get("keyword", "") if c["derived_from"] else "",
            c["derived_from"][0].get("timestamp", "") if c["derived_from"] else "",
            c.get("claim", ""),
        ))
        trimmed.extend(group[:_CLAIMS_PER_KIND_CAP])
    return trimmed


def _top_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the top ``_TOP_WINDOWS_CAP`` windows by event_count.

    Secondary key is ``start`` so ties are stable across runs.
    """
    ranked = sorted(
        windows,
        key=lambda w: (-int(w.get("event_count", 0)), w.get("start", "")),
    )
    return ranked[:_TOP_WINDOWS_CAP]


def _pointer(period: str, ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "period": period,
        "hit_id": ev.get("hit_id"),
        "keyword": ev.get("keyword", ""),
        "timestamp": ev.get("timestamp", ""),
    }


def _cooccurrence_keysets(windows: list[dict[str, Any]]) -> set[tuple[str, ...]]:
    """Collapse every window's ``keywords_present`` list into a tuple set."""
    out: set[tuple[str, ...]] = set()
    for w in windows:
        kws = tuple(sorted(w.get("keywords_present", [])))
        if kws:
            out.add(kws)
    return out


def behavioral_delta(
    axiom: Any,
    entity_value: str,
    baseline_start: str,
    baseline_end: str,
    incident_start: str,
    incident_end: str,
    seed_keywords: list[str] | str | None = None,
    window_minutes: int = 60,
    limit_per_keyword: int = 500,
) -> dict[str, Any]:
    """Run baseline-vs-incident behavioural delta for one entity.

    Args:
        axiom: Active ``AxiomMfdbConnector`` (or any object with the same
            ``search`` / ``_iso_to_ms`` interface). The shared
            ``correlate_keywords`` helper drives the actual querying.
        entity_value: Primary keyword — the entity under investigation
            (e.g. "bomgar-pec").
        baseline_start / baseline_end: ISO date range for the baseline
            period (what the entity "normally" looks like).
        incident_start / incident_end: ISO date range for the incident
            period (the window being scrutinised).
        seed_keywords: Extra keywords to correlate against the entity —
            e.g. ``["4648", "7045"]`` to see whether PRA presence
            coincides with explicit-credential-use or new-service
            activity. Accepted as list or comma-separated string.
        window_minutes: Co-occurrence window size — same semantics as
            ``correlate_keywords``.
        limit_per_keyword: Per-keyword search cap inside each period.
            Counts in ``per_keyword_totals`` use the true total (from
            ``axiom.search``) so truncation never distorts the ratio;
            the sampled events used for first/last timestamps only
            reflect the returned sample (flagged in
            ``truncation_warnings``).

    Returns the structured envelope documented at module scope. Never
    raises on "no data" — an absent entity in both periods produces a
    single ``no_activity_in_either_period`` claim rather than an error.

    Matching semantics (important — Codex post-review #2):
        ``entity_value`` and every seed keyword are forwarded to
        ``axiom.search``, which performs a substring LIKE match against
        string fragments. ``"bomgar-pec"`` therefore matches both the
        executable and every related artefact such as
        ``"bomgar-pec-hook-x64.dll"``. This is "keyword-presence delta",
        not "exact-entity delta". If you need exact-entity semantics,
        add a ``match_mode`` parameter to ``correlate_keywords`` /
        ``axiom.search`` first — do not filter here, because that would
        hide the behaviour from other callers.
    """
    from core.analysis.correlator import correlate_keywords

    seeds = _normalize_seed_keywords(entity_value, seed_keywords)
    if not seeds:
        return {
            "ok": False,
            "error": "entity_value is empty after normalization",
            "entity": {"value": entity_value, "seed_keywords": []},
        }

    baseline_corr = correlate_keywords(
        axiom, seeds,
        start_date=baseline_start, end_date=baseline_end,
        window_minutes=window_minutes, limit=limit_per_keyword,
    )
    incident_corr = correlate_keywords(
        axiom, seeds,
        start_date=incident_start, end_date=incident_end,
        window_minutes=window_minutes, limit=limit_per_keyword,
    )

    b_per_kw = baseline_corr.get("per_keyword", {})
    i_per_kw = incident_corr.get("per_keyword", {})
    b_totals = _period_totals(b_per_kw)
    i_totals = _period_totals(i_per_kw)
    b_events = baseline_corr.get("chronological_events", []) or []
    i_events = incident_corr.get("chronological_events", []) or []
    b_windows = baseline_corr.get("co_occurrence_windows", []) or []
    i_windows = incident_corr.get("co_occurrence_windows", []) or []
    # Dormant gap is measured against the PRIMARY entity keyword only —
    # "how long was bomgar-pec silent" is a different question from "how
    # long was any seed keyword silent". The seed-keyword events are
    # still reported in top_windows / co_occurrence_growth; they just
    # don't distort the dormant-gap semantics.
    b_entity_events = [e for e in b_events if e.get("keyword") == entity_value]
    i_entity_events = [e for e in i_events if e.get("keyword") == entity_value]
    b_last = _extreme_event(b_entity_events, newest=True)
    i_first = _extreme_event(i_entity_events, newest=False)

    gap_seconds, gap_reason = _dormant_gap(b_last, i_first)
    ratios = _volume_ratios(b_totals, i_totals)

    b_keysets = _cooccurrence_keysets(b_windows)
    i_keysets = _cooccurrence_keysets(i_windows)
    new_keysets = sorted(i_keysets - b_keysets)
    new_cooccurring_keywords = sorted({kw for ks in new_keysets for kw in ks})

    b_total_events = baseline_corr.get("total_chronological_events", 0)
    i_total_events = incident_corr.get("total_chronological_events", 0)
    b_win_count = baseline_corr.get("total_co_occurrences", 0)
    i_win_count = incident_corr.get("total_co_occurrences", 0)
    # Symmetrical to dormant_gap_reason so a caller never has to interpret
    # a bare ``null`` ratio.
    if b_win_count == 0 and i_win_count == 0:
        cooc_ratio: float | None = None
        cooc_ratio_reason = "no_windows_in_either_period"
    elif b_win_count == 0:
        cooc_ratio = None  # incident-only — see new_cooccurring_keywords claim
        cooc_ratio_reason = "baseline_zero_windows"
    elif i_win_count == 0:
        cooc_ratio = 0.0
        cooc_ratio_reason = "incident_zero_windows"
    else:
        cooc_ratio = i_win_count / b_win_count
        cooc_ratio_reason = "computed"

    claims: list[dict[str, Any]] = []
    # Use entity-only counts for the primary activity classification so a
    # noisy seed keyword cannot mask an entity that is itself silent.
    b_entity_count = len(b_entity_events)
    i_entity_count = len(i_entity_events)

    if b_entity_count == 0 and i_entity_count == 0:
        claims.append(_claim(
            _KIND_NO_ACTIVITY,
            f"'{entity_value}' produced no timestamped events in either period.",
            [],
        ))
    elif b_entity_count == 0:
        claims.append(_claim(
            _KIND_NET_NEW,
            f"'{entity_value}' first appears in the incident period; no matching "
            f"activity in the baseline period.",
            [_pointer("incident", i_first)] if i_first else [],
        ))
    elif i_entity_count == 0:
        claims.append(_claim(
            _KIND_WENT_SILENT,
            f"'{entity_value}' was active in the baseline period but produced no "
            f"events during the incident window.",
            [_pointer("baseline", b_last)] if b_last else [],
        ))
    else:
        if gap_reason == "computed" and gap_seconds is not None and gap_seconds > 0:
            claims.append(_claim(
                _KIND_DORMANT_THEN_ACTIVE,
                f"'{entity_value}' had its last baseline event at "
                f"{b_last['timestamp']} and its first incident event at "
                f"{i_first['timestamp']} — gap of {gap_seconds:.0f}s "
                f"({gap_seconds / 86400:.1f} days).",
                [_pointer("baseline", b_last), _pointer("incident", i_first)],
            ))

    # Volume change claims — one per keyword with a real ratio.
    for kw in sorted(ratios):
        entry = ratios[kw]
        note = entry["ratio_note"]
        if note == "no_activity_in_either_period":
            continue
        if note in {"baseline_zero_entity_net_new", "incident_zero_entity_went_silent"}:
            # Already captured by net_new / went_silent claims.
            continue
        # Only emit when the change is non-trivial — identical totals are noise.
        if entry["baseline"] == entry["incident"]:
            continue
        # Find a derivation pointer for this keyword from each period, if any.
        b_kw_event = next(
            (e for e in b_events if e.get("keyword") == kw), None,
        )
        i_kw_event = next(
            (e for e in i_events if e.get("keyword") == kw), None,
        )
        pointers = []
        if b_kw_event:
            pointers.append(_pointer("baseline", b_kw_event))
        if i_kw_event:
            pointers.append(_pointer("incident", i_kw_event))
        claims.append(_claim(
            _KIND_VOLUME_CHANGE,
            f"keyword '{kw}': baseline={entry['baseline']} events, "
            f"incident={entry['incident']} events (ratio {entry['ratio']:.2f}).",
            pointers,
        ))

    # Co-occurrence structure change claims.
    for keyset in new_keysets:
        pointer_window = next(
            (w for w in i_windows if tuple(sorted(w.get("keywords_present", []))) == keyset),
            None,
        )
        ptr: list[dict[str, Any]] = []
        if pointer_window:
            # We only have the window start, not a hit_id — pointer still
            # identifies the window deterministically.
            ptr.append({
                "period": "incident",
                "hit_id": None,
                "keyword": ",".join(keyset),
                "timestamp": pointer_window.get("start", ""),
            })
        claims.append(_claim(
            _KIND_COOCCURRENCE_CHANGE,
            f"keyword combination {list(keyset)} co-occurred in the incident "
            f"period but never in the baseline period.",
            ptr,
        ))

    claims = _cap_claims(claims)

    truncation_warnings = (
        _truncation_warnings("baseline", b_per_kw)
        + _truncation_warnings("incident", i_per_kw)
    )

    return {
        "ok": True,
        "entity": {"value": entity_value, "seed_keywords": seeds},
        "periods": {
            "baseline": {"start": baseline_start, "end": baseline_end},
            "incident": {"start": incident_start, "end": incident_end},
        },
        "baseline": {
            "total_events": b_total_events,
            "co_occurrence_windows": b_win_count,
            "last_event_ts": b_last["timestamp"] if b_last else None,
            "per_keyword_totals": b_totals,
        },
        "incident": {
            "total_events": i_total_events,
            "co_occurrence_windows": i_win_count,
            "first_event_ts": i_first["timestamp"] if i_first else None,
            "per_keyword_totals": i_totals,
            "top_windows": _top_windows(i_windows),
        },
        "delta": {
            "dormant_gap_seconds": gap_seconds,
            "dormant_gap_reason": gap_reason,
            "new_cooccurring_keywords": new_cooccurring_keywords,
            "volume_ratio_per_keyword": ratios,
            "co_occurrence_growth": {
                "baseline": b_win_count,
                "incident": i_win_count,
                "ratio": cooc_ratio,
                "ratio_reason": cooc_ratio_reason,
            },
        },
        "claims": claims,
        "truncation_warnings": truncation_warnings,
        "notes": [
            "Composition tool — runs correlate_keywords twice and compares. "
            "No new detection logic; every claim carries derived_from.",
            "Claims describe OBSERVED CHANGE, not anomaly. Baseline-vs-incident "
            "difference is evidence for the analyst to interpret.",
            "Volume ratios use total_hits (true counts), so truncated search "
            "results never distort the ratio. top_windows reflects only the "
            "returned sample — see truncation_warnings if the sample was capped.",
        ],
    }
