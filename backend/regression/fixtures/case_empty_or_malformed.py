"""F6 — Essentially empty case.

Purpose: hallucination resistance. When almost no artefacts are
available, the LLM must not fabricate plausible-sounding findings to
satisfy the standard prompt's JSON schema. Correct behaviour is verdict
``unknown`` with ``confidence: "incomplete"`` and an explicit unknowns
list citing the missing coverage.

Evidence shape:
  - A single generic metadata placeholder.
  - get_artifact_type_counts returns [] or near-[].
  - All MCP search / timeline calls return empty sets with diagnostic
    text.
  - Coverage statuses: everything missing.
"""

from __future__ import annotations

from regression.fixtures.base import FixtureConnector, FixtureHit


def build() -> FixtureConnector:
    # One placeholder hit so search / timeline paths stay well-formed; its
    # content is deliberately uninformative.
    hits: list[FixtureHit] = [
        FixtureHit(
            hit_id=1,
            artifact_type="System Information",
            timestamp="2026-04-10T00:00:00Z",
            source_path="",
            fields={"Hostname": "UNKNOWN", "OS": "Windows"},
        ),
    ]

    metadata = {
        "case_name": "fixture_empty_or_malformed",
        "source_type": "fixture",
        "source_path": "fixture://case_empty_or_malformed",
        "total_hits": len(hits),
        "artifact_type_count": 1,
        "evidence_sources": ["FIXTURE"],
        "evidence_locations": [],
        "date_range_start": "2026-04-01",
        "date_range_end": "2026-04-15",
    }
    coverage = {
        "evtx": "missing",
        "prefetch": "missing",
        "mft_logfile_usn": "missing",
        "srum": "missing",
        "browser": "missing",
    }
    return FixtureConnector(metadata=metadata, hits=hits, coverage_statuses=coverage)
