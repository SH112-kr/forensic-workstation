"""Synthetic fixture connectors for the regression harness.

Each fixture is a deterministic stub that satisfies the subset of the
``axiom_mfdb`` / ``kape_csv`` interface actually exercised by MCP tools.
Use :func:`load` to get a connector instance by fixture name.
"""

from __future__ import annotations

from typing import Any

from regression.fixtures.base import FixtureConnector


_REGISTRY: dict[str, Any] = {}


def _register():
    """Lazy-register fixtures so ``load`` can find them by name."""
    global _REGISTRY
    if _REGISTRY:
        return
    from regression.fixtures import (
        case_ransomware_inc_like,
        case_benign_remote_work,
        case_partial_evidence,
        case_insider_data_exfil,
        case_anti_forensics_heavy,
        case_empty_or_malformed,
    )
    _REGISTRY = {
        "case_ransomware_inc_like": case_ransomware_inc_like.build,
        "case_benign_remote_work": case_benign_remote_work.build,
        "case_partial_evidence": case_partial_evidence.build,
        "case_insider_data_exfil": case_insider_data_exfil.build,
        "case_anti_forensics_heavy": case_anti_forensics_heavy.build,
        "case_empty_or_malformed": case_empty_or_malformed.build,
    }


def available() -> list[str]:
    _register()
    return sorted(_REGISTRY.keys())


def load(fixture_name: str) -> FixtureConnector:
    """Return a fresh connector instance for the named fixture.

    Raises ``KeyError`` for unknown fixtures. Callers (preload hook, tests)
    convert this into a user-facing error.
    """
    _register()
    if fixture_name not in _REGISTRY:
        raise KeyError(
            f"Unknown fixture: {fixture_name!r}. Available: {available()}"
        )
    return _REGISTRY[fixture_name]()
