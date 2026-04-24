"""Tier A5 regression harness — manual edition.

This package contains fixtures, metrics, and an ingest CLI for measuring
LLM bias in forensic-workstation analyses. LLM execution itself is
manual: the user runs each fixture in a Claude Code session, then feeds
the final verdict + session log into the harness.

See docs/LLM_REGRESSION_HARNESS_SPEC.md for the design.
"""
