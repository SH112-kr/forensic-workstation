---
name: incident-response
description: Windows endpoint incident response, evidence coverage checks, timeline building, and hypothesis refutation
version: 1.1.1
---

# Incident Response

Use this skill for Windows endpoint incident response when the goal is to
reduce missed evidence and confirmation bias. The workflow is coverage-first:
record what was checked, what was unavailable, and what still needs
corroboration before drawing conclusions.

## Core Rules

- Keep evidence sources separate: parsed case, mounted image, exported file,
  and imported log are not interchangeable.
- Do not treat missing event logs as proof that the behavior did not happen.
  Cross-check services, scheduled tasks, Run keys, file timestamps, Prefetch,
  SRUM, WER, and other artifacts.
- Automated detections are leads, not verdicts.
- A zero-result query means no parsed item matched the current source and
  filters. Check coverage, parser failures, date filters, and alternate
  artifacts before interpreting it.
- Long-running analysis should expose current phase and resulting artifacts.

## Windows Endpoint Triage

1. Confirm scope and evidence state first.
   - With a parsed AXIOM/KAPE case, start with `case_health`,
     `coverage_explainer`, and `initial_triage_pack`.
   - With only a raw image, start with `raw_image_triage_gate`,
     `service_persistence_gate`, `query_evtx_file`,
     `query_prefetch_files`, and `query_registry_hive`.

2. Review persistence without relying only on EVTX.
   - Services: SYSTEM hive `ControlSet*\\Services`; for svchost services,
     follow `Parameters\\ServiceDll`.
   - Scheduled tasks: TaskCache registry keys and task XML files.
   - Startup: Run/RunOnce keys and Startup folders.
   - Drivers: service Type 1/2 entries.

3. Corroborate execution from multiple families.
   - Prefetch is strong execution evidence when enabled, but can be disabled
     or cleaned.
   - AmCache, ShimCache, and UserAssist should not be used as standalone
     verdicts.
   - Combine SRUM, EVTX, WER, LNK, JumpList, and filesystem timestamps.

4. Analyze files statically first.
   - Hash, signature, version info, and timestamps come before reverse
     engineering.
   - Never execute extracted evidence.
   - Ghidra, strings, and import analysis describe capability; keep that
     separate from execution or load evidence.

5. Build timelines by hypothesis.
   - Separate initial access, execution, persistence, privilege escalation,
     defense evasion, lateral movement, exfiltration, and cleanup.
   - Temporal proximity is not causation. Items in the same time window are
     candidates until token-linked or artifact-linked evidence supports them.

## Report Checklist

- Evidence source names, paths, and active image/case identifiers.
- Parser failures, missing artifact families, and shadow copy status.
- Strong evidence vs weak/contextual evidence.
- Alternative hypotheses that were not fully refuted.
- Reproducible MCP calls or original artifact paths.
