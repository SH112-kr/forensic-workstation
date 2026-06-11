# Raw Image Index Handoff

This worktree was created for the raw-image-first migration.

Worktree:

- Path: `C:\Users\fsec\forensic-workstation-rawindex`
- Branch: `raw-image-index`
- Base commit: `bb34f9a Add evidence access guardrails`
- Original worktree remains at `C:\Users\fsec\forensic-workstation`

The original worktree has uncommitted MCP/tooling changes from the prior session.
Those changes are intentionally not present here. Keep this worktree focused on
raw image indexing unless the user explicitly asks to port those changes.

## Session History

The investigation tooling was originally centered on AXIOM `.mfdb` and KAPE CSV
outputs. The user now wants to deprecate AXIOM and KAPE gradually and make raw
disk images the primary source while preserving the same investigation speed and
analysis coverage.

Important conclusions from the prior discussion:

- Raw image direct parsing on every query will be too slow.
- The intended replacement is a case-local sidecar SQLite index built from the
  raw image.
- The sidecar index must provide the same practical API shape as the current
  AXIOM/KAPE connectors: `search`, `get_timeline`, `get_hit_detail`,
  artifact counts, and coverage metadata.
- AXIOM/KAPE should stay as parity references during migration.
- Do not remove AXIOM/KAPE code in the first phase.
- No estimated count, sampling shortcut, or candidate pruning may be used if it
  can miss results.
- Parser failures, skipped sources, unsupported artifact families, and timeouts
  must be surfaced as `not_evaluable` or `coverage_gap`.
- Sidecar cache/index files are case-local forensic data and must not be
  committed.

### Update 2026-06-11 — TB-safe $MFT indexing (file inventory)

The directory-walk file indexer was replaced by a `$MFT`-stream indexer and
then parallelized. Validated on a real Windows endpoint E01 (`/c:`, 1,270,784 MFT segments):

- **Directory walk (old)**: timed out on full `/c:` at ~20 min, and the long
  walk **corrupted the dissect handle** so subsequent SYSTEM/Prefetch reads
  failed. Replaced.
- **Serial `$MFT` stream**: completed — 1,270,537 files, 170 record-level gaps
  (invalid signature / utf-16 decode, recorded as `coverage_gap`, **no-miss**),
  deleted records (`in_use=False`) included. Handle stayed healthy
  (post-scan SYSTEM extract OK). ~1,186 s.
- **`full_path()` cache (rejected)**: empirically disproven — dissect's
  `full_path()` already memoizes `mft.get()`; a Python reimplementation was
  0.4–0.98× (equal or slower) and diverged on hardlink/DOS 8.3 names. The
  per-record cost is dissect attribute parsing, not the parent walk.
- **Parallel `$MFT` shard scan (shipped)**: `core/raw_index/mft_parallel.py`
  shards `Mft.segments(start, end)` across worker processes (each opens its own
  E01 once via a Pool initializer); the parent still inserts serially so FTS /
  search-text / id integrity is untouched. Validated: **273 s (4.34×)**, output
  byte-identical to serial (files Δ+0, gaps Δ+0), handle healthy. Worker default
  is capped at 8 (`_MAX_DEFAULT_WORKERS`): the serial insert (~220 s) is the
  wall-clock floor and each worker holds a full ~1.7 GB image handle, so more
  shards only add memory pressure.
- **Background mode (shipped)**: `build_raw_file_index(background=True)` runs the
  build on a daemon thread and returns `{status: "indexing_started", job_id}`
  immediately; `raw_file_index_status(job_id)` polls live `indexed_files` /
  `gap_count` and the final result. This removes the synchronous MCP timeout as
  the TB-scale ceiling (the original "TB면 어쩌려고" concern). The image must
  stay mounted until the job finishes.

Tests: full suite green (no failures), `bias-guard --no-external` 7/7,
new `tests/test_mft_parallel.py` + background-job tests in
`tests/test_raw_index_mcp.py`.

## Hard Constraints

1. No-miss semantics are more important than speed.
2. Fast paths must return exact results for the indexed artifact family.
3. Any optimization that uses a candidate set must revalidate final results
   against the original indexed records or raw artifact source.
4. Cache miss, cache corruption, schema mismatch, and parser failure must fall
   back to source parsing or emit a coverage gap. They must not silently return
   zero.
5. Sidecar files belong under an ignored local path such as
   `export/cache/raw_index/<fingerprint>/`.
6. Do not access live C2 or external URLs as part of implementation tests.
7. Do not include incident IOCs, hostnames, usernames, file paths, or evidence
   paths in committed docs or tests.

## Suggested Goal Prompt

Use this in the new Codex session from this directory:

```text
Build a raw-image-first forensic artifact index in this isolated worktree.
Create a case-local SQLite sidecar index and connector that can eventually
replace AXIOM/KAPE search and timeline flows while preserving no-miss
investigation semantics. Do not remove AXIOM/KAPE in phase 1. Do not use
estimated counts, sampling shortcuts, or silent fallbacks. Every parser failure,
timeout, unsupported artifact family, or cache mismatch must be reported as
not_evaluable or coverage_gap. Verify with tests before claiming completion.
```

## First Plan To Follow

Read and execute:

`docs/superpowers/plans/2026-06-04-raw-image-index.md`

The first useful milestone is not a full raw parser. It is a sidecar SQLite
schema plus a `RawImageIndexConnector` that satisfies the existing connector
contract against seeded sidecar data. After that, add raw image file indexing
and parity checks one artifact family at a time.

