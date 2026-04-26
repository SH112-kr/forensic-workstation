# Autonomous E01 Validation Log

Purpose: keep improving the Windows E01 based autonomous DFIR framework through repeatable public-case validation, while preventing answer leakage, unsafe sample execution, and biased scoring.

## Operating Rules

- Do not execute EXE, DLL, scripts, payloads, or files recovered from images.
- Treat public writeups and answer PDFs as post-analysis scoring material only.
- Do not use prior `blind_*`, `answer_comparison*`, `analysis_workspace/*`, or handoff notes as blind-analysis input.
- Cases already discussed in this project are regression cases, not blind benchmarks.
- MCP-path operational evaluation and direct parser regression are recorded separately.
- If a case is incomplete, encrypted, unsupported, or mostly unparsed, exclude it from accuracy scoring and record the degraded condition explicitly.
- USB/data-volume-only images are no longer part of the active improvement loop. The active loop targets Windows OS images from incident, CTF, or enterprise-style scenarios.

## Implemented Improvements

### Lazy E01 Extraction

- Added a KAPE/MFDB-inspired lazy target manifest in `backend/core/analysis/e01_artifact_cache.py`.
- Default extraction now targets high-value Windows and data-volume artifacts without broad recursive scans.
- Added support for:
  - drive-letter paths such as `/c:/Windows/...`
  - root-mounted Windows volumes such as `/Windows/...`
  - XP-style `/Documents and Settings`
  - NTFS metadata at both `/c:/$MFT` and `/$MFT`
  - root-level USB/data-volume documents and archives
  - FAT16/FAT32 root-directory fallback for E01 data volumes that `dissect.target` does not mount
- Fixed a performance bug by replacing connector-wide recursive globbing with bounded one-level directory scans.
- Added a generic data-volume root item target so USB evidence is indexed without hardcoded case filenames.
- Lazy records now include target metadata such as `target_id`, `mfdb_artifact_name`, `kape_tool`, and resolution source.

### EVTX Semantic Parser

- Added `backend/core/analysis/evtx_semantic.py`.
- Supports static parsing of EVTX XML records through `python-evtx` when available.
- Extracts structured fields and conservative labels for:
  - `4624` successful logon
  - `4625` failed logon
  - `4648` explicit credential use
  - `4672` special privileges
  - `4720`, `4722` account creation/enabling
  - `4728`, `4732`, `4756` group membership changes
  - `7045` service installation
  - `1102` audit log cleared
- Rule output is treated as evidence/hints. It does not bypass verdict guardrails.

### Autonomous Validation Runner

- Added `backend/regression/autonomous_validation_runner.py`.
- Added CLI entry point: `python -m regression.cli autonomous-validation`.
- The runner:
  - runs external regression datasets
  - probes configured E01 cases
  - measures parsed vs unparsed volume coverage
  - separates scoring cases from candidate/degraded cases
  - can request a Claude review through `--claude-review`
- `autonomous_enable_recommended` is false whenever discussion items remain, even if scored tests pass.

## 2026-04-26 Latest Run

Command:

```powershell
$env:PYTHONPATH='backend'; .venv\Scripts\python.exe -m regression.autonomous_validation_runner --claude-review
```

Earlier reports:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T051926Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T052005Z.md`
- `external/dfir_validation/autonomous_runs/claude_review_ascii_20260426T051926Z.json`

Current reports after LoneWolf multipart download and safety-test hardening:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T055948Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T060036Z.md`
- `external/dfir_validation/autonomous_runs/claude_review_20260426T055948Z.json`

Current reports after EVTX expansion, LoneWolf scoring, and DOMEX clean baseline:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T063223Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T063223Z.md`

Current reports after answer-leakage cleanup, M57 USB downloads, and FAT fallback:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T065228Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T065228Z.md`

Current reports after adding a larger M57 Windows system image:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T065709Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T065709Z.md`

Current reports after restricting the active loop to Windows OS images and adding Magnet CTF 2019 Windows Desktop:

- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T072558Z.json`
- `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T072558Z.md`

Current overall result:

- `ok`: true
- `autonomous_enable_recommended`: false
- external regression: passed 5, failed 0
- bias guard: 11 checks, failed 0
- synthetic fixtures: 6 cases
- tests: 374 passed, 2 skipped

E01 probe result:

| Case | Scope | Scoring | Status | Records | Main finding |
| --- | --- | ---: | --- | ---: | --- |
| `cfreds_hacking` | Windows system | yes | ok | 92 | Registry, user hives, Prefetch, NTFS metadata, and root items found |
| `m57_jean` | Windows system | yes | ok | 139 | Registry, multiple user hives, Prefetch, NTFS metadata, and root items found |
| `m57_jo_newcomputer_20091120` | Windows system | no | ok | 103 | Windows-system coverage case; Registry, user hives, Prefetch, NTFS metadata, and root items found |
| `magnet_2019_windows_desktop` | Windows system | no | ok | 281 | Magnet CTF Windows Desktop coverage case; EVTX, Registry, user hives, Prefetch, NTFS metadata, and root items found |
| `nps_domexusers_redacted` | Windows system benign | yes | ok | 46 | Non-empty clean baseline; no impact candidates |
| `lonewolf` | Windows system | yes | ok | 267 | E02-E09 were downloaded; EVTX, Registry, user hives, Prefetch, NTFS metadata, root items, and 10/10 expected markers found |

LoneWolf correction:

- Previous degraded result was caused by missing multipart E01 companion segments.
- Downloaded `LoneWolf.E02` through `LoneWolf.E09` from the allowlisted Digital Corpora source.
- The rerun changed LoneWolf from `records=2`, `issues=[missing/metadata/unparsed]` to `records=264`, `issues=[]`.
- This is still not a scored benchmark because no project-local known-answer rubric has been added for LoneWolf yet.
- Later update: LoneWolf is now a scored marker benchmark using public Axiom report paths. Ten marker paths are checked from the E01 directly.
- Answer-leakage cleanup: expected marker paths are no longer injected into the lazy artifact cache. LoneWolf cache records dropped from 274 to 264 before the root-item target was added; marker paths are now checked only as a separate scoring step.

M57 USB update:

- Downloaded additional Digital Corpora M57 USB E01 images:
  - `terry-work-usb-2009-12-11.E01`
  - `jo-work-usb-2009-12-11.E01`
  - `jo-favorites-usb-2009-12-11.E01`
- Initial run found all three as degraded because the volumes were FAT16/FAT32 with `fs=None` in `dissect.target`.
- Added a generic FAT16/FAT32 root fallback in `backend/core/connectors/e01_image.py`.
- Added a generic `data_volume_root_items` lazy target in `backend/core/analysis/e01_artifact_cache.py`.
- Rerun changed all three added USB cases from `degraded` to `ok`; they remain excluded from accuracy scoring until a project-local answer rubric exists.
- Later policy update: USB/data-volume-only cases are disabled in the active autonomous validation loop. They remain in the registry only as historical parser-coverage references.

M57 Windows-system update:

- Downloaded `jo-2009-11-20-newComputer.E01` from Digital Corpora.
- The image is registered as `coverage_regression` and excluded from accuracy scoring until a project-local answer rubric exists.
- Initial probe result: `ok`, `records=103`, `issues=[]`.

Magnet CTF 2019 Windows Desktop update:

- Downloaded `2019 CTF - Windows-Desktop.zip` from Digital Corpora.
- Extracted `2019 CTF - Windows-Desktop-001.E01`.
- Registered as `magnet_2019_windows_desktop`, `coverage_regression`, `scoring_included=false`.
- Initial probe result: `ok`, `records=281`, `issues=[]`.
- This is a Windows OS CTF image and remains excluded from accuracy scoring until a blind answer-rubric workflow is added.

Blind analysis update:

- Added `backend/regression/blind_e01_analysis.py`.
- Ran a blind first-pass analysis before opening public writeups:
  - `external/dfir_validation/blind_runs/magnet_2019_windows_desktop_blind_analysis.json`
  - `external/dfir_validation/blind_runs/magnet_2019_windows_desktop_blind_analysis.md`
- Initial blind verdict was `suspicious_remote_access_possible` with `allow_strong_conclusion=false`.
- Post-answer comparison showed the initial RDP emphasis was a bias surface because the stronger source was TeamViewer application logs.
- Added generic, non-case-specific lazy targets for:
  - TeamViewer / remote-access application logs
  - Windows notification databases
  - user Downloads root items
- Reran blind analysis. Current verdict is `third_party_remote_access_activity_observed`, still with `allow_strong_conclusion=false`.
- Post-answer comparison report:
  - `external/dfir_validation/blind_runs/magnet_2019_windows_desktop_comparison.md`
- Current test status after this loop: `377 passed, 2 skipped`.

Prefetch parser update:

- Added `backend/core/analysis/prefetch_semantic.py`.
- Supports Windows 10 `MAM\x04` compressed Prefetch through Windows `ntdll` XPRESS-HUFF decompression.
- Extracts `executable_name`, `run_count`, `latest_run_time_utc`, and `last_run_times_utc`.
- Output is explicitly guarded:
  - `evidence_state= pending_corroboration`
  - `standalone_verdict_allowed=false`
  - `absence_is_negative_evidence=false`
  - `referenced_paths_are_execution_evidence=false`
- Magnet 2019 blind rerun now decodes `TEAMVIEWER_DESKTOP.EXE` with `run_count=3`, matching the public writeup after the blind run.
- Signal name was changed from `living_off_the_land_prefetch_present` to `common_admin_tool_prefetch_present` to reduce wording-driven overcall bias.
- Version handling: Windows XP/v17 stores one last-run timestamp; Vista+/Win10 formats return up to eight last-run slots when present.
- Claude review result: conditional PASS; safe to keep while Prefetch remains pending corroboration and is not used as standalone incident proof.
- Current test status after this loop: `379 passed, 2 skipped`.

Non-volatile guardrail update:

- Added a `Non-volatile autonomous E01 rules` section to `docs/ANALYSIS_GUARDRAILS.md`.
- Added `backend/tests/test_autonomous_policy_guardrails.py`.
- The policy tests enforce:
  - active E01 validation loop is Windows OS only
  - `data_volume` cases are disabled and unscored
  - `backend/core/**` contains no case-specific benchmark strings
  - Prefetch semantic output remains non-escalating
  - blind reports do not claim answer material was used
- Latest full test result after policy hardening: `384 passed, 2 skipped`.
- Latest autonomous validation run:
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T083444Z.json`
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T083444Z.md`
- Claude final review result: PASS. Remaining concerns are next-iteration improvements, not current blockers:
  - expose Prefetch referenced paths later as non-execution `raw_referenced_paths`
  - reduce manual maintenance of forbidden benchmark strings when adding new cases
  - keep known-answer registry data isolated from blind analysis paths

Follow-up guardrail improvements:

- Prefetch now exposes `raw_referenced_paths` for visibility while keeping
  `referenced_paths=[]` and `referenced_paths_are_execution_evidence=false`.
  These raw paths do not affect verdicts, signals, or strong-conclusion gates.
- Policy tests now derive additional forbidden core-code strings from
  `E01_CASE_REGISTRY` metadata and expected-marker basenames, with generic terms
  excluded to avoid noisy failures.
- Added a policy test that `blind_e01_analysis.py` does not import
  `e01_case_registry`, `E01_CASE_REGISTRY`, `expected_marker_paths`, or
  `Expected Scenario Path`.
- Magnet 2019 rerun check:
  - `TEAMVIEWER_DESKTOP.EXE` `run_count=3`
  - `raw_referenced_paths=80`
  - `referenced_paths=0`
  - `allow_strong_conclusion=false`
- Latest full test result: `385 passed, 2 skipped`.
- Latest autonomous validation run:
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T085300Z.json`
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T085300Z.md`

Integrated timeline update:

- Added `backend/core/analysis/timeline_schema.py` as a shared conservative
  event schema. Each event carries `event_time`, `event_time_type`, `timezone`,
  `source_artifact`, `sequence_role`, `confidence`, and
  `corroboration_state`.
- `backend/regression/blind_e01_analysis.py` now emits an integrated timeline
  from EVTX, Chrome visits/downloads, TeamViewer connection logs, and Prefetch
  notables without loading answer material.
- Timeline candidate chains are deliberately weak evidence:
  - `corroboration_state=candidate_chain`
  - local/unknown TeamViewer timestamps are not silently promoted to UTC
  - Prefetch remains `pending_corroboration`
  - broad same-host/same-log joins were rejected to reduce false correlation
- Magnet 2019 Windows blind rerun:
  - `answer_material_used=false`
  - `verdict=third_party_remote_access_activity_observed`
  - `allow_strong_conclusion=false`
  - integrated timeline events: `314`
  - source counts: EVTX `213`, Prefetch `31`, Browser History `54`,
    Browser Downloads `6`, Remote Access Log `10`
  - meaningful TeamViewer sequence is now visible across download, service
    install, Prefetch execution, and TeamViewer session log events.
- Latest full test result: `390 passed, 2 skipped`.
- Latest autonomous validation run:
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T140538Z.json`
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T140538Z.md`

Cross-case timeline/noise check:

- Re-ran the blind timeline runner on the DFIR Madness Case001 DC01 E01 without
  loading answer material:
  - `external/dfir_validation/blind_runs/dfir_madness_case001_dc01_timeline_regression_blind_analysis.json`
  - `external/dfir_validation/blind_runs/dfir_madness_case001_dc01_timeline_regression_blind_analysis.md`
- Initial timeline output exposed a bias risk: Windows driver, VMware, and AD
  role service-install events were all represented as `persistence`, which
  buried higher-value service-install follow-up candidates.
- Added generic service-install classification in the blind runner:
  - `likely_system_driver`
  - `likely_platform_or_role_service`
  - `unusual_service_path`
  - `system32_executable_service_needs_context`
  - `executable_service_needs_context`
  - `unknown_service_install`
- After classification, the DC01 run moved platform service noise out of the
  persistence lane:
  - `likely_system_driver=17`
  - `likely_platform_or_role_service=17`
  - service follow-up count: `0`
  - verdict became `activity_requires_followup`, preserving conservative
    behavior when E01-only evidence does not expose a corroborated malicious
    service.
- Magnet 2019 was rerun after this change and retained the TeamViewer-focused
  verdict because it has independent browser, remote-access-log, and Prefetch
  evidence.
- Latest full test result: `391 passed, 2 skipped`.
- Latest autonomous validation run:
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T141138Z.json`
  - `external/dfir_validation/autonomous_runs/autonomous_validation_20260426T141138Z.md`

EVTX validation update:

- EVTX-ATTACK-SAMPLES coverage increased from 3 selected scenarios to 43 labeled scenarios.
- Added generic evidence-hint rules for Sysmon process creation, LSASS access, network connections, directory object changes, sensitive object access, audit log clear, PowerShell 4104, and discovery named pipes/account enumeration.
- RDP tunneling C2 attribution remains an attribution limitation, not an undercall residual risk, because EVTX alone cannot prove the tunnel's command-and-control role.

Clean baseline update:

- Downloaded `nps-2009-domexusers.redacted.E01-E03` from Digital Corpora as a non-empty benign Windows baseline.
- `normal_nps_2010_emails` produced zero indexed artifacts and is now separated into `clean_baseline_gaps` rather than counted as an FP-rate baseline.

Safety hardening added:

- `privacy_gateway_secret_redaction`: LLM-safe artifacts now redact password/token/api_key/secret/client_secret assignments and Bearer tokens.
- `e01_extract_static_only`: `extract_file` now returns `execute_allowed=false` and writes a malware-do-not-execute marker.

## Claude Review Summary

Earlier Claude review agreed with the initial scoring policy:

- The three fully parsed, scoped cases can be scored as regression.
- LoneWolf must stay excluded because 99.9% of bytes are unread and only two NTFS metadata records were recovered.
- Scoring LoneWolf now would pollute the accuracy signal.

Claude identified required human/project decisions:

- Determine why LoneWolf's large partition is `fs=None`: missing segment, BitLocker/full-disk encryption, or unsupported filesystem.
- Define LoneWolf's benchmark scope: exclude permanently, mark as graceful-degraded encrypted/unsupported case, or hold until fully parseable.
- Confirm that the M57 Charlie USB fixture is intentionally scoped as a data-volume case, not a Windows-system case.

Conclusion from review:

- Fully autonomous operation should not be enabled yet.
- A degraded/encrypted/unsupported image policy must be implemented first: retry, escalate, skip-and-log, or abort.

Current Claude review after the multipart fix and safety hardening:

- Conditional pass.
- Safety checks for privacy redaction and static-only extraction are now visible and passed.
- Full human-out-of-the-loop autonomy is still not recommended.
- Remaining blockers:
  - EVTX known-gap coverage is too narrow.
  - LoneWolf now parses but still lacks a known-answer scoring rubric.
  - Clean benign Windows E01 false-positive baseline is still thin.

## Verification

Command:

```powershell
python -m pytest backend/tests/test_autonomous_validation_runner.py backend/tests/test_evtx_semantic.py backend/tests/test_e01_artifact_cache.py backend/tests
```

Result:

- 374 passed
- 2 skipped

## Current Engineering Judgment

Confirmed improvements can stay:

- KAPE/MFDB-style lazy target extraction is beneficial and does not force broad, slow scans.
- Root-mounted volume handling is necessary for real E01 variability.
- Data-volume support is necessary because not every valid E01 is a Windows system volume.
- EVTX semantic parsing improves evidence quality, but its labels must remain evidence-level signals rather than final verdicts.
- Degraded-image detection improves bias control because it prevents false confidence from incomplete evidence.

Needs discussion before stronger automation:

- LoneWolf handling policy.
- Whether data-volume cases should have separate scoring rubrics from Windows-system E01 cases.
- Whether autonomous runs should abort on mostly unparsed candidate images or continue with a hard warning.

## Next Queue

1. Add a case registry that records `expected_scope`, `scoring_included`, `benchmark_type`, and known degraded/encrypted status.
2. Implement a degraded-image policy gate for mostly unparsed E01 files.
3. Confirm M57 Charlie USB as a data-volume fixture and keep it out of Windows-system parser coverage scoring.
4. Add Registry semantic parsing for Services, Run keys, AppCompatCache confidence by Windows version, and UserAssist through a validated library.
5. Add Prefetch semantic parsing for execution count, last run times, and loaded module evidence.
6. Add MFT/USN streaming or an explicit parser-unavailable gap with hard limits.
7. Re-run all prior regression cases after each new parser feature to detect accuracy regression or bias drift.
