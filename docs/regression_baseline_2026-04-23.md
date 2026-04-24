# LLM Regression Baseline — 2026-04-23 (expanded 6-fixture edition)

Baseline measurement of the forensic-workstation LLM-autonomous analysis
pipeline with all bias remediation (Patch 1-3 + Fix + A3+A1 + metric
calibration) in place.

This supersedes the earlier 3-fixture note. Metric calibration
(refutation-aware prohibited matching, synonym-group required phrases)
makes these numbers directly comparable to future runs.

## Environment

- Model: `claude-sonnet-4-6` (Claude Code CLI default, invoked via
  `claude --print --output-format stream-json --permission-mode
  bypassPermissions --max-turns 35`).
- Fixtures preloaded via `FW_FIXTURE=<name>` env.
- Prompt version: 1.0.
- Harness: `backend/regression/` (290 pytest tests pass).
- Raw transcripts: `%TEMP%/fw_baseline/` (not committed).
- Metrics report: `backend/regression/reports/run_20260423_090216Z.{csv,md}`
  (gitignored).

## Summary

| Fixture | Runs | Verdict Correct | FP | Avg Diversity | Uncertainty Avg |
|---|---|---|---|---|---|
| case_ransomware_inc_like | 3 | **3/3** | — | 0.46 | 2.0 / 3 |
| case_benign_remote_work | 3 | **3/3** | **0/3** | 0.43 | 2.0 / 3 |
| case_partial_evidence | 3 | **3/3** | — | 0.61 | 2.0 / 3 |
| case_insider_data_exfil | 3 | **3/3** | — | 0.53 | 2.33 / 3 |
| case_anti_forensics_heavy | 3 | **2/3** | — | 0.51 | 2.0 / 3 |
| case_empty_or_malformed | 3 | **3/3** | — | 0.80 | 2.0 / 3 |

**Overall: 17/18 correct (94.4%), 0/3 benign false positives, 1 true
regression signal (F5 anti-forensics anchoring).**

## Cost & time

- Total runs: 18.
- Per-run cost: $0.18 – $0.53.
- Total cost: ~$5.80.
- Per-run duration: 1 – 3 minutes.
- Parallelised 3-at-a-time: total wall clock ~20 minutes after helper
  scripting.

## Key findings

### Bias remediation stack works for 5/6 scenarios

**F1 ransomware** (3/3): LLM correctly identifies ransomware with hedged
language ("evidence suggests", "INC-README"). No overconfident
"definitely" phrasing in any run. Moderate confidence preserved.

**F2 benign remote work** (3/3, **0 FP**): The critical test — past
user false positive (PRA / Bomgar remote work misclassified as lurking
compromise) does not recur. Every run cites "no encrypted files", "no
impact observed", and hedged language around the net-new service. The
fixture was built exactly to trap the prior failure mode; the stack
blocks it.

**F3 partial evidence** (3/3): `investigation_incomplete: true` in every
run. Blocked lanes correctly identified (`ingress_access`,
`persistence_cleanup`). Model refuses strong verdict despite one
mildly suspicious AmCache entry.

**F4 insider data exfil** (3/3): **Taxonomy overflow success.** The
`candidate_axes` taxonomy does not include insider-data-only scenarios,
yet the LLM reached the correct `insider` verdict in all 3 runs by
citing exfil-pattern evidence directly (USB device, cloud sync volume,
shellbags navigation through sensitive shares). This is direct
validation of the CLAUDE.md "fourth angle" rule.

**F6 empty / malformed** (3/3): No hallucination. Verdict `unknown /
incomplete` in every run. Highest tool diversity (0.80) because the
model actively probed multiple artefact families to confirm absence
rather than concluding early. No fabricated findings.

### Real regression signal — F5 anti-forensics heavy (2/3)

Run 2 of F5 produced `ransomware` as verdict despite **zero encryption
evidence, zero ransom notes, zero file-signature mismatches** in the
fixture. The transcript reveals a textbook anchoring failure:

1. `hypothesis_declared` opened with:
   > "Primary suspicion: ransomware intrusion — pre-encryption lateral
   > movement or data staging."

2. `refutation_checked` ran alternatives (benign admin, insider, supply
   chain) and explicitly noted:
   > "absence of confirmed encryption artifacts"

3. `considered_alternatives` listed wiper, insider, supply chain, pentest
   as live alternatives with appropriate hedging.

4. Final verdict: **`ransomware` / moderate**, ignoring its own
   refutation.

**Mechanism:** The LLM anchored on the initially declared hypothesis
even after explicitly refuting the distinguishing evidence. The
candidate_axes taxonomy does include an `anti_forensics` category, but
the model did not pivot to it. The standard prompt's
`hypothesis_declared` field encourages a single primary hypothesis,
which itself is a taxonomy-first anchoring artifact.

Runs 1 and 3 on the same fixture avoided this (both `unknown`), so the
failure mode is probabilistic, not deterministic. Estimated rate from
3 runs: ~33 %. Not enough for a stable estimate — need 10+ runs to
measure the true rate.

### Metric calibration worked

Calibration changes landed before the rerun:

- **Prohibited phrase matching now refutation-aware.** Zero false-flag
  prohibited hits across all 18 runs (vs 6/9 false flags in the
  pre-calibration baseline).
- **Required phrase synonym groups.** F1 / F2 required-phrase scores
  jumped from 1/2 ≈ 50% to 3/3 = 100% without changing LLM behaviour,
  because the synonym groups now accept the equivalent wording the
  model actually uses (`"structurally missing"` ≈ `"missing coverage"`,
  `"evidence suggests"` ≈ `"evidence indicates"`, etc.).

Remaining calibration gap: the `applicability_mentioned` uncertainty
marker still fires in only 1/18 runs. The standard prompt does not
prompt the model to cite `applicability.primary_domain`. Prompt v1.1
candidate.

## Interpretation

The remediation stack works in the **common cases** (ransomware, benign
remote work, partial evidence, insider exfil, empty case) but has a
**probabilistic anchoring failure** on anti-forensics-heavy cases where
VSS deletion + log clearing are present without encryption evidence.
The LLM's training prior associates VSS deletion with ransomware
strongly enough that, one run in three, the anchoring overrides the
refutation step.

This is the first real bias signal the harness has produced. The
earlier 3-fixture baseline showed 9/9 clean — expanding to 6 fixtures
immediately found an attackable weakness. Validates the Phase 2 fixture
expansion plan.

## Phase 1 priority update — A4 refutation tools become relevant again

Previously we downgraded A4 (refutation-first meta-tools) because F2
already worked. F5 run 2 reverses that:

- Adding a **`declare_investigation_hypothesis`** meta-tool that
  requires two OR three equally weighted hypotheses at declaration
  time would likely unblock this exact failure mode.
- A **post-hoc `verify_refutation_applied`** check — where the runner
  compares the final verdict against the refutation_checked list and
  down-ranks verdicts that match refuted hypotheses — would catch run 2
  automatically.

Both are within the A4 scope we already specified in the plan but had
deprioritised.

## Updated Phase 1 priority list

1. **Prompt v1.1** — rework `hypothesis_declared` to require 2-3
   equally weighted hypotheses rather than a single "primary
   suspicion." Include `applicability.primary_domain` citation in the
   answer schema. (Smallest change, fastest ship.)
2. **A4 refutation meta-tools** — `declare_investigation_hypothesis`,
   `verify_benign_explanation`, `check_alternative_hypothesis`. Revert
   from Phase 2 to Phase 1. This is the signal-based upgrade.
3. **Rerun baseline after prompt v1.1 + A4.** Target: F5 correctness ≥
   95 % at N = 10 runs.

A2 (field-order reshuffle), B3 (memory hygiene) and CI integration
remain lower priority — the rerun will tell us whether they move the
needle or not.

## Limitations

- **Single model** (Sonnet 4.6). Opus / Haiku variance unmeasured.
- **N = 3 runs per fixture.** F5 run 2 shows variance, but 3 is too
  small to estimate rate reliably. Any follow-up bias claim needs N ≥
  10.
- **6 fixtures only.** Still missing supply chain, credential theft,
  firmware, persistence-only, near-miss (dropped-but-quarantined),
  multi-stage attacks.
- **Prompt v1.0** is a measurement target itself — anchoring in F5 run
  2 may partly be a prompt design artifact.
- **No cross-session persistence test** — every fixture is a single
  session; we have not verified that memory / case_snapshot
  interactions introduce additional bias.

## Reproducing

```
cd forensic-workstation/backend
python -m regression.cli list-fixtures
for fixture in $(python -m regression.cli list-fixtures); do
    for run in 1 2 3; do
        python -m regression.run_one $fixture $run
    done
done
python -m regression.cli finalize
```

Requires: `claude` CLI authenticated, forensic-workstation MCP
registered (`claude mcp list`), ~$6 Claude Code allowance, ~20 minutes
wall-clock.
