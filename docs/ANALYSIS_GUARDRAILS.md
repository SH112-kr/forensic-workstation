# Analysis Guardrails

These rules exist to prevent case-specific overfitting and early anchoring.

## Non-negotiable rules

- Do not let deterministic rule severity become the primary analysis axis.
- Treat rule output as evidence inventory and priority hints, not as a case verdict.
- Keep ingress / access, execution / impact, and persistence / cleanup as separate analysis lanes.
- A strong finding in one lane does not satisfy verification in the others.
- Hypothesis generation must remain flexible and may use LLM reasoning, but every hypothesis must be tied to deterministic evidence pointers.
- Every surfaced hypothesis must include:
  - supporting evidence
  - contradicting evidence
  - unknowns / coverage gaps
  - next verification steps
- Avoid family-specific or incident-specific tuning unless the feature is explicitly opt-in.
- Prefer behavior-oriented framing over tool-oriented framing.
- Use evidence classes before case-specific IOC. Examples of evidence classes: new executable, note creation, extension churn, AV detection, remote access followed by file operations.
- If strong ingress / access evidence appears, run a minimum execution / impact verification pass before issuing a strong case conclusion.
- Any optimization or ranking change must be reviewed for:
  - anchoring risk
  - category dominance
  - case-specific overfitting
  - loss of cross-case applicability

## Non-volatile autonomous E01 rules

These rules must hold across new sessions and new execution environments. They
are enforced by tests where possible.

- Active autonomous improvement targets must be Windows OS incident/CTF images.
  USB-only and data-volume-only images may remain as historical parser coverage
  references, but must not be enabled in the active E01 validation loop.
- Blind analysis must write a report before public answer material, writeups, or
  comparison JSON are opened. A blind report must record
  `answer_material_used=false`.
- Known-answer markers, expected paths, and public writeup facts must never be
  injected into core lazy artifact records. They may be used only in separate
  regression scoring/comparison steps.
- `backend/core/**` must not contain case-specific names, challenge aliases, or
  answer strings from public benchmark cases. Case-specific data belongs in
  `backend/regression/**`, tests, or external validation records.
- Prefetch semantic output is execution evidence that remains
  `pending_corroboration` until independently corroborated by SRUM, EVTX,
  AmCache, Registry, MFT, or application logs.
- Prefetch absence is not negative evidence unless OS type, ProductType, and
  Prefetch configuration prove Prefetch should have been available.
- Prefetch referenced paths are not execution evidence by themselves.
- Integrated timeline fields must preserve timestamp meaning, timezone
  certainty, confidence, and corroboration state. A time-near chain is a
  follow-up lead, not proof of causation.
- Timeline correlation must avoid broad same-host or same-log joins. Candidate
  chains should require meaningful shared context such as a remote-access tool,
  LOLBin, user/object overlap, or another specific artifact-level connection.
- E01-extracted files are static-analysis-only. Executables, DLLs, scripts, and
  payloads recovered from evidence must not be executed.
- LLM-facing artifacts must pass privacy projection/redaction before being sent
  to a model or MCP consumer.

## Validation rules

- Validate every implementation step on a real case when feasible.
- Compare before/after outputs, not just tests.
- Check whether the new behavior broadens visibility without introducing a new dominant bias.
- If a change improves one case by specializing to that case, reject or redesign it.
- A change is only acceptable when there is a reasonable argument it generalizes across multiple case shapes.

## Review checklist

- Does one rule family dominate the first screen?
- Does one entity or tool name monopolize the follow-up workflow?
- Is any critical lane still unverified?
- Are alternative hypotheses still visible?
- Are missing artifact families and corroboration gaps explicit?
- Is the system encouraging verification, not just explanation?

## Operational reference

- See `docs/ANALYSIS_PLAYBOOK.md` for the lane-based workflow and triggered minimum verification steps.
