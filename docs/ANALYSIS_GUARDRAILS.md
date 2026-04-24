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
