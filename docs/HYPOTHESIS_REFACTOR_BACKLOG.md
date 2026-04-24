# Hypothesis Refactor Backlog

This backlog tracks the migration from rule-driven narrative anchoring to
evidence-first, hypothesis-driven analysis.

## IR-001 Summary Contract De-anchoring

Goal:
- Stop summary surfaces from presenting severity-ranked findings as the main case axis.

Deliverables:
- Replace `top_findings`-first UI framing with `alert_summary`.
- Surface `finding_balance` warnings wherever triage results are shown.
- Keep backward compatibility temporarily, but de-emphasize legacy naming.

Validation:
- Compare old severity-only top list vs balanced summary on a real case.
- Confirm that multiple categories remain visible.
- Confirm that the change does not hide strong anti-forensics or impact signals.

## IR-002 Multi-hypothesis Output Envelope

Goal:
- Introduce a first-class hypothesis payload rather than pushing analysts into a single entity or rule.

Deliverables:
- New output shape with 3-5 candidate hypotheses.
- Each hypothesis includes support, contradiction, unknowns, and next queries.
- Explicit separation between confirmed facts and working hypotheses.

Validation:
- Ensure no single tool/path dominates the hypothesis list unless the evidence is overwhelming and corroborated.
- Check that at least one alternative hypothesis survives when multiple high-priority categories exist.

## IR-003 Multi-entity Seed and Story Flow

Goal:
- Remove single-entity dependence from seed/story/hunt-pack workflows.

Deliverables:
- Hunt packs accept multiple recommended entities.
- Story and delta tools can iterate or compare candidates.
- Dominance warnings when one source/rule monopolizes seed selection.

Validation:
- Compare single-entity vs multi-entity runs on a real case.
- Confirm that secondary entities are not silently dropped.

## IR-004 Hypothesis Verification Layer

Goal:
- Make the system behave like a senior analyst by forcing refutation and gap analysis.

Deliverables:
- Deterministic verification pass for each hypothesis.
- Support score, contradiction score, coverage risk, and status.
- Hypothesis status cannot become `supported` without sufficient corroboration.

Validation:
- Confirm that weak-but-plausible stories remain marked as uncertain.
- Confirm that missing coverage prevents overconfident conclusions.

## IR-005 Cross-case Evaluation Harness

Goal:
- Prevent bomgar-style or ransomware-style overcorrection.

Deliverables:
- A reusable evaluation set across multiple case shapes.
- Metrics for dominance, missed high-signal artifacts, and unsupported hypothesis rate.
- A regression workflow for summary and hypothesis outputs.

Validation:
- Run against at least:
  - persistence-heavy case
  - impact / ransom-note case
  - credential-abuse case
  - anti-forensics case
  - benign admin-tool case
