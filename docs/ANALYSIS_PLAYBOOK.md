# Analysis Playbook

This playbook exists to prevent early anchoring on a single strong signal.
It complements `ANALYSIS_GUARDRAILS.md` with concrete operating steps.

## Safety boundary

Extracted or parsed suspicious files must never be executed by the analyst.

- `extract_file` output is for static analysis only.
- Use artifact evidence, timestamps, Prefetch, logs, SRUM, and Ghidra output to determine whether malware executed.
- "execution / impact" in this document means verifying execution from forensic evidence, not running the sample.

## Core model

Treat each case as at least three parallel lanes:

- ingress / access
- execution / impact
- persistence / cleanup

A strong chain in one lane does not close the other lanes.

## Lane definitions

### Ingress / access

Questions:

- How did the actor get access?
- Which account, channel, or remote tool was involved?
- When was the last meaningful access event?

Typical evidence:

- browser history
- remote admin tools
- logon events
- account use
- network usage

### Execution / impact

Questions:

- What actually ran?
- What changed on disk?
- Was there encryption, staging, exfiltration, note creation, or destructive action?

Typical evidence:

- new executables
- Prefetch
- note files
- extension churn
- document folder changes
- AV / EDR detections
- SRUM
- file system timestamps

### Persistence / cleanup

Questions:

- What remained after execution?
- Was persistence added, refreshed, or removed?
- Was there cleanup, anti-forensics, or rollback activity?

Typical evidence:

- services
- scheduled tasks
- startup items
- uninstall / cleanup commands
- log clearing
- snapshot deletion

## Triggered minimum verification

Do not wait for a full narrative before checking the paired lane.

### If ingress / access evidence is strong

Immediately open the execution / impact lane and verify at minimum:

- recent new executables in user and root paths
- recent Prefetch for unfamiliar binaries
- note / readme / instruction file creation
- extension churn or bulk rename patterns
- Defender / AV / EDR detections
- recent Desktop and Documents activity

### If a new executable is found

Immediately verify:

- exact creation, rename, and path movement
- whether it executed
- whether it produced downstream file changes
- whether AV detected or quarantined it
- whether it aligns with a prior access channel

### If a note file or extension churn is found

Immediately verify:

- candidate payload executable(s)
- recent remote access or account activity
- scope of modified files
- cleanup or persistence after impact

## Time window discipline

Every meaningful anchor event must open a narrow time window.

Default window:

- anchor minus 30 minutes
- anchor plus 30 minutes

Expand only when needed.

Examples of anchor events:

- remote access reconnect
- service install
- first payload drop
- first note creation
- first AV detection

## Evidence classes before case-specific IOC

Use generalized evidence classes first:

- new executable
- note creation
- extension churn
- bulk document modification
- AV detection
- remote access followed by file operations

Use case-specific IOC only after a class fires.

Examples:

- `.INC` is a case-specific example of extension churn
- `INC-README.txt` is a case-specific example of note creation
- `win.exe` is a case-specific example of a newly dropped executable

This prevents overfitting the workflow to one family or one incident.

## State board

Maintain a state board while investigating:

- ingress / access: confirmed | suggested | unverified | not seen
- execution / impact: confirmed | suggested | unverified | not seen
- persistence / cleanup: confirmed | suggested | unverified | not seen

Do not issue a strong end-to-end conclusion while a critical lane remains `unverified`.

## Conclusion contract

Separate the output into:

- confirmed facts
- working hypotheses
- unknowns / coverage gaps
- next verification steps

Do not say:

- "no second-stage payload"
- "just a remote admin tool"
- "only persistence"

unless the execution / impact lane was explicitly checked.

Prefer wording like:

- "Within the ingress-focused pivots completed so far, no impact artifact has yet been confirmed."
- "Execution / impact lane remains unverified."

## Review questions before finalizing

- Did one entity or tool name dominate the whole investigation?
- Was impact checked separately from access?
- Was the key anchor time window examined?
- Are alternative hypotheses still visible?
- Is any strong conclusion resting on an unverified lane?
