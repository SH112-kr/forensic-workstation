# DFIR Validation Plan

Goal: validate autonomous forensic analysis without downloading dangerous
malware samples or executing unknown binaries.

## Safety Policy

- Do not download live malware, cracked tools, payload archives, or unknown
  executable samples.
- Prefer public datasets that provide logs, timelines, CSV artifacts, disk-image
  metadata, or challenge writeups with expected answers.
- Treat any external archive as untrusted evidence. Store it outside execution
  paths and never run extracted binaries.
- Synthetic fixtures are the default CI input. Public datasets are optional
  offline regression material.

## Validation Tiers

1. Synthetic fixtures
   - Ransomware-like impact
   - Benign remote administration
   - Partial evidence
   - Insider exfiltration
   - Anti-forensics-heavy ambiguous case
   - Empty or malformed case

2. Public non-executable DFIR data
   - Event logs, KAPE CSVs, Zeek logs, timelines, registry exports, and memory
     plugin text outputs.
   - Expected outputs must be converted into ground-truth JSON before adding
     automated assertions.

3. Full forensic images
   - Use only trusted educational datasets.
   - Mount/read as evidence. Do not execute files extracted from the image.
   - Record image hash, source URL, date acquired, parser versions, and expected
     answer references.

## Metrics

- Verdict accuracy against ground truth.
- Feature bias regression: every feature change must rerun prior normal,
  incident, ambiguous, and external cases to detect new overcall/undercall
  drift.
- Strong-conclusion gate correctness.
- False-positive resistance on benign/admin cases.
- Parser-failure visibility.
- Negative-evidence accounting.
- Source conflict preservation.
- Causal graph edge discipline: temporal candidates must not become causal
  claims without confirming artifacts.
- Privacy leakage tests: raw sensitive values must not appear in LLM/MCP-safe
  outputs unless an explicit reveal policy allows them.
- PCAP checks are optional supplementary validation. Missing PCAP tooling should
  not lower Windows endpoint E01 readiness unless a case explicitly includes
  PCAP evidence and the analyst requests that lane.

## Candidate Public Sources

- NIST CFReDS, when datasets are logs/images suitable for offline parsing.
- SANS/DFIR public challenges, when artifacts are non-executable or can be
  handled as inert evidence.
- Blue-team CTF forensic artifacts that include event logs, packet captures, or
  parsed CSV outputs.

## Current Allowlisted External Checks

Run:

```powershell
.\.venv\Scripts\python.exe backend\regression\external_validation.py --json
```

Feature-level bias guard:

```powershell
cd backend
..\.venv\Scripts\python.exe -m regression.cli bias-guard --json
```

Run this guard after every analysis feature change. It reruns all synthetic
ground-truth fixtures plus the already-downloaded allowlisted E01/APT/EVTX/OTRF
checks. A failure means the feature introduced classification drift, overcall
bias on benign or incomplete cases, or undercall bias on incident/APT stages.

Claude post-evaluation review:

```powershell
cd backend
..\.venv\Scripts\python.exe -m regression.cli bias-guard --claude-review --claude-review-output ..\external\dfir_validation\last_claude_review.json
```

Rule: after a material improvement and local evaluation complete, run Claude
Code review against the validation summary before considering the change done.
The review is a second-opinion gate for accuracy, bias, privacy leakage, and
unsafe evidence handling. On Windows, the helper prefers `claude.cmd` so the
PowerShell script execution policy does not block the call.

Allowlisted downloads:

- `sbousseaden/EVTX-ATTACK-SAMPLES` `evtx_data.csv`
  - Parsed Windows event-log CSV.
  - Used to compare fired EVTX rules against `EVTX_Tactic` labels.
  - Current scenarios: SMB remote file copy, Kerberos password spray, RDP
    tunneling known-gap.
- `OTRF/Security-Datasets` `psh_disable_eventlog_service_startuptype_modification.zip`
  - Zipped JSON event logs.
  - Used to validate EventLog service registry tamper detection.
- Digital Corpora `nps-2010-emails.E01`
  - Benign public E01 training image.
  - Used as the normal side of the E01 overcall/undercall pair.
- Digital Corpora M57 `charlie-work-usb-2009-12-11.E01`
  - Public USB E01 from the M57 patents scenario.
  - Used as a data-leakage E01 case by checking expected scenario paths without
    executing extracted files.
- Digital Corpora M57-Jean `nps-2008-jean.E01` and `.E02`
  - Public multi-part E01 laptop image from the M57-Jean scenario.
  - Used as a spear-phishing data-leakage case by checking the expected
    spreadsheet path without executing extracted files.
- `skrghosh/apt-dataset` `apt29.json.zip`
  - Public zipped JSON audit logs from a CALDERA-based APT29 simulation.
  - Used to validate multi-stage APT reconstruction against published campaign
    stages without downloading or executing malware binaries.
- NIST CFReDS `Hacking Case` `4Dell Latitude CPi.E01/.E02`
  - Public EnCase training image with official answer PDF.
  - Used to validate hacking-tool, attribution, and packet-sniffing evidence
    without extracting or executing files.

Known intentional gap:

- RDP 1149 by itself supports remote access/lateral movement evidence. It does
  not prove Command-and-Control tunneling without network/session context. The
  validation harness records this as a known gap rather than overfitting an
  EVTX-only rule.

## E01 Validation

Current default CI does not download E01 images. E01 images are large evidence
containers and can contain executable malware. The project validates E01 in two
layers:

1. Contract tests with a fake E01 connector.
   - Verifies high-value artifact inventory logic.
   - Verifies source attribution, temporal layer, parser status, and lane
     counts.
2. Optional real E01 integration test.
   - Set `FW_TEST_E01_PATH` to a known-safe training/public E01 image.
   - Run `pytest backend/tests/test_e01_artifact_cache.py`.
   - The test opens the image read-only through `E01ImageConnector` and builds
     an artifact inventory cache.
3. Allowlisted E01 pair regression.
   - `nps-2010-emails.E01` is treated as benign.
   - `charlie-work-usb-2009-12-11.E01` is treated as a data-leakage scenario.
   - `nps-2008-jean.E01`/`.E02` is treated as a spear-phishing data-leakage
     scenario when the large files are present locally.
   - The evaluator must not require ransomware notes or encrypted extensions
     for data-leakage cases, and must not call benign documents malicious by
     themselves.

No E01 file should be committed to this repository.

Every external dataset added to regression must include a `SAFE_DATASET.md`
entry documenting why it is safe to store and parse in this repository.
