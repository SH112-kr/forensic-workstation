# Forensic Workstation

Local-first DFIR workstation for Windows endpoint investigations. The project combines a FastAPI backend, React UI, and a Claude/Codex MCP bridge so analysts can inspect parsed cases, mounted disk images, memory dumps, logs, and binaries without sending evidence to external services.

Korean documentation: [README.ko.md](README.ko.md)

Privacy and MCP disclosure gate proposal (NOT yet implemented — MCP responses currently reach the LLM with masking only): [docs/MCP_DISCLOSURE_GATE_SPEC.md](docs/MCP_DISCLOSURE_GATE_SPEC.md)

Documentation index with per-spec implementation status: [docs/README.md](docs/README.md)

## What It Does

- Opens AXIOM `.mfdb` cases and KAPE CSV output directories.
- Mounts E01, VM, and raw disk images for static file extraction and raw artifact queries.
- Parses high-value Windows artifacts such as EVTX, Prefetch, SRUM, registry hives, WER, services, and timestamps.
- Runs structured suspicious-activity rules, anti-forensics checks, MITRE mapping, timeline views, IOC extraction, and report generation.
- Exposes the same investigation functions through MCP for Claude Code/Codex workflows.
- Shows runtime dependency health so missing modules such as `regipy` are visible before they silently block analysis.

## Quick Start

### Windows Native

Use this mode when you need KAPE collection/parsing, mounted images, Ghidra, Volatility, or local tool auto-detection.

```powershell
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

powershell -ExecutionPolicy Bypass -File install.ps1 -Full
start.bat
```

The installer creates `.venv`, installs backend dependencies into that environment, builds the frontend, and registers the MCP server to use the same `.venv` Python. This avoids the common failure where `regipy` is installed in one Python but MCP runs another.

Open the UI at:

```text
http://localhost:8001
```

### Docker

Docker is useful for parsed case analysis. KAPE itself is a Windows tool, so collect/parse KAPE output on Windows first, then mount the output into Docker.

```powershell
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

powershell -ExecutionPolicy Bypass -File setup-docker.ps1
docker compose up --build -d
```

## Runtime Dependency Health

The UI exposes dependency status in `Settings` and in direct image mode. MCP tool failures also include dependency diagnostics in the MCP Monitor.

Tracked dependencies include:

| Dependency | Used For | Impact When Missing |
|---|---|---|
| `regipy` | Offline registry hive parsing | Blocks service persistence, USB, timezone, SAM/SYSTEM/SOFTWARE registry pivots |
| `dissect.target` | E01/VM/raw image mounting | Blocks mounted image browsing and raw image extraction |
| `python-evtx` | Offline EVTX parsing | Falls back to PowerShell `Get-WinEvent` where possible |
| `volatility3` | Memory analysis | Blocks memory process, network, and malfind views |
| `yara-python` | YARA scans | Blocks YARA rule loading and scans |
| `pyshark` + `tshark` | Optional PCAP analysis | Blocks PCAP-only conversation, DNS, HTTP, and IOC extraction. Missing PCAP dependencies do not degrade endpoint E01 readiness. |
| `pyhidra` | Ghidra integration | Blocks decompile/import/string/API views |

You can query dependency health directly:

```powershell
.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'backend'); from core.dependencies import dependency_report; print(dependency_report())"
```

Or through MCP:

```text
dependency_health
```

## Supported Evidence

| Evidence Type | Examples | Notes |
|---|---|---|
| AXIOM case | `.mfdb` | Full artifact search, timeline, detection, MITRE, report workflows |
| KAPE parsed output | CSV directory | Full artifact workflows when expected CSVs are present |
| Disk image | `.E01`, `.VMDK`, `.VHDX`, `.VDI`, `.QCOW2`, raw image | Static extraction and raw artifact tools; KAPE parsing recommended for full detection |
| Memory dump | `.raw`, `.vmem`, `.dmp` | Volatility-backed analysis |
| Windows registry hive | `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT` | Requires `regipy` |
| Windows event log | `.evtx` | Offline parser with fallback behavior |
| Document file | `.docx`, `.hwp`, `.pdf`, `.txt` | Metadata/path/timestamp context only; content extraction and reading are blocked |
| Binary | `.exe`, `.dll` | Static Ghidra analysis only; never execute extracted files |
| Logs | IIS, Apache, syslog-style logs | Import and keyword/status/IP search |
| Network capture | `.pcap`, `.pcapng` | Optional supplementary evidence; requires `pyshark` and `tshark` when used |

## MCP Tools

The MCP bridge exposes offline DFIR tools to Claude Code/Codex. Key groups:

### Case and Search

- `open_case`, `get_summary`, `get_artifact_types`
- `search_artifacts`, `get_hit_detail`, `search_by_hash`
- `build_timeline`, `slice_timeline`, `correlate`
- `extract_iocs`, `map_to_mitre`
- `compare_cases`, `pivot_across_cases`

### Triage and Detection

- `initial_triage_pack`
- `find_suspicious`
- `detect_anti_forensics`
- `hunt_evtx_rules`
- `assess_evidence_strength`
- `baseline_diff`
- `investigation_gap_report`
- `hypothesis_refutation_pack`

### Raw Disk Image

- `mount_image`, `list_files`, `extract_file`
- `get_file_timestamps`
- `raw_image_triage_gate`
- `query_evtx_file`
- `query_prefetch_files`
- `query_registry_hive`
- `service_persistence_gate`

### Binary, Memory, Logs

- `analyze_binary`, `ghidra_decompile`, `ghidra_imports`, `ghidra_strings`, `ghidra_suspicious_apis`
- `vol_load_memory`, `vol_pslist`, `vol_pstree`, `vol_netscan`, `vol_cmdline`, `vol_malfind`
- `import_logs`, `search_logs`, `log_stats`
- `search_wer_reports`, `srum_by_process`

### Operations

- `dependency_health`
- `server_runtime_info`
- `get_evidence_context`
- `enable_masking`, `disable_masking`
- `set_timezone`
- `save_case_snapshot`, `load_case_snapshot`, `list_case_snapshots`
- `generate_report`
- `auto_triage`

## Raw Image Workflow

When only a disk image is loaded, start with source coverage instead of assuming parsed artifacts exist:

```text
mount_image(evidence_ref="active_image")
dependency_health()
raw_image_triage_gate()
query_evtx_file(evtx_path="/c:/Windows/System32/winevt/Logs/System.evtx", event_ids="7045,104,1102")
query_prefetch_files(directory="/c:/Windows/Prefetch")
service_persistence_gate(include_mounted_image=True)
```

Raw-image mode is useful for targeted validation, but a KAPE/AXIOM parsed case gives broader coverage for timelines, rule packs, and report generation.

## Environment Variables

| Variable | Default | Purpose |
|---|---:|---|
| `FW_TIMEOUT_LIGHT` | `120` | Metadata and lightweight MCP calls |
| `FW_TIMEOUT_MEDIUM` | `600` | Search, IOC extraction, Volatility, reports |
| `FW_TIMEOUT_HEAVY` | `1200` | Timeline, correlation, detection, auto triage |
| `FW_EVENT_LOG_MAX_BYTES` | `20971520` | MCP event log rotation size |
| `FW_EVENT_BACKFILL` | `50` | MCP Monitor replay count on connect |
| `FORENSIC_KAPE_PATH` | empty | Explicit `kape.exe` path |
| `FORENSIC_GHIDRA_DIR` | empty | Explicit Ghidra install directory |

## Development

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd frontend
npm install
```

Run focused backend tests:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\test_dependency_diagnostics.py
.\.venv\Scripts\python.exe -m pytest backend\tests\test_evtx_semantic.py backend\tests\test_vss_tools.py
```

Build frontend:

```powershell
cd frontend
npm.cmd run build
```

Run frontend dev server:

```powershell
cd frontend
npm.cmd run dev -- --host 127.0.0.1
```

## Project Layout

```text
forensic-workstation/
├── backend/
│   ├── api/                 # FastAPI routes
│   ├── core/                # Connectors, parsers, analysis modules
│   ├── tests/               # Backend tests
│   └── mcp_bridge.py        # MCP server
├── frontend/
│   └── src/                 # React UI
├── kape_custom/             # Custom KAPE targets/modules
├── docs/                    # Design notes and validation logs
├── install.ps1              # Windows native installer
├── setup-docker.ps1         # Docker setup helper
└── docker-compose.yml
```

## Local State

The following files are generated locally and ignored by git:

- `backend/.active_case.json`
- `backend/.allowed_evidence.json`
- `backend/.mcp_events.jsonl`
- `backend/state/snapshots/`
- `backend/state/suppressions.json`
- `backend/hunt_packs/local/`
- `export/`

## Safety Notes

- Extracted files from evidence may be malware. Treat all extracted binaries as static-analysis-only artifacts.
- A missing artifact or 0-result query is not proof of absence. Check coverage, parser failures, and source availability.
- Registry state proves configuration in the captured hive, not necessarily execution.
- Prefetch is execution evidence when enabled, but it is not a full incident verdict by itself.

## License

Internal Use Only.
