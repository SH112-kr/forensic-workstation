# Forensic Workstation

Windows 엔드포인트 침해사고 대응과 디지털 포렌식을 위한 로컬 우선 DFIR 워크스테이션입니다. FastAPI 백엔드, React UI, Claude/Codex MCP 브리지를 함께 제공해서 AXIOM/KAPE 케이스, 디스크 이미지, 메모리 덤프, 로그, 바이너리를 외부 서비스로 전송하지 않고 분석할 수 있습니다.

English documentation: [README.md](README.md)

## 주요 기능

- AXIOM `.mfdb` 케이스와 KAPE CSV 출력 디렉터리를 엽니다.
- E01/raw 디스크 이미지를 마운트하고 정적 파일 추출 및 raw artifact 쿼리를 수행합니다.
- EVTX, Prefetch, SRUM, Registry hive, WER, 서비스, NTFS 타임스탬프 등 주요 Windows 아티팩트를 분석합니다.
- 의심 행위 룰, 안티포렌식 탐지, MITRE 매핑, 타임라인, IOC 추출, HTML 리포트를 제공합니다.
- Claude Code/Codex에서 동일한 분석 기능을 MCP 도구로 호출할 수 있습니다.
- `regipy` 같은 런타임 의존성 누락을 UI와 MCP 결과에서 명확히 보여줍니다.

## 빠른 시작

### Windows 네이티브

KAPE 수집/파싱, 디스크 이미지 마운트, Ghidra, Volatility, 로컬 도구 자동 탐지가 필요하면 이 방식을 권장합니다.

```powershell
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

powershell -ExecutionPolicy Bypass -File install.ps1 -Full
start.bat
```

설치 스크립트는 `.venv`를 만들고, 백엔드 의존성을 그 가상환경에 설치하고, 프론트엔드를 빌드하고, MCP 서버도 같은 `.venv` Python을 사용하도록 등록합니다. 이렇게 하면 `regipy`를 설치했는데 MCP가 다른 Python으로 실행되어 모듈을 못 찾는 문제를 줄일 수 있습니다.

UI 주소:

```text
http://localhost:8001
```

### Docker

Docker는 이미 파싱된 케이스를 분석할 때 유용합니다. KAPE 자체는 Windows 도구이므로 KAPE 수집/파싱은 Windows에서 수행한 뒤 결과를 Docker에 마운트하세요.

```powershell
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

powershell -ExecutionPolicy Bypass -File setup-docker.ps1
docker compose up --build -d
```

## 런타임 의존성 진단

UI의 `Settings`와 E01 direct mode 화면에서 의존성 상태를 확인할 수 있습니다. MCP 도구 호출이 의존성 문제로 실패하면 MCP Monitor에도 원인과 복구 방법이 표시됩니다.

| 의존성 | 사용 목적 | 없을 때 영향 |
|---|---|---|
| `regipy` | 오프라인 Registry hive 파싱 | 서비스 지속성, USB, TimeZone, SAM/SYSTEM/SOFTWARE registry pivot 차단 |
| `dissect.target` | E01/raw 이미지 마운트 | 이미지 브라우징, raw image 파일 추출 차단 |
| `python-evtx` | 오프라인 EVTX 파싱 | 가능한 경우 PowerShell `Get-WinEvent` fallback 사용 |
| `volatility3` | 메모리 분석 | 메모리 프로세스, 네트워크, malfind 분석 차단 |
| `yara-python` | YARA 스캔 | YARA 룰 로드와 파일 스캔 차단 |
| `pyshark` + `tshark` | PCAP 분석 | 네트워크 대화, DNS, HTTP, IOC 추출 차단 |
| `pyhidra` | Ghidra 연동 | 디컴파일, import, string, suspicious API 분석 차단 |

직접 의존성 상태를 확인하는 명령:

```powershell
.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'backend'); from core.dependencies import dependency_report; print(dependency_report())"
```

MCP에서는 다음 도구를 호출하면 됩니다.

```text
dependency_health
```

## 지원 증거 형식

| 증거 형식 | 예시 | 비고 |
|---|---|---|
| AXIOM 케이스 | `.mfdb` | 검색, 타임라인, 탐지, MITRE, 리포트 전체 워크플로우 |
| KAPE 파싱 결과 | CSV 디렉터리 | 필요한 CSV가 있으면 전체 artifact 워크플로우 가능 |
| 디스크 이미지 | `.E01`, raw image | 정적 추출 및 raw artifact 도구 지원, 전체 탐지는 KAPE 파싱 권장 |
| 메모리 덤프 | `.raw`, `.vmem`, `.dmp` | Volatility 기반 분석 |
| Windows Registry hive | `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT` | `regipy` 필요 |
| Windows 이벤트 로그 | `.evtx` | 오프라인 파서와 fallback 동작 |
| 바이너리 | `.exe`, `.dll` | 정적 Ghidra 분석 전용, 추출 파일 실행 금지 |
| 로그 | IIS, Apache, syslog 계열 | import 후 키워드/status/IP 검색 |
| 네트워크 캡처 | `.pcap`, `.pcapng` | `pyshark`, `tshark` 필요 |

## MCP 도구

MCP 브리지는 Claude Code/Codex에서 오프라인 DFIR 도구를 호출할 수 있게 합니다.

### 케이스와 검색

- `open_case`, `get_summary`, `get_artifact_types`
- `search_artifacts`, `get_hit_detail`, `search_by_hash`
- `build_timeline`, `slice_timeline`, `correlate`
- `extract_iocs`, `map_to_mitre`
- `compare_cases`, `pivot_across_cases`

### 초기 분석과 탐지

- `initial_triage_pack`
- `find_suspicious`
- `detect_anti_forensics`
- `hunt_evtx_rules`
- `assess_evidence_strength`
- `baseline_diff`
- `investigation_gap_report`
- `hypothesis_refutation_pack`

### Raw 디스크 이미지

- `mount_image`, `list_files`, `extract_file`
- `get_file_timestamps`
- `raw_image_triage_gate`
- `query_evtx_file`
- `query_prefetch_files`
- `query_registry_hive`
- `service_persistence_gate`

### 바이너리, 메모리, 로그

- `analyze_binary`, `ghidra_decompile`, `ghidra_imports`, `ghidra_strings`, `ghidra_suspicious_apis`
- `vol_load_memory`, `vol_pslist`, `vol_pstree`, `vol_netscan`, `vol_cmdline`, `vol_malfind`
- `import_logs`, `search_logs`, `log_stats`
- `search_wer_reports`, `srum_by_process`

### 운영과 상태

- `dependency_health`
- `server_runtime_info`
- `get_evidence_context`
- `enable_masking`, `disable_masking`
- `set_timezone`
- `save_case_snapshot`, `load_case_snapshot`, `list_case_snapshots`
- `generate_report`
- `auto_triage`

## Raw 이미지 분석 흐름

E01/raw 이미지만 로드된 경우에는 파싱된 아티팩트가 있다고 가정하지 말고 먼저 소스 커버리지를 확인하세요.

```text
mount_image(evidence_ref="active_image")
dependency_health()
raw_image_triage_gate()
query_evtx_file(evtx_path="/c:/Windows/System32/winevt/Logs/System.evtx", event_ids="7045,104,1102")
query_prefetch_files(directory="/c:/Windows/Prefetch")
service_persistence_gate(include_mounted_image=True)
```

Raw-image mode는 표적 검증에 유용하지만, 타임라인, 룰팩, 리포트까지 넓게 보려면 KAPE/AXIOM 파싱 케이스가 더 적합합니다.

## 환경 변수

| 변수 | 기본값 | 목적 |
|---|---:|---|
| `FW_TIMEOUT_LIGHT` | `120` | 메타데이터와 가벼운 MCP 호출 |
| `FW_TIMEOUT_MEDIUM` | `600` | 검색, IOC 추출, Volatility, 리포트 |
| `FW_TIMEOUT_HEAVY` | `1200` | 타임라인, 상관분석, 탐지, auto triage |
| `FW_EVENT_LOG_MAX_BYTES` | `20971520` | MCP 이벤트 로그 회전 크기 |
| `FW_EVENT_BACKFILL` | `50` | MCP Monitor 연결 시 되돌려 보여줄 이벤트 수 |
| `FORENSIC_KAPE_PATH` | empty | 명시적 `kape.exe` 경로 |
| `FORENSIC_GHIDRA_DIR` | empty | 명시적 Ghidra 설치 경로 |

## 개발

의존성 설치:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd frontend
npm install
```

주요 백엔드 테스트:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\test_dependency_diagnostics.py
.\.venv\Scripts\python.exe -m pytest backend\tests\test_evtx_semantic.py backend\tests\test_vss_tools.py
```

프론트엔드 빌드:

```powershell
cd frontend
npm.cmd run build
```

프론트엔드 개발 서버:

```powershell
cd frontend
npm.cmd run dev -- --host 127.0.0.1
```

## 프로젝트 구조

```text
forensic-workstation/
├── backend/
│   ├── api/                 # FastAPI routes
│   ├── core/                # Connector, parser, analysis module
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

## 로컬 상태 파일

다음 파일과 디렉터리는 로컬에서 생성되며 git에 포함하지 않습니다.

- `backend/.active_case.json`
- `backend/.allowed_evidence.json`
- `backend/.mcp_events.jsonl`
- `backend/state/snapshots/`
- `backend/state/suppressions.json`
- `backend/hunt_packs/local/`
- `export/`

## 안전 주의사항

- 증거에서 추출한 파일은 악성일 수 있습니다. 추출된 바이너리는 정적 분석 대상으로만 다루고 실행하지 마세요.
- 0건 결과나 아티팩트 부재는 행위 부재의 증거가 아닙니다. 커버리지, 파서 실패, 소스 가용성을 같이 확인해야 합니다.
- Registry state는 캡처된 hive의 설정 상태를 보여줄 뿐 실행을 직접 증명하지 않습니다.
- Prefetch는 활성화된 시스템에서 실행 증거가 될 수 있지만, 단독으로 침해 결론을 내리기에는 부족합니다.

## 라이선스

Internal Use Only.
