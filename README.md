# Forensic Workstation

디지털 포렌식 및 침해사고 대응(DFIR) 통합 분석 플랫폼

## 설치 방법

### 방법 1: Docker (권장 — 환경 설정 불필요)

```bash
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

# 자동 설치 (Docker 빌드 + MCP 등록 + KAPE 설정)
powershell -ExecutionPolicy Bypass -File setup-docker.ps1

# 또는 수동
docker compose up --build -d
```

브라우저에서 `http://localhost:8001` 접속
Claude Code 재시작하면 MCP 도구 자동 연결

> **KAPE 관련 참고사항**
>
> KAPE(수집/파싱)는 Windows 전용 도구이므로 Docker 환경에서는 실행할 수 없습니다.
> KAPE는 별도 Windows PC에서 실행한 후, 파싱된 결과(CSV)를 evidence 디렉토리에 넣으면 Docker에서 분석 가능합니다.
>
> ```bash
> # Windows에서 KAPE 수집 후 결과를 마운트
> docker run -p 8001:8001 \
>   -v /path/to/kape/parsed:/evidence/kape_output \
>   -v /path/to/Case.mfdb:/evidence/Case.mfdb \
>   forensic-workstation
> ```

### 방법 2: Windows 네이티브 (KAPE 수집까지 필요한 경우)

```powershell
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

# 자동 설치 (Python 3.10+, Node.js 필수)
powershell -ExecutionPolicy Bypass -File install.ps1 -Full

# 실행
start.bat
```

`install.ps1 -Full`이 자동으로 설치하는 것:
- Python 패키지 (FastAPI, Volatility3, pyhidra 등)
- Node.js 프론트엔드 빌드
- EZ Tools, Hayabusa (자동 다운로드)
- JDK 21, Ghidra, Wireshark (winget)
- KAPE 경로 탐지 + 커스텀 Target/Module 배포
- KAPE EZ Tools runtimeconfig.json 자동 수정
- Claude Code MCP 서버 등록

> **KAPE는 수동 설치 필요**: [Kroll KAPE 다운로드](https://www.kroll.com/kape) (라이선스 필요)
> 설치 후 `install.ps1`을 다시 실행하면 자동 탐지됩니다.

## Docker vs Windows 기능 비교

| 기능 | Docker | Windows 네이티브 |
|------|--------|-----------------|
| MFDB (AXIOM) 분석 | O | O |
| KAPE CSV 분석 | O | O |
| 위협 탐지 (13개 룰) | O | O |
| 타임라인 / 검색 / IOC | O | O |
| SRUM 네트워크 분석 | O | O |
| Volatility 메모리 분석 | O | O |
| Ghidra 바이너리 분석 | O (Full) | O |
| YARA 스캔 | O | O |
| 네트워크 분석 (pyshark) | O (Full) | O |
| **KAPE 수집/파싱** | **X** | **O** |
| **EZ Tools 재파싱** | **X** | **O** |
| **SRUM 자동 복구** | **X** | **O** |

## 지원 파일 형식

| 형식 | 확장자 | 비고 |
|------|--------|------|
| AXIOM Case | `.mfdb` | 144종 아티팩트 |
| KAPE 파싱 결과 | CSV 디렉토리 | 26종 아티팩트 |
| 메모리 덤프 | `.raw`, `.vmem`, `.dmp` | Volatility3 |
| 디스크 이미지 | `.E01`, `.raw` | 파일 추출용 |
| 바이너리 | `.exe`, `.dll` | Ghidra 정적 분석 |
| 이벤트 로그 | `.evtx` | Hayabusa |
| 네트워크 캡처 | `.pcap`, `.pcapng` | pyshark |

## MCP 도구 요약

Claude Code / Codex에서 호출 가능한 도구들입니다. 모든 도구는 오프라인이며 외부 API를 호출하지 않습니다.

### 케이스 / 검색
- `open_case`, `get_summary`, `get_artifact_types`
- `search_artifacts`, `get_hit_detail`, `search_by_hash`
- `build_timeline`, `correlate`, `extract_iocs`, `map_to_mitre`
- `slice_timeline` — user/process/host/path 필터 적용한 타임라인
- `query_result`, `get_tagged_hits`

### 멀티케이스 (여러 케이스 동시 로드)
- `compare_cases` — 메타데이터 + 아티팩트 카운트 매트릭스
- `pivot_across_cases` — hash/ip/username/filename/keyword로 전체 케이스 피벗
- `coverage_explainer` — 검색 가능 / 레코드 없음 / 구조적 미제공 분류
- `explain_zero_results` — 0건 결과의 원인 진단 + 후속 쿼리 제안

### 탐지
- `find_suspicious` — 13개 구조화된 룰 + CLAUDE.md 강도 태그 + 증거 출처 + 룰 suppression 자동 적용
- `detect_anti_forensics` — ATT&CK T1070.*/T1562.*/T1490 번들 (volume snapshot 삭제, 로그 정리, USN 삭제, PS 로깅 tamper 등)
- `hunt_evtx_rules` — 12개 내장 Sigma-style 룰 (failed logon burst, 계정 생성, Kerberos weak enc, firewall edits 등)
- `assess_evidence_strength` — confirmed / strong / moderate / weak 분류
- `baseline_diff` — 정상 Windows 기준선 또는 레퍼런스 케이스 대비 net-new 서비스/태스크/자동실행/사용자

### 조사 관리
- `save_case_snapshot` / `list_case_snapshots` / `load_case_snapshot` — 태그/필터/노트 스냅샷
- `list_suppressions` / `add_suppression` / `remove_suppression` — 노이즈 룰 정확 ID 매칭 무시
- `list_hunt_packs` / `run_hunt_pack` — 내장 레시피(`log_tamper_sweep`, `persistence_sweep`, `remote_access_sweep`) 원콜 실행

### E01 이미지 / 바이너리 / 메모리
- `mount_image`, `list_files`, `extract_file`, `get_file_timestamps`
- `analyze_binary`, `ghidra_decompile`, `ghidra_suspicious_apis`, `ghidra_strings`, `ghidra_functions`, `ghidra_exports`, `ghidra_imports`
- `vol_load_memory`, `vol_pslist`, `vol_pstree`, `vol_netscan`, `vol_cmdline`, `vol_malfind`

### 로그 / WER / SRUM
- `import_logs`, `search_logs`, `log_stats`
- `search_wer_reports`, `srum_by_process`

### 마스킹 / 타임존 / 리포트 / 자동
- `enable_masking`, `disable_masking`, `set_timezone`
- `generate_report` — HTML 리포트(coverage + anti-forensics + strength 통합)
- `auto_triage` — KAPE 수집 → 파싱 → find_suspicious → strength + anti-forensics + coverage → 리포트 자동화

## 환경변수

| 변수 | 기본값 | 용도 |
|---|---|---|
| `FW_TIMEOUT_LIGHT` | 120 | 메타데이터 / Ghidra 조회 등 가벼운 도구 타임아웃(초) |
| `FW_TIMEOUT_MEDIUM` | 600 | Volatility / 검색 / IOC 추출 / 리포트 |
| `FW_TIMEOUT_HEAVY` | 1200 | `build_timeline` / `correlate` / `find_suspicious` / `auto_triage` |
| `FW_EVENT_LOG_MAX_BYTES` | 20971520 | `.mcp_events.jsonl` 회전 크기(바이트). 초과 시 덮어쓰기 |
| `FW_EVENT_BACKFILL` | 50 | CopilotPanel WebSocket 접속 시 백필할 이벤트 수 |
| `FORENSIC_KAPE_PATH` | — | KAPE.exe 명시 경로 (자동 탐지 실패 시) |
| `FORENSIC_GHIDRA_DIR` | — | Ghidra 설치 디렉토리 (자동 탐지 실패 시) |

## 개발 / 기여

### 테스트 실행
```bash
cd backend
pip install pytest
pytest
```
67개 단위 테스트가 오프라인으로 `MockConnector` 픽스처를 사용해 실행됩니다. 실제 MFDB/KAPE 데이터 불필요.

GitHub Actions CI가 push/PR마다 동일 스위트를 자동 실행합니다 (`.github/workflows/tests.yml`).

### 저장소 내 상태 파일 (gitignored)
- `backend/.active_case.json` — 활성 케이스 메타
- `backend/.allowed_evidence.json` — 사용자 허용 증거 경로
- `backend/.mcp_events.jsonl` — MCP 실행 로그 (회전됨)
- `backend/state/snapshots/` — 조사 스냅샷
- `backend/state/suppressions.json` — 룰 무시 목록
- `backend/hunt_packs/local/` — 분석가 자작 헌트 팩

## 프로젝트 구조

```
forensic-workstation/
├── backend/           # Python FastAPI 백엔드
│   ├── api/           # REST API 엔드포인트
│   ├── core/          # 커넥터, 분석 엔진, 파서
│   └── mcp_bridge.py  # Claude Code MCP 서버
├── frontend/          # React 웹 UI
├── kape_custom/       # 커스텀 KAPE Target/Module
│   ├── Targets/       # ForensicWorkstation.tkape 등
│   └── Modules/       # RECmd_Kroll.mkape 등
├── Dockerfile         # Full (Ghidra + Volatility)
├── Dockerfile.lite    # Lite (Ghidra 제외)
├── docker-compose.yml
├── install.ps1        # Windows 자동 설치
└── start.bat          # Windows 실행
```

## 라이선스

Internal Use Only
