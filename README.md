# Forensic Workstation

디지털 포렌식 및 침해사고 대응(DFIR) 통합 분석 플랫폼

## 설치 방법

### 방법 1: Docker (권장 — 환경 설정 불필요)

```bash
git clone https://github.com/SH112-kr/forensic-workstation.git
cd forensic-workstation

# Full 버전 (Ghidra + Volatility + 모든 분석 도구)
docker compose up --build

# 또는 Lite 버전 (Ghidra 제외, 빠른 빌드)
docker build -f Dockerfile.lite -t forensic-workstation-lite .
docker run -p 8001:8001 -v ./evidence:/evidence forensic-workstation-lite
```

브라우저에서 `http://localhost:8001` 접속

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
