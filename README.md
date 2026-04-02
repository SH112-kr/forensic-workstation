# Forensic Workstation

디지털 포렌식 및 침해사고 대응(DFIR) 통합 분석 플랫폼

## 요구사항

- Python 3.10+
- Node.js 18+
- 분석 도구 (선택): Hayabusa, Volatility3, Ghidra, YARA

## 설치

```powershell
# Windows 자동 설치 (권장)
powershell -ExecutionPolicy Bypass -File install.ps1 -Full

# 또는 수동 설치
cd backend && pip install -r requirements.txt
cd frontend && npm install && npm run build

# 환경 변수 설정
cp backend/.env.example backend/.env
# backend/.env 파일을 편집하여 Ghidra 경로 등 설정
```

## 실행

```bash
# 개발 모드 (프론트엔드 + 백엔드 분리)
cd frontend && npm run dev      # 터미널 1 - http://localhost:5173
cd backend && python main.py    # 터미널 2 - http://localhost:8001

# 프로덕션 모드 (빌드 후 통합 실행)
python backend/main.py
```

포트 충돌 시 8001~8010 범위에서 자동으로 사용 가능한 포트를 선택합니다.

## 지원 파일 형식

| 형식 | 확장자 | 분석 도구 |
|------|--------|-----------|
| AXIOM Case | `.mfdb` | 내장 파서 |
| 메모리 덤프 | `.raw`, `.vmem` | Volatility3 |
| 바이너리 | `.exe`, `.dll` | Ghidra |
| 이벤트 로그 | `.evtx` | Hayabusa |
| 네트워크 캡처 | `.pcap` | 내장 파서 |

## 환경 변수 (선택)

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `PORT` | 백엔드 포트 | `8001` |
| `FORENSIC_HAYABUSA_PATH` | Hayabusa 실행 파일 경로 | PATH에서 탐색 |

## 라이선스

Internal Use Only
