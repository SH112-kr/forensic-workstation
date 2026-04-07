# KAPE Targets & Modules

이 디렉토리에는 KAPE의 전체 Target(379개)과 Module(493개) 설정 파일이 포함되어 있습니다.
바이너리(exe/dll)는 포함되지 않으며, `install.ps1`이 자동 다운로드합니다.

## 설치

`install.ps1` 실행 시 KAPE가 감지되면 이 파일들이 자동으로 KAPE 디렉토리에 복사됩니다.

수동 복사:
```
kape_custom/Targets/* → {KAPE}/Targets/
kape_custom/Modules/* → {KAPE}/Modules/
```

## 커스텀 파일 (우리가 추가/수정한 것)

### Targets
- **`Compound/ForensicWorkstation.tkape`** — AXIOM 동등 이상 커버리지의 통합 수집 Target (40+ 카테고리)
- **`Apps/OpenSSHServer.tkape`** — SYSTEM/NetworkService/LocalService .ssh 경로 추가 (C2 IP 수집)

### Modules
- **`Compound/ForensicWorkstation.mkape`** — EZ Parser + Hayabusa + Persistence 통합 Module (20개 파서)
- **`EZTools/RECmd/RECmd_Kroll.mkape`** — Kroll Batch 레지스트리 분석 Module

## 바이너리 (별도 설치 필요)

`install.ps1 -Full` 실행 시 자동 다운로드:
- EZ Tools (PECmd, MFTECmd, AmcacheParser 등) — ericzimmerman.github.io
- Hayabusa — github.com/Yamato-Security/hayabusa

수동 설치:
- KAPE (kape.exe) — kroll.com/kape (라이선스 필요)
