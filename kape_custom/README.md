# KAPE Custom Targets & Modules

이 디렉토리의 파일들은 `install.ps1` 실행 시 KAPE 설치 디렉토리로 자동 복사됩니다.

## Targets

### ForensicWorkstation.tkape
AXIOM 동등 이상 커버리지의 통합 수집 Target. 40+ 아티팩트 카테고리 포함:
- 파일시스템 ($MFT, $J, $LogFile)
- 실행 증거 (Prefetch, AmCache, ShimCache)
- 레지스트리 (System, User, Other)
- 이벤트 로그 + RDP + ETL
- SRUM / SUM
- 브라우저 (Chrome, Edge, Firefox, IE)
- **SSH (OpenSSH Client + Server + SYSTEM 프로필)**
- 원격 접속 (RDP, TeamViewer, AnyDesk 등 16종)
- AV/보안 (Windows Defender + 서드파티)
- WER, 방화벽, 스케줄러, 클라우드, 메시징

### OpenSSHServer.tkape (수정)
기본 OpenSSH Server Target에 SYSTEM/NetworkService/LocalService 계정의 `.ssh` 디렉토리 추가.
침해사고에서 sshd는 SYSTEM으로 실행되므로 `C:\Windows\System32\config\systemprofile\.ssh\known_hosts`에 C2 IP가 기록됨.

## Modules

### RECmd_Kroll.mkape
RECmd의 Kroll Batch 파일을 사용한 레지스트리 종합 분석 모듈.
90,000+ key/value 추출 (Services, User Activity, Persistence 등).
