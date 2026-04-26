# Windows IR Knowledge Base for Framework Review

작성일: 2026-04-26

목적: 다음 세션에서 현재 프로젝트가 국내외 IR 지식, 방법론, 기술을 충분히 흡수했는지 검토하고, Windows 전용 자율 포렌식 프레임워크의 부족한 부분과 발전 방향을 논의하기 위한 기준 문서다.

## 1. 평가 범위

이 문서는 Windows endpoint IR, E01/디스크 이미지, EVTX, Registry, Prefetch, Amcache/Shimcache, SRUM, LNK/JumpList, USN/MFT, VSS, EDR/XDR telemetry 중심으로 작성한다.

범위 밖:

- Linux/macOS/cloud-only/network-device IR
- OT/ICS 전용 사고 대응
- 악성코드 동적 실행 분석
- 실제 악성 샘플 다운로드/실행

## 2. 국내 IR 기준

### 2.1 신고와 자료 보전

KISA 보호나라/KrCERT 침해사고 신고 안내는 국내 민간 분야 대응에서 반드시 반영해야 할 운영 기준이다.

핵심:

- 정보통신서비스 제공자는 침해사고 발생 사실을 알게 된 때부터 24시간 이내 신고해야 한다.
- 침해사고 원인 분석과 확산 방지를 위해 관련 자료 보전, 자료 제출, 현장조사 대응이 요구될 수 있다.
- 신고서에는 사고 유형, 기업/신고자 정보, 사고 현황, 대응 현황이 포함된다.

프로젝트 반영점:

- 분석 결과에는 `신고 필요성`, `자료 보전 필요성`, `원인분석 가능/불가능 사유`가 별도 필드로 나와야 한다.
- 자율 분석 결과가 “침해 가능성 있음”이어도 증거 불완전성, parser failure, blocked lane을 함께 기록해야 한다.
- E01/EVTX/Registry 원본 경로, 해시, parser status, chain of custody 필드를 보존해야 한다.

출처: [KISA 보호나라/KrCERT 침해사고 신고 안내](https://www.krcert.or.kr/kr/subPage.do?menuNo=205033)

### 2.2 국내 랜섬웨어/침해사고 기술보고서 관점

KrCERT/KISA 기술보고서는 국내 사고 대응에서 다음 항목을 반복적으로 강조한다.

- VPN/RDP/외부 접속 경로 통제
- 해외 접속, 불필요 계정, 허용 IP 관리
- 랜섬웨어 대응 가이드와 안전한 백업 체계
- 사고 후 원인분석, 재발방지, 접근통제 강화

프로젝트 반영점:

- Windows 원격접속 이벤트는 단일 이벤트로 C2를 확정하지 말고, 접속 계정, 접속 시간, 소스 IP, 이후 실행/파일/네트워크 행위와 연결해야 한다.
- ransomware verdict는 ransom note + encrypted extension + file rewrite/USN/MFT + process lineage 중 최소 2개 이상을 요구해야 한다.
- 백업/VSS 삭제는 공격 신호일 수 있지만 정상 운영 신호와 구분하기 위한 maintenance window, admin account, change ticket proxy가 필요하다.

출처: [KrCERT 블랙캣 랜섬웨어 침해사고 기술보고서](https://www.krcert.or.kr/common/cmm/fms/FileDown.do?atchFileId=FILE_000000000081203&bbsId=B0000127&fileSn=1)

## 3. 해외 IR 방법론

### 3.1 NIST SP 800-61 Rev. 3

NIST SP 800-61 Rev. 3는 기존의 정적인 incident handling guide에서 벗어나 CSF 2.0과 연결된 위험관리형 IR로 바뀌었다. 핵심 구조는 다음과 같다.

- 준비 기반: Govern, Identify, Protect
- IR 생명주기: Detect, Respond, Recover
- 지속 개선: lessons learned를 Identify/Improvement로 되돌려 모든 기능에 반영

프로젝트 반영점:

- 단순 verdict가 아니라 `detect/respond/recover` 단계별 산출물을 분리해야 한다.
- bias guard는 NIST의 continuous improvement에 해당한다.
- blocked lane, negative evidence, parser failure는 Detect 단계의 한계로 명시해야 한다.

출처: [NIST Incident Response / SP 800-61 Rev. 3](https://csrc.nist.gov/projects/incident-response)

### 3.2 SANS PICERL

SANS의 고전적 IR 단계는 다음 6단계다.

- Preparation
- Identification
- Containment
- Eradication
- Recovery
- Lessons Learned

프로젝트 반영점:

- 현재 프로젝트는 Identification과 일부 Containment handoff에 강하다.
- Eradication/Recovery는 아직 “권고” 수준이며 자동 검증 체계는 약하다.
- Lessons Learned는 regression fixture와 external validation으로 구현되어야 한다.

출처: [SANS Incident Management 101](https://www.sans.org/white-papers/1516/), [SANS 504 Incident Response Cycle Cheat Sheet](https://www.sans.org/media/score/504-incident-response-cycle.pdf)

### 3.3 CISA Incident and Vulnerability Response Playbooks

CISA 연방정부 playbook은 incident와 vulnerability response를 표준 절차로 분리한다. 핵심은 식별, 조정, 완화, 복구, 추적이다.

프로젝트 반영점:

- 사고 판정과 취약점/노출 판정을 분리해야 한다.
- “취약한 VPN/RDP가 있었다”와 “그 경로로 침해가 발생했다”는 별도 결론이어야 한다.
- 자율 분석 결과에 `mitigation_tracking` 또는 `remediation_tasks`를 추가할 가치가 있다.

출처: [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/ncas/current-activity/2021/11/16/new-federal-government-cybersecurity-incident-and-vulnerability)

### 3.4 Microsoft Incident Response / DART Ransomware Approach

Microsoft IR은 ransomware 조사에서 데이터 기반 접근을 강조한다.

핵심:

- 현재 상황과 범위를 먼저 파악한다.
- 최초 인지 시점, 영향 범위, 진입 경로를 묻는다.
- 공격자가 증거를 삭제하거나 은폐할 수 있으므로 전체 chain이 항상 남지는 않는다.
- Defender for Endpoint, Identity, Office 365, Cloud Apps 등 여러 telemetry를 결합한다.

프로젝트 반영점:

- ransomware는 “암호화 결과”만이 아니라 initial access, identity compromise, lateral movement, backup destruction까지 chain으로 재구성해야 한다.
- 증거 은폐 가능성 때문에 “없음”과 “수집되지 않음”을 구분해야 한다.
- Windows endpoint만 보더라도 identity telemetry와 endpoint telemetry를 분리해야 한다.

출처: [Microsoft Incident Response ransomware approach](https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach)

## 4. Windows IR 핵심 증거 축

### 4.1 Event Logs / EVTX

중요 이벤트군:

- Logon/logoff: 4624, 4625, 4634, 4648, 4672
- Account changes: 4720, 4722, 4728, 4732, 4738
- Service install: 7045
- Scheduled tasks: 4698, 4702, TaskScheduler Operational
- PowerShell: 4103, 4104, 400, 600
- Log clear: 1102, 104
- RDP: 1149, 21, 24, 25, 4624 type 10
- Sysmon if present: 1, 3, 7, 10, 11, 13, 22

프로젝트 개선 후보:

- EVTX semantic parser를 E01 내부에서 직접 실행
- 단일 이벤트 rule이 아니라 sequence rule 도입
- RDP 1149 known_gap을 `RDP access evidence`와 `C2 tunneling evidence`로 분리
- Hayabusa/Sigma 결과를 normalized artifact로 import

관련 도구/자료:

- [Velociraptor forensic analysis](https://docs.velociraptor.app/docs/forensic/)
- [Hayabusa GitHub](https://github.com/Yamato-Security/hayabusa)
- [SigmaHQ](https://sigmahq.io/sigma/)

### 4.2 Registry

중요 hive와 key:

- SYSTEM: services, ControlSet, mounted devices, timezone
- SOFTWARE: installed software, uninstall, policy, Windows Defender
- SAM/SECURITY: local users, logon policy
- NTUSER.DAT: Run/RunOnce, Explorer artifacts, UserAssist, MRU
- UsrClass.dat: Shellbags, COM, file association abuse

프로젝트 개선 후보:

- E01에서 Registry hive 후보만 찾는 단계를 넘어 RECmd-like key extraction 구현
- persistence 판단은 Run key, Services, Scheduled Tasks, WMI, Startup Folder를 cross-check
- 정상 admin tool과 persistence abuse를 분리하기 위한 signer/path/account 기준 추가

### 4.3 Prefetch / Amcache / Shimcache

분석 목적:

- 실행 흔적
- 최초/마지막 실행 시각
- 실행 경로
- 프로그램 존재 여부
- 삭제된 파일의 과거 실행 단서

주의:

- Prefetch 존재는 실행 강한 증거지만 모든 시스템에서 활성화되어 있지 않을 수 있다.
- Shimcache/Amcache는 실행 증거와 파일 존재 증거가 혼재되므로 단독 결론에 쓰면 안 된다.

프로젝트 개선 후보:

- E01 내부 Prefetch parser 추가
- Amcache/Shimcache를 `execution_possible`, `execution_likely`, `file_seen`로 구분
- malicious verdict에는 process lineage 또는 timeline corroboration 요구

### 4.4 MFT / USN / $LogFile

분석 목적:

- 대량 파일 변경
- extension churn
- 삭제/rename/write burst
- ransomware impact
- staging/archive creation

프로젝트 개선 후보:

- ransomware 판정에 USN/MFT burst score 추가
- 정상 대량 migration/backup과 ransomware를 구분하기 위한 entropy, extension pattern, process owner, write fan-out 비교
- E01에서 $MFT/$UsnJrnl parser lazy extraction 구현

### 4.5 SRUM / Network / Browser

분석 목적:

- 프로세스별 네트워크 사용량
- cloud sync / browser upload
- user-driven exfil vs background sync

주의:

- SRUM 대량 송신은 exfil 후보일 뿐이다.
- 정상 백업, 클라우드 마이그레이션, 브라우저 다운로드/업로드와 구분이 필요하다.

프로젝트 개선 후보:

- 정상 cloud migration fixture 추가
- insider exfil verdict에 business-hour, approved app, change-window, destination classification 기준 추가
- cloud_exfil은 USB/sensitive access와 AND 조건만으로는 부족하며 account role과 data sensitivity 근거가 필요하다.

### 4.6 VSS / Backup / Anti-Forensics

분석 목적:

- vssadmin delete shadows
- wbadmin delete catalog
- bcdedit recovery disable
- wevtutil clear-log
- PowerShell logging tamper

주의:

- VSS/log clearing은 강한 suspicious signal이지만 정상 관리 작업 가능성이 있다.
- anti-forensics는 impact lane을 자동으로 확정하지 않는다.

프로젝트 개선 후보:

- anti-forensics verdict는 `tamper action + suspicious actor/process + temporal proximity to intrusion/impact`를 요구
- 정상 maintenance fixture 추가
- `preserve_and_reconstruct` decision은 낮은 confidence와 next evidence collection 중심으로 제한

## 5. Detection Engineering 지식

### 5.1 MITRE ATT&CK

ATT&CK는 공격자 행위를 tactic/technique/data source로 정리한다. 중요한 것은 technique 이름 자체가 아니라 data source와 data component다.

프로젝트 반영점:

- “T1059 PowerShell” 같은 label만으로 결론을 내면 안 된다.
- command, process, file, registry, logon session, network traffic 등 data source별 관측 근거를 별도 보존해야 한다.
- ATT&CK analytics는 cause-effect chain을 강조한다. 예: user-facing app open → downloaded file → LOLBin child process → outbound network.

출처:

- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/)
- [MITRE ATT&CK Analytics](https://attack.mitre.org/analytics/)
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/)

### 5.2 Sigma / Hayabusa / Chainsaw 계열

Sigma는 SIEM/log detection을 공유하기 위한 YAML rule format이다. Hayabusa는 Windows EVTX를 빠르게 timeline/threat hunting 형태로 요약한다.

프로젝트 반영점:

- Sigma rule을 직접 소비하거나 Hayabusa output을 normalized artifact로 import할 수 있어야 한다.
- Sigma rule hit는 verdict가 아니라 evidence candidate로 취급해야 한다.
- rule severity와 false positive notes를 bias guard에 반영해야 한다.

출처:

- [SigmaHQ](https://sigmahq.io/sigma/)
- [Hayabusa](https://github.com/Yamato-Security/hayabusa)

### 5.3 Velociraptor / Live Response

Velociraptor는 VQL 기반으로 filesystem, EVTX, ETW, volatile state를 수집/분석한다. Live response의 장점은 휘발성 지표를 볼 수 있다는 점이다.

프로젝트 반영점:

- 현재 프로젝트는 offline E01/MFDB/KAPE에 강하다.
- 향후 live endpoint 수집 결과를 동일 normalized schema로 ingest하면 실무성이 올라간다.
- live response는 오염 가능성이 있으므로 collection provenance와 read-only/offline evidence를 분리해야 한다.

출처: [Velociraptor forensic analysis](https://docs.velociraptor.app/docs/forensic/)

## 6. 고급 Windows IR 분석가의 사고방식

### 6.1 단일 IOC보다 chain

고급 분석가는 다음 질문을 연결한다.

- 누가 실행했는가?
- 어떤 부모 프로세스에서 시작됐는가?
- 파일은 어디서 생성됐는가?
- 같은 시간대 logon/session은 무엇인가?
- 네트워크/파일/registry 변화가 뒤따랐는가?
- 정상 운영 설명이 가능한가?

프로젝트 개선 후보:

- causal_chain graph를 더 엄격하게 사용
- temporal proximity만으로 causal claim을 만들지 않기
- parent-child-process, user session, file write, network connect를 같은 chain id로 묶기

### 6.2 부재 증거의 의미를 구분

구분해야 할 상태:

- not_seen: 수집했지만 없음
- unavailable: 시스템에 원래 없음
- not_loaded: 수집했지만 parser 미실행
- parser_failed: 수집했지만 분석 실패
- truncated: pagination/limit 때문에 일부만 봄

프로젝트 개선 후보:

- `truncated=true`면 strong conclusion 금지
- 2500 row limit 초과 시 undercall risk 자동 표시
- parser failure를 hidden warning이 아니라 verdict confidence에 반영

### 6.3 정상 운영 가설을 강제로 생성

오탐을 줄이려면 모든 suspicious pattern에 정상 가설이 필요하다.

예:

- VSS deletion: 정기 백업/스토리지 정리
- RDP logon: helpdesk/admin maintenance
- cloud upload: 승인된 migration/backup
- PowerShell: 관리 스크립트
- archive creation: 배포/백업/압축 업무

프로젝트 개선 후보:

- benign alternative generator
- maintenance window detector
- business-hour/account-role baseline
- approved tool inventory

## 7. 현재 프로젝트와의 매핑

이미 반영된 강점:

- synthetic fixture 기반 편향 회귀검사
- benign remote admin false positive 방지
- incomplete/empty case에서 강한 결론 금지
- APT29 stage reconstruction 검증
- E01 direct inventory와 expected marker 검증
- privacy gateway와 sensitive value tokenization
- Claude post-review gate

부족한 부분:

- E01 내부 EVTX/Registry/Prefetch semantic parser
- 대형 케이스 pagination/truncation gate
- 정상 cloud migration/backup fixture
- 정상 VSS/log clearing maintenance fixture
- Sigma/Hayabusa/Chainsaw output ingest
- Registry/USN/MFT parser 수준의 ransomware impact scoring
- RDP tunneling attribution을 위한 network/session correlation

## 8. 다음 세션 논의 질문

1. Windows-only 기준에서 가장 먼저 구현할 parser는 무엇인가?
   - EVTX semantic parser
   - Registry hive parser
   - Prefetch parser
   - USN/MFT parser

2. anti-forensics 과탐을 어떻게 줄일 것인가?
   - 단일 category 금지
   - 정상 maintenance 가설 생성
   - intrusion/impact temporal proximity 요구

3. insider exfil 과탐을 어떻게 줄일 것인가?
   - 정상 cloud migration fixture
   - 승인 앱/승인 계정/업무 시간/대상 도메인 기준
   - USB + cloud + sensitive access 외 추가 corroboration

4. E01을 KAPE/MFDB 대체 수준까지 끌어올리려면 어떤 lazy parser pipeline이 필요한가?
   - artifact inventory
   - parser selection
   - extract-to-memory/read-only parsing
   - normalized artifacts
   - parser failure accounting

5. 해외 고급 Windows DFIR 분석가를 넘기 위한 자동화 차별점은 무엇인가?
   - bias regression by design
   - negative evidence accounting
   - causal chain discipline
   - multi-hypothesis verdict
   - privacy-preserving LLM handoff

## 9. 우선순위 제안

1. `truncated`/pagination hard gate
   - 대형 케이스 undercall 방지
   - strong conclusion 차단

2. E01 내부 EVTX parser
   - Windows IR 정확도에 가장 큰 직접 효과
   - Hayabusa/Sigma 연동 가능

3. 정상 cloud migration/backup fixture
   - insider exfil 과탐 검증

4. 정상 maintenance/VSS fixture
   - anti-forensics 과탐 검증

5. Registry + Prefetch parser
   - persistence/execution confidence 강화

6. USN/MFT burst scoring
   - ransomware impact 정확도 강화

## 10. 참고 출처

- NIST Incident Response / SP 800-61 Rev. 3: https://csrc.nist.gov/projects/incident-response
- SANS Incident Management 101: https://www.sans.org/white-papers/1516/
- SANS 504 Incident Response Cycle Cheat Sheet: https://www.sans.org/media/score/504-incident-response-cycle.pdf
- CISA Federal Incident and Vulnerability Response Playbooks: https://www.cisa.gov/ncas/current-activity/2021/11/16/new-federal-government-cybersecurity-incident-and-vulnerability
- Microsoft Incident Response ransomware approach: https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach
- KISA 보호나라/KrCERT 침해사고 신고 안내: https://www.krcert.or.kr/kr/subPage.do?menuNo=205033
- KrCERT 블랙캣 랜섬웨어 침해사고 기술보고서: https://www.krcert.or.kr/common/cmm/fms/FileDown.do?atchFileId=FILE_000000000081203&bbsId=B0000127&fileSn=1
- MITRE ATT&CK Data Sources: https://attack.mitre.org/datasources/
- MITRE ATT&CK Analytics: https://attack.mitre.org/analytics/
- MITRE ATT&CK Detection Strategies: https://attack.mitre.org/detectionstrategies/
- SigmaHQ: https://sigmahq.io/sigma/
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Velociraptor forensic analysis: https://docs.velociraptor.app/docs/forensic/
