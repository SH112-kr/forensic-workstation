# Windows IR Improvement Roadmap

작성일: 2026-04-26

이 문서는 현재 프로젝트를 Windows endpoint DFIR 자율 분석 프레임워크로 평가한 결과와, Claude의 추가 리뷰를 반영한 실행 로드맵이다.

## 1. 현재 평가

Claude 평가 기준 총점: **7.3 / 10**

| 항목 | 점수 | 요약 |
|---|---:|---|
| 정확도 | 7.5 | synthetic/external 검증은 통과. production recall/precision은 미측정 |
| 편향 억제 | 8.0 | bias guard, competing hypotheses, negative evidence 구조는 강점 |
| E01 직접 분석 | 6.5 | inventory/marker 검증은 가능. full semantic parsing은 미완 |
| APT급 재구성 | 7.5 | APT29 JSON stage 9/9 성공. multi-artifact/multi-host는 미검증 |
| 자율성 | 7.0 | gated verdict는 좋지만 adaptive evidence collection loop가 부족 |

현재 역할:

- Windows endpoint IR 1차 분석 보조: 투입 가능
- 단독 최종 판정 엔진: 아직 부족

## 2. 핵심 판단

로드맵의 큰 순서는 맞다.

1. 기반 안정화
2. 편향 fixture 보강
3. E01/Windows parser 확장
4. 대형 artifact scoring
5. multi-artifact APT reconstruction
6. multi-host lateral movement graph

다만 각 단계는 서로 다른 편향/성능 리스크를 갖는다. 특히 P1, P5, P6/P7은 기능 가치가 높은 만큼 새 overcall 표면과 성능 병목을 만들 수 있다.

## 3. 우선순위 로드맵

## P0. Pagination / Truncation Hard Gate

목표: 대형 케이스에서 핵심 증거가 limit 뒤에 있어 undercall되는 문제 방지.

편향 리스크: 낮음  
성능 리스크: 중간

구현 항목:

- 모든 search/timeline/query 결과에 `total`, `returned`, `truncated`, `remaining_count` 표준화
- `truncated=true`면 `allow_strong_conclusion=false`
- `truncated=true`면 autonomous output에 `pagination_required` next step 추가
- 자동 pagination loop 추가
- `max_pages` 상한 추가
  - 기본 후보: `max_pages=20`
  - 초과 시 남은 건수를 gap으로 기록하고 중단
  - 초과 상태에서는 strong conclusion 계속 금지

fixture 설계:

- 단순히 “2500번째 이후에만 증거가 있음”은 너무 인위적이다.
- 더 현실적인 fixture:
  - benign noise 10,000 rows
  - 증거가 2,000번째, 3,500번째, 7,000번째에 분산
  - 일부 artifact family는 page 1에 있고 일부는 page 3 이후에 있음

구현 전 결정사항:

- `max_pages` 기본값
- page size 기본값
- 전체 query timeout
- page budget 초과 시 report 문구

성공 기준:

- 분산 증거 fixture에서 모든 page를 순차 확인
- budget 초과 시 undercall risk가 명시됨
- truncated 상태에서는 strong verdict가 절대 나오지 않음

## P1. E01 Internal EVTX Semantic Parser

목표: KAPE/MFDB 없이 E01 내부 EVTX를 직접 구조화해 Windows IR 핵심 이벤트를 분석.

편향 리스크: 높음  
성능 리스크: 높음

구현 항목:

- E01 내부 EVTX 후보 탐색
- read-only stream parsing 또는 temp-safe parsing
- 주요 이벤트 normalization
  - 4624, 4625, 4648, 4672
  - 7045
  - 4698, 4702
  - 1102, 104
  - 4103, 4104
  - TerminalServices 1149, 21, 24, 25
- parser failure와 missing channel 구분
- normalized artifact schema로 저장
- EVTX parser 추가 후 `bias-guard` 즉시 재실행 gate 추가

중요 정책:

- Sigma/Hayabusa rule hit는 verdict가 아니라 evidence hint다.
- rule hit가 `allow_strong_conclusion`을 우회해서 verdict를 직접 상승시키면 안 된다.
- EVTX temp 추출은 실행이 아니라 read-only parsing 용도로만 허용한다.
- temp 추출 디렉터리에는 `DO_NOT_EXECUTE` marker를 생성한다.
- 추출 파일을 subprocess로 실행하는 경로는 금지한다.

구현 전 결정사항:

- EVTX 라이브러리 선택
  - `python-evtx`: 설치 쉬움, 순수 Python, 대형 파일에서 느림
  - `libevtx-python`: C binding, 빠름, 설치/배포 검증 필요
  - Rust `evtx` crate bridge: 성능 우수, Python 연동 필요
- E01 내부 EVTX를 stream parsing할지 temp-safe parsing할지
- Security.evtx 수백 MB 이상에서 memory/time budget

성공 기준:

- CFReDS/M57/E01에서 EVTX 직접 구조화
- RDP access evidence와 C2 tunneling attribution 분리
- log clear 단독으로 compromise verdict 상승 금지
- EVTX parser 추가 후 기존 bias guard 0 failure 유지

## P2. Registry + Prefetch Parser

목표: execution/persistence confidence를 상용 도구에 가까운 수준으로 강화.

편향 리스크: 중간  
성능 리스크: 낮음

구현 항목:

- Registry hive parser
  - SYSTEM services
  - SOFTWARE uninstall/policy
  - NTUSER Run/RunOnce/UserAssist/MRU
  - UsrClass Shellbags
- Prefetch parser
  - executable name
  - run count
  - first/last run
  - path/volume references
  - loaded files/DLL references if available
- Amcache/ShimCache confidence 분리
  - `file_seen`
  - `execution_possible`
  - `execution_likely`

중요 편향 주의:

- Windows 10/11 ShimCache에는 executed bit가 없다.
- Win10/11 ShimCache entry는 기본적으로 `file_seen` 이상으로 상승시키면 안 된다.
- Windows 7/8에서 executed bit가 있는 경우에만 `execution_possible` 이상을 검토한다.
- UserAssist는 ROT13 decoding과 FILETIME/counter 해석 오류가 흔하다. 직접 구현보다 검증된 parser 사용을 우선한다.

구현 전 결정사항:

- Registry parser 라이브러리 선택
  - `python-registry`
  - `regipy`
  - 기타
- ShimCache OS version detection 방식
- UserAssist parser 직접 구현 여부

성공 기준:

- persistence verdict가 단순 key/path match가 아니라 Registry + execution + timeline corroboration을 요구
- Prefetch 기반 LOLBin 실행 chain 구성
- Win10/11 ShimCache만으로 execution verdict가 상승하지 않음

## P3. Normal Cloud Migration / Backup Fixture

목표: insider exfil 과탐 억제.

편향 리스크: 중간  
성능 리스크: 낮음

구현 항목:

- 정상 cloud migration fixture
- 정상 IT backup fixture
- 대량 파일 업로드 + USB backup + sensitive fileserver access 포함
- 승인 계정, 승인 앱, 업무 시간, change-window proxy 포함
- insider exfil 판정 시 benign business transfer alternative mandatory
- `business_transfer_likelihood` surface 추가

주의:

- `business_transfer_likelihood`가 너무 강하면 실제 insider exfil을 undercall할 수 있다.
- calibration 전에는 verdict를 직접 차단하지 말고 confidence 조정과 alternative 제시에만 사용한다.
- 승인 앱 판단은 filename allowlist만으로 하면 rename 우회에 취약하다.
- signer/path/account/window를 함께 본다.

구현 전 결정사항:

- business transfer 점수 범위
- threshold 초기값
- 승인 앱/계정/시간대 ground truth 표현 방식

성공 기준:

- 정상 migration case에서 `preserve_and_scope_exfiltration` 과잉 상승 없음
- 기존 insider exfil fixture는 계속 탐지

## P4. Normal Maintenance / VSS Fixture

목표: anti-forensics 과탐 억제.

편향 리스크: 중간  
성능 리스크: 낮음

구현 항목:

- 정상 VSS cleanup fixture
- 정상 event log rotation/clear fixture
- admin maintenance window simulation
- anti-forensics escalation 조건 강화
  - suspicious actor/process
  - intrusion/impact temporal proximity
  - multiple tamper families OR single family + intrusion proximity

주의:

- multiple tamper families만 요구하면 VSS delete 하나만 수행한 실제 공격자를 undercall할 수 있다.
- proximity window가 너무 넓으면 정상 maintenance FP가 증가한다.
- proximity window가 너무 좁으면 delayed cleanup FN이 증가한다.

구현 전 결정사항:

- proximity window 기본값
  - 후보: 30분, 2시간, 24시간
- single-family anti-forensics 공격자 처리 정책
- 정상 event log rotation과 adversary log clear 구분 필드

성공 기준:

- 정상 maintenance는 `monitor_or_validate_admin_activity`
- 공격성 anti-forensics는 `preserve_and_reconstruct`
- VSS/log clear 단독으로 compromise verdict가 상승하지 않음

## P0.5. Population-Based Calibration Track

목표: guardrail threshold가 policy 값에 머무르는 문제 완화.

필요성:

- P3/P4 fixture는 synthetic이므로 threshold 검증에 한계가 있다.
- 공개 DFIR challenge/writeup 기반 labelled cases라도 추가해야 threshold 조정이 데이터 기반이 된다.

구현 항목:

- 공개 DFIR challenge/writeup 기반 labelled cases 수집
- 정상/침해/애매한 케이스 분리
- threshold 변화에 따른 FP/FN 기록
- anti-forensics, cloud transfer, ransomware burst threshold calibration
- synthetic fixture와 public challenge 결과를 분리 보고

후보:

- Digital Corpora scenarios
- NIST CFReDS
- EVTX Attack Samples
- OTRF Security-Datasets
- 공개 DFIR CTF writeup + artifact

성공 기준:

- threshold 변경 전후 FP/FN 변화가 report에 남음
- policy threshold와 data-supported threshold를 구분

## P5. USN/MFT Burst Scoring

목표: ransomware impact 판단 고급화.

편향 리스크: 낮음에서 중간  
성능 리스크: 최고

구현 항목:

- `$MFT`, `$UsnJrnl`, `$LogFile` parser 검토
- streaming parser 또는 sparse E01 index 전략 결정
- chunk 단위 처리
- `max_rows_per_run` / `max_bytes_per_run` budget
- extension churn score
- write/delete/rename fan-out score
- file family diversity
- process/time/user correlation
- 정상 backup/copy와 ransomware 구분

성능 주의:

- 1TB 드라이브의 `$MFT`는 수백 MB에서 1GB 이상 가능
- `$UsnJrnl:$J`는 GB 단위 가능
- E01 내부에서 전체 추출 후 parsing하면 I/O와 CPU 모두 병목

구현 전 결정사항:

- streaming chunk 방식 vs sparse E01 index 방식
- burst threshold 초기값
  - 파일 수/분
  - rename/write/delete 비율
  - extension diversity
  - directory fan-out
- 정상 backup/copy fixture와 ransomware fixture를 먼저 확보할지

성공 기준:

- ransom note 없이도 대량 encrypted extension + USN burst로 impact suspected 가능
- ransom note만으로 ransomware 확정 금지
- 정상 backup/copy는 ransomware로 과탐하지 않음

## P6. Multi-Artifact APT Reconstruction

목표: 깨끗한 JSON 기반 APT 재구성을 실전 artifact 혼합 조건으로 확장.

편향 리스크: 중간  
성능 리스크: 높음

구현 항목:

- stage별 required evidence families 정의
- EVTX, Registry, Prefetch, MFT, memory output을 stage graph로 병합
- stage confidence 계산
- missing family와 parser failure 반영
- source conflict policy 추가
- entity index 선구축
  - process name/path/hash
  - user/session
  - host
  - IP/domain
  - file path

중요 설계 문제:

- EVTX는 T1, Registry last-write는 T2, Prefetch last-run은 T3처럼 시간이 충돌할 수 있다.
- temporal order를 causal order로 자동 변환하면 안 된다.
- naive cross-source join은 O(n²) 이상으로 커질 수 있다.

구현 전 결정사항:

- evidence conflict 처리 규칙
- clock skew 표시 방식
- entity index key 설계
- artifact family 간 join budget

성공 기준:

- 단일 source가 아닌 EVTX + Registry + Prefetch + MFT 기반 stage reconstruction
- stage별 undercall/overcall bias guard 추가
- 충돌하는 timestamp를 verdict에서 보존

## P7. Multi-Host Lateral Movement Graph

목표: 단일 endpoint 분석을 넘어 host-to-host 침해 경로 재구성.

편향 리스크: 중간  
성능 리스크: 높음

구현 항목:

- host entity schema
- user/session entity schema
- source/destination host edges
- RDP/SMB/WinRM/PsExec/Service install chain
- timeline merge
- entity index 기반 correlation
- naive all-to-all join 금지

구현 전 결정사항:

- host identity normalization 방식
- NAT/VPN/RDP gateway 표현 방식
- missing host evidence를 confidence에 반영하는 방식
- multi-host graph storage schema

성공 기준:

- “이 호스트에서 무슨 일이 있었는가”를 넘어 “어떤 순서로 이동했는가” 출력
- lateral movement confidence와 missing hosts 표시
- host 간 이동 edge가 단일 약한 이벤트로 과잉 생성되지 않음

## 4. 구현 순서

권장 순서:

1. P0 Pagination / Truncation Hard Gate
2. P3 Normal Cloud Migration / Backup Fixture
3. P4 Normal Maintenance / VSS Fixture
4. P0.5 Population-Based Calibration Track
5. P1 E01 Internal EVTX Semantic Parser
6. P2 Registry + Prefetch Parser
7. P5 USN/MFT Burst Scoring
8. P6 Multi-Artifact APT Reconstruction
9. P7 Multi-Host Lateral Movement Graph

이 순서의 이유:

- P0은 모든 대형 케이스 정확도에 영향을 주는 기반 문제다.
- P3/P4는 현재 확인된 overcall risk를 직접 줄인다.
- P0.5는 threshold가 순수 policy 값으로 남는 문제를 줄인다.
- P1/P2는 E01 단독 분석 능력을 실질적으로 끌어올린다.
- P5는 성능 리스크가 가장 크므로 parser 전략 결정 후 진행한다.
- P6/P7은 고급 분석가 초과 목표에 해당한다.

## 5. 점수 목표

현재:

| 항목 | 현재 |
|---|---:|
| 총점 | 7.3 |
| 정확도 | 7.5 |
| 편향 억제 | 8.0 |
| E01 직접 분석 | 6.5 |
| APT급 재구성 | 7.5 |
| 자율성 | 7.0 |

P0-P4 완료 후 목표:

| 항목 | 목표 |
|---|---:|
| 총점 | 8.3 - 8.6 |
| 정확도 | 8.3 |
| 편향 억제 | 8.7 |
| E01 직접 분석 | 7.8 |
| APT급 재구성 | 7.9 |
| 자율성 | 8.0 |

P0-P7 완료 후 목표:

| 항목 | 목표 |
|---|---:|
| 총점 | 9.0+ |
| 정확도 | 9.0 |
| 편향 억제 | 9.0 |
| E01 직접 분석 | 8.8 |
| APT급 재구성 | 9.0 |
| 자율성 | 8.8 |

## 6. 다음 세션 결정사항

1. P0부터 바로 구현할지
2. P0 `max_pages`, page size, timeout budget을 어떻게 둘지
3. P1 EVTX parser 라이브러리를 무엇으로 선택할지
   - `python-evtx`
   - `libevtx-python`
   - Rust `evtx` crate bridge
4. E01 EVTX parser를 직접 구현할지, Hayabusa/Chainsaw/Sigma output ingest부터 갈지
5. E01 parser에서 temp-safe extraction을 허용할지, stream parsing만 허용할지
6. P2 ShimCache Windows 버전별 confidence 정책을 어떻게 둘지
7. P3 정상 cloud migration fixture ground truth를 어떻게 설계할지
8. P4 정상 maintenance/VSS fixture에서 어떤 event 조합을 benign으로 둘지
9. P5 USN/MFT parser를 streaming chunk로 갈지 sparse E01 index로 갈지
10. P6/P7 entity index schema를 어떻게 설계할지

## 7. 결론

로드맵 방향은 맞다. 다만 P1, P5, P6/P7은 구현 방식에 따라 성능 병목과 새로운 편향 표면을 만들 수 있다. 다음 개발은 단순 기능 추가가 아니라 `budget`, `truncation`, `confidence`, `parser failure`, `rule-hit-is-not-verdict` 원칙을 먼저 고정한 뒤 진행해야 한다.
