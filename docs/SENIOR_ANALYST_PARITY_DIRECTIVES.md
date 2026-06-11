# Senior Analyst Parity — AI 개선 지시문

작성일: 2026-06-10
작성 주체: 침해사고 대응 분석가 관점의 코드베이스 전수 평가 (branch: raw-image-index 기준)
목표: **침해사고 조사 시 분석 성능(재현율/정밀도)과 속도가 고급 분석가 수준에 도달**

이 문서는 AI(Claude Code / Codex)에게 그대로 전달하는 실행 지시문이다.
기존 `docs/WINDOWS_IR_IMPROVEMENT_ROADMAP.md`(P0~P7)와
`docs/HYPOTHESIS_REFACTOR_BACKLOG.md`(IR-001~005)를 대체하지 않으며,
그 위에 얹는 **추가 격차**와 **우선순위 재조정**을 기술한다.
중복 항목은 해당 문서를 참조로만 표기한다.

## 실데이터 검증 결과 (2026-06-10, 실제 Windows 엔드포인트 E01)

raw 인덱서를 실제 Windows 엔드포인트 E01 이미지에 직접 실행해 end-to-end 검증.
- **Registry 인덱서 ✅ 1,388건**: System Services 846 / BAM 107 / USB 15 /
  AutoRun 14 / Office Trusted Documents 173 / Office Recent 233. (RDP Client
  Destinations 0 — 이 호스트는 아웃바운드 RDP 미사용, 정상)
- **MOTW 인덱서 ✅ 499건**: Downloads 1,735개 중 500 cap 도달을 정확히
  coverage_gap으로 보고.
- **EVTX 인덱서 ✅ 2,612건** (8채널): 없는 채널 2개 + OAlerts 1건 파싱실패를
  모두 coverage_gap으로 명시. no-miss semantics 실증.
- **발견·조치**: `python-evtx`가 런타임에 미설치여서 EVTX가 조용히 0건이 되던
  문제를 실데이터가 즉시 노출 → 설치 + `dependency_health`에 python-evtx(required)
  와 PyYAML(optional) 추가해 사전 감지. EVTX 전체 파싱이 ~10분으로 느림(순수
  파이썬 python-evtx) — 정확성은 OK, 성능은 로드맵 P1(libevtx/rust evtx)로.
- 검증 결론: 신규 아티팩트 파서(A-1~A-7) 전부 실데이터 작동 확인. 전체 793 passed.

---

## 0. 현재 상태 평가 요약

| 평가 축 | 점수 (10) | 근거 |
|---|---:|---|
| 편향 억제 구조 | 8.0 | lane_state_board hard gate, candidate_axes, negative_evidence, evidence_strength 4-tier — 동급 도구 대비 최상위. 단 soft warning 의존 구간과 silent-disable 경로 존재 |
| 실행 증거(execution) 커버리지 | 7.5 | Prefetch/AmCache/ShimCache/SRUM/UserAssist 완비. **BAM/DAM 부재**, MUICache 부재 |
| 초기 침투(ingress) 커버리지 | **4.5** | 3-lane 중 가장 약함. 브라우저 다운로드 + RDP뿐. **MOTW(Zone.Identifier), 이메일, Office TrustRecords, USB 이력 부재** |
| 영속성(persistence) 커버리지 | 6.5 | 서비스/스케줄 태스크/AutoRun 양호. **WMI 구독, BITS job, COM hijack/IFEO 부재** (코드 내 KNOWN_COVERAGE_GAPS로 자인) |
| 측면 이동(lateral movement) | 5.0 | 4624 Type 10/4648은 있으나 WinRM, 아웃바운드 RDP MRU, SmbClient, 4778/4779 부재. multi-host 그래프 없음 (P7) |
| 안티포렌식 | 7.0 | 로그 삭제/VSS/USN/서비스 중지 양호. **타임스톰프($SI vs $FN) 자동 탐지 부재** |
| 탐지 룰 폭 | 5.5 | find_suspicious 13개 + evtx 24개 = 정적 하드코딩. Sigma는 Hayabusa 외부 바이너리 의존, 갱신 경로 없음 |
| 분석 속도 (LLM 도구 호출 효율) | 6.5 | 91개 MCP 도구 중 8개 복합 팩은 우수. 페이지네이션 마찰(200 limit), auto-page 부재, 중복 커버리지 조회 |
| 성능 측정 가능성 | 6.0 | (2026-06-10 정정: 초기 평가 "5% 구현"은 오류) harness는 fixture 6종 + M1~M4 지표 + ingest/bias-guard CLI까지 구현되어 있고 baseline 1회 측정 존재(`docs/regression_baseline_2026-04-23.md`). 실제 공백은 분산 증거 fixture와 truncation 규율 지표였음 — 본 지시문 E-1에서 보완 완료 |

**핵심 판단 3가지:**

1. 이 도구의 최대 약점은 탐지 로직이 아니라 **ingress lane의 아티팩트 공백**이다.
   3-lane 가드레일(ingress / execution / persistence)이 잘 설계되어 있어도,
   ingress lane에 채울 아티팩트가 구조적으로 부족하면 lane gate가
   "ingress unverified" 상태로 영구 고착되어 모든 케이스에서 strong conclusion이
   차단되거나(과억제), 반대로 분석자가 gate를 우회하는 습관이 생긴다(가드레일 무력화).
2. 편향 억제는 구조가 아니라 **측정**이 병목이다. bias guard fixture는 있으나
   공개 데이터셋 기반 recall/precision 수치가 없어, 어떤 개선이 실제로
   분석 품질을 올렸는지 판단할 근거가 없다. IR-005를 뒤로 미루면 안 된다.
3. 속도의 병목은 파서 성능이 아니라 **LLM 왕복 횟수**다. truncation 재조회,
   페이지네이션 루프, lane 검증용 추가 호출이 한 케이스당 수십 회의 왕복을
   만든다. auto-page와 팩 통합이 파서 최적화보다 우선이다.

---

## 1. 공통 제약 (모든 지시 공통, 위반 시 작업 중단)

1. **추출 파일 실행 금지** — CLAUDE.md 절대 금지 사항 유지. 새 파서는 read-only
   stream parsing 또는 temp-safe parsing만 허용, temp 디렉터리에 `DO_NOT_EXECUTE`
   marker 생성 (로드맵 P1 정책 승계).
2. **No-miss semantics** — raw 인덱싱 경로의 최적화는 원본 재검증 가능해야 하며,
   추정 카운트/샘플링/silent fallback 금지 (`docs/raw-image-index-handoff.md` 승계).
3. **rule hit ≠ verdict** — 새 룰/파서의 hit는 evidence hint다.
   `allow_strong_conclusion` 게이트를 우회해 verdict를 직접 상승시키는 경로 금지.
4. **파서 추가 후 bias guard 재실행** — 새 아티팩트 family 추가 시
   `backend/regression/bias_guard.py` 0 failure 확인 후 머지.
5. **Codex 상호 검토 루프** — 기능 추가/수정은 사전·사후 Codex 교차 검토
   (overfitting / silent error / contract break / test coverage 4개 축).
6. **새 아티팩트는 3개 표면에 동시 등록** — (a) 커넥터 매핑,
   (b) `evidence_strength.py` tier 선언, (c) `rule_coverage.py` family 선언.
   하나라도 빠지면 해당 아티팩트는 가드레일 사각지대가 된다. 이를 검증하는
   단위 테스트(아티팩트 타입 ↔ 3개 표면 교차 대조)를 먼저 작성하라.

---

## 2. Part A — 아티팩트 커버리지 확장 지시

우선순위 기준: (lane 불균형 해소 기여) × (실제 침해사고 빈도) × (구현 비용).
**A-1~A-4는 기존 로드맵 P1/P2보다 먼저 또는 병행 착수하라** — P1/P2는
이미 있는 lane(execution)을 깊게 하지만, A-1~A-4는 비어 있는 lane(ingress)을 채운다.

### A-1. Mark-of-the-Web (Zone.Identifier ADS) 파서 — ✅ raw 경로 완료 (2026-06-10)

> **수행 결과**: `index_motw_artifacts`로 Downloads/Desktop/Documents의
> `<path>:Zone.Identifier` ADS를 파싱(ZoneId/ReferrerUrl/HostUrl),
> ADS 전수 읽기 실패는 `ads_read_unsupported` gap으로 표기(MOTW not-evaluable).
> 연계 룰 `motw_internet_origin_risky_file`(ZoneId 3/4 + 위험 확장자) 추가,
> evidence_strength=strong, rule_coverage alias 등록. **잔여**: KAPE/AXIOM
> 경로(MFTECmd ADS 컬럼) 매핑.

- **현재 상태**: 미지원. MFT 파싱(MFTECmd) 결과에 ADS 정보가 있어도 정규화/룰 없음.
- **지시**: MFT 레코드의 `Zone.Identifier` ADS를 파싱해
  `ZoneId`, `ReferrerUrl`, `HostUrl`을 정규화 아티팩트로 노출하라.
  KAPE 경로(MFTECmd CSV의 ADS 컬럼)와 raw 경로($MFT 직접) 모두 지원.
- **연계 룰**: "실행 증거가 있는 파일 중 ZoneId=3(인터넷 유래) + HostUrl 보유"를
  find_suspicious 신규 룰로 추가. 이것이 ingress→execution lane을 잇는
  가장 강한 단일 브리지 증거다.
- **수용 기준**: ingress lane의 `lane_evidence_summary`에 MOTW family가 표시되고,
  다운로드 유래 실행 파일에 대해 출처 URL이 타임라인에 나타난다.

### A-2. BAM/DAM (Background Activity Moderator) — ✅ raw 경로 구현 완료 (2026-06-10, D-4 §참조; KAPE/AXIOM 경로 매핑은 잔여)

- **현재 상태**: 미지원. SYSTEM hive `bam\State\UserSettings`는 Win10 1709+에서
  사용자별 실행 파일 경로 + 마지막 실행 시각을 제공하는 핵심 실행 증거.
- **지시**: registry 파서(P2와 통합)에 BAM/DAM 추출을 포함하고
  `evidence_strength.py`에 tier 선언 (단독 = strong, Prefetch/SRUM corroboration 시
  confirmed 상향 대상). **사용자 SID 귀속이 가능한 유일한 OS 실행 아티팩트**라는
  점을 docstring에 명시 — 계정 귀속 시나리오에서 우선 조회 대상.
- **수용 기준**: Prefetch가 비활성화된 서버 OS fixture에서 BAM만으로
  execution lane이 "suggested" 이상으로 채워진다.

### A-3. USB / 외부 장치 이력 — 🟡 USBSTOR raw 경로 구현 완료 (2026-06-10; setupapi.dev.log·MountPoints2·competing_hypotheses 연계 잔여)

- **현재 상태**: 미지원 (SRUM 네트워크는 있으나 물리 매체 없음).
  insider_data_exfil이 competing hypotheses 4개 중 하나인데 USB 증거가 없다.
- **지시**: ① SYSTEM hive `USBSTOR`/`USB` 키 (장치 시리얼, First/Last Connect),
  ② `C:\Windows\INF\setupapi.dev.log` (최초 연결 타임스탬프),
  ③ NTUSER `MountPoints2` (사용자-장치 연결) 3종을 파싱해
  "External Device" 아티팩트 family로 정규화하라.
- **연계**: `competing_hypotheses.py`의 insider_exfil 가설 supporting_signals에
  external_device 신호 추가. 단, **장치 연결 = 유출 아님** —
  연결 시각과 sensitive file access의 temporal correlation까지만 기술하고
  인과 주장 금지 (CLAUDE.md 상관≠인과 원칙).
- **수용 기준**: insider exfil fixture에서 USB 연결 ↔ 파일 접근 타임라인
  상관이 표시되고, 정상 백업 fixture(P3)에서 과탐하지 않는다.

### A-4. Office/문서 기반 초기 침투 아티팩트 — ✅ raw 경로 완료 (2026-06-10: TrustRecords + Office MRU + OAlerts EID 300 + `office_trustrecords_macro_enabled` 룰; KAPE 경로 매핑 잔여)

- **현재 상태**: 미지원. 피싱(악성 문서)이 ingress 1순위 벡터인데 증거 표면 없음.
- **지시**: ① NTUSER `...\Office\<ver>\<app>\Security\Trusted Documents\TrustRecords`
  (매크로 차단 해제 기록 — 사용자가 "콘텐츠 사용"을 누른 문서),
  ② Office MRU (최근 문서 + 시각), ③ `OAlerts.evtx` 파싱.
- **연계 룰**: "TrustRecords 등재 문서 + 동시간대 자식 프로세스 실행 증거" 신규 룰.
- **수용 기준**: 매크로 문서 fixture에서 ingress lane이 confirmed로 채워진다.

### A-5. WMI 영속성 + BITS job — 🟡 EVTX 룰로 부분 해소 (2026-06-10)

> **수행 결과**: BITS는 `fw-evtx-036`(BITS-Client 59/60/3)로 로그 기반 탐지
> 추가, KNOWN_COVERAGE_GAPS의 `bits_job_persistence`/`defender_tamper_events`/
> `wmi_event_subscription_persistence` 항목을 covered-by 주석으로 갱신.
> **잔여**: `OBJECTS.DATA`(WMI 구독) + `qmgr.db`(BITS ESE) 직접 파서는
> 미구현 — EVTX가 수집되지 않은 케이스에선 여전히 공백.

- **현재 상태**: `evtx_rules.py` KNOWN_COVERAGE_GAPS에 명시된 자인 공백.
- **지시**: ① `OBJECTS.DATA` 파서로 WMI event subscription
  (EventFilter / EventConsumer / FilterToConsumerBinding) 추출,
  ② `qmgr.db`(ESE) 파서로 BITS job (URL, 대상 경로, notify cmdline) 추출,
  ③ Microsoft-Windows-Bits-Client/Operational EVTX (EID 59/60/61) 룰 추가.
- **수용 기준**: KNOWN_COVERAGE_GAPS에서 두 항목 제거,
  persistence_sweep 헌트 팩에 단계 추가.

### A-6. 측면 이동(lateral movement) 아티팩트 묶음 — ✅ 대부분 완료 (2026-06-10)

> **수행 결과**: ① Terminal Server Client MRU 파서(`parse_rdp_client_mru`,
> Servers/Default 레이아웃 모두) → "RDP Client Destinations" 아티팩트(아웃바운드
> RDP 대상). ② EVTX 룰 추가: WinRM(`fw-evtx-037`), 4778/4779(`fw-evtx-038`),
> 아웃바운드 RDPClient 1024(`fw-evtx-039`), 4697 서비스 설치(`fw-evtx-025`).
> ③ 신규 헌트 팩 `lateral_movement_sweep.json` — **인바운드(피해자) vs
> 아웃바운드(발판)를 별도 lane으로 분리**해 묻는 구조. evidence_strength +
> rule_coverage 등록 완료. **잔여**: SmbClient EID 31001 룰.

- **현재 상태**: 인바운드 RDP만. 아웃바운드/원격 실행 흔적 부족.
- **지시**: ① NTUSER `Terminal Server Client\Servers` (아웃바운드 RDP 대상 MRU),
  ② Microsoft-Windows-WinRM/Operational (EID 6/91/168),
  ③ Microsoft-Windows-SmbClient/Security (EID 31001),
  ④ Security 4697(서비스 설치 — 7045의 Security 채널 쌍), 4778/4779(RDP 세션 재연결),
  ⑤ TerminalServices-RDPClient/Operational EID 1024/1102 (아웃바운드 연결 대상).
- **연계**: 신규 헌트 팩 `lateral_movement_sweep.json` 작성 —
  "이 호스트가 피해자인가, 발판(pivot)인가"를 양방향으로 묻는 구조로.
- **수용 기준**: 발판 호스트 fixture에서 아웃바운드 증거가 ingress 증거와
  분리된 lane으로 보고된다.

### A-7. Windows Defender 흔적 — 🟡 EVTX 룰로 부분 해소 (2026-06-10)

> **수행 결과**: `fw-evtx-034`(Defender 1116/1117 탐지),
> `fw-evtx-035`(5001/5007/1119 실시간 보호 해제/탐플) 룰 추가 — Operational
> EVTX 수집 시 삭제된 악성코드 탐지 이력 복원. **잔여**: MPLog-*.log +
> DetectionHistory 파일 파서(파일 기반, EVTX 미수집 케이스 대비).

- **현재 상태**: 미지원. 공격자가 파일을 지워도 Defender 로그에 탐지 이력이 남는
  경우가 많다 — 고급 분석가가 가장 먼저 보는 표면 중 하나.
- **지시**: ① Microsoft-Windows-Windows Defender/Operational EVTX
  (EID 1116/1117/1119, 5001/5007 — 탐지 + 보호 해제),
  ② `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`,
  ③ DetectionHistory 파일 파싱.
- **수용 기준**: 삭제된 악성 파일의 원경로/해시가 Defender 이력으로 복원되는
  fixture 통과. anti_forensics에 "Defender 실시간 보호 해제(5001)" 룰 추가.

### A-8. 서버 케이스 대비 — UAL (User Access Logging)

- **현재 상태**: 미지원. Windows Server의 `Current.mdb`(UAL)는 계정×원본IP×서비스
  접근 이력을 1년치 보관 — 서버 침해 케이스에서 가장 효율 높은 단일 아티팩트.
- **지시**: ESE 파서(A-5의 qmgr.db와 라이브러리 공유)로 UAL을 정규화하라.
  CLIENTS 테이블의 (사용자, 원본 IP, 서비스, 일별 접근 횟수)를 노출.
- **수용 기준**: 서버 이미지 fixture에서 의심 계정의 원본 IP 이력이
  search_artifacts로 조회된다.

### A-9. 타임스톰프 자동 탐지 — anti_forensics 공백 — ✅ 완료 (2026-06-10)

> **수행 결과**: `anti_forensics.py`에 `_rule_timestomp` 추가(T1070.006) —
> ① $SI Created < $FN Created(1초 초과) backdating, ② $SI sub-second=0 &
> $FN≠0(설치/압축 정상 패턴이므로 **의심 경로 게이트** 적용). MFT family
> 부재/$SI·$FN 컬럼 없음은 None(=미평가, not clean). 단독 weak, notes에
> "verdict 단독 상승 금지" 명시. AXIOM/MFTECmd/raw 행 shape 모두 대응하는
> 다중 필드명 후보. 검증: 6개 테스트.

- **현재 상태**: `get_file_timestamps`로 수동 확인만 가능. $SI/$FN 비교 룰 없음.
- **지시**: `anti_forensics.py`에 timestomp 룰 추가 —
  ① $STANDARD_INFORMATION < $FILE_NAME 생성 시각 (전형적 backdating),
  ② 초 단위 잘림(sub-second = 0) 휴리스틱.
  단, ②는 설치 프로그램/압축 해제에서 흔한 정상 패턴이므로
  **단독으로는 weak tier, 의심 경로/실행 증거 corroboration 시에만 상향**.
- **수용 기준**: timestomp fixture 탐지 + 정상 설치 fixture 무과탐.

### A-10. 적용 보류 (명시적 비대상)

- 모바일/채팅/카빙 계열은 AXIOM 고유 영역으로 raw 재구현 금지 (투자 대비 효과 낮음).
- 클라우드(M365 UAL, Entra 로그)는 `applicability.primary_domain` 확장이 선행돼야
  하므로 본 지시문 범위 밖. 단, `external_log_rescan_pack`이 받을 수 있는
  로그 포맷 목록에 M365 UAL CSV를 추가하는 것은 허용.

---

## 3. Part B — 탐지 룰 확장 지시

### B-1. Sigma 룰 네이티브 수용 (정적 하드코딩 탈피) — ✅ 완료 (2026-06-10)

> **수행 결과**: `core/analysis/sigma_loader.py` 신설 — Sigma YAML 서브셋
> (`logsource.product=windows` + `detection.selection`의 EventID + `|contains`
> 키워드, `condition: selection`만)을 BUILTIN_RULES 형식으로 변환.
> 미지원 기능(`|re`/`|base64`/`|all`/numeric/`1 of`/multiple selection)은
> **근사하지 않고 사유와 함께 drop**, `sigma_load.unsupported_feature_counts`
> +`unsupported_ratio`로 보고. 룰마다 `provenance.origin=sigma-community` +
> `evidence_hint_only` 강제. `hunt_evtx_rules(include_sigma=True)`가 빌트인과
> 합쳐 실행, 결과 정렬은 "유의성 아님" 명시. PyYAML 의존성 requirements 추가
> (없으면 graceful degradade). 룰 디렉터리 `backend/hunt_packs/sigma/` +
> 샘플 룰 + README. 검증: 12개 테스트, 전체 787 passed.

- **현재 상태**: find_suspicious 13개 + evtx_rules 24개가 Python dict 하드코딩.
  Sigma는 Hayabusa 외부 바이너리로만 가능, 룰 갱신 경로 없음.
- **지시**: `evtx_rules.py`에 Sigma YAML 서브셋 로더를 추가하라
  (`logsource.product=windows` + `detection.selection`의 EID/키워드 매칭 수준이면
  충분 — 풀 Sigma 스펙 구현 금지, 미지원 modifier는 명시적 skip + 사유 기록).
  룰 디렉터리: `backend/hunt_packs/sigma/`. 룰마다 `provenance` 필드
  (origin: builtin / sigma-community / case-derived)를 강제하라.
- **편향 주의**: 룰 수가 늘수록 "룰 hit 많음 = 침해"로 기울 수 있다.
  Sigma hit는 Hayabusa와 동일하게 evidence hint이며 severity 정렬 금지,
  `bias_remediation.select_key_findings`의 per-rule cap 적용 대상.
- **수용 기준**: 미지원 modifier 비율이 skip 사유와 함께 보고되고,
  bias guard 0 failure 유지.

### B-2. find_suspicious 룰의 캠페인 과적합 방지 태깅 — ✅ 완료 (2026-06-10)

> **수행 결과**: `RULE_SCOPE_MAP`으로 15개 룰 전부 scope 태깅 —
> `prefetch_pentest_tool_names`/`amcache_remote_access_tool_names`=
> campaign_specific, `prefetch_security_sw_werfault_correlation`=
> region_specific, 나머지 generic. findings[]·zero_result_rules[]에 `scope`
> 부착, campaign/region 룰의 0건엔 `scope_hint`로 "이 캠페인 미매칭 ≠ 클린"
> 경고. find_suspicious docstring에 해석 규칙 추가. (이미 E-1에서
> extension_churn 캠페인 과적합도 개수 기반으로 일반화함.)

- **현재 상태**: `prefetch_security_sw_werfault_correlation`(한국 보안SW watering
  hole)처럼 특정 캠페인에 과적합된 룰이 일반 룰과 동일하게 노출된다.
- **지시**: 모든 룰에 `scope` 메타데이터를 추가하라 —
  `generic` / `campaign_specific` / `region_specific`. 응답의 findings[]에
  이 필드를 포함시켜, LLM이 campaign_specific 룰 0건을 "해당 캠페인 아님"으로만
  읽고 "침해 아님"으로 확대 해석하지 않게 하라. docstring에 해석 규칙 1줄 추가.
- **수용 기준**: 13개 룰 전부 scope 태깅 완료.

### B-3. EVTX 룰 공백 보강 (A-5/A-6/A-7과 중복 제외 잔여분) — ✅ 대부분 완료 (2026-06-10)

> **수행 결과**: BUILTIN_RULES에 fw-evtx-025~039 (15개) 추가 —
> PowerShell 400/600(`026`), Sysmon 11/12·13/22/8(`027`~`030`),
> DCSync 4662(`031`), WFP 5156(`032`), TaskScheduler 실행 129/200/201(`033`,
> 생성과 구분), Defender(`034`/`035`), BITS(`036`), WinRM(`037`),
> RDP 4778/4779(`038`)/아웃바운드 1024(`039`). KNOWN_COVERAGE_GAPS 15개 중
> 9개를 covered-by 주석으로 갱신(절반 이하로 감소). **잔여**: TaskCache
> 레지스트리 ↔ XML ↔ 106 3원 대조(삭제된 태스크 탐지), SmbClient 31001.

- **지시**: 다음 EID 룰을 추가하라 —
  PowerShell 400/600 (엔진 시작 — 4104 비활성 환경의 폴백),
  Sysmon 11(FileCreate)/13(RegistryValueSet)/22(DNSQuery)/8(CreateRemoteThread),
  Security 4662(DCSync — KNOWN_GAPS 자인 항목), 5156(WFP 허용 연결),
  Microsoft-Windows-TaskScheduler/Operational 129/200/201 (태스크 실행 — 생성(106)과 구분).
- **연계**: TaskCache 레지스트리(P2) ↔ 태스크 XML ↔ EVTX 106 3원 대조로
  **삭제된 스케줄 태스크** 탐지 룰 추가 (잔존 TaskCache GUID, XML 부재).
- **수용 기준**: KNOWN_COVERAGE_GAPS 목록이 절반 이하로 감소.

---

## 4. Part C — 편향 억제 강화 지시

구조는 이미 강하다. 아래는 전수 평가에서 확인된 **잔존 누수 경로**다.

### C-1. Silent disable 차단

- **현재 상태**: `FW_BIAS_REMEDIATION_DISABLE=1`이면 모든 가드레일이 통지 없이
  꺼진다. LLM은 가드레일 부재 상태를 인지할 방법이 없다.
- **지시**: 비활성 상태일 때 모든 detection/triage 응답에
  `"guardrails_active": false` + 경고 문자열을 강제 포함하라.
  `server_runtime_info`에도 노출.
- **수용 기준**: disable 상태 fixture에서 응답에 경고 필드 존재 검증 테스트.

### C-2. 빈 결과 3중 의미의 단일 필드 통합

- **현재 상태**: `findings: []`가 ① 룰 미평가(unevaluable) ② 평가했으나 0건
  ③ 아티팩트 미수집의 3가지 의미를 갖고, LLM이 3개 필드를 교차해 해석해야 한다
  (`unevaluable_rules[]`, `diagnostic`, `blocking_records`).
- **지시**: 모든 검색/탐지 응답에 단일 `empty_interpretation` 필드를 추가하라 —
  `"not_evaluable" | "evaluated_zero_hits" | "artifact_not_collected"` +
  근거 1줄. 기존 3개 필드는 유지(상세용)하되 이 필드가 1차 해석 지점.
- **수용 기준**: 빈 응답 fixture 3종에서 각각 올바른 enum 반환.

### C-3. evidence_strength 룰 순서 의존성 제거 — ✅ 완료 (2026-06-10)

> **수행 결과**: `tests/test_evidence_strength_golden.py` 신설 — 21개 family →
> tier 매핑을 고정한 golden 테이블(파라미터화 24 케이스). 새 _RULES 항목이
> 기존 family의 tier를 의도치 않게 바꾸면 즉시 실패. 4104가 confirmed 룰에
> 흡수되지 않고 strong 유지됨도 명시 검증. first-match 로직 자체는 유지(전환
> 리스크 회피), 회귀는 golden 테스트로 차단.

- **현재 상태**: `evidence_strength.py::_RULES`가 first-match-wins 리스트라
  룰 추가/정규식 수정 시 의도치 않은 tier 변동 위험 (Part A로 아티팩트가
  대량 추가되면 이 위험이 현실화된다).
- **지시**: ① 모든 (아티팩트 family → 기대 tier) 쌍을 고정한 golden 테이블
  테스트를 작성하고, ② first-match를 "최고 특이도 매치 우선"(가장 긴/구체적
  패턴 우선)으로 바꾸거나 family 명시 매핑 테이블로 전환하라.
- **수용 기준**: Part A 아티팩트 추가 전후 golden 테스트 diff가 의도 변경만 포함.

### C-4. 가설 선언 게이트 (CLAUDE.md 규칙의 구조화) — ✅ 완료 (2026-06-10)

> **수행 결과**: `find_suspicious`에 `declared_hypothesis` 파라미터 추가.
> 값이 있으면 `build_refutation_hint`가 6개 가설 클래스(ransomware/insider/
> lateral/persistence/anti_forensics/credential)별 "반증하려면 무엇을 봐야
> 하는지" + absence_refutes + next_tool 반환. **hard gate 아님** — 미선언 시
> 호출은 막지 않고 `hypothesis_declaration.declared=false` 안내만 부착(우회
> 습관 방지). 미매핑 가설은 hypothesis_refutation_pack로 유도.

- **현재 상태**: "가설 선언 후 도구 호출" 원칙이 CLAUDE.md 문서로만 존재 —
  LLM이 잊으면 강제 수단이 없다.
- **지시**: `find_suspicious`/`run_hunt_pack`에 선택 파라미터
  `declared_hypothesis: str`을 추가하라. 값이 있으면 응답에
  `refutation_hint` (이 가설을 반증하려면 어떤 lane/family를 봐야 하는지,
  `hypothesis_refutation_pack` 연계 호출 안내)를 포함하라.
  **강제(hard gate)는 하지 마라** — 탐색 단계 호출까지 막으면 우회 습관이 생긴다.
  대신 `investigation_gap_report`에 "가설 미선언 상태로 호출된 탐지 도구 횟수"를
  카운트해 보고하라.
- **수용 기준**: declared_hypothesis 전달 시 refutation_hint 반환,
  gap report에 카운터 노출.

### C-5. ingress lane 고착 모니터링 (Part A의 편향 측면 검증) — ✅ 완료 (2026-06-10)

> **수행 결과**: 점검 결과 Part A 신규 ingress 아티팩트(MOTW/TrustRecords/
> Office MRU/USB/RDP destinations)가 `_classify_entry`의 어느 axis 패턴에도
> 없어 lane gate에 **전혀 기여하지 못하는** 고착을 확인 — 이것이 C-5가 경고한
> 바로 그 문제였다. `_USER_PATTERNS`에 MOTW/Zone.Identifier/TrustRecords/
> Office MRU/USB, `_NETWORK_PATTERNS`에 RDP destinations, `_EXECUTION_PATTERNS`
> 에 BAM을 추가. MOTW+TrustRecords만 있는 케이스에서 ingress lane이
> not_seen을 벗어남을 회귀 테스트로 고정.

- **지시**: Part A-1~A-4 구현 후, 기존 bias guard fixture 전체에서
  lane_state_board의 lane별 상태 분포를 전/후 비교 리포트로 남겨라.
  ingress lane이 여전히 systematically unverified면 lane 정의 자체
  (LANE_REQUIRED_FAMILIES)를 재조정 대상으로 보고하라.
- **수용 기준**: lane 상태 분포 전후 비교가 `docs/`에 기록됨.

### C-6. 중복 gap 서술 통합 — 🟡 핵심 완료 (2026-06-10)

> **수행 결과**: `investigation_gap.make_gap_id(*parts)` 공통 헬퍼(SHA1 12자,
> 결정론적, 대소문자/공백 정규화). lane_state_board 차단 레인과
> investigation_gap의 substrate/detection gap이 동일 (lane/family, state)에
> 대해 같은 gap_id 공유. **잔여**: negative_evidence 표면에도 동일 id 부착
> (3-표면 완전 통합).

- **현재 상태**: 동일한 커버리지 공백이 lane_board / negative_evidence /
  investigation_gap 3곳에서 서로 다른 문구로 기술되어 LLM이 별개 문제로
  해석할 수 있다.
- **지시**: gap 항목에 안정적 `gap_id`(family+lane 해시)를 부여하고 3개 표면이
  동일 id를 공유하게 하라. 문구 자체는 표면별로 달라도 된다.
- **수용 기준**: 동일 gap이 3개 표면에서 같은 gap_id로 추적된다.

---

## 5. Part D — 속도/워크플로우 지시

목표: 전형적 단일 호스트 케이스의 1차 트리아지를 **LLM 도구 호출 15회 이내,
truncation 재조회 0회**로.

### D-1. Auto-pagination 내장 (로드맵 P0 승계 + 구체화) — ✅ 완료 (2026-06-10)

> **수행 결과**: ① `search_artifacts`/`build_timeline`에 `fetch_all` 파라미터
> 추가 (내부 20페이지 루프, hit_id dedupe, 예산 초과 시 `remaining_count` +
> `pagination_gap` 명시, 기본 compact 행 투영 + `get_hit_detail` 안내).
> ② `initial_triage` 내부 타임라인 스캔에 자동 확장(8,000행 예산) +
> 초과 시 `allow_strong_conclusion=false` 하드 게이트 + `pagination_required`.
> ③ C-1: `FW_BIAS_REMEDIATION_DISABLE` 시 `guardrails_active:false` + 경고
> 문자열 강제, `server_runtime_info`에도 노출. ④ C-2: `empty_interpretation`
> 단일 필드를 search_artifacts / build_timeline(fetch_all) / find_suspicious에
> 부착. 검증: 신규 테스트 10건 포함 전체 712 passed, bias guard 7/7.

- **지시**: P0의 자동 pagination loop를 구현하되, MCP 표면에는
  `search_artifacts` 등 기존 도구에 `fetch_all: bool` 파라미터를 추가하는
  방식으로 하라 (별도 도구 신설로 91개를 더 늘리지 마라).
  `fetch_all=true`면 내부 루프(max_pages=20)로 전량 수집,
  초과 시 `remaining_count` + gap 기록. **응답 크기 폭발 방지**:
  fetch_all 시 details는 룰별 요약 + 대표 N건으로 압축하고 전체는
  `query_result` 핸들로 노출.
- **수용 기준**: 분산 증거 fixture(P0 fixture 설계 승계)에서
  단일 호출로 전 페이지 증거 확보.

### D-2. initial_triage_pack 내부 중복 제거 — ✅ 완료 (2026-06-10)

> **수행 결과**: `initial_triage`가 `_artifact_counts`를 1회 계산해
> `_coverage_gate(counts=...)`로 전달 — get_artifact_type_counts 재조회 제거.
> `_coverage_gate`는 counts 미전달 시 기존대로 자체 조회(하위 호환). 응답
> 스키마 무변경 순수 내부 최적화, 전체 793 passed로 동작 동일성 확인.

- **현재 상태**: build_case_health와 _coverage_gate가 동일 아티팩트 카운트를
  2회 조회, day anchor가 타임라인 재조회.
- **지시**: 아티팩트 카운트를 1회 조회 후 파라미터로 전달하는 구조로 리팩터.
  동작 계약(응답 스키마) 변경 금지 — 순수 내부 최적화.
- **수용 기준**: 동일 케이스에서 SQL 쿼리 수 감소를 로그로 확인, 응답 diff 없음.

### D-3. 도구 표면 정리 (91개 → 탐색 비용 절감)

- **지시**: 도구 신설 대신 **docstring에 라우팅 힌트를 표준화**하라 —
  각 도구 첫 줄에 `[stage: triage|hunt|verify|report] [lane: ...]` 태그.
  LLM의 도구 선택 오류(비슷한 도구 91개 중 잘못 고름)가 왕복 낭비의
  실측 원인 중 하나다. 또한 `get_summary` 응답에 "현 케이스 상태에서
  권장되는 다음 도구 3개"를 결정론적 규칙으로 포함하라
  (케이스 미오픈 → open_case, 오픈 직후 → initial_triage_pack, ...).
- **편향 주의**: 권장 도구는 워크플로우 안내이지 분석 방향 유도가 아니다 —
  탐지 룰이나 가설을 권장하는 것은 금지, 도구 단계만 안내.
- **수용 기준**: 전 도구 docstring 태깅 완료.

### D-4. raw-image-index 브랜치 완결 (현 브랜치 최우선 잔여 작업) — 🟡 대부분 완료 (2026-06-10)

> **수행 결과**: ① `core/raw_index/artifact_indexer.py` 신설 —
> EVTX 시맨틱 인덱서 (9개 핵심 채널: Security/System/Application/PowerShell/
> TaskScheduler/TerminalServices×2/BITS/Defender; P1 이벤트셋 + 4697/4778/4779,
> 채널 부재·파싱 실패·레코드 캡 도달을 전부 coverage_gap으로 기록,
> DO_NOT_EXECUTE 마커 + read-only temp 추출),
> 레지스트리 인덱서 (SYSTEM: 서비스 + **A-2 BAM/DAM**(SID 귀속 실행 증거,
> FILETIME 디코딩) + **A-3 USBSTOR**; NTUSER: Run/RunOnce +
> **A-4 Office TrustRecords**(macro-enabled 마커 FF FF FF 7F 탐지)).
> ② MCP 도구 `build_raw_artifact_index` 추가.
> ③ 신규 타입 3-표면 등록: BAM=strong, USB Devices=moderate,
> Office Trusted Documents=strong (evidence_strength) + rule_coverage aliases.
> ④ `initial_triage_pack`에 `raw_parity_status` (4개 family per-family parity).
> ⑤ sidecar 검증은 기존 connect()의 schema+fingerprint+roots+parser-run
> 4중 검증으로 충족 확인.
> **잔여**: raw-only 케이스에서 initial_triage_pack의 full lane 채움
> (raw connector에 artifact_queries 표면 추가 필요 — 후속 작업),
> 실제 E01 이미지 대상 end-to-end 검증 (synthetic 테스트만 통과한 상태).

- **지시**: handoff 문서 기준 잔여 작업을 다음 순서로 완료하라 —
  ① raw EVTX 시맨틱 파서(P1과 동일 항목 — 이 브랜치에서 수행),
  ② registry hive 파서 (이때 A-2 BAM, A-3 USBSTOR를 같은 파서에 포함해
  중복 작업 방지), ③ parity 결과를 `initial_triage_pack` 응답에
  `raw_parity_status` 필드로 통합, ④ sidecar 3-way 검증
  (schema + fingerprint + row count).
- **수용 기준**: AXIOM 없이 E01만으로 initial_triage_pack이 lane 3개를
  채울 수 있고, parity 리포트가 AXIOM 대비 공백을 family 단위로 명시.

### D-5. 케이스 오픈 시 백그라운드 사전 계산

- **지시**: `open_case`/`mount_image` 직후 (a) 아티팩트 타입 카운트,
  (b) 타임라인 일자별 히스토그램을 백그라운드로 사전 계산해 캐시하라.
  initial_triage_pack과 explain_zero_results가 이 캐시를 사용.
  캐시는 케이스 fingerprint에 바인딩하고 stale 시 자동 무효화.
- **수용 기준**: 두 번째 팩 호출부터 응답 시간 단축이 측정됨.

---

## 6. Part E — 성능 측정 지시 (모든 Part의 전제)

### E-1. IR-005 regression harness를 최우선으로 격상 — ✅ 완료 (2026-06-10)

- **현재 상태 (정정)**: 초기 평가의 "설계 5%, fixture 비어 있음"은 오류였다.
  실태: fixture 6종(ransomware / benign remote work / partial / insider exfil /
  anti-forensics / empty) + lane 기대 상태를 포함한 ground truth + M1~M4 지표 +
  ingest/finalize/bias-guard CLI가 이미 구현되어 있었다 (manual edition,
  `docs/LLM_REGRESSION_HARNESS_SPEC.md` 스코프 준수). 실제 공백은 두 가지였다.
- **수행 결과**:
  - `case_paginated_evidence` fixture 추가 — 노이즈 5,000행 + 증거 4클러스터
    (ingress/persistence/impact/anti-forensics)를 1페이지 밖(타임라인 위치
    1,600~2,810)에 분산 배치한 P0 fixture. 추가 직후 bias guard가
    **실제 undercall을 검출** (initial_triage 내부 스캔 1,200행 한계로
    증거 미도달 → lane gate 영구 차단).
  - 이를 근거로 P0 자동 페이지네이션을 `initial_triage.py`에 구현:
    스캔 truncation 시 max_pages(20)×batch(400)=8,000행까지 자동 확장,
    초과 시 `remaining_unscanned` gap 기록 + `allow_strong_conclusion=false`
    하드 게이트 + `pagination_required` 플래그.
  - `extension_churn` 신호의 `.INC/.locked` 캠페인 과적합 제거 —
    Encrypted Files ≥25행 개수 기반 일반 신호 추가 (B-2 원칙의 첫 적용).
  - M5 truncation 규율 지표 추가 (`metrics.truncation_discipline` +
    세션 로그에서 truncated 결과/페이지네이션 후속 호출 추출), CLI·리포트에
    연결, 리포트 Flags에 "TRUNCATION IGNORED" 표기.
- **검증**: bias guard 7/7 ok, 전체 테스트 702 passed.
- **잔여**: LLM 수동 세션 baseline 재측정(수동 워크플로우 — 사용자 실행 필요),
  정상 cloud migration fixture(P3 겸용)는 P3 구현 시점에 추가.

### E-2. 공개 데이터셋 라벨 케이스 (로드맵 P0.5 승계)

- **지시**: EVTX-Attack-Samples와 OTRF Security-Datasets에서 본 지시문의
  신규 아티팩트(WMI, BITS, WinRM, Defender)가 포함된 샘플을 우선 선별해
  labelled case로 등록하라 — 신규 파서의 실데이터 검증과 threshold
  calibration을 겸한다.

---

## 7. 실행 순서 (의존성 반영)

| 순서 | 항목 | 이유 |
|---|---|---|
| 1 | E-1 (측정 harness) — ✅ 완료 2026-06-10 | 이후 모든 변경의 효과 측정 전제 |
| 2 | D-1 (auto-page) + C-1, C-2 (저비용 누수 차단) — ✅ 완료 2026-06-10 | 작고 독립적, 즉시 효과 |
| 3 | D-4 (raw index 완결: EVTX→Registry, A-2/A-3 동시 포함) — 🟡 대부분 완료 2026-06-10 (raw-only full triage + 실이미지 검증 잔여) | 현 브랜치 완결 + execution/ingress 동시 보강 |
| 4 | A-1 (MOTW), A-4 (Office) — 🟡 A-4 TrustRecords는 raw 경로에 구현 완료(OAlerts/MRU·KAPE 경로·연계 룰 잔여), A-1 미착수 | ingress lane 구조 공백 — lane gate 정상 작동의 전제 |
| 5 | A-5, A-6, A-7 + B-3 — ✅ 대부분 완료 2026-06-10; **MPLog 파서 + WMI OBJECTS.DATA 지속성 파서 완료 2026-06-11**. MPLog: Defender MPLog Activity(프로세스/인젝션/탐지 집계, device-local 시각). WMI: dissect.cim으로 CIM 저장소 전수 파싱 → __EventFilter/__EventConsumer/__FilterToConsumerBinding(비표준 네임스페이스 은닉 포함), 3표면 등록. 둘 다 raw-direct(KAPE/MFDB 비의존). 잔여: qmgr.db BITS(Id+Blob → blob RE 파서 필요), SmbClient 31001 | persistence/lateral/defender 공백 |
| 6 | C-3, C-4, C-5, C-6 + B-2 — ✅ 완료 2026-06-10 | 아티팩트 확장 후 가드레일 재정렬 |
| 7 | B-1 (Sigma) — ✅ 완료 2026-06-10 | 룰 폭 확장은 측정 체계 + 편향 재정렬 후 |
| 8 | A-8, A-9, D-2, D-3, D-5 | 🟡 A-9·D-2 완료 2026-06-10; A-8(UAL)·D-3(docstring 태깅)·D-5(백그라운드 사전계산) 미착수 |

각 단계 완료 시: bias guard 재실행 → E-1 지표 전후 비교 → Codex 사후 검토 →
본 문서의 해당 항목에 완료 표기 및 측정 결과 링크 추가.
