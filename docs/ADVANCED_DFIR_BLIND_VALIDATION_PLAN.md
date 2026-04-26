# Advanced DFIR Blind Validation Plan

목적: 공개 DFIR 케이스를 답지 없이 먼저 분석하고, 분석 결과를 파일로 고정한 뒤에만 답지와 비교한다. 이 절차는 프레임워크가 답지에 맞춰지는 편향을 줄이고, 실제 자동 분석 성능을 평가하기 위한 것이다.

## 원칙

- Evidence first: E01, EVTX, PCAP, Registry, Prefetch, MFT/USN 등 증거를 먼저 파싱한다.
- Answer last: writeup, answer key, walkthrough는 blind result 저장 후에만 연다.
- No execution: E01 안에서 추출된 EXE, DLL, script, payload는 실행하지 않는다. 정적 파싱과 해시/문자열/메타데이터 분석만 허용한다.
- Source separation: rule/Sigma/YARA/LLM 결과는 판정이 아니라 evidence hint로만 취급한다.
- Strong conclusion gate: truncation, parser failure, missing artifact family가 있으면 강한 결론을 제한한다.

## Current Dataset: DFIR Madness Case001

케이스: `Case 001 - The Stolen Szechuan Sauce`

다운로드/추출된 증거:

- `external/dfir_validation/dfir_madness_case001/DC01-E01.zip`
- `external/dfir_validation/dfir_madness_case001/case001-pcap.zip`
- `external/dfir_validation/dfir_madness_case001/extracted/E01-DC01/20200918_0347_CDrive.E01`
- `external/dfir_validation/dfir_madness_case001/extracted/E01-DC01/20200918_0347_CDrive.E02`
- `external/dfir_validation/dfir_madness_case001/extracted_pcap/case001.pcap`

안전 표시:

- `external/dfir_validation/dfir_madness_case001/extracted/DO_NOT_EXECUTE_EXTRACTED_FILES.txt`
- `external/dfir_validation/dfir_madness_case001/extracted_pcap/DO_NOT_EXECUTE_EXTRACTED_FILES.txt`

## Blind Analysis Artifacts

답지 공개 전 저장된 결과:

- `external/dfir_validation/dfir_madness_case001/blind_download_record.json`
- `external/dfir_validation/dfir_madness_case001/blind_e01_probe_result.json`
- `external/dfir_validation/dfir_madness_case001/analysis_workspace/blind_evtx_summary.json`
- `external/dfir_validation/dfir_madness_case001/analysis_workspace/blind_evtx_targeted.json`
- `external/dfir_validation/dfir_madness_case001/analysis_workspace/blind_pcap_summary.json`
- `external/dfir_validation/dfir_madness_case001/blind_analysis_result.json`

답지 공개 후 비교 결과:

- `external/dfir_validation/dfir_madness_case001/blind_answer_comparison.json`
- `external/dfir_validation/dfir_madness_case001/blind_answer_comparison_manual.json`

## Blind Findings

Blind phase에서 확인한 핵심 신호:

- `CITADEL-DC01` / `C137` 도메인 컨트롤러 식별
- `194.61.24.102`와 `10.42.85.10` 사이의 대량 RDP(3389) 트래픽
- `10.42.85.10`과 `10.42.85.115` 사이의 내부 RDP 트래픽
- `2020-09-19T02:35:55Z`부터 내부 RDP lateral movement 가능성
- Windows PowerShell `ServerRemoteHost` 활동
- `ricksanchez` 계정 생성 및 Domain Admins/Builtin Administrators 추가
- 다수 계정 생성 이벤트와 반복적인 `birdman` 계정 생성

중요한 부정/제한 증거:

- Sysmon 로그 없음
- Prefetch 디렉터리 미확인
- 전체 E01 global inventory는 15분 제한에서 timeout
- 7045 service install은 blind EVTX 범위에서는 OS/VMware/AD 설치성 이벤트만 확인됨
- PCAP은 TLS/SMB 재조립 없이 요약 파싱만 수행

## Answer Comparison

공개 정답 기준 핵심 사건:

- 외부 `194.61.24.102`에서 DC `10.42.85.10`으로 RDP brute force
- `Administrator` 계정 compromise
- Internet Explorer로 `coreupdater.exe`를 `194.61.24.102`에서 다운로드
- meterpreter 사용, `coreupdater`에서 `spoolsv.exe`로 migrate
- C2 `203.78.103.109`
- DC와 Desktop에 service/registry persistence
- `secret.zip`, `loot.zip` exfiltration
- `Szechuan Sauce.txt` 접근
- `Beth_Secret.txt` 삭제/재생성/timestomp
- DC에서 Desktop `10.42.85.115`로 RDP lateral movement

Strict string comparison:

- expected: 16
- observed: 14
- exact matched: 2
- missed: 14
- unexpected: 12

Manual assessment:

- matched/partial: 4 of 16
- estimated score: 25%
- PCAP HTTP pivot까지 reveal phase에서 추가하면 약 31%

## Bias Assessment

- Availability bias: 높음. EVTX 계정 이벤트와 단순 RDP 흐름은 잘 잡았지만, PCAP payload, Registry, service persistence, filesystem exfil artifact를 충분히 해석하지 못했다.
- Overcall bias: 중간. 답지의 핵심 침해 원인이 아닌 계정 생성/권한 변경 이벤트가 blind story에서 크게 부각됐다.
- Undercall bias: 높음. malware, C2, exfiltration, timestomp, persistence를 놓쳤다.
- Confirmation bias: 낮음. APT/국가배후/actor attribution 같은 강한 결론은 내리지 않았고 제한사항을 기록했다.

## Engineering Implications

이 케이스는 현재 로드맵의 우선순위가 맞다는 것을 확인시킨다.

1. E01 global inventory 대신 known-path lazy extraction을 기본 경로로 둔다.
2. PCAP HTTP object extraction과 suspicious host pivot을 자동화해야 한다.
3. EVTX semantic parser는 4624/4625/4776/1149/7045/4697/4688/1102를 구조화해야 한다.
4. Registry service/run key parser가 없으면 persistence 판단이 약하다.
5. MFT/USN parser가 없으면 exfil/delete/timestomp 판단이 약하다.
6. Multi-host graph가 없으면 DC to Desktop lateral movement는 맞춰도 전체 공격 흐름 재구성이 약하다.
7. Bias guard에 "easy artifact dominance" 검사를 추가해야 한다. 한 artifact family만 풍부할 때 강한 결론을 제한해야 한다.

## Next Validation Targets

- DFIR Madness Case001 Desktop E01 추가 분석
- Case001 DC protected files/autoruns/memory output 정적 분석
- Hacking Case / M57 기존 케이스로 regression 재검증
- malware execution 없이 PCAP object, registry, MFT/USN 기반으로 meterpreter/persistence/exfil 탐지 개선
