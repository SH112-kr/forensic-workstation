# Forensic Workstation - Codex Agent Guide

이 파일은 Codex와 기타 agent가 이 저장소에서 작업할 때 적용할 운영 지침이다.
`CLAUDE.md`의 포렌식 분석 원칙을 Codex에서도 동일하게 따르도록 옮긴다.

## 절대 금지 사항

### 추출된 파일 실행 금지

- `extract_file`로 추출한 파일은 악성코드일 수 있으므로 절대 실행하지 않는다.
- `backend/extracted/` 또는 evidence export 경로의 파일을 Bash, PowerShell, Python, `open`, `Start-Process`, `subprocess`, `os.system`, `exec`, `eval` 등 어떤 방식으로도 실행하지 않는다.
- Ghidra 기반 `analyze_binary`는 정적 분석만 수행한다. 추출 바이너리에 대한 허용된 접근은 정적 분석, 해시, 메타데이터, 문자열, import, decompile 확인으로 제한한다.
- 사용자가 추출 파일 실행을 요청하더라도 거부하고 정적 분석 대안을 제안한다.

### 민감 데이터 보호

- 포렌식 데이터에는 개인정보, 내부 경로, IP, 호스트명, 사용자명, 해시, credential, token, 브라우저/이벤트 로그 원문이 포함될 수 있다.
- MCP 분석 전에는 가능한 경우 `enable_masking`을 활성화한다.
- 마스킹되지 않은 원본 데이터를 대화에 그대로 길게 출력하지 않는다.
- 보고서나 요약에는 확인된 사실, 추정, 미검증 정보를 구분해서 쓴다.

## 기본 분석 워크플로우

1. `open_case`로 AXIOM/KAPE 케이스를 로드한다.
2. `find_suspicious` / `search_artifacts`로 의심 항목을 식별한다.
3. `mount_image`로 E01/VM/raw 이미지를 마운트한다.
4. `get_file_timestamps`로 의심 파일의 MFT/NTFS 타임스탬프를 확인한다.
5. `extract_file`은 정적 분석 목적에 한해 사용한다.
6. `analyze_binary`로 Ghidra 정적 분석을 수행한다.
7. `ghidra_suspicious_apis`, `ghidra_imports`, `ghidra_strings`, `ghidra_decompile`로 capability를 분석하되 실행 증거와 구분한다.

## 분석 원칙

### 0건 결과 해석

- 0건은 "활동 없음" 또는 "데이터 없음"의 증거가 아니다.
- `diagnostic`, coverage, parser failure, artifact type count, 날짜/키워드 필터를 확인한다.
- 필요하면 필터를 제거하고 같은 artifact family를 재검색한다.
- zero-result tool 결과 직후에는 `explain_zero_results` 또는 `coverage_explainer`를 우선 고려한다.

### 증거 강도 구분

- `confirmed`: Prefetch + SRUM 동시기록, MFT/NTFS timestamp, 결정적 EID 등.
- `strong`: Prefetch Last Run, Sysmon, PowerShell ScriptBlock 등.
- `moderate`: AmCache, UserAssist, Scheduled Task state 등.
- `weak`: ShimCache, Link Date, 단순 파일 존재 등.
- Prefetch는 실행 증거가 될 수 있지만 단독 사건 결론은 아니다.
- Registry state는 캡처 시점의 설정 존재를 증명할 뿐 실행 자체를 증명하지 않는다.

### 가설과 반증

- 도구 결과는 판정이 아니라 증거 목록과 우선순위 힌트다.
- 가설을 세웠으면 지지 증거만 따라가지 말고 반증 가능한 증거를 먼저 확인한다.
- 시간적 근접, 같은 토큰, 같은 호스트 출현을 인과관계로 비약하지 않는다.
- ingress/access, execution/impact, persistence/cleanup 레인을 분리해서 판단한다.

### truncated 결과

- `find_suspicious` 결과에 `truncated: true`가 있으면 해당 rule을 결론 근거로 쓰기 전 반드시 해당 rule만 재조회한다.
- `matching_count - returned_count`는 아직 확인하지 않은 증거 수다.
- 미확인 범위에 핵심 아티팩트가 있을 수 있으므로 결론 전에 pagination 또는 rule-specific rerun을 수행한다.

### 외부 정보와 CVE

- 학습 데이터의 CVE, 취약점명, 캠페인명, actor attribution을 확정 사실로 쓰지 않는다.
- 최신 CVE/벤더 정보가 필요하면 NVD, KISA, 벤더 공지 등 1차 출처로 검증한다.
- 검증할 수 없으면 "미검증"으로 명시한다.

## MCP 응답 해석 규칙

- `rule_name`, `query_description`, `matching_count`, `details[]`는 사실 데이터다.
- `lane_evidence_summary`는 artifact family 존재 요약이지 severity 판정이 아니다.
- `initial_triage_pack`, `auto_triage` 등은 `windows_endpoint_ir`에 최적화된 하네스다. 다른 도메인에서는 degraded hint로만 취급한다.
- `correlate`, `behavioral_delta`, `bridged_precursor`는 공변/근접성을 보여주는 도구이며 인과를 증명하지 않는다.
- 과거 memory 또는 이전 사건 기록을 새 케이스에 자동 패턴으로 적용하지 않는다. 현재 케이스 증거로 독립 재검증한다.

## 프로젝트 작업 원칙

- 기존 사용자 변경을 되돌리지 않는다.
- 포렌식 기능 변경은 가능하면 테스트를 먼저 추가하고, coverage gap과 negative evidence 해석을 보존한다.
- E01 endpoint IR 기본 분석에서 PCAP은 선택적 보조 증거다. `pyshark`/`tshark` 누락만으로 endpoint readiness를 degraded로 판단하지 않는다.
- 큰 결론을 내기 전에 `docs/ANALYSIS_GUARDRAILS.md`, `docs/ANALYSIS_PLAYBOOK.md`, `docs/DFIR_VALIDATION_PLAN.md`의 원칙과 충돌하지 않는지 확인한다.
