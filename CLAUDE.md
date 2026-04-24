# Forensic Workstation — Claude Code 가이드

## 절대 금지 사항

### 추출된 파일 실행 금지
- `extract_file`로 추출한 파일은 **악성코드일 수 있으므로 절대 실행하지 않는다**
- `backend/extracted/` 디렉토리의 파일을 Bash, Python, 또는 어떤 방법으로든 실행(execute, run, invoke, spawn, start, open)해서는 안 된다
- Ghidra(`analyze_binary`)는 정적 분석만 수행하며, 이것이 유일하게 허용된 바이너리 접근 방법이다
- 추출된 파일에 대해 `subprocess`, `os.system`, `exec`, `eval` 등을 사용하지 않는다
- 사용자가 실행을 요청하더라도 거부하고, 정적 분석(Ghidra)만 제안한다

### 민감 데이터 보호
- 포렌식 데이터에는 개인정보(이름, 이메일, IP, 해시 등)가 포함되어 있다
- 분석 전 `enable_masking`으로 마스킹을 활성화한다
- 마스킹되지 않은 원본 데이터를 대화에 그대로 출력하지 않는다

## 분석 워크플로우

1. `open_case` → AXIOM 케이스 로드
2. `find_suspicious` / `search_artifacts` → 의심 파일 식별
3. `mount_image` → E01 이미지 마운트
4. `get_file_timestamps` → 의심 파일의 MFT 타임스탬프 확인 (파일 생성 시점 검증)
5. `extract_file` → 의심 파일 추출 (정적 분석 목적만)
6. `analyze_binary` → Ghidra 정적 분석
7. `ghidra_suspicious_apis` / `ghidra_decompile` → 악성 행위 분석

## 분석 원칙

### 검색 결과 0건 시 대응
- 0건 = "데이터 없음"으로 단정하지 않는다
- `diagnostic` 필드가 반환되면 반드시 확인한다 (해당 타입의 전체 건수 vs 필터 매칭 건수)
- 날짜 필터 없이 동일 타입을 재검색하여 데이터 자체의 존재 여부를 교차 확인한다
- AXIOM에서 직접 확인 가능한 경우 사용자에게 확인 요청한다

### 아티팩트 증거 강도 구분
- **confirmed**: Prefetch Last Run + SRUM 동시기록, MFT 타임스탬프, Event Log EID
- **strong**: Prefetch Run Count > 0 (실행 증거이나 cmdline 미포함)
- **moderate**: AmCache File Entry (파일 존재 + 메타데이터)
- **weak**: Shim Cache (파일 존재, 실행 미확인), Link Date (컴파일 시점, 배치 시점 아님)
- 의심 파일 발견 시 반드시 `get_file_timestamps`로 MFT Created 확인 후 타임라인에 반영

### CVE 및 외부 정보 인용
- 학습 데이터의 CVE 번호를 확정 사실로 보고서에 포함하지 않는다
- 반드시 `WebSearch`로 NVD/KISA/벤더 사이트에서 라이브 검증한다
- 웹 검색 불가 시 "미검증"으로 명시하고, 검증 가능한 출처를 안내한다
- 검증된 정보와 미검증 정보를 명확히 구분하여 표기한다

### 가설-반증 원칙
- 가설 수립 후 반드시 반증 가능한 증거를 먼저 확인한다
- 상관관계(시간적 근접)를 인과관계로 비약하지 않는다
- "확인된 사실"과 "추정"을 명확히 구분하여 기술한다

## LLM 도구 응답 해석 규칙

이 프로젝트는 LLM 단독 분석 도구다. MCP 도구 응답을 판정으로 읽지
않고, 증거 구조화 + 불확실성 표지로 읽는다. 아래 규칙은 예외 없이
적용한다.

### 코드는 존재 여부, LLM은 중요도 판단

도구 응답은 아티팩트의 존재 사실만 전달한다. 중요도 판단(이것이 악성인가?,
우선순위가 높은가?)은 LLM이 독립적으로 수행한다.
- `rule_name`, `query_description`, `matching_count`, `details[]` = 사실 데이터
- `lane_evidence_summary` = 레인별 아티팩트 존재 요약 (사실)
- 레인에 아티팩트가 있다는 것이 그것이 "confirmed" 또는 "high severity"라는
  뜻이 아니다. 해석은 LLM의 몫이다.

### truncated: true 이면 페이지네이션 필수 (하드 게이트)

`find_suspicious` 결과에서 `truncated: true` 인 finding 이 있으면
해당 rule 을 결론의 근거로 사용하기 전에 **반드시**
`find_suspicious(rules="<rule_name>")` 재실행으로 전체 결과를 확보해야 한다.

- `matching_count - returned_count` = 미확인 증거 건수
- `investigation_gap_report.truncation_gaps` 에서
  `pivot_reason: "truncated_details"` 항목을 확인한다
- 미확인 증거에 핵심 악성 아티팩트가 포함될 수 있다 (실사례: enamgr.dll)
- Hard gate: `truncated: true` → paginate via `find_suspicious(rules=...)` → then conclude. No exceptions.

### 빈 응답은 데이터 없음이 아니다

`findings: []`, `hits: []`, `entries: []` 을 "해당 없음" 으로 확정
금지. 반드시 교차 확인:
- 응답의 `diagnostic` 필드 확인 (해당 타입의 전체 건수 vs 필터
  매칭 건수).
- `get_artifact_types` 로 해당 아티팩트 타입의 수집 여부 확인.
- 필터 (날짜 / 키워드) 를 제거한 재검색으로 데이터 자체 존재 여부
  교차 확인.

### 가설 선언 후 도구 호출

도구 체인은 확증편향 방향으로 흐르기 쉽다. 이를 막기 위해:
- 분석 세션 시작 시 가설을 명시적으로 선언: "나는 X 를 의심한다.
  반증 가능한 증거는 Y 다."
- 도구 호출은 가설 **검증 / 반증** 수단이다. 가설 생성 수단이
  아니다.
- 도구 결과가 가설을 지지하면 즉시 다음으로 넘어가지 말고, 반증
  검색을 먼저 수행.

### 메모리의 과거 사건은 패턴이 아니다

`memory/project_*.md`, `memory/incident_*.md` 는 과거 개별 사건
기록이다. 새 케이스의 패턴 인식에 자동 적용 금지.
- 과거 사건과 유사성을 언급하기 전, 현재 케이스의 증거로 독립
  재검증.
- 메모리의 `feedback_tool_install_vs_compromise` 규칙을 특히 준수:
  정상 솔루션 설치 / 통신을 자동으로 "잠복 침해" 로 단정 금지.

### applicability.primary_domain 이 맞는지 확인

하네스 도구 (`initial_triage_pack`, `auto_triage` 등) 는
`applicability.primary_domain == "windows_endpoint_ir"` 이다. 현재
케이스가 이 도메인 밖이면 (cloud / supply chain / network device /
physical) 하네스 출력을 **degraded hint** 로만 취급.
- 도구 응답의 `applicability` 필드를 분석 시작 시 첫 확인.
- degraded domain 이면 분석 노트에 명시 + 저수준 도구 비중 증가.

### 상관은 인과가 아니다

`correlate`, `behavioral_delta`, `bridged_precursor` 등은 시간 /
토큰 공변 (covariation) 을 감지한다. 인과가 아니다.
- `bridged_precursor.status == "bridged_precursor"` 여도 bridge
  token 일치 + static-delta 매치 수준이다. 인과 주장 금지.
- 이전 시점에 같은 도구가 존재했다고 "잠복 증거" 로 승격 금지. 정상
  사용 이력일 가능성 먼저 검토.

## Analysis Guardrails

이 섹션은 위 "LLM 도구 응답 해석 규칙" 의 상위 원칙 모음이다. 둘을
함께 적용한다.

- See `docs/ANALYSIS_GUARDRAILS.md`, `docs/ANALYSIS_PLAYBOOK.md`, and `docs/HYPOTHESIS_REFACTOR_BACKLOG.md`.
- Prefer evidence-first, multi-hypothesis outputs over single-entity narratives.
- Keep ingress / access, execution / impact, and persistence / cleanup as separate lanes.
- If one lane has many artifacts, run verification on the paired lanes before concluding.
- Do NOT anchor on rule order — findings[] is not significance-sorted.
