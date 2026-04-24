# LLM Consumer Hygiene Spec

이 프로젝트는 LLM 단독 분석 도구 (Claude / Codex) 로 사용된다. UI 는
감사용 참조다. LLM 이 MCP 도구를 통해 분석을 수행하므로, 보호
메커니즘은 세 곳에만 존재할 수 있다: (a) MCP 도구 docstring,
(b) JSON 응답 스키마, (c) CLAUDE.md / 메모리 주입 규칙. **UI 기반
가드레일은 LLM 을 전혀 보호하지 않는다.**

이 스펙은 Tier A 의 **A3 (CLAUDE.md 메타 규칙) + A1 (MCP docstring
audit)** 을 한 묶음으로 구현한다. A2 / A4 / A5 는 별도 스펙.

연관 문서:
- `CLAUDE.md` — 이 스펙의 A3 가 대상.
- `backend/mcp_bridge.py` — 이 스펙의 A1 이 대상.
- `docs/BIAS_REMEDIATION_SPEC.md` — Patch 1-3 의 JSON 응답 필드
  (alert_summary / candidate_axes / lane_state_board) 가 LLM 이 읽을
  재료. 이 스펙은 그것을 LLM 이 **올바르게** 읽게 만든다.

## Problem statement

Patch 1-3 으로 JSON 응답에 uncertainty 필드들
(`allow_strong_conclusion`, `blocked_claims`, `candidate_axes`,
`balance.warnings` 등) 이 추가됐지만, LLM 이 이 필드들을 **정확히
어떻게 읽어야 하는지에 대한 체계적 지침이 없다**. 결과:

- 도구 응답의 분류 필드 (`incident_type`, `operator_style`,
  `rule_name`) 를 판정으로 오독.
- `confidence=high` / `confidence=low` 라벨의 실제 가중치 모름.
- `candidate_axes` 를 가능한 가설의 망라로 오인 → 택소노미 바깥
  공격 각도 누락.
- 메모리의 과거 사건 기록을 새 케이스에 자동 적용.
- 빈 응답 (`findings: []`, `hits: []`) 을 "데이터 없음" 으로 확정.
- 도구 체인이 가설 선언 없이 시작 → 확증편향 방향.

또한 MCP 도구 docstring 이 대부분 **인간 사용자 대상** 으로 작성돼
있어 LLM 이 도구 선택 / 결과 해석에서 오독한다. 특히:

- `auto_triage`, `initial_triage_pack` 같은 이름은 "one-stop 도구"
  신호로 읽혀 저수준 도구 드릴다운이 skip 됨.
- `classification.incident_type` 같은 필드가 판정처럼 자연어 추론의
  anchor 가 됨.
- 응답에 `applicability.degraded_domains` 있어도 docstring 에 언급
  없으면 LLM 이 자기 케이스가 해당되는지 능동 판단 안 함.

## Goal

- CLAUDE.md 에 LLM 구조화 필드 해석 규칙 섹션 추가.
- 고위험 MCP 도구 8 개의 docstring 에 "Reading guide for AI
  consumers" 섹션 추가. 기존 기능 설명은 보존.

## Non-goals

- MCP 도구의 기능 로직 변경.
- JSON 응답 스키마 변경 (A2 범위).
- 새 MCP 도구 추가 (A4 범위).
- 측정 harness (A5 범위).
- 모든 MCP 도구 docstring 수정 — 이 스펙은 고위험 8 개만. 나머지는
  후속 PR.

## Success criteria

- CLAUDE.md 에 "LLM 도구 응답 해석 규칙" 섹션이 추가되고 최소 6 개
  규칙 포함.
- 8 개 MCP 도구 docstring 이 "Reading guide for AI consumers" 섹션
  포함.
- 기존 pytest 전부 통과 (docstring 수정은 기능 무영향).
- `python -c "from backend import mcp_bridge"` 가 syntax 에러 없이
  import.

---

## A3. CLAUDE.md 메타 규칙 섹션 추가

### 위치

기존 "Analysis Guardrails" 섹션 **위** (= "분석 원칙" 섹션 **아래**)
에 새 섹션 삽입. 순서 의미: 절대 금지 → 워크플로우 → 분석 원칙 →
**LLM 도구 응답 해석 규칙 (신규)** → Analysis Guardrails 링크.

### 삽입할 전체 텍스트

```markdown
## LLM 도구 응답 해석 규칙

이 프로젝트는 LLM 단독 분석 도구다. MCP 도구 응답을 판정으로 읽지
않고, 증거 구조화 + 불확실성 표지로 읽는다. 아래 규칙은 예외 없이
적용한다.

### 구조화 필드는 휴리스틱 라벨이다

도구 응답의 분류 필드는 판정이 아니라 휴리스틱 라벨이다.
- 대상 필드 예시: `classification.incident_type`,
  `classification.operator_style`, `rule_name`, `severity`,
  `verification.status`.
- 결론에 이 필드를 직접 인용 금지. 대신 해당 필드와 함께 제공되는
  `*_basis` / `supporting_signals` 를 근거로 인용.
- 표현 예: "incident_type: ransomware" 를 "This is ransomware" 로
  읽지 말 것. "evidence suggests ransomware-style impact (basis:
  encrypted-files + ransom-note)" 로 읽을 것.

### allow_strong_conclusion 은 하드 게이트

`lane_state_board.allow_strong_conclusion == false` 이면 강한 결론
보류. `classification.incident_confidence == "high"` 라도 이 게이트가
false 면 단정 금지.
- 반드시 결론 앞에 "Investigation incomplete:" 접두 + `blocked_lanes`
  리스트 명시.
- "확증된 것" 과 "아직 검증 안 된 레인" 을 분리 서술.

### candidate_axes 는 가설의 부분집합이다

`candidate_axes.candidate_axes` 는 8 개 카테고리 택소노미
(`anti_forensics`, `credential_access`, `execution`,
`initial_access`, `persistence`, `remote_access`, `tool_execution`,
`tool_installation`, `impact`) 안에서 생성된다. 이 택소노미 바깥의
공격 각도는 응답에 나타나지 않는다.
- 모든 분석에서 "택소노미 바깥의 네 번째 각도" 를 능동 검토: 공급망,
  firmware, insider data exfil (extortion 없음), data destruction
  (금전 요구 없음), 물리 접근.
- 이 각도가 현 케이스에 해당할 수 있으면 분석 노트에 명시.

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
```

### 기존 Analysis Guardrails 섹션 조정

기존:
```markdown
## Analysis Guardrails
- See `docs/ANALYSIS_GUARDRAILS.md`, ...
```

신규 (맨 위에 한 줄 추가):
```markdown
## Analysis Guardrails

이 섹션은 위 "LLM 도구 응답 해석 규칙" 의 상위 원칙 모음이다. 둘을
함께 적용한다.

- See `docs/ANALYSIS_GUARDRAILS.md`, ...
```

---

## A1. MCP Docstring Audit

### 공통 템플릿

모든 대상 도구의 docstring 끝에 다음 형태로 섹션 추가. 기존 설명은
보존.

```
Reading guide for AI consumers:
- <field>: <어떻게 읽어야 하는지>.
- <field>: <어떻게 읽으면 안 되는지>.
- Before quoting <field>, check <guard_field>.
- If <guard_field> indicates <degraded_state>, phrase conclusions
  as "<hedged phrasing>".
```

4-8 줄. 한국어 / 영어 혼용 가능하지만 **영어 권장** — LLM 이 MCP
docstring 을 영어 컨텍스트로 파싱.

### 대상 도구 8 개 + 각 가이드 문구

**1. `auto_triage` — 최우선**

Anchoring 위험: "comprehensive one-stop" 오해. 분석가가 저수준 도구
드릴다운을 skip.

추가할 섹션:
```
Reading guide for AI consumers:
- This tool orchestrates a full-pipeline pass. It does NOT replace
  hypothesis-driven drill-down. Use its output as a starting index,
  not a verdict.
- result.initial_triage.incident_type is a heuristic label. Do NOT
  quote it as the case's verdict. Quote initial_triage.incident_basis
  with hedged phrasing ("evidence suggests").
- If result.lane_state_board.allow_strong_conclusion is false,
  prepend conclusions with "Investigation incomplete:" and list
  blocked_lanes.
- result.top_findings is legacy severity-sorted. Prefer
  result.alert_summary.key_findings for balanced reading.
- Before closing the investigation, run at least one refutation
  pass (e.g., verify benign explanation for the primary remote tool
  or service).
```

**2. `initial_triage_pack`**

Anchoring 위험: classification 필드가 판정으로 읽힘.

추가할 섹션:
```
Reading guide for AI consumers:
- classification.incident_type is a HEURISTIC LABEL, not a verdict.
  Do NOT quote it directly. Cite classification.incident_basis with
  "evidence suggests" phrasing.
- If lane_state_board.allow_strong_conclusion is false, treat the
  classification as a working hypothesis only.
- applicability.primary_domain is "windows_endpoint_ir". If the case
  is cloud / supply-chain / network-device / physical, the output
  is a degraded hint. Weight accordingly.
- precursor_context.status == "bridged_precursor" means shared token
  overlap, not causation. Do NOT assume the static-delta item
  actually participated in the incident without direct execution
  evidence.
- anchoring_warnings is a live list of bias risks in this pass.
  Read it before concluding.
```

**3. `find_suspicious`**

Anchoring 위험: severity 단일 정렬이 판정 축으로 오독.

추가할 섹션:
```
Reading guide for AI consumers:
- findings[] is severity-sorted. Severity is a rule-defined priority
  hint, not a case verdict. High-severity findings can be benign;
  low-severity findings can be critical depending on context.
- Prefer alert_summary.key_findings (balanced per category / rule)
  over findings[] for top-level reading.
- alert_summary.balance.warnings reports dominance risk. If present,
  review alternative categories before concluding.
- For each finding, examine details[] and absent_corroboration
  before quoting. A finding with no corroboration is a hint, not
  evidence.
```

**4. `baseline_diff`**

Anchoring 위험: net-new = 악성 오독.

추가할 섹션:
```
Reading guide for AI consumers:
- "net_new" items exist in the active case but not in the reference
  baseline. This is NOT a malice indicator. Legitimate third-party
  software, legitimate admin tools, and case-normal services will
  appear as net-new.
- Use baseline_diff as noise reduction, not as a verdict generator.
  Triage each net-new item with get_hit_detail /
  get_file_timestamps / direct evidence before treating it as
  suspicious.
- reference_source == "builtin_windows_baseline" means the reference
  is a tiny curated list. Expect high noise. For serious triage,
  diff against a golden-image reference case.
```

**5. `correlate`**

Anchoring 위험: 상관 → 인과 미끄러짐.

추가할 섹션:
```
Reading guide for AI consumers:
- Correlation results show temporal or keyword co-occurrence. They
  do NOT prove causation.
- co_occurrence_windows is a list of time buckets where multiple
  seeds fired together. A window appearing here is a prompt to
  investigate, not a proof of sequence.
- Do not infer "A caused B" from "A and B appear in the same
  window". Verify the actual sequence via direct timestamps
  (get_file_timestamps / timeline).
- Empty or truncated results do not mean "no correlation exists".
  Check truncation_warnings and consider wider windows.
```

**6. `behavioral_delta_pack`**

Anchoring 위험: "delta" 를 anomaly verdict 로 오독.

추가할 섹션:
```
Reading guide for AI consumers:
- This tool reports OBSERVED CHANGE between two periods. It does NOT
  classify the change as anomalous, malicious, or benign. Change
  alone is not a verdict.
- claims[].kind values like entity_net_new_in_incident or
  observed_volume_change describe structural difference only. The
  analyst (LLM or human) interprets the meaning.
- derived_from pointers on each claim are the evidence pointers to
  verify the claim. Do not quote the claim without reading at least
  one derived_from entry.
- dormant_gap_reason can be "truncated_sample" or "baseline_empty"
  etc. These reasons invalidate the gap measurement — do not use
  the gap as evidence in those cases.
```

**7. `investigation_gap_report`**

Anchoring 위험: "gap" 을 "아직 조사 안 한 것" 으로 오독 → 무비판
pivot 체인.

추가할 섹션:
```
Reading guide for AI consumers:
- pivots_not_attempted lists suggested next queries. These are
  POINTERS for further investigation, not required follow-ups.
  Chasing every pivot produces confirmation bias and wasted effort.
- Weak-strength signals are intentionally suppressed in
  pivots_not_attempted to reduce bias. If you want to corroborate a
  weak finding, do it manually with explicit uncertainty.
- If findings_available is false, sections requiring findings are
  listed in skipped_sections. Do NOT read a missing section as
  "no gaps there".
- bucket_gaps.stale_references lists bucketed hit_ids no longer in
  any loaded case. A saved snapshot referencing stale hits must not
  be read as current evidence.
```

**8. `detect_anti_forensics`**

Anchoring 위험: rule firing = 확정 tampering 오독.

추가할 섹션:
```
Reading guide for AI consumers:
- A fired rule means the pattern matched. It does NOT confirm
  malicious tampering. Administrators legitimately clear logs,
  delete shadow copies during maintenance, and disable scriptblock
  logging in test environments.
- Before concluding anti-forensic activity, correlate with (a)
  timing relative to other incident signals, (b) the actor account,
  (c) whether the action aligns with a known administrative task.
- rules_fired count is NOT a severity score. A single log-cleared-
  Security-1102 rule firing can be more significant than ten VSS-
  shadow-deletion rule firings, depending on context.
- If event logs are missing (coverage_gate.statuses.evtx ==
  "missing"), negative results here have limited weight. Do not
  read "0 rules fired" as "no tampering".
```

### 대상 도구 위치

`backend/mcp_bridge.py` 에서 각 도구의 `@mcp.tool()` 데코레이터
바로 아래 함수 docstring. 정확한 라인은 grep 으로 확인:

```
grep -n "^async def \(auto_triage\|initial_triage_pack\|find_suspicious\|baseline_diff\|correlate\|behavioral_delta_pack\|investigation_gap_report\|detect_anti_forensics\)" backend/mcp_bridge.py
```

---

## Test plan

### 자동 검증

- 기존 pytest 스위트 전부 통과 — docstring 수정은 기능 무영향이므로
  회귀 없어야 함.
- `python -c "from core.analysis import bias_remediation"` 및
  `python -c "import mcp_bridge"` 모두 SyntaxError / IndentationError
  없이 import.
- Docstring 포함 여부 검증 테스트 (신규):
  `backend/tests/test_mcp_docstring_hygiene.py` 에서 8 개 도구의
  `__doc__` 문자열이 "Reading guide for AI consumers" substring 을
  포함하는지 assert.

### 수동 검증

- CLAUDE.md 신규 섹션 마크다운 렌더링 확인 (VSCode 프리뷰 또는
  GitHub 렌더링).
- MCP 서버 재시작 후 `list_tools` 호출 시 docstring 이 정상 반환되는지
  확인 (MCP 클라이언트에 보이는 description 이 새 가이드 포함).

---

## Rollback

A3 (CLAUDE.md) 와 A1 (mcp_bridge.py docstring) 은 독립 롤백 가능.
문서 / 주석 변경만이므로 롤백 비용 없음.

## Codex 리뷰 체크리스트

- [ ] **기능 로직 무변경.** A3 는 CLAUDE.md 문서 수정. A1 은
      docstring 수정. 함수 본문 / 응답 dict / 테스트 로직 변경 금지.
- [ ] **기존 docstring 보존.** A1 은 기존 설명을 덮어쓰지 않는다.
      새 섹션을 **끝에** 추가한다.
- [ ] **Reading guide 형식 일관성.** 8 개 도구 모두 같은 형식 사용.
      4-8 줄 불릿.
- [ ] **도메인 언급 정확.** `applicability.primary_domain ==
      "windows_endpoint_ir"` 은 `initial_triage_pack` 관련 도구에만
      해당. `baseline_diff` 나 `correlate` 같은 일반 도구에는 해당
      없음.
- [ ] **Overfitting 금지.** 가이드 문구에 특정 사건명 / 도구명 /
      IOC 하드코딩 금지. 제네릭 표현 유지.
- [ ] **CLAUDE.md 섹션 위치.** "분석 원칙" 아래, "Analysis
      Guardrails" 위. 순서 지킬 것.
- [ ] **신규 테스트 통과.** test_mcp_docstring_hygiene.py 가 8 개
      도구의 가이드 섹션 포함 여부를 assert.
- [ ] **Deviation 명시.** 가이드 문구가 위 스펙과 다르면 이유 기재.

## Out of scope

- A1 Phase 2 (나머지 ~30+ MCP 도구 docstring) — 후속 PR.
- A2 응답 필드 순서 재배열.
- A4 반증 전용 도구 추가.
- A5 LLM-flow regression harness.
- A5 가 없는 한, 이 스펙의 효과는 측정 불가. 설계 기반 추정.

---

## Codex 핸드오프 프롬프트

```
docs/LLM_CONSUMER_HYGIENE_SPEC.md 를 구현해. 이건 기능 변경 0, 문서 /
docstring 수정만. A3 (CLAUDE.md 메타 규칙) + A1 (MCP docstring
audit 8 개) 를 한 PR 에 묶는다.

## 먼저 할 일

1. docs/LLM_CONSUMER_HYGIENE_SPEC.md 전체 읽기.
2. CLAUDE.md 현재 구조 확인. "분석 원칙" 섹션이 어디 끝나고
   "Analysis Guardrails" 가 어디 시작하는지 라인 번호 확인.
3. backend/mcp_bridge.py 에서 8 개 대상 함수 위치 grep:
   auto_triage / initial_triage_pack / find_suspicious /
   baseline_diff / correlate / behavioral_delta_pack /
   investigation_gap_report / detect_anti_forensics.
4. 각 함수의 기존 docstring 을 먼저 읽고, 새 섹션을 어디 삽입할지
   파악. 기존 설명은 보존.

## 절대 지킬 것

- **기능 로직 무변경.** 함수 본문 / 응답 dict / 테스트 로직 건드리지
  말 것. docstring 수정만.
- **기존 docstring 보존.** 새 "Reading guide for AI consumers" 섹션은
  기존 docstring **끝에** 추가. 덮어쓰기 금지.
- **형식 일관성.** 스펙의 8 개 도구별 가이드 문구를 그대로 사용. 임의
  패러프레이즈 금지. 문구에 이견이 있으면 먼저 질문.
- **CLAUDE.md 섹션 위치 준수.** "분석 원칙" 아래 / "Analysis
  Guardrails" 위. 임의 위치 이동 금지.
- **Overfitting 금지.** 가이드 문구에 특정 사건명 (INC, Bomgar 등),
  특정 도구명 (Bomgar, AnyDesk 등 구체 brand), 특정 IOC 값 하드
  코딩 금지. 제네릭 표현만 사용.

## 작업 흐름

1. 신규 테스트 먼저: backend/tests/test_mcp_docstring_hygiene.py
   작성. 8 개 도구의 __doc__ 이 "Reading guide for AI consumers"
   substring 포함하는지 assert. 실패 확인.
2. A3 적용: CLAUDE.md 신규 섹션 삽입. 마크다운 렌더 확인.
3. A1 적용: mcp_bridge.py 의 8 개 함수 docstring 에 스펙의 가이드
   문구 추가. 기존 설명은 그대로 보존.
4. 신규 테스트 통과 확인.
5. 기존 pytest backend/tests 전체 통과 확인.
6. python -c "import mcp_bridge" 로 SyntaxError 없음 확인.

## 질문해야 할 순간

- 8 개 도구 중 현재 코드에 존재하지 않거나 이름이 다른 것이 있으면
  스펙이 스테일한 것. 구현 전 질문.
- 기존 docstring 이 이미 "Reading guide" 비슷한 섹션을 포함하고
  있으면 중복 회피 방법 질문.
- CLAUDE.md 의 "분석 원칙" 이 여러 하위 섹션으로 구성돼 어느 끝에
  삽입할지 애매하면 질문.

## 출력

- 단일 PR. 커밋은 A3 와 A1 분리 권장 (CLAUDE.md 커밋 / mcp_bridge.py
  커밋).
- PR 본문:
  - CLAUDE.md 신규 섹션 전체 텍스트 인용.
  - 8 개 도구 docstring 변경 요약 (각 도구명 + 추가된 가이드 섹션
    요약 1 줄).
  - pytest 결과 (신규 테스트 통과 + 기존 회귀 없음).
  - Codex 리뷰 체크리스트 (스펙 하단 8 개) 체크 + 근거 위치.
  - Deviation 섹션. 가이드 문구를 패러프레이즈했으면 각 항목 명시.
    없어야 정상.
```
