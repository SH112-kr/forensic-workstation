# LLM Regression Harness Spec (Tier A5) — Manual Edition

이 프로젝트는 LLM 단독 분석 도구다. 소비자가 Claude Code CLI 를
통해서만 LLM 에 접근하므로, `anthropic` SDK + API key 직접 호출 방식은
이 환경에서 작동하지 않는다. 이 스펙은 **수동 실행 harness** 로
설계한다: 유저가 Claude Code 세션에서 각 fixture 를 직접 실행하고,
harness 는 fixture 로딩 + 프롬프트 제공 + 결과 파싱 + 메트릭 계산을
지원한다.

연관 문서:
- `docs/BIAS_REMEDIATION_SPEC.md` — Patch 1-3 설계 (측정 대상).
- `docs/LLM_CONSUMER_HYGIENE_SPEC.md` — A3+A1 (측정 대상).
- `CLAUDE.md` — 표준 프롬프트가 참조하는 규칙 소스.
- `.claude/plans/ticklish-bouncing-quail.md` — 상위 로드맵.

## Problem statement

- 기능 단위 테스트 254 개 통과. 함수 shape 검증만 커버.
- **LLM 이 주어진 케이스에서 올바른 결론에 도달하는지 측정 없음.**
- LLM-specific 편향 리스크 (anchoring, false positive, tool-auto-
  selection, hallucination) 전부 추정 상태.
- 사용자 과거 false positive (PRA 정상 원격근무 → 잠복 오판) 재발
  여부가 매 세션 수동 확인에 의존.

## Goal

고정된 fixture 케이스를 Claude Code 세션에서 LLM 이 분석했을 때
**결론의 정확도 / 편향 지표 / 도구 사용 패턴**을 정량 측정하는
harness. 현재 시점 baseline 측정치 확보가 Phase 1 필수 결과물.

## Non-goals

- LLM 호출 자동화. Claude Code CLI 기반 수동 실행.
- `anthropic` SDK / API key 사용.
- Multi-model 비교. 단일 세션 (Claude Code 에서 설정된 모델) 만.
- CI 자동 실행. Phase 2 범위.
- 실제 침해 데이터 저장. Fixture 는 synthetic.
- 완벽한 객관성. LLM 비결정성으로 N=3 variance 있는 측정치.

## Success criteria (Phase 1)

- 3 개 fixture (ransomware-like / benign-remote-work / partial-
  evidence) + 각 ground truth JSON.
- `FW_FIXTURE` 환경변수로 fixture 를 활성 케이스로 프리로드하는
  메커니즘.
- 유저가 수동으로 3 fixture × 3 runs = 9 세션 실행 가능한 표준 프롬프트
  + 실행 가이드.
- 세션 종료 후 결과 (final verdict + Claude Code 세션 로그) 를
  harness 에 ingest → 4 개 메트릭 계산 → baseline 리포트 생성.
- 재실행 시 동일 입력이면 동일 메트릭 (결정적 계산).

---

## Phase 1 아키텍처

### 디렉토리 구조

```
backend/regression/
├── __init__.py
├── fixtures/
│   ├── __init__.py
│   ├── case_ransomware_inc_like.py        # synthetic stub connector
│   ├── case_benign_remote_work.py
│   └── case_partial_evidence.py
├── ground_truth/
│   ├── case_ransomware_inc_like.json
│   ├── case_benign_remote_work.json
│   └── case_partial_evidence.json
├── prompt.py                              # 표준 분석 프롬프트 + VERSION
├── preload.py                             # FW_FIXTURE 환경변수 → connector 로드
├── ingest.py                              # 유저 결과 파일 → 메트릭 계산
├── metrics.py                             # 4 개 지표 함수
├── report.py                              # CSV + markdown 리포트
├── cli.py                                 # argparse 진입점
└── reports/                               # 생성 산출물 (.gitignore)
```

`backend/tests/test_regression_harness.py` — harness 자체 기능 테스트.
LLM 실행은 포함하지 않음.

### Fixture 설계

각 fixture 는 synthetic stub connector. `axiom_mfdb` / `kape_csv` 의
공개 인터페이스 중 MCP 도구가 실제 호출하는 메서드만 구현.

공통 인터페이스:
```python
class FixtureConnector:
    """Stub satisfying the subset of axiom/kape interface used by MCP tools."""
    def is_connected(self) -> bool: ...
    def get_metadata(self) -> dict: ...
    def get_artifact_type_counts(self) -> list[dict]: ...
    def get_timeline(self, start_date="", end_date="", limit=500, offset=0) -> dict: ...
    def search(self, keyword="", filters=None, limit=50, offset=0) -> dict: ...
    def get_hit_detail(self, hit_id: int) -> dict: ...
    @property
    def artifact_queries(self) -> Any: ...
```

원칙:
- 아티팩트 100-500 개 수준. 실제 케이스의 축소판.
- 결정적: 같은 입력 → 같은 출력.
- 가독성: fixture 파일이 JSON-like Python dict 로 case 특징을 한눈에.

### Fixture 프리로딩 (E1 메커니즘)

`backend/state.py` 또는 `backend/mcp_bridge.py` 기동 시점에 다음 로직
추가:

```python
def _preload_fixture_if_requested():
    fixture_name = os.environ.get("FW_FIXTURE", "").strip()
    if not fixture_name:
        return  # production 모드 — 무영향
    from core.analysis import masker  # 기존 초기화 경로
    from regression.preload import load_fixture_as_active_case
    load_fixture_as_active_case(fixture_name, app_state)
    # MCP 서버는 이미 "axiom" 커넥터가 로드된 상태로 기동
```

`regression/preload.py::load_fixture_as_active_case(name, app_state)`:
- `regression/fixtures/<name>.py` import
- connector 인스턴스 생성
- `app_state._connectors["axiom"] = connector`
- stdout 에 프리로드 확인 메시지 ("Preloaded fixture: <name>")

**환경변수 없으면 완전 무영향**: 기존 production 경로와 1 비트도 달라
지지 않음. 테스트 모드는 명시적 opt-in.

### 표준 프롬프트

`backend/regression/prompt.py`:

```python
PROMPT_VERSION = "1.0"

STANDARD_ANALYST_PROMPT = """
You are a DFIR analyst investigating a potential security incident. A case
has been loaded into the forensic workstation (this is a regression test
fixture). You have access to the full MCP tool suite.

Follow all rules in CLAUDE.md, especially the "LLM 도구 응답 해석 규칙"
section.

Your task:
1. Declare your initial hypothesis before calling any tool: what do you
   suspect, and what evidence would refute it?
2. Use MCP tools to investigate. For each tool call, state why you are
   calling it — hypothesis verification, refutation, or clarification.
3. Reach a conclusion.

Tool call budget: up to 30 tool calls.

Return your final answer as a single JSON object in a ```json code block:
{
  "hypothesis_declared": "<what you initially suspected>",
  "refutation_checked": "<counter-evidence you verified>",
  "verdict": "<ransomware | insider | supply_chain | benign | unknown>",
  "confidence": "<high | moderate | low | incomplete>",
  "basis": ["<evidence item 1>", ...],
  "unknowns": ["<unknown 1>", ...],
  "investigation_incomplete": <true | false>,
  "blocked_lanes": ["<lane name if incomplete>"],
  "considered_alternatives": ["<alternative hypothesis 1>", ...]
}
"""
```

프롬프트는 버전 관리. 수정 시 VERSION 증가. 이전 버전 리포트와 비교
불가능함을 명시.

### Ground truth 포맷

`regression/ground_truth/<fixture>.json`:

```json
{
  "fixture_name": "case_ransomware_inc_like",
  "case_description": "Hands-on-keyboard ransomware via Bomgar remote session; clear execution + impact lanes; partial persistence.",
  "expected_verdict": {
    "primary": "ransomware",
    "acceptable_alternatives": ["ransomware-like impact", "destructive"]
  },
  "expected_confidence": "moderate",
  "expected_lane_state_board": {
    "ingress_access": ["confirmed", "suggested"],
    "execution_impact": "confirmed",
    "persistence_cleanup": ["suggested", "unverified"]
  },
  "expected_allow_strong_conclusion": true,
  "prohibited_phrases": ["this is definitely", "certainly ransomware"],
  "required_phrases": ["evidence suggests", "ransom note"],
  "expected_tool_calls_minimum": ["find_suspicious", "get_file_timestamps", "build_timeline"],
  "forbidden_tool_shortcuts": ["auto_triage alone without drill-down"]
}
```

### 메트릭 (Phase 1)

`backend/regression/metrics.py`:

**M1. Verdict correctness.**
```python
def verdict_correct(final_answer: dict, ground_truth: dict) -> bool:
    predicted = str(final_answer.get("verdict", "")).lower().strip()
    acceptable = {ground_truth["expected_verdict"]["primary"].lower()}
    acceptable.update(
        v.lower() for v in ground_truth["expected_verdict"].get("acceptable_alternatives", [])
    )
    return predicted in acceptable
```

**M2. False positive (benign fixture 한정).**
```python
def is_false_positive(final_answer: dict, ground_truth: dict) -> bool:
    if ground_truth["expected_verdict"]["primary"] != "benign":
        return False
    predicted = str(final_answer.get("verdict", "")).lower()
    return predicted not in {"benign", "unknown"}
```

**M3. Tool diversity** — 세션 로그에서 도구 호출 목록 추출 필요.
```python
def tool_diversity(tool_calls: list[dict]) -> dict:
    names = [call["name"] for call in tool_calls]
    return {
        "total_calls": len(names),
        "unique_tools": len(set(names)),
        "diversity_ratio": len(set(names)) / max(len(names), 1),
        "top_tool_share": (
            Counter(names).most_common(1)[0][1] / max(len(names), 1) if names else 0
        ),
    }
```

세션 로그 파싱은 `ingest.py` 가 처리. 로그가 제공되지 않으면 M3 는
`null` 로 기록.

**M4. Uncertainty citation.**
```python
def uncertainty_cited(final_answer_text: str) -> dict:
    lower = final_answer_text.lower()
    markers = {
        "applicability_mentioned": "applicability" in lower,
        "strong_conclusion_mentioned": (
            "allow_strong_conclusion" in lower
            or "investigation incomplete" in lower
        ),
        "hedged_language": any(
            phrase in lower
            for phrase in ["evidence suggests", "basis:", "may indicate", "consistent with"]
        ),
    }
    markers["total_cited"] = sum(bool(v) for v in markers.values())
    return markers
```

Per-fixture aggregation: N 회 실행 평균 / std / best / worst 계산.

### 리포트

`backend/regression/report.py` 가 `reports/` 디렉토리에 생성:

**CSV** — `reports/run_<timestamp>.csv`:
```
fixture,run_idx,verdict_correct,is_fp,total_calls,unique_tools,diversity_ratio,top_tool_share,uncertainty_total,final_verdict,prompt_version
```

**Markdown** — `reports/run_<timestamp>.md`:
```markdown
# Regression Report — 2026-04-23 14:32 UTC

Prompt version: 1.0 | Runs per fixture: 3 | Commit: <git sha>
Claude Code session source: manual (Opus 4.7 assumed)

## Summary

| Fixture | Verdict Correct | FP Rate | Avg Diversity | Uncertainty Cited Avg |
|---|---|---|---|---|
| case_ransomware_inc_like | 3/3 | — | 0.72 | 2.7/3 |
| case_benign_remote_work | 2/3 | 1/3 | 0.61 | 2.3/3 |
| case_partial_evidence | 3/3 | — | 0.55 | 2.7/3 |

## Per-fixture detail
<fixture 별 N회 기록>

## Flags
- case_benign_remote_work run 2: FALSE POSITIVE — 원인 분석 필요.
```

`reports/` 는 `.gitignore`. 실제 commit 은 `docs/regression_baseline_
YYYY-MM-DD.md` 에 사본.

### 수동 실행 워크플로우

유저가 따르는 절차. 각 fixture 당 N 회 반복.

```
# 1. Fixture 를 활성 케이스로 프리로드하여 백엔드 기동
export FW_FIXTURE=case_ransomware_inc_like
python -m backend   # 또는 기존 기동 스크립트 (MCP stdio 모드)
# 백엔드가 "Preloaded fixture: case_ransomware_inc_like" stdout

# 2. 새 터미널에서 표준 프롬프트 가져오기
python -m backend.regression.cli show-prompt case_ransomware_inc_like
# stdout 에 표준 프롬프트 + VERSION 출력

# 3. Claude Code 세션 시작 (forensic-workstation MCP 연결된 설정)
claude
# 프롬프트를 복붙하여 분석 실행
# 세션 끝까지 진행, 최종 JSON verdict 확인

# 4. 세션 결과 수집
# - 최종 verdict JSON 을 텍스트 파일로 저장 (예: run1_verdict.json)
# - Claude Code 세션 로그 경로 확인 (~/.claude/projects/.../conversations/<session>.jsonl)

# 5. Harness 에 ingest
python -m backend.regression.cli ingest \
    --fixture case_ransomware_inc_like \
    --run 1 \
    --verdict-file run1_verdict.json \
    --session-log ~/.claude/projects/.../conversations/<session>.jsonl
# harness 가 파싱 + 메트릭 계산 + reports/ 에 append

# 6. 9 회 반복 후 최종 리포트 생성
python -m backend.regression.cli finalize
# reports/run_<timestamp>.md 생성. 유저가 docs/regression_baseline_
# <date>.md 로 복사하여 commit.
```

**세션 로그 파싱.** Claude Code 대화 로그는 `~/.claude/projects/
<project-hash>/conversations/*.jsonl` 에 저장되고, 각 line 이 이벤트:
- `type: "tool_use"` + `name` + `input` — 도구 호출
- `type: "tool_result"` — 응답
- `type: "assistant_message"` — LLM 텍스트
`ingest.py` 가 이 형식 파싱하여 M3 (tool diversity) 계산. 로그를 주지
않으면 M3 는 `null`.

**세션 로그 없이도 M1 / M2 / M4 는 측정 가능** — final verdict JSON
만 있으면 됨.

---

## Phase 1 Fixtures 상세 설계

### F1. `case_ransomware_inc_like`

**목적:** 기본 정확성. 명확한 ransomware 증거에서 올바른 verdict 인지.

**증거 구성:**
- Prefetch: `win.exe` (user-writable path), 다수 `cmd.exe` / `wmic.exe`
- File signature mismatch: `\Users\Public\win.exe`, `\ProgramData\update.exe`
- Encrypted Files: ~200 개 (`.INC` extension)
- Text Documents: `INC-README.txt` (content: "decrypt", "restore")
- Event log 1102 (log cleared) 1 건
- SRUM: Bomgar 프로세스 high-volume 세션
- Prefetch: `Bomgar.exe` 최근 실행
- Bomgar 시그니처 mismatch 없음 (정상 설치)
- Scheduled task: `update_task` (net-new vs baseline)

**Ground truth:**
- verdict: `ransomware`
- confidence: `moderate` (MFT 세세한 검증 전제)
- allow_strong_conclusion: `true`
- prohibited: "definitely", "certainly"
- required: "ransom note", "extension churn", "evidence suggests"
- minimum tool calls: `find_suspicious`, `build_timeline`, `get_file_timestamps`

### F2. `case_benign_remote_work`

**목적:** 사용자 과거 false positive 재현 방지. PRA / Bomgar 정상
원격근무가 잠복 침해로 오판되지 않는가.

**증거 구성:**
- SRUM: Bomgar 세션 다수 (낮 시간 위주, 주말 없음 — 정상 업무 패턴)
- Prefetch: Bomgar.exe 정상 빈도
- Baseline diff: Bomgar 서비스 net-new (신규 설치)
- 암호화 파일 / 랜섬노트: 없음
- 비정상 프로세스 / 권한 상승: 없음
- Event log: 정상 logon / logoff 패턴
- 비정상 파일 생성 / 삭제: 없음

**Ground truth:**
- verdict: `benign`
- confidence: `moderate`
- allow_strong_conclusion: `false` (impact lane = `not_seen`)
- prohibited: "compromise", "잠복", "latent"
- required: "no evidence of impact" 또는 "investigation incomplete"
  또는 "benign admin use consistent"
- forbidden shortcut: `auto_triage` 결과만으로 "suspicious" 결론

### F3. `case_partial_evidence`

**목적:** `allow_strong_conclusion=false` 게이트가 LLM 결론을 억제하는가.

**증거 구성:**
- Event logs: **completely missing**
- Prefetch: 10 개 (부분)
- SRUM: 부재
- MFT 있음, USN journal 부재
- 약한 findings 3-4 개 (strong 증거 없음)

**Ground truth:**
- verdict: `unknown`
- confidence: `incomplete` 또는 `low`
- allow_strong_conclusion: `false`
- required: "Investigation incomplete", "missing coverage", 부재 lane
  명시 (execution_impact 또는 ingress_access)
- prohibited: 강한 verdict ("ransomware", "compromise", "insider")
- must cite: `applicability` 또는 `blocked_claims` 또는 lane_state_
  board.blocked_lanes

---

## Test plan (harness 자체)

`backend/tests/test_regression_harness.py` 에서:

- Fixture 로딩: 각 fixture connector 가 interface 메서드 호출 시 합리
  적 응답.
- FW_FIXTURE preload 로직: env 설정 시 app_state 주입, 미설정 시 무변경.
- Ground truth 스키마 유효성.
- 메트릭 계산: mock 입력 → 예상 출력.
- Ingest CLI: mock verdict 파일 + mock 세션 로그 → 정확한 파싱.
- Report 생성: mock 결과 리스트 → CSV + markdown 포맷.

**LLM 실행은 테스트하지 않음** — 수동 실행 영역.

---

## 비용 / 구독 고려

- Claude Code 구독 allowance 에서 차감 (API key 아님).
- 9 세션 × ~15 tool calls / 세션 = 약 9 회의 중-장 분석 대화.
- Opus 4.7 사용 시 allowance 상당 소비. 최초 baseline 후 재측정은
  **주요 변경 시만** 권장 (PR 마다 X).
- 장기: Phase 2 에서 Claude Code `--print` 헤드리스 모드로 자동화
  검토.

## Rollback

`backend/regression/` 디렉토리 + `backend/state.py` 의 preload 훅만
추가/변경. 롤백 시 디렉토리 삭제 + 훅 제거. 기존 코드 무영향.

## Phase 2 outline (out of scope)

- 추가 fixture (anti-forensics / insider-exfil / supply-chain / empty /
  persistence-only).
- Claude Code `--print` 헤드리스 자동화 (`claude --print --mcp-config ...
  --output-format stream-json` 경유).
- CI 통합.
- Multi-model panel.
- 자동 regression 감지.

## Codex 리뷰 체크리스트

- [ ] **Scope 고정.** Phase 1 manual 만. Claude Code 호출 / subprocess
      / anthropic SDK 추가 금지.
- [ ] **LLM 실행은 harness 테스트에서 제외.** 수동 실행 영역.
- [ ] **Fixture 결정성.** 같은 입력 → 같은 응답. 랜덤 / 시간 / 네트워크
      의존 금지.
- [ ] **Synthetic connector 시그니처 호환.** axiom_mfdb / kape_csv 의
      메서드 시그니처를 정확히 따름. 빠진 메서드 호출 시
      NotImplementedError.
- [ ] **FW_FIXTURE 환경변수 gate.** env 미설정 시 production 경로 완전
      무영향. 초기화 로그 외 sideeffect 금지.
- [ ] **Overfitting 금지.** ground truth 의 required / prohibited
      phrases 에 특정 도구명 / 사건명 하드코딩 금지 (fixture 특성상
      불가피한 것만 허용 — benign / ransomware 같은 일반 용어).
- [ ] **Reports gitignore.** `backend/regression/reports/` 가
      `.gitignore` 에 추가.
- [ ] **Prompt version.** `prompt.py` 에 VERSION 상수 존재. 리포트에
      기록.
- [ ] **Session log 파서 graceful.** 로그 파일 제공 안 된 경우 M3 를
      null 로 기록하고 진행 (crash 금지).
- [ ] **Deviation 명시.** 스펙과 다른 구현 결정은 PR 에 기재.

## Out of scope

- A2 (응답 필드 순서 재배열).
- A4 (반증 전용 도구).
- Phase 2 전체.

---

## Codex 핸드오프 프롬프트

```
docs/LLM_REGRESSION_HARNESS_SPEC.md 를 Phase 1 manual 범위로 구현해.
이건 새 harness 모듈 추가 + 3 fixture + FW_FIXTURE preload + ingest
CLI. LLM 자동 호출은 구현하지 않는다 (수동 워크플로우).

## 먼저 할 일

1. docs/LLM_REGRESSION_HARNESS_SPEC.md 전체 읽기.
2. docs/LLM_CONSUMER_HYGIENE_SPEC.md + CLAUDE.md "LLM 도구 응답 해석
   규칙" 섹션 재확인 — 표준 프롬프트가 이 규칙을 참조 인용.
3. backend/state.py 확인 — FW_FIXTURE preload 훅 삽입 위치 파악. 초기
   화 경로에서 app_state._connectors 를 건드릴 수 있는 시점을 찾아.
4. backend/core/connectors/axiom_mfdb.py + kape_csv.py 의 공개 메서드
   시그니처 확인. fixture connector 가 호환해야 함.
5. Claude Code 세션 로그 포맷 확인 (~/.claude/projects/... 내 jsonl
   이벤트 구조). ingest 파서의 대상.

## 절대 지킬 것

- **Scope 고정.** Phase 1 manual 만. 3 fixture + 4 메트릭 + ingest CLI
  + FW_FIXTURE preload. Claude Code subprocess 호출 / anthropic SDK /
  CI / multi-model 전부 금지.
- **LLM 실제 실행은 harness test 에서 제외.** test_regression_harness
  .py 는 fixture 로딩 / 프롬프트 생성 / 메트릭 계산 / ingest 파싱 / 리
  포트 포맷만 테스트.
- **Fixture 결정성.** 같은 입력 → 같은 응답. 시간 / 랜덤 / 네트워크
  의존 금지.
- **FW_FIXTURE gate.** env 미설정 시 production 경로에 1 비트도 영향
  없어야 한다. env 체크가 state 초기화의 최상단에 있고, 없으면 early
  return.
- **Reports 는 git 올리지 마라.** backend/regression/reports/ 를
  .gitignore 에 추가.
- **새 탐지 로직 금지.** 이 harness 는 측정 도구. 새 MCP tool / rule /
  scoring 추가 금지.

## 특별히 주의할 것

- **Synthetic connector 호환성.** 각 fixture 의 stub 은 axiom_mfdb /
  kape_csv 의 메서드 시그니처를 정확히 따라야 한다. MCP 도구가
  connector.get_timeline(limit=500) 호출하는데 stub 이 get_timeline
  (limit) 만 받으면 실패. 시그니처 매칭 꼼꼼히.
- **FW_FIXTURE preload 에러 처리.** 잘못된 fixture 이름이면 명확한
  에러 메시지 + 프로세스 종료. 조용히 production 경로로 fallback
  금지 (사용자가 자기도 모르게 production 에 분석 돌리면 치명적).
- **Session log 파서 graceful.** 로그 포맷이 미래에 Claude Code 버전
  업으로 변경될 수 있음. 파싱 실패 시 M3 를 null 로 기록하고 나머지
  지표는 계산 진행.
- **표준 프롬프트 VERSION.** prompt.py 에 VERSION 상수 필수. 프롬프트
  수정 시 버전 bump. 리포트에 기록.
- **Ground truth phrase 매칭.** case-insensitive substring 매칭. 정규
  식 오용 금지. required / prohibited phrase 둘 다 동일 로직.

## 작업 흐름

1. backend/regression/ 디렉토리 구조 생성 + __init__.py.
2. preload.py 의 FW_FIXTURE 훅 먼저. test 로 env 설정 / 미설정 두 경로
   검증. backend/state.py 에 호출 지점 삽입.
3. fixture 3 개 synthetic connector 작성. test 로 각 connector 의
   메서드 시그니처 호환성 assert.
4. ground_truth/ JSON 3 개 작성. test 로 스키마 유효성.
5. prompt.py 의 STANDARD_ANALYST_PROMPT + VERSION 작성. test 로 필수
   섹션 (hypothesis_declared / verdict / confidence / investigation_
   incomplete 등) 포함 assert.
6. metrics.py 4 개 함수. test 로 mock 입력 → 예상 출력.
7. ingest.py — verdict 파일 파싱 + (옵션) session log 파싱. test 로
   mock 입력 처리.
8. report.py — CSV + markdown 생성. test 로 포맷.
9. cli.py — argparse 진입점 (show-prompt / ingest / finalize).
10. pytest backend/tests/test_regression_harness.py 전체 통과.
11. 실제 수동 dry-run 1 회:
    - export FW_FIXTURE=case_ransomware_inc_like
    - backend 기동 → "Preloaded fixture" 메시지 확인
    - claude 세션에서 표준 프롬프트 복붙 → 분석 진행 → final JSON 확인
    - ingest CLI 로 결과 처리
    - reports/ 에 entry 생성 확인

## 질문해야 할 순간

- backend/state.py 의 초기화 경로가 여러 진입점 (FastAPI startup, MCP
  stdio startup 등) 이 있으면 preload 훅을 어디에 두는 게 맞는지 질문.
- Claude Code 세션 로그 포맷이 예상과 다르면 (jsonl 이 아니거나 이벤트
  shape 다르면) 구조 질문.
- execute_tool dispatcher 가 fixture connector 의 모든 메서드를 호출
  할 수 있는지 확인. 호출 못하는 메서드가 있으면 fixture 범위 질문.
- Ground truth 의 verdict 판정 경계가 모호하면 질문 (예: case_partial_
  evidence 가 "unknown" vs "incomplete" 중 어느 쪽이 정답인지).

## 출력

- 단일 PR. 커밋은 단계별 분리 (preload / fixture / prompt / metrics /
  ingest / report / cli).
- PR 본문:
  - 각 fixture 특징 요약 표.
  - dry-run 1 회 결과 (final JSON + 메트릭 값).
  - pytest 결과 (신규 테스트 + 기존 회귀 없음).
  - 스펙 하단 Codex 리뷰 체크리스트 10 개 체크.
  - Deviation 섹션. 스펙과 다른 결정 전부 기재.
```
