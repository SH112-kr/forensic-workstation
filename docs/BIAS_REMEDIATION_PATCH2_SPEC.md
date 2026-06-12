# Bias Remediation Patch 2 Spec

> **상태: 구현 완료** — [BIAS_REMEDIATION_SPEC.md](BIAS_REMEDIATION_SPEC.md) 의
> 후속 2단계. 잔여 이슈는 [BIAS_REMEDIATION_PATCH2_FIX.md](BIAS_REMEDIATION_PATCH2_FIX.md) 로 마감됨.

Patch 1 과 Patch 3 으로 백엔드 응답 스키마와 `lane_state_board` /
`candidate_axes` 생성은 완료됐다. Patch 2 는 이 데이터를 UI 지배 축에
도달시키는 단계다. 동시에 Patch 3 후속 리뷰에서 발견된 두 개 gap 을
마무리한다.

연관 문서:
- `docs/BIAS_REMEDIATION_SPEC.md` — 원 설계.
- Patch 3 리뷰 Issue B (lane_state_board 가 MCP/REST 표면에 없음).
- Patch 3 리뷰 Issue A (helper 재사용 cleanup).

## Problem statement

- `/api/detection/run`, `/api/triage/run`, `auto_triage` MCP 응답에
  `alert_summary` / `candidate_axes` 는 surface 되지만 `lane_state_board`
  는 응답에 포함되지 않는다. 리포트 HTML 에서만 렌더된다.
- Dashboard / DetectionPanel 프론트엔드는 여전히 `detection.findings` 를
  severity 단일 정렬로 소비한다. `balance.warnings`, `candidate_axes`,
  `lane_state_board` 는 UI 에 도달하지 않는다.
- `report_generator.py` 가 `build_bias_remediation_surface` 와
  `initial_triage` 를 별도로 호출한다 — 장기적 중복.

## Goal

`lane_state_board` 를 MCP/REST 표면에 올리고, Dashboard / DetectionPanel /
Settings (triage 결과) UI 가 balanced surface 를 기본 소비하게 바꾼다.
helper 를 확장해 lane_state_board 생성 경로를 단일화한다.

## Non-goals

- 새 탐지 규칙 / 새 lane 정의 추가.
- React Jest 테스트 도입 (프로젝트 자체에 없음 — 수동 검증 유지).
- Settings.tsx 의 triage UI 전면 재구조화 (배지 한 줄만 추가).

## Success criteria

- `/api/detection/run`, `/api/triage/run`, `auto_triage` MCP 응답 모두
  `lane_state_board` 키 포함. 기존 키 무손실.
- Dashboard 가 `alert_summary.balance.warnings` 배너 +
  `lane_state_board` 3 레인 배지 + `allow_strong_conclusion == false`
  시 "Investigation incomplete" 경고를 렌더한다.
- DetectionPanel 기본 탭이 `alert_summary.key_findings` 기준. "All
  findings (legacy)" 탭이 drill-down 으로 분리된다.
- `build_lane_state_board_surface` helper 가 lane_state_board 생성의
  단일 진입점. `report_generator` 가 helper 경유로 호출.
- 전체 pytest 통과 (240 이상 유지).

---

## Patch 2-A — 새 helper `build_lane_state_board_surface`

`backend/core/analysis/bias_remediation.py` 에 추가.

```python
def build_lane_state_board_surface(
    connector: Any,
    *,
    triage_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return {'lane_state_board': {...}} or {} if disabled.

    If the caller has already run ``initial_triage`` they can pass the
    payload via ``triage_payload`` to avoid a second timeline scan.
    Otherwise the helper runs it internally.

    Failure mode: silent-error surfacing. Failures return
    {'lane_state_board': {'error': str(e)}} so a consumer can tell the
    difference between 'disabled' and 'crashed'.
    """
    if not is_bias_remediation_enabled():
        return {}
    try:
        if triage_payload is None:
            from core.analysis.initial_triage import initial_triage
            triage_payload = initial_triage(connector, scope_mode="recent_14d")
        return {
            "lane_state_board": triage_payload.get("lane_state_board", {}) or {},
        }
    except Exception as e:
        return {"lane_state_board": {"error": str(e)}}
```

**설계 의도.** `triage_payload` 인자는 이미 initial_triage 를 돌린
호출자 (`api/triage.py`, `mcp_bridge.py::auto_triage`) 가 double-call
을 피하기 위한 것이다. report_generator 같이 triage pre-run 없는
호출자는 인자 없이 호출해서 내부에서 돌린다.

## Patch 2-B — MCP / REST 응답에 lane_state_board 주입

### 2-B.1 `backend/api/triage.py::run_triage` (`:262-303` 근방)

현재 `initial_triage(axiom, scope_mode="recent_14d")` 를 `:189-202` 에서
호출해서 `initial_triage_summary` 를 뽑고 `triage` 변수는 함수 내
로컬로 버려진다. `triage` 변수를 바깥 스코프로 유지하고
`build_lane_state_board_surface(axiom, triage_payload=triage)` 를 기존
`bias_surface` 생성 바로 뒤에 추가한다.

```python
triage: dict[str, Any] | None = None
try:
    triage = initial_triage(axiom, scope_mode="recent_14d")
    initial_triage_summary = { ... }
except Exception as e:
    steps.append({"step": "initial_triage_pack", "error": str(e)})

...

bias_surface = build_bias_remediation_surface(axiom, {"findings": findings}, findings=findings)
lane_surface = build_lane_state_board_surface(axiom, triage_payload=triage)

_triage_state["result"] = {
    ...
    "initial_triage": initial_triage_summary,
    **bias_surface,
    **lane_surface,                         # NEW
    "top_findings": [...],
    "top_findings_policy": "legacy_severity_sorted",
    ...
}
```

`triage` 가 None 이어도 `build_lane_state_board_surface` 가 내부에서
재실행을 시도하므로 안전. 실패 시 silent-error 표면화.

### 2-B.2 `backend/mcp_bridge.py::auto_triage` (`:3030-3201` 근방)

동일 패턴. `:3032-3046` 에서 `initial_triage` 호출 결과 `triage` 를
이미 보유하고 있다. `:3158` 의 `bias_surface` 생성 직후
`lane_surface = build_lane_state_board_surface(c, triage_payload=triage)`
추가 후 응답 dict 에 `**lane_surface` 로 병합한다.

`triage` 변수 라이프사이클을 try 블록 바깥으로 끌어내야 한다 (Patch 3
구현에서 이미 정리돼 있는지 구현 전에 확인).

### 2-B.3 새 엔드포인트 `/api/triage/lane-state` (GET)

Dashboard 가 case 로드 직후 병렬로 fetch 할 수 있는 가벼운 엔드포인트.

`backend/api/triage.py` 에 추가:

```python
@router.get("/lane-state")
async def get_lane_state():
    from state import app_state
    from core.analysis.bias_remediation import build_lane_state_board_surface
    try:
        axiom = app_state.get_axiom()
        return build_lane_state_board_surface(axiom)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

응답 shape:
- 활성 + 성공: `{"lane_state_board": {...}}`
- feature flag disable: `{}`
- 내부 오류: `{"lane_state_board": {"error": ...}}`

**주의.** 이 엔드포인트가 initial_triage 를 매번 돌리므로 호출 빈도
제어 필요. 프론트엔드는 케이스 로드 시 1 회만 호출한다. 사용자
재조회는 명시적 새로고침 버튼에 한정 (이 패치 범위 밖).

## Patch 2-C — `report_generator.py` cleanup

`:686-712` 의 분기 로직을 새 helper 로 교체.

기존:
```python
bias_surface = build_bias_remediation_surface(axiom, sus, findings=...)
try:
    triage = initial_triage(axiom, scope_mode="recent_14d")
    lane_state_board = triage.get("lane_state_board", {})
except Exception as e:
    lane_state_board = {"error": str(e)}
...
if lane_state_board is not None:
    json_data["lane_state_board"] = lane_state_board
```

신규:
```python
bias_surface = build_bias_remediation_surface(
    axiom, sus, findings=sus.get("findings", []),
)
lane_surface = build_lane_state_board_surface(axiom)
json_data.update(bias_surface)
json_data.update(lane_surface)
```

`_render_lane_state_board_html` 호출부 (`:732`) 도
`lane_surface.get("lane_state_board")` 를 읽도록 수정. feature flag
disable 시 `lane_surface` 가 `{}` 이므로 placeholder 가 빈 문자열로
치환된다 — 리포트 섹션이 완전히 사라지는 것이 의도된 동작.

---

## Patch 2-D — `frontend/src/components/Dashboard.tsx`

### 2-D.1 데이터 소스 추가

`useStore` 에 `laneStateBoard` 를 추가하거나 Dashboard 내부 state 로
관리. `useEffect` 에서 `get('/api/triage/lane-state')` 를
`/api/cases/summary` 와 병렬 호출. 실패 / 빈 응답은 조용히 배지 섹션을
숨긴다.

### 2-D.2 신규 렌더 요소 (기존 레이아웃 유지, 추가만)

anti-forensics 배너 (`:133-155`) 다음 줄에 3 개 블록을 순서대로 삽입.

**a. Investigation Incomplete gate (`allow_strong_conclusion == false` 시)**

노란 배경 (`var(--high-bg)`) 배너:
```
⚠ Investigation incomplete
Lanes unverified: Ingress / Access, Execution
Do not issue strong end-to-end conclusions.
```
`lane_state_board.blocked_lanes` 리스트를 한국어 라벨로 매핑해 렌더.

**b. Lane state 3 배지 카드**

```
[Ingress / Access: SUGGESTED] [Execution / Impact: CONFIRMED] [Persistence / Cleanup: NOT_SEEN]
```

각 state 별 색:
- `confirmed` → `var(--low-bg)` (초록)
- `suggested` → `var(--medium-bg)` (파랑)
- `unverified` → `var(--high-bg)` (노랑)
- `not_seen` → `var(--text-dim)` (회색)

각 카드에 `basis` 상위 2–3 항목을 보조 텍스트로 표시. 클릭 시
DetectionPanel 로 이동 (lane 별 artifact type 필터는 후속 enhancement).

**c. Balance warnings 배너 (`alert_summary.balance.warnings.length > 0` 시)**

중립 색 (`var(--surface)`) 배너:
```
ⓘ One category dominates current findings (persistence 70%). Review alternatives in Detection.
```
클릭 시 Detection 뷰로 이동.

### 2-D.3 risk level 재정의

`:68-70` 의 `hasCritical / hasHigh` 판정을 `alert_summary.key_findings`
기준으로 변경.

```tsx
const keyFindings = detection?.alert_summary?.key_findings || findings.slice(0, 10);
const hasCritical = keyFindings.some((f: any) => f.severity === 'critical');
const hasHigh = keyFindings.some((f: any) => f.severity === 'high');
```

`lane_state_board.allow_strong_conclusion == false` 이면 riskLevel 을
한 단계 낮춘다 (`critical` → `high`, `high` → `medium`). 시각적 과신
방지. `low` 는 더 낮추지 않는다. 감쇄 발생 시 배지 옆에 "incomplete"
라벨을 보조 표시해 원인을 명시한다.

## Patch 2-E — `frontend/src/components/DetectionPanel.tsx`

기존 단일 리스트 뷰를 탭 구조로 변경.

```
┌ Tabs ─────────────────────────────────────────────────────┐
│ [Key findings (balanced)] [Candidate axes] [All (legacy)] │
└───────────────────────────────────────────────────────────┘
```

**탭 1 — Key findings (default active)**
- 소스: `detection.alert_summary.key_findings`
- 상단: `detection.alert_summary.balance.warnings` 배너 (dominance 있으면).
- 렌더: 기존 finding row 컴포넌트 재사용. 색 / 레이아웃 변경 없음.
- 데이터 없으면 "Balanced 알고리즘이 걸러낸 결과가 0 개. All findings
  탭 확인 권장." 유도.

**탭 2 — Candidate axes**
- 소스: `detection.candidate_axes.candidate_axes`
- 각 axis 카드:
  - 제목: `label`
  - 배지: `verification.status` (`supported` / `plausible` / `weak`)
  - 리스트: `supporting_signals` (rule_name + severity + count)
  - 접힌 섹션: `unknowns` (질문 목록)
  - 경고: `verification.why_not_higher` (있으면)
- `candidate_axes.length == 0` 이면 empty state.

**탭 3 — All findings (legacy severity)**
- 소스: `detection.findings` 원본 (기존 동작 그대로)
- 상단 배지: "Legacy severity sort" 표시.

### 2-E.1 상태 관리

탭 전환은 local state (`useState<'key' | 'axes' | 'all'>('key')`). URL
해시 연동 여부는 구현자 재량.

## Patch 2-F — `frontend/src/components/Settings.tsx` (triage result)

`:404-407` 의 `triageResult.top_findings` 렌더 위에 lane_state_board
1 줄 요약 추가.

```tsx
{triageResult.lane_state_board && (
  <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
    <span>Ingress: {laneState(triageResult.lane_state_board.ingress_access)}</span>
    <span>Execution: {laneState(triageResult.lane_state_board.execution_impact)}</span>
    <span>Persistence: {laneState(triageResult.lane_state_board.persistence_cleanup)}</span>
    {!triageResult.lane_state_board.allow_strong_conclusion && (
      <span style={{ color: 'var(--high)' }}>⚠ Incomplete</span>
    )}
  </div>
)}
```

소형 배지 row, 디자인 변경 최소.

---

## Test plan

### Backend

- `backend/tests/test_bias_remediation_surface.py` 확장:
  - `build_lane_state_board_surface` with / without `triage_payload` 두
    경로 모두 커버.
  - feature flag disable 시 `{}` 반환.
  - initial_triage 가 예외를 던질 때
    `{"lane_state_board": {"error": ...}}` 반환.
- `test_auto_triage_contract.py` 확장: 응답에 `lane_state_board` 키
  존재 assert + double-call 방지 검증 (`initial_triage` monkey patch
  가 한 번만 호출됐는지).
- 신규 `test_triage_lane_state_endpoint.py`: `/api/triage/lane-state`
  GET 이 `lane_state_board` 를 반환하는 케이스.
- `test_report_generator_guardrails.py`: helper 경유로 바뀐 뒤에도
  기존 HTML 렌더 테스트 전부 통과 (investigation incomplete 배너 /
  candidate hypotheses 섹션 조건 포함).

### Frontend (수동 검증 체크리스트, PR 설명 첨부)

- [ ] 케이스 오픈 → Dashboard 에 3 레인 배지가 렌더됨.
- [ ] `allow_strong_conclusion == false` 인 fixture 에서 Investigation
      Incomplete 배너가 실제로 나옴.
- [ ] Balance warnings 있는 fixture 에서 Dashboard + DetectionPanel
      둘 다 배너 렌더.
- [ ] DetectionPanel 기본 탭이 "Key findings (balanced)" 이고 항목
      수가 ≤ 10.
- [ ] "All findings (legacy)" 탭에서 기존과 동일한 전체 목록 보임.
- [ ] Candidate axes 탭에서 axis ≥ 1 개 카드 렌더 (2 개 이상 fixture).
- [ ] `/api/triage/lane-state` 응답이 비어있는 (feature flag disable)
      경우 Dashboard 가 깨지지 않고 배지 섹션만 숨김.
- [ ] 기존 Dashboard 기능 (anti-forensics 배너, coverage, next steps)
      회귀 없음.

---

## Rollback

- 2-A 는 independent 모듈 추가. 다른 변경이 helper 를 쓰지 않으면 무해.
- 2-B / 2-C 는 백엔드 스키마 additive. 롤백 시 키만 사라지고 기존
  소비자 무영향.
- 2-D / 2-E / 2-F 는 UI 변경. 롤백 시 UI 만 되돌리면 API 는 유지.
- 전체 롤백 시 Patch 3 상태로 복귀.

## Feature flag

기존 `FW_BIAS_REMEDIATION_DISABLE=1` 이 `is_bias_remediation_enabled()`
을 통해 새 helper 까지 커버한다. Dashboard / DetectionPanel 은 신규
필드가 없으면 자동으로 배지 / 배너 섹션을 숨기도록 구현 (`if (data)`
가드). 별도 UI flag 불필요.

## Codex 리뷰 체크리스트

- [ ] **Overfitting 방지.** lane 식별자 외 도메인 하드코딩 없음. lane
      라벨 string 은 상수 또는 i18n 키로 유지.
- [ ] **Silent error 금지.** helper 와 엔드포인트 모두 error 를
      `{"error": ...}` 로 surface. UI 는 `error` 키가 있으면
      "Unavailable" 로 표시.
- [ ] **Contract break 금지.** `findings`, `top_findings`,
      `strength_rollup`, `initial_triage`, `alert_summary`,
      `candidate_axes` 전부 유지. `lane_state_board` 만 additive.
- [ ] **Double-call 방지.** `api/triage.py` 와
      `mcp_bridge.py::auto_triage` 에서
      `build_lane_state_board_surface(..., triage_payload=triage)` 로
      triage 재활용. 구현 후 단위 테스트로 `initial_triage` 호출
      횟수가 1 인지 assert.
- [ ] **Test coverage.** 백엔드 4 개 테스트 + 수동 체크리스트 8 개
      항목 전부 PR 본문에 기재.
- [ ] **Frontend graceful degrade.** feature flag disable 시 Dashboard /
      DetectionPanel 이 레거시 모드로 동작 (배지 / 배너 숨김, 기존
      findings 리스트 그대로).
- [ ] **Deviation 명시.** 표현 수준의 차이도 전부 Deviation 섹션에
      기재. Patch 1 의 `top_findings_policy` 같은 미세 변경 누락 사례
      재발 방지.

## Out of scope (후속 스펙 필요)

- **S5 cross-case regression harness** — 별도
  `docs/REGRESSION_HARNESS_SPEC.md`.
- **S6 baseline auto-generation** — `install.ps1` 확장. 별도.
- **Candidate axes drill-down UX** — 각 axis 에 "verify this" 버튼으로
  MCP 도구 호출을 연결하는 UX. 별도 UX 스펙.
- **Lane 배지 클릭 시 DetectionPanel 자동 필터** — 후속 enhancement.
- **Dashboard 에서 `/api/triage/lane-state` 수동 새로고침 버튼** —
  후속.
