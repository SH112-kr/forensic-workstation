# Bias Remediation Patch 2 Fix — lane_state_board Double-Call Cleanup

Patch 2 사후 리뷰에서 발견된 설계 이탈을 교정하는 짧은 후속 작업이다.
변경량은 백엔드 1 줄 삭제 + 프런트엔드 1 줄 수정 + 테스트 assertion
조정 1–2 줄.

연관 문서:
- `docs/BIAS_REMEDIATION_PATCH2_SPEC.md` — 원 설계 (특히 2-B.3 근거
  섹션).

## Problem statement

Patch 2 구현 후 다음 상태가 됐다.

- `backend/api/detection.py:35` — `/api/detection/run` 응답이
  `build_lane_state_board_surface(connector)` 를 호출해 응답에
  `lane_state_board` 를 포함한다.
- `backend/api/triage.py:548` — 별도 엔드포인트 `/api/triage/lane-state`
  도 같은 helper 를 호출한다.
- `frontend/src/components/Dashboard.tsx:71-73` — Dashboard 는 두 경로를
  `Promise.all` 로 **병렬 호출**한다.

결과적으로 케이스 오픈 시 `initial_triage` 가 서버 측에서 **2 회
실행**된다. `build_lane_state_board_surface` 의 `triage_payload` 인자는
double-call 방지 목적인데, `detection.py` 호출부는 이 인자를 넘기지
않으므로 helper 가 내부에서 `initial_triage` 를 새로 돌린다.

실질 영향:
- 소형 케이스: 무시 수준.
- 대형 케이스 (20 만+ hits): timeline scan 이 2 회 → 체감 수 초 ~
  10+ 초 추가 지연.
- `useStore.ts:71` 의 `setDetection` 이 `det?.lane_state_board ?? null`
  로 store 를 채우는 코드도 이 구조의 흔적 — detection 응답만으로도
  lane 이 채워지도록 만들려던 설계 혼선.

원 스펙 2-B.3 에서는 `/api/detection/run` 에 `lane_state_board` 를
넣지 **않기로** 했다. detection 호출이 무거워지는 것을 피하고, 가벼운
별도 엔드포인트로 분리하는 것이 명시적 설계였다. 현재 구현은 이 결정을
위반한다.

## Goal

`/api/detection/run` 은 `lane_state_board` 를 생성하지 않는다.
`/api/triage/lane-state` 가 단일 진입점이다. Dashboard 는 이미 별도
fetch 중이므로 UI 수정 없이 복원된다.

## Non-goals

- `build_lane_state_board_surface` helper 자체 수정.
- `/api/triage/lane-state` 엔드포인트 구조 변경.
- UI 컴포넌트 재설계.

## Success criteria

- `/api/detection/run` 응답에 `lane_state_board` 키 부재.
- Dashboard 는 `/api/triage/lane-state` 로만 lane 정보를 받는다.
- 케이스 오픈 시 서버 측 `initial_triage` 호출이 **1 회**로 감소.
- 전체 pytest 통과 유지.

---

## Fix

### F-1. `backend/api/detection.py:15-38`

기존 (Patch 2):
```python
@router.post("/run")
async def run_detection(req: DetectionRequest):
    from state import app_state
    from core.analysis.bias_remediation import (
        build_bias_remediation_surface,
        build_lane_state_board_surface,
    )
    from core.analysis.suspicious import find_suspicious
    ...
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        score_findings(payload)
        attach_provenance(payload, app_state._connectors)
        apply_suppressions(payload)
        attach_rule_coverage(payload, app_state._connectors)
        payload.update(build_bias_remediation_surface(connector, payload))
        payload.update(build_lane_state_board_surface(connector))    # ← DELETE
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

신규:
```python
@router.post("/run")
async def run_detection(req: DetectionRequest):
    from state import app_state
    from core.analysis.bias_remediation import build_bias_remediation_surface
    from core.analysis.suspicious import find_suspicious
    ...
    try:
        connector = app_state.get_axiom()
        payload = find_suspicious(connector.artifact_queries, rules=req.rules)
        score_findings(payload)
        attach_provenance(payload, app_state._connectors)
        apply_suppressions(payload)
        attach_rule_coverage(payload, app_state._connectors)
        payload.update(build_bias_remediation_surface(connector, payload))
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

변경 내용: `build_lane_state_board_surface` import 제거 + 호출 줄 삭제.

### F-2. `frontend/src/hooks/useStore.ts:71`

기존:
```typescript
setDetection: (det, mit) => set({
  detection: det,
  mitre: mit,
  laneStateBoard: det?.lane_state_board ?? null,
}),
```

신규:
```typescript
setDetection: (det, mit) => set({
  detection: det,
  mitre: mit,
}),
```

`det?.lane_state_board` 참조 제거. Detection 응답에서 lane 을 읽지
않도록 store 계약 정리. lane_state_board 는 오직
`setLaneStateBoard` 로만 업데이트된다.

### F-3. `frontend/src/components/Dashboard.tsx` (`:81-82`, `:131`)

Dashboard 의 lane state fallback 경로 정리.

기존:
```tsx
if (shouldLoadLaneState || (shouldLoadDetection && det?.lane_state_board !== undefined)) {
  setLaneStateBoard(lane?.lane_state_board ?? det?.lane_state_board ?? {});
}
...
const laneBoard = laneStateBoard || detection?.lane_state_board || null;
```

신규:
```tsx
if (shouldLoadLaneState) {
  setLaneStateBoard(lane?.lane_state_board ?? {});
}
...
const laneBoard = laneStateBoard || null;
```

`detection?.lane_state_board` fallback 제거. `/api/triage/lane-state`
가 단일 출처.

### F-4. 테스트 조정

- `backend/tests/test_detection_api_contract.py` — detection 응답에서
  `lane_state_board` 키 부재를 assert (있던 assertion 이 있으면 반대로
  교체). 대신 `/api/triage/lane-state` 엔드포인트 테스트에서 존재
  assert (이미 존재하는 `test_triage_lane_state_endpoint.py` 로 커버됨).
- `backend/tests/test_bias_remediation_surface.py` — 기존 helper 단위
  테스트는 수정 불필요 (helper 자체는 건드리지 않음).
- `backend/tests/test_auto_triage_contract.py:133` — `initial_triage`
  호출 1 회 assert 는 그대로 유지 (auto_triage 경로에는 영향 없음).

단, `test_detection_api_contract.py` 가 현재 `lane_state_board` 를
assert 하고 있으면 **그 assertion 을 반대로 바꿔야 한다** (키 부재
확인 또는 assertion 제거). 구현 전에 현재 테스트 내용 확인 필수.

---

## Rollback

세 변경 모두 개별 독립. F-1 만 돌리면 백엔드 복귀. F-2 / F-3 은 UI
레이어만 영향. 전체 롤백 시 Patch 2 상태.

## Codex 리뷰 체크리스트

- [ ] **Root-cause 이해.** 이 fix 는 버그 수정이 아니라 **스펙 이탈
      교정**이다. Patch 2 원 스펙 2-B.3 섹션이 "detection 에 넣지 말
      것"을 명시했음을 PR 본문에 인용.
- [ ] **Contract break 허용.** `/api/detection/run` 응답에서
      `lane_state_board` 키 제거는 **의도된 contract 변경**. Patch 2
      이전 (Patch 1 / 3) 에는 이 키가 없었으므로, Patch 2 이후 잠깐만
      있던 필드를 원상 복귀하는 것. UI 가 의존 안 하도록 F-2 / F-3
      동반.
- [ ] **Double-call 재발 방지.** 구현 후 `pytest` 로 `initial_triage`
      monkeypatch 호출 카운터가 case 오픈 경로 전체에서 몇 번
      나오는지 확인. Dashboard 재현 테스트는 없지만 백엔드 단위
      테스트 수준에서 detection 호출이 `initial_triage` 를 트리거하지
      않는지 assert.
- [ ] **Test coverage.** test_detection_api_contract.py 수정 내역을
      diff 로 PR 본문에 기재.
- [ ] **Deviation 명시.** 이번에는 Deviation 없어야 정상. 있다면 명시.

---

## Codex 핸드오프 프롬프트

Codex 에게 이 fix 를 넘길 때 다음 프롬프트를 사용한다.

```
docs/BIAS_REMEDIATION_PATCH2_FIX.md 를 구현해. 이건 Patch 2 의 설계
이탈 교정이다. 기능 추가가 아니다.

## 먼저 할 일

1. docs/BIAS_REMEDIATION_PATCH2_FIX.md 전체 읽기.
2. docs/BIAS_REMEDIATION_PATCH2_SPEC.md 의 2-B.3 섹션 재확인 — 원 설계
   의도 ("detection 에 넣지 말 것") 이해.
3. backend/api/detection.py:35, frontend/src/hooks/useStore.ts:71,
   frontend/src/components/Dashboard.tsx:81-82, :131 위치의 현재 코드
   직접 확인. 스펙과 어긋나면 질문.
4. backend/tests/test_detection_api_contract.py 에서 lane_state_board
   관련 assertion 이 어느 라인에 어떻게 있는지 먼저 확인.

## 절대 지킬 것

- **스코프 고정.** F-1 / F-2 / F-3 / F-4 네 변경만. 추가 리팩터링
  금지. build_lane_state_board_surface 자체는 건드리지 말 것.
- **helper 재사용.** /api/triage/lane-state 엔드포인트는 그대로 유지
  돼야 한다. 이 fix 는 그 엔드포인트를 단일 진입점으로 확립하는 것.
- **UI 기능 동등.** Dashboard 가 렌더하는 lane 배지 / Investigation
  Incomplete 배너 / risk 감쇄 로직 전부 동일하게 작동해야 한다. 현
  Dashboard 가 이미 /api/triage/lane-state 를 fetch 중이므로 UI 변경
  없이 동작 유지돼야 한다.

## 작업 흐름

1. 먼저 test_detection_api_contract.py 를 수정 (assertion 을 키 부재
   쪽으로) → 실패 확인.
2. F-1 적용 (detection.py:35 줄 삭제, import 정리) → 테스트 통과.
3. F-2, F-3 적용 (frontend store / Dashboard cleanup).
4. pytest backend/tests 전체 통과 확인.
5. npm run lint 또는 tsc --noEmit 으로 frontend 타입 에러 없는지
   확인 (pre-existing TS6133 외).
6. 실제 케이스로 브라우저에서 Dashboard 오픈 → 레인 배지가 여전히
   정상 렌더되는지 육안 확인.
7. Network 탭에서 케이스 오픈 시 /api/detection/run 과 /api/triage/
   lane-state 가 각각 1 회씩 호출되는지 확인 (중복 없음).

## 출력

- 단일 PR. 커밋 하나로 묶어도 됨 (변경량 작음).
- PR 본문:
  - Before / After 응답 JSON 예시 (detection 응답에서 lane_state_board
    제거).
  - Network 탭 스크린샷 또는 요약 — initial_triage 호출이 1 회로
    감소됐음을 확인.
  - Codex 리뷰 체크리스트 (FIX 문서 하단) 5 개 항목 체크.
  - Deviation 섹션 — 없어야 정상.
```

---

## Out of scope

이 fix 다음 단계는 S5 (cross-case regression harness). 별도
`docs/REGRESSION_HARNESS_SPEC.md` 로 진행한다. S5 가 있어야 "편향이
숫자로 얼마나 줄었는가" 를 측정할 수 있다.
