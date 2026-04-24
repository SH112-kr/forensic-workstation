# Frontend Build Cleanup + Patch 2 Production Verification

`npm run build` 를 막고 있는 pre-existing TS6133 3 건을 제거하고,
Production preview 에서 Patch 2 Fix 의 실측 검증을 마무리한다.

이 작업의 1 차 목적은 production 배포 가능 상태 복구, 2 차 목적은
Patch 2 Fix 가 의도한 "initial_triage 호출 1 회" 를 production 환경에서
실제 Network 수준으로 확인하는 것.

연관 문서:
- `docs/BIAS_REMEDIATION_PATCH2_FIX.md` — 직전 fix. 이 스펙은 그
  후속 검증 단계.

## Background — React StrictMode 관련

Patch 2 Fix 구현 후 dev 서버에서 Dashboard 가 `/api/detection/run` 과
`/api/triage/lane-state` 를 각각 2 회 호출하는 현상이 관찰됐다.
`frontend/src/main.tsx:7` 이 `<App />` 을 `<StrictMode>` 로 감싸고
있어, React 18 StrictMode 가 dev 모드에서 `useEffect` 를 의도적으로
2 회 invoke 한 결과다.

Production build 에서는 StrictMode 가 effect 를 1 회만 invoke 한다.
따라서 **Dashboard fetch dedupe 로직을 추가하지 말 것.** dedupe 코드는
StrictMode 가 검출하려는 실제 effect 결함을 가리는 anti-pattern 이
될 수 있다. 올바른 검증 경로는 production build 를 돌려서 실제 Network
탭에서 1 회 호출을 확인하는 것.

## Problem statement

`npm run build` (`tsc -b && vite build`) 가 다음 3 개 TS6133 에러로
실패한다.

```
src/components/ArtifactBrowser.tsx(13,11): error TS6133: 'setActiveView' is declared but its value is never read.
src/components/CaseManager.tsx(354,9): error TS6133: 'inputStyle' is declared but its value is never read.
src/components/TimelineView.tsx(7,21): error TS6133: 'setActiveView' is declared but its value is never read.
```

이 세 변수는 전부 Patch 2 이전부터 미사용 상태였고, Patch 2 Fix 와
무관하다. 하지만 `npm run build` 가 실패하는 동안 production preview 를
돌릴 수 없어, Patch 2 Fix 의 실측 검증도 막힌다.

## Goal

- 세 TS6133 에러를 제거해 `npm run build` 가 통과한다.
- `npm run preview` 로 production build 를 서빙하고 Dashboard 오픈 시
  `/api/detection/run` 과 `/api/triage/lane-state` 가 각각 **1 회만**
  호출되는지 Network 탭으로 확인한다.

## Non-goals

- 관련 파일의 다른 리팩터링. 미사용 destructure / 변수 제거만.
- Dashboard fetch 경로 변경. StrictMode dev-artifact 는 건드리지 않는다.
- 다른 pre-existing 경고 / lint 정리.

## Success criteria

- `npm run build` 가 에러 없이 종료.
- `npm run preview` 실행 후 케이스 오픈 → DevTools Network 탭에서:
  - `/api/detection/run` 1 회
  - `/api/triage/lane-state` 1 회
- UI 기능 회귀 없음 (3 개 수정 파일의 렌더 동작 동일).

---

## Fix

### F-A. `frontend/src/components/ArtifactBrowser.tsx:13`

기존:
```tsx
const { setActiveView, caseInfo } = useStore();
```

`setActiveView` 는 이 컴포넌트에서 사용되지 않는다. 제거.

신규:
```tsx
const { caseInfo } = useStore();
```

파일 전체 grep 으로 `setActiveView` 참조가 정말 없는지 확인한 뒤
제거.

### F-B. `frontend/src/components/CaseManager.tsx:354`

기존:
```tsx
const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 12px', borderRadius: 6,
  border: '1px solid var(--border)', background: 'var(--bg)',
  color: 'var(--text)', fontSize: 13, fontFamily: 'monospace',
};
```

`inputStyle` 변수가 선언만 되고 JSX 에서 사용되지 않음. 제거.

주의: grep 으로 `inputStyle` 참조가 있는지 확인. 다른 분기에서 쓰고
있다면 제거 금지, PR 에 Deviation 으로 명시.

### F-C. `frontend/src/components/TimelineView.tsx:7`

기존:
```tsx
const { caseInfo, setActiveView } = useStore();
```

`setActiveView` 미사용. 제거.

신규:
```tsx
const { caseInfo } = useStore();
```

---

## Verification

### V-1. `npm run build` 통과 확인

로컬에서 실행:
```
cd frontend
npm run build
```
에러 없이 종료되고 `dist/` 디렉토리가 생성돼야 한다.

### V-2. Production preview 에서 fetch 1 회 확인

로컬에서 실행:
```
npm run preview
```

브라우저에서 preview 서버 주소 (기본 `http://localhost:4173`) 접속 후:

1. DevTools → Network 탭 열고 XHR 필터.
2. Preserve log 켜고 모든 요청 기록.
3. 케이스 오픈 또는 Dashboard 새로고침.
4. 다음 항목 확인:
   - `/api/detection/run` — 호출 횟수 **1 회**
   - `/api/triage/lane-state` — 호출 횟수 **1 회**

만약 여전히 2 회 나오면 StrictMode 외 다른 원인이 있는 것. 이 경우
Dashboard.tsx 의 useEffect 의존성 배열 / 상태 업데이트 순서를 재확인.
기본 가설은 "production 에서는 1 회" 이므로 실측이 이와 다르면 버그.

### V-3. UI 회귀 점검

- ArtifactBrowser 뷰에서 아티팩트 검색 / 필터 / 페이징 정상 동작.
- CaseManager 뷰에서 케이스 오픈 / 추가 정상 동작.
- TimelineView 뷰에서 타임라인 로드 / 필터 정상 동작.

---

## Rollback

세 변경 모두 독립. 개별 revert 가능. 전체 롤백 시에도 UI 동작 복원
(제거된 변수들은 원래 아무도 참조하지 않았으므로 revert 가 오히려
dead code 만 복원).

## Codex 리뷰 체크리스트

- [ ] **Scope 고정.** F-A / F-B / F-C 세 변경만. 추가 리팩터링 금지.
      Dashboard fetch 로직 건드리지 말 것.
- [ ] **StrictMode 이해.** Dashboard 의 2 회 fetch 는 StrictMode dev-
      artifact 다. dedupe 코드 추가 금지. production preview 로 1 회
      확인하는 것이 올바른 검증 경로.
- [ ] **grep 확인.** 각 변수를 제거하기 전 `grep -n` 으로 전체 파일
      에서 해당 identifier 참조가 정말 없는지 확인. 있다면 Deviation
      으로 PR 에 명시.
- [ ] **Production preview 실측.** V-2 결과를 PR 본문에 기재. Network
      탭 스크린샷 또는 텍스트 요약 (호출 횟수 숫자) 필수.
- [ ] **UI 회귀 검증.** V-3 세 뷰 전부 육안 확인. 결과를 PR 본문에
      한 줄씩 기재.
- [ ] **Deviation 명시.** 이번에도 없어야 정상.

---

## Codex 핸드오프 프롬프트

```
docs/FRONTEND_BUILD_CLEANUP_SPEC.md 를 구현해. 이건 production build
복구 + Patch 2 Fix 의 실측 마무리다. 기능 변경 0.

## 먼저 할 일

1. docs/FRONTEND_BUILD_CLEANUP_SPEC.md 전체 읽기.
2. docs/BIAS_REMEDIATION_PATCH2_FIX.md 의 "Background — React StrictMode
   관련" 섹션 재확인 (이 스펙 상단과 동일 내용). StrictMode dev-
   artifact 를 건드리지 않는다는 원칙 이해.
3. npm run build 를 먼저 실행해서 현재 TS6133 에러 3 건을 눈으로 확인.

## 절대 지킬 것

- **Scope 고정.** 세 변수 제거만. Dashboard fetch 경로 / useEffect /
  store 건드리지 말 것.
- **StrictMode dedupe 금지.** dev 에서 2 회 fetch 는 React 설계. 코드에
  방어 로직 넣지 마. production preview 로 1 회 확인하는 게 정답.
- **grep 확인 선행.** 각 변수 제거 전 `grep -n "setActiveView" <file>`
  또는 동등한 검색으로 참조가 없음을 확인. 있으면 멈추고 질문.

## 작업 흐름

1. grep 으로 F-A / F-B / F-C 세 변수가 정말 미참조인지 확인.
2. 각 파일에서 변수 제거 (destructure 에서 제외, 또는 선언 줄 삭제).
3. npm run build 실행 → 통과 확인.
4. npm run preview 실행 → 브라우저에서 케이스 오픈 → Network 탭에서
   /api/detection/run 1 회, /api/triage/lane-state 1 회 확인.
5. ArtifactBrowser / CaseManager / TimelineView 세 뷰 육안 회귀 확인.

## 질문해야 할 순간

- grep 결과 해당 변수가 다른 곳에서 참조되고 있으면 제거 금지, 질문.
- production preview 에서도 2 회 fetch 가 관찰되면 stop. StrictMode
  외 원인이 있으므로 분석 필요. Dashboard.tsx 의 useEffect / 상태
  업데이트 순서를 면밀히 검토하고 질문.

## 출력

- 단일 PR. 커밋 하나 또는 파일별 3 개 커밋. 작은 변경이므로 재량.
  커밋 메시지 예: "Remove unused setActiveView from ArtifactBrowser".
- PR 본문:
  - npm run build 통과 로그 요약.
  - npm run preview 에서 Network 탭 호출 횟수 (detection 1, lane-
    state 1).
  - UI 회귀 점검 결과 (세 뷰 각 한 줄).
  - 스펙 하단 Codex 리뷰 체크리스트 6 개 항목 체크.
  - Deviation 섹션. 없어야 정상.
```

---

## Out of scope

- S5 cross-case regression harness — 이 cleanup 이 통과된 후 별도
  `docs/REGRESSION_HARNESS_SPEC.md` 로.
- 다른 pre-existing 경고 / ESLint 수정 — 별도 cleanup PR.
- StrictMode 를 해제하거나 Dashboard effect 를 근본 개편 — 범위 밖.
