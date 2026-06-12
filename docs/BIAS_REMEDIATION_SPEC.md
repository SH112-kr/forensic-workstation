# Bias Remediation Spec

> **상태: 구현 완료** — Patch 1–3 머지됨 (`backend/core/analysis/bias_remediation.py`,
> `lane_state_board` / `candidate_axes`). 후속 보완은
> [BIAS_REMEDIATION_PATCH2_SPEC.md](BIAS_REMEDIATION_PATCH2_SPEC.md) →
> [BIAS_REMEDIATION_PATCH2_FIX.md](BIAS_REMEDIATION_PATCH2_FIX.md) 순서로 읽는다.

이 문서는 분석 파이프라인의 지배 축 편향을 줄이기 위한 구체 구현 스펙이다.
Codex 가 이 스펙에 따라 3 개 패치로 구현한다. 각 패치는 독립 PR 로 머지 가능하고
revert 단위도 분리된다.

연관 문서:
- `docs/ANALYSIS_GUARDRAILS.md` — 편향 방지 규칙 (상위 원칙)
- `docs/ANALYSIS_PLAYBOOK.md` — lane-based 운영 절차
- `docs/HYPOTHESIS_REFACTOR_BACKLOG.md` — IR-001 ~ IR-005 로드맵 (이 스펙은 IR-001/IR-002/IR-004 일부 구현)

## Problem statement

분석 파이프라인의 기본 응답 스키마에서 지배 축이 `severity` 단일 정렬
(`backend/core/analysis/suspicious.py:133`) 로 남아 있다. 이미 작성된 편향 억제
모듈 (`finding_selection`, `hypothesis_context`) 은 자기 모듈과 테스트 밖에서
호출되지 않는다. `initial_triage` 는 호출되지만 결과가 요약 4 개 필드
(`incident_type`, `operator_style`, `top_window_count`, `precursor_status`) 로
축소돼 `top_findings` 와 병렬로 공존하며 표면 리스트의 지배 축을 바꾸지
못한다. 또한 `baseline_diff` 가 `initial_triage._build_precursor_context` /
`auto_seed_entities._context_bucket_seed` 를 통해 쉽게 인과성 맥락으로
승격된다.

한 줄 요약: **하네스가 전혀 안 꽂힌 건 아니지만, 기본 응답 스키마의 지배 축을
바꾸지 못해서 편향이 실제로는 계속 남아 있다.**

## Goal

응답 스키마의 지배 축을 "severity 정렬 1 위" 에서
"multi-axis balanced set + hypothesis candidates + lane state" 로 교체한다.
레거시 키는 지우지 않고 보조로 강등한다.

## Non-goals

- 새로운 탐지 규칙 추가
- severity 스코어링 재정의
- UI 전면 리디자인
- `baseline_diff` 삭제 또는 의미 변경

## Success criteria

S5 regression harness (별도 스펙) 가 가동된 이후 측정 가능한 지표.

- `alert_summary` 의 `balance.dominant_category.share` 가 severity 정렬 상위
  10 의 동일 지표 대비 평균 ≥ 15% 하락 (최소 3 개 fixture 케이스 평균).
- `candidate_axes` 개수가 평균 ≥ 2 (single-entity 지배 감소).
- `lane_state_board.allow_strong_conclusion == true` 인 경우에만 리포트
  Executive Summary 에 단일 내러티브가 렌더된다.

---

## Patch 1 — 응답 스키마 교체

목적: MCP / REST 응답에 harness 출력을 강제 주입. 레거시 키는 유지.

### 1-A. `backend/core/analysis/suspicious.py`

변경 없음. 정렬 함수 자체는 drill-down 뷰에서도 쓰이므로 유지.

### 1-B. `backend/api/detection.py::run_detection` (`:16` 근방)

기존 흐름 뒤에 hypothesis / finding-selection wiring 을 추가한다.
응답 dict 를 아래 순서로 재구성한다 — Python dict insertion order 가
JSON 직렬화 순서 = "중요도 순서" 임을 암묵 계약으로 사용한다.

```python
payload = find_suspicious(connector.artifact_queries, rules=req.rules)
score_findings(payload)
attach_provenance(payload, app_state._connectors)
apply_suppressions(payload)
attach_rule_coverage(payload, app_state._connectors)

# --- NEW: harness wiring (additive, backward compatible) ---
from core.analysis.finding_selection import (
    select_key_findings,
    analyze_finding_balance,
)
from core.analysis.hypothesis_context import build_hypothesis_context

findings = payload.get("findings", [])
payload["alert_summary"] = {
    "key_findings": select_key_findings(
        findings, limit=10, per_category_cap=2, per_rule_cap=1,
    ),
    "balance": analyze_finding_balance(findings),
    "surface_policy": "balanced_per_category_rule",
}
payload["candidate_axes"] = build_hypothesis_context(connector, payload)
return payload
```

**Breaking-change 여부:** 없음. `findings` / `strength_rollup` / 기존 키 전부
유지. 신규 키 2 개 (`alert_summary`, `candidate_axes`) 만 추가.

### 1-C. `backend/api/triage.py::run_triage` (`:266-290` 근방)

`_triage_state["result"]` dict 에 아래 키를 **`top_findings` 앞에** 삽입.
`top_findings` 는 유지하되 `top_findings_policy` 플래그로 레거시 역할을 명시.

```python
from core.analysis.finding_selection import (
    select_key_findings,
    analyze_finding_balance,
)
from core.analysis.hypothesis_context import build_hypothesis_context

_triage_state["result"] = {
    "status": "complete",
    ...
    "initial_triage": initial_triage_summary,
    # NEW — 표면 리스트 지배 축
    "alert_summary": {
        "key_findings": select_key_findings(findings),
        "balance": analyze_finding_balance(findings),
    },
    "candidate_axes": build_hypothesis_context(axiom, {"findings": findings}),
    # 기존 키 유지, 역할만 표기
    "top_findings": [...],
    "top_findings_policy": "legacy_severity_sorted",
    ...
}
```

### 1-D. `backend/mcp_bridge.py::auto_triage` (`:3160-3192`)

`return _mask({...})` 블록에 `alert_summary`, `candidate_axes` 추가.
`top_findings` / `top_findings_policy` 는 `api/triage.py` 와 동일 패턴.

### 1-E. Frontend

이번 패치 범위에서 **건드리지 않는다.**

- `Dashboard.tsx:64` — `detection.findings` 직접 소비. 그대로 동작.
- `DetectionPanel.tsx:16` — 동일.
- `Settings.tsx:404` — `triageResult.top_findings` 직접 소비. 그대로 동작.

레거시 경로가 살아있으므로 현재 UI 는 변경 없이 작동한다. MCP / LLM 소비자는
새 필드를 볼 수 있다. UI 반영은 Patch 2 에서.

### 1-F. 테스트 (필수)

- `backend/tests/test_detection_api_contract.py` 확장: `/api/detection/run`
  응답에 아래 키 존재 assert.
  - 신규: `alert_summary.key_findings`, `alert_summary.balance`,
    `alert_summary.surface_policy`, `candidate_axes.candidate_axes`
  - 기존 (contract guard): `findings`, `strength_rollup`
- `backend/tests/test_initial_triage.py` 또는 신규 파일: 다중 규칙 fixture
  에서 `alert_summary.balance.warnings` 가 적절히 생성되는지,
  `candidate_axes.candidate_axes` 최소 1 개 나오는지.
- `auto_triage` contract 테스트: `top_findings`, `top_findings_policy`,
  `alert_summary`, `candidate_axes` 모두 존재.

---

## Patch 2 — UI 지배 축 교체

목적: 응답 스키마 변경을 UI 에 반영. Patch 1 이 선행돼야 한다.

### 2-A. `frontend/src/components/DetectionPanel.tsx`

최상단 섹션을 아래 순서로 재구성.

1. `detection.alert_summary.balance.warnings` 있으면 상단 경고 배너
   (dominance / anchoring 경고 메시지).
2. `detection.alert_summary.key_findings` → "Key findings (balanced)" 탭.
   기본 활성.
3. `detection.candidate_axes.candidate_axes` → "Candidate axes" 패널. 각
   axis 의 `label`, `supporting_signals`, `unknowns`, `verification.status`
   렌더.
4. `detection.findings` 전체 → "All findings (legacy severity)" 탭. drill
   down 용. 기본 비활성.

### 2-B. `frontend/src/components/Dashboard.tsx` (`:64-70`)

```tsx
const findings = detection?.findings || [];                           // 유지
const keyFindings =
  detection?.alert_summary?.key_findings ||
  findings.slice(0, 10);                                              // 신규
```

- `riskLevel` 판정은 `keyFindings` 기준으로 변경 — severity 단일 정렬 효과
  감소.
- `detection?.alert_summary?.balance?.warnings` 가 있으면 anti-forensics
  배너 다음 줄에 중립 색 배너로 렌더. 문구 예시:
  > One category dominates current findings. Open Detection to review
  > alternatives.

### 2-C. 테스트

프론트엔드에 Jest 테스트가 없으므로 수동 검증 체크리스트를 PR 설명에
포함한다. `CLAUDE.md` 지침에 따라 UI 변경은 브라우저에서 실제 동작 확인이
필요하다.

체크리스트:
- [ ] `alert_summary` 없는 레거시 응답에서도 Dashboard / DetectionPanel 이
      깨지지 않고 렌더됨.
- [ ] dominance 경고 배너가 필요한 fixture 에서 실제로 표시됨.
- [ ] "All findings (legacy severity)" 탭이 기존과 동일한 항목을 보여줌.

---

## Patch 3 — Precursor bridging 강화 + 리포트 wiring

목적: baseline_diff 누수 경로를 좁히고, 리포트가 lane state 와 candidate
axes 를 반영하도록 한다.

### 3-A. `backend/core/analysis/initial_triage.py::_build_precursor_context` (`:811-826`)

Bridging 승격 게이트 강화.

기존:
```python
if bridged:
    context["status"] = "bridged_precursor"
    context["bridged_precursors"] = bridged[:10]
```

신규:
```python
_strong_enough = (
    top_windows
    and top_windows[0].get("status") == "incident-central"
    and int(top_windows[0].get("independent_axes", 0)) >= 2
)
if bridged and _strong_enough:
    context["status"] = "bridged_precursor"
    context["bridged_precursors"] = bridged[:10]
elif bridged:
    context["status"] = "candidate_bridge"
    context["bridged_precursors"] = bridged[:10]
    context["notes"].append(
        "Bridge tokens matched baseline_diff samples, but top window is "
        "not incident-central with multi-axis corroboration. Treat as "
        "candidate only."
    )
```

### 3-B. `backend/core/analysis/initial_triage.py` — `lane_state_board` 도입

`initial_triage()` 의 반환 dict 에 `lane_state_board` 키 추가.

```python
def _build_lane_state_board(
    top_windows: list[dict[str, Any]],
    coverage_gate: dict[str, Any],
    classification: dict[str, Any],
) -> dict[str, Any]:
    """
    Returns:
      {
        "ingress_access":      {"state": str, "basis": [str, ...]},
        "execution_impact":    {"state": str, "basis": [str, ...]},
        "persistence_cleanup": {"state": str, "basis": [str, ...]},
        "allow_strong_conclusion": bool,
        "blocked_lanes": [lane_name, ...],
      }

    state ∈ {"confirmed", "suggested", "unverified", "not_seen"}
    """
```

**판정 규칙 (deterministic):**

레인 → axis 매핑 (`ANALYSIS_PLAYBOOK.md` 와 일치):
- `ingress_access` ← `network_session`, `user_interaction` axes + remote-tool /
  browser token presence
- `execution_impact` ← `execution`, `filesystem_impact` axes
- `persistence_cleanup` ← `persistence_identity` axis

상태 판정 (top_windows[0] 기준, 없으면 top_windows 전체 합산):
- `confirmed` — 해당 lane 의 매핑된 axis count 합계 ≥ 2 AND `coverage_gate
  .blocked_claims` 에 이 lane 관련 claim 없음.
- `suggested` — axis count 합계 ≥ 1 but (coverage blocked claim 해당
  또는 independent_axes 부족).
- `unverified` — axis count == 0 but 관련 artifact family 가
  `coverage_gate.statuses` 에서 `present` 또는 `thin` 으로 존재.
- `not_seen` — axis count == 0 AND 관련 artifact family 가 `missing`.

`allow_strong_conclusion`:
```python
all(
    board[lane]["state"] in {"confirmed", "suggested"}
    for lane in ("ingress_access", "execution_impact", "persistence_cleanup")
) and "overall_case_confidence" not in {
    c["claim"] for c in coverage_gate.get("capped_confidence_claims", [])
}
```

`blocked_lanes` — `state in {"unverified", "not_seen"}` 인 레인 이름 리스트.

`initial_triage()` 반환 dict 의 기존 키 바로 다음 (classification 뒤, precursor_context 앞)에 삽입:

```python
return {
    ...
    "classification": classification,
    "lane_state_board": _build_lane_state_board(
        top_windows, coverage_gate, classification,
    ),
    "anchor_days": anchor_days,
    "precursor_context": precursor_context,
    ...
}
```

### 3-C. `backend/core/analysis/report_generator.py::generate_report` (`:639-733`)

`json_data` 에 3 개 키를 추가한다.

```python
from core.analysis.finding_selection import (
    select_key_findings,
    analyze_finding_balance,
)
from core.analysis.hypothesis_context import build_hypothesis_context
from core.analysis.initial_triage import initial_triage

triage = initial_triage(axiom, scope_mode="recent_14d")
findings = sus.get("findings", [])
json_data = {
    "alert_summary": {
        "key_findings": select_key_findings(findings),
        "balance": analyze_finding_balance(findings),
    },
    "candidate_axes": build_hypothesis_context(axiom, sus),
    "lane_state_board": triage.get("lane_state_board", {}),
    "findings": findings,
    "strength_rollup": sus.get("strength_rollup", {}),
    "iocs": iocs.get("iocs", []),
    "narrative": narrative.get("narrative", []),
    "timeline": timeline.get("entries", []),
    "artifact_types": types,
    "anti_forensics": anti,
    "coverage": coverage,
}
```

HTML 템플릿 Executive Summary 섹션에 조건부 렌더 추가:
- `lane_state_board.allow_strong_conclusion == false` 이면 상단에 노란
  경고 배너: "Investigation incomplete — one or more lanes unverified"
  + `blocked_lanes` 리스트 렌더.
- `candidate_axes.candidate_axes.length > 1` 이면 "Candidate hypotheses"
  블록에 각 axis 의 `label` / `supporting_signals` / `unknowns` /
  `verification.status` 렌더.
- 기존 severity 랭킹 섹션은 "Detailed Findings" 탭으로 강등 (템플릿 내
  섹션 순서 재배치만).

### 3-D. `backend/core/analysis/auto_seed_entities.py::_context_bucket_seed` (`:258-264`)

`entity_adjacent` 승격이 baseline-only 토큰에 대해 일어나지 않도록 가드.

기존:
```python
def _context_bucket_seed(entry, entity_token):
    token = str(entry.get("token", ""))
    if entity_token and token == entity_token:
        return "entity_adjacent", "primary entity basename surfaced from baseline/reference context"
    if any(k.startswith("baseline_") for k in entry.get("source_kinds", [])):
        return "baseline_common", "baseline-only context with no direct finding support"
    return "other_context", "non-priority context retained for model visibility"
```

신규:
```python
def _context_bucket_seed(entry, entity_token):
    token = str(entry.get("token", ""))
    if entity_token and token == entity_token:
        sources = {str(s) for s in entry.get("sources", [])}
        if sources <= {"baseline_diff"}:
            return (
                "baseline_common",
                "baseline-only token declined entity-adjacent promotion",
            )
        return (
            "entity_adjacent",
            "primary entity basename surfaced with non-baseline source",
        )
    if any(k.startswith("baseline_") for k in entry.get("source_kinds", [])):
        return "baseline_common", "baseline-only context with no direct finding support"
    return "other_context", "non-priority context retained for model visibility"
```

### 3-E. 테스트

- `backend/tests/test_initial_triage.py`:
  - `lane_state_board` 스키마 assert.
  - 4 개 상태 (`confirmed` / `suggested` / `unverified` / `not_seen`) 각각
    재현하는 fixture.
  - `allow_strong_conclusion` AND 로직 검증 (한 레인이라도
    unverified / not_seen 이면 false).
  - Weak top_window (non-incident-central 또는 independent_axes < 2) 에서
    bridge_tokens 매치 시 `precursor_context.status == "candidate_bridge"`
    임을 assert (not `bridged_precursor`).
- `backend/tests/test_auto_seed_entities.py`:
  - `sources == {"baseline_diff"}` 인 토큰이 `entity_token` 과 동일해도
    `entity_adjacent_context` 에 들어가지 않는지.
  - finding 기반 소스가 섞이면 정상적으로 `entity_adjacent` 로 승격되는지.
- `backend/tests/test_report_generator_guardrails.py`:
  - `allow_strong_conclusion == false` 인 fixture 에서 리포트 HTML 에
    "Investigation incomplete" 문자열 포함.
  - `candidate_axes.candidate_axes.length > 1` 인 fixture 에서 리포트
    HTML 에 "Candidate hypotheses" 섹션 포함.
  - `allow_strong_conclusion == true` 인 fixture 에서 경고 배너 부재.

---

## Rollback

- Patch 1 단독 롤백 가능 — 신규 키 제거로 충분, 레거시 소비자 무영향.
- Patch 2 는 Patch 1 이 머지된 상태에서만 의미가 있다. 롤백 시 UI 만
  되돌리면 MCP / REST 서피스는 유지된다.
- Patch 3 는 독립. `lane_state_board` 소비자가 없는 상태면 키만 남고 무해.

## Feature flag

환경변수 `FW_BIAS_REMEDIATION_DISABLE=1` 설정 시 `alert_summary`,
`candidate_axes`, `lane_state_board` 키를 응답에서 생략한다. 디폴트는 활성.
문제 발생 시 런타임 fallback 수단 보장.

구현 위치: 각 wiring 지점 (`api/detection.py`, `api/triage.py`,
`mcp_bridge.py::auto_triage`, `report_generator.py`) 에서 동일한 env 체크
helper 를 경유한다. 중복 구현 금지.

## Codex 리뷰 체크리스트

메모리 `feedback_codex_review_loop` 준수. PR 마다 사전 / 사후 검토 시
아래 항목을 명시 확인한다.

- [ ] **Overfitting 방지** — `select_key_findings` 의 `per_category_cap=2`,
      `per_rule_cap=1` 은 제네릭 값으로 유지. 특정 규칙 이름 /
      카테고리 이름 / IOC 값을 코드에 하드코딩하지 않는다.
- [ ] **Silent error 금지** — 새 모듈 호출은 `try/except` 으로 감싸고
      실패 시 `alert_summary={"error": str(e)}` 형태로 표면화한다. 조용히
      빈 dict 반환 금지.
- [ ] **Contract break 금지** — 기존 소비자가 읽는 키를 유지한다.
      대상: `findings`, `top_findings`, `strength_rollup`, `initial_triage`,
      `incident_type`, `operator_style`, `precursor_context`. 삭제 /
      이름변경 금지.
- [ ] **Test coverage** — Patch 1 이 머지되기 전
      `test_detection_api_contract.py` 가 새 키 3 개와 레거시 키 2 개
      이상을 모두 assert. Patch 3 테스트는 위 3-E 목록 전부 포함.
- [ ] **Lane mapping** — `_build_lane_state_board` 의 axis → lane 매핑이
      `ANALYSIS_PLAYBOOK.md` 섹션 "Lane definitions" 과 일치하는지
      코드 주석으로 참조 링크.

## Out of scope

별도 스펙이 필요한 항목. 이 문서 범위 밖이다.

- **S5 cross-case regression harness** — fixture 5 종 (ransomware /
  persistence-heavy / credential-abuse / anti-forensics / benign-admin)
  을 만들고, dominance / missed-signal / unsupported-hypothesis 지표를
  CSV 로 출력. 측정치 없이는 bias 감소 검증 불가. 별도
  `docs/REGRESSION_HARNESS_SPEC.md` 로 분리.
- **S6 baseline auto-generation** — `install.ps1` 확장으로 clean Windows
  이미지에서 `windows_baseline_auto.json` 자동 생성. 별도 스펙.
- **Frontend candidate_axes drill-down UI** — Patch 2 는 리스트 렌더까지만
  한다. 각 axis 별 "verify this" 버튼으로 MCP 도구 호출로 연결하는 UX 는
  후속 작업.
