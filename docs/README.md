# docs/ 인덱스

각 문서 상단의 `> 상태:` 헤더가 구현 여부의 단일 출처다. 새 스펙을 추가할
때는 반드시 상태 헤더를 붙이고, 구현/폐기 시 갱신한다.

## 운영 원칙 (항상 적용)

| 문서 | 내용 |
|---|---|
| [ANALYSIS_GUARDRAILS.md](ANALYSIS_GUARDRAILS.md) | 편향 방지 상위 원칙 (비협상 규칙) |
| [ANALYSIS_PLAYBOOK.md](ANALYSIS_PLAYBOOK.md) | 3-레인 증거 모델 + 최소 검증 절차 |
| [WINDOWS_IR_KNOWLEDGE_BASE.md](WINDOWS_IR_KNOWLEDGE_BASE.md) | Windows IR 아티팩트 해석 지식 |

## 스펙 — 구현 완료

| 문서 | 구현 위치 |
|---|---|
| [LLM_CONSUMER_HYGIENE_SPEC.md](LLM_CONSUMER_HYGIENE_SPEC.md) | `mcp_bridge.py` reading guides + `test_mcp_docstring_hygiene.py` |
| [BIAS_REMEDIATION_SPEC.md](BIAS_REMEDIATION_SPEC.md) → [PATCH2_SPEC](BIAS_REMEDIATION_PATCH2_SPEC.md) → [PATCH2_FIX](BIAS_REMEDIATION_PATCH2_FIX.md) | `core/analysis/bias_remediation.py` (3부작, 이 순서로 읽기) |
| [LLM_REGRESSION_HARNESS_SPEC.md](LLM_REGRESSION_HARNESS_SPEC.md) | `backend/regression/` (Phase 1 수동 실행; Phase 2 미착수) |
| [FRONTEND_BUILD_CLEANUP_SPEC.md](FRONTEND_BUILD_CLEANUP_SPEC.md) | frontend 빌드 정리 |

## 스펙 — 제안 / 백로그 (미구현)

| 문서 | 상태 |
|---|---|
| [MCP_DISCLOSURE_GATE_SPEC.md](MCP_DISCLOSURE_GATE_SPEC.md) | 제안. Phase 1–4 미착수 — 현재 공개 게이트 없음 |
| [HYPOTHESIS_REFACTOR_BACKLOG.md](HYPOTHESIS_REFACTOR_BACKLOG.md) | IR-001~005 전체 미착수 |
| [WINDOWS_IR_IMPROVEMENT_ROADMAP.md](WINDOWS_IR_IMPROVEMENT_ROADMAP.md) | 로드맵 (항목별 상태는 본문 참조) |
| [SENIOR_ANALYST_PARITY_DIRECTIVES.md](SENIOR_ANALYST_PARITY_DIRECTIVES.md) | 진행 중 (메모리 `project_parity_directives_progress` 참조) |

## 검증 계획 / 기록

| 문서 | 내용 |
|---|---|
| [DFIR_VALIDATION_PLAN.md](DFIR_VALIDATION_PLAN.md) | 합성 픽스처 → 공개 데이터셋 검증 계획 |
| [ADVANCED_DFIR_BLIND_VALIDATION_PLAN.md](ADVANCED_DFIR_BLIND_VALIDATION_PLAN.md) | 블라인드 검증 계획 |
| [AUTONOMOUS_E01_VALIDATION_LOG.md](AUTONOMOUS_E01_VALIDATION_LOG.md) | 자율 E01 검증 기록 (스냅샷) |
| [regression_baseline_2026-04-23.md](regression_baseline_2026-04-23.md) | LLM 회귀 하네스 수동 baseline |
| [raw-image-index-handoff.md](raw-image-index-handoff.md) | raw-image-index 브랜치 핸드오프 노트 |
