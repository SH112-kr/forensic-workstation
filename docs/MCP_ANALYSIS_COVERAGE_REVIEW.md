# MCP 분석 방법론 및 아티팩트 커버리지 검토 보고서

- 대상 문서: `docs/MCP_ANALYSIS_ARTIFACT_COVERAGE.md`
- 검토 기준: 실제 백엔드 구현(`backend/core/raw_index/artifact_indexer.py`, `backend/core/analysis/evtx_rules.py`, `backend/mcp_bridge.py`, `backend/core/connectors/*`) 대조 + DFIR 표준 아티팩트 비교
- 검토 범위: (1) 방법론 논리 건전성, (2) 문서 주장 커버리지 ↔ 실제 구현 일치 여부, (3) 누락 아티팩트
- 작성일: 2026-06-17
- 개정: 2026-06-17 (rev.2) — 작성자 반론에 대한 코드 재검증 결과를 반영하여 §1-A 전면 철회, §1-C(Prefetch) 정정

---

## 0. 총평

대상 문서의 방법론 골격은 LLM 단독 침해사고조사 도구로서 **DFIR 기준으로 견고하다.**
핵심 원칙(증거≠판정, 0건≠부재, coverage gap 우선 기록, strong-conclusion gate, 가설-반증)이
일관되게 적용되어 있고, 특히 Strong-Conclusion Gates 표의 `Blocking condition` 컬럼은
AI가 약한 증거로 단정하는 것을 막는 장치로 잘 설계되었다.

> **rev.2 정정 요지.** 초판(rev.1)은 "raw-only 모드에서 `hunt_evtx_rules`가 조용한 0건을
> 반환한다"를 P0로 제기했으나, **코드 재검증 결과 이 주장은 틀렸다.** 해당 도구는 raw-only일 때
> 실행 전에 `not_evaluable`로 단락하며 조용한 0건 경로가 존재하지 않는다. 초판의 Prefetch =
> AXIOM 전용 주장도 틀렸다(직접 parser 존재). 두 항목을 철회·정정한다(§1-A, §1-C). 철회 경위는
> §6에 남긴다.

판정 요약(rev.2):

| 영역 | 평가 |
| --- | --- |
| 방법론 논리 | 견고. 일부 lane/타임존/메모리 보강 권고(잔존) |
| 문서↔구현 일치 | 초판이 지목한 P0(조용한 0건)는 **오탐으로 철회.** 잔존 불일치는 raw sidecar 채널 커버리지 갭(경미) |
| 아티팩트 커버리지 | 블라인드 스팟 목록 양호. 초판 지적 항목은 작성자가 이미 반영 |

---

## 1. 문서 ↔ 구현 불일치 검증 결과

### ⬜ A. (철회) "룰 EID와 raw index 불일치 → 조용한 0건" — 오탐

**상태: RETRACTED (코드로 반증됨).**

초판 주장: raw-only에서 `hunt_evtx_rules`가 raw index의 48-EID 서브셋을 대상으로 돌아,
인덱스에 없는 EID(5140/5145/4719/4768/4769/4674/Sysmon)에 대해 coverage 신호 없이 0건을
반환한다.

재검증 결과 — **틀렸다:**

- `mcp_bridge.py:4440`의 `hunt_evtx_rules` 래퍼는 `raw and not _parsed_case_available()`일 때
  **룰 실행 전에 단락**하여 다음을 반환한다(`:4443~4477`):
  - `"ok": False`, `"status": "not_evaluable"`, `"source_type": "raw_image_sidecar"`
  - 요청 룰별 `unevaluable_rules[].reason = "raw_evtx_hunt_unsupported"`
  - `coverage_gap.detail` = "hunt_evtx_rules requires parsed Windows Event Log records …"
  - `notes` = "Do not interpret this as no EVTX activity."
- 초판이 지목한 `evtx_rules.py:481`의 silent `continue`는 **parsed(AXIOM) 모드에서만** 도달한다.
  그 모드에서 `query_event_logs`(`axiom_artifact_queries.py:53`)는 AXIOM SQLite 전체를 조회하므로
  5140/4719/Sysmon 등이 모두 존재한다 → 조용한 0건이 성립하지 않는다.
- `query_event_logs`는 AXIOM 커넥터에만 정의되어 있고 raw index 구현이 없다. 즉 룰이 raw index
  서브셋을 대상으로 도는 경로 자체가 존재하지 않는다.

결론: 초판의 전제(룰이 raw index를 조회한다)가 사실과 다르다. **이 항목은 무효.**

잔존 사항(P3, 경미): `search_artifacts(artifact_type="Windows Event Logs", keyword="Event ID=5140")`
같은 **수동 검색**은 raw sidecar에서 0건을 낼 수 있다(해당 EID 미인덱스). 이 경로는 일반
coverage 블록은 붙지만 "이 EID는 인덱스 서브셋 밖"이라는 특정 신호는 없다. 다만 작성자가 채널/EID
갭을 문서에 명시했으므로 잔여 위험은 낮다. 필요 시 raw 검색에 "indexed EID/channel 화이트리스트
대비 미수집" 힌트를 추가하면 완결된다.

### 🟢 B. raw sidecar 미수집 채널 (작성자 반영 완료)

raw index의 `CORE_EVTX_CHANNELS`(12개)에 Sysmon/WinRM/DNS-Client/WMI-Activity/클래식 PowerShell
채널이 없다는 지적은 유효했고, **작성자가 이미 gap으로 명시**했다(Sysmon/WinRM/DNS-Client/
WMI-Activity/classic PowerShell/PCA/ShellBags/ActivitiesCache). 추가 조치 불요 — 향후 이 채널들을
sidecar에 first-class로 인덱싱하면 raw-only 탐지 범위가 넓어진다(개선 백로그).

### 🟦 C. (정정) Sufficiency Matrix "Primary coverage"의 raw-only 표기

**Prefetch 부분: 정정.** 초판은 Prefetch/SRUM을 "AXIOM 전용"으로 묶었으나, `query_prefetch_files`
(`mcp_bridge.py:7955`)는 마운트 이미지의 `/c:/Windows/Prefetch/*.pf`를 `parse_prefetch_bytes`로
**직접 파싱**한다 — AXIOM/KAPE 의존이 아니다. 작성자가 구분한 "직접 parser 존재 ↔ raw sidecar
first-class parity 미보장"이 정확한 표현이다.

**잔존(P2):** SRUM은 문서가 이미 "raw-index unsupported = gap"으로 인정. raw sidecar first-class
parity와 직접 parser 가용성을 표에서 시각적으로 구분하면(예: `direct-parser` / `sidecar-indexed`
표기) 독자가 모드별 가용성을 오해하지 않는다. 작성자가 source 분리(parsed/raw sidecar/raw direct
parser/VSS/memory)를 이미 도입했으므로 대부분 해소.

### 🟢 D. CurrentControlSet 한정 (작성자 반영 완료)

raw sidecar의 Services/BAM/USBSTOR가 CurrentControlSet 중심이라는 지적은 유효했고, **작성자가
registry 표·limitation 양쪽에 정정**하고 `ControlSet*` 검증을 `service_persistence_gate` 역할로
분리했다. 적절한 조치.

### 🟡 E. 채널당 20,000 레코드 캡 (잔존, P2)

`artifact_indexer.py:69`의 per-file 20,000 레코드 캡은 바쁜 서버의 `Security.evtx`를 초과할 수 있다.
"사건 기간 내 이벤트가 캡으로 잘릴 수 있다"는 점과 **채널별 캡 도달 여부를 결론 전 확인**하는
체크리스트 항목은 여전히 보강 가치가 있다.

---

## 2. 블라인드 스팟 — 작성자 반영 확인

초판이 목록에서 누락됐다고 지적한 표준 아티팩트(ShellBags, PCA `pca.db`, Windows Timeline/
`ActivitiesCache.db`, WMI-Activity EVTX, DNS-Client EVTX, 클럭 무결성류, 역사적 ControlSet)는
**작성자가 gap 목록과 limitation에 반영**했다. 코드상으로도 이들이 raw sidecar first-class가
아님을 확인했다(개선 백로그 후보). 추가 분쟁 없음.

잔존 권고(P2): 클럭 무결성(EID 4616, 6005/6006/6008)과 Defender 1013(history deleted)은 anti-forensics
직접 증거이므로 우선순위가 높은 인덱싱 후보다.

---

## 3. 방법론 자체의 보완점 (잔존, 코드 무관)

작성자가 anchoring 방지(coverage-first, timeline-window, lane-balanced round-robin, strong-conclusion
gate)를 분석 절차에 추가한 것은 적절. 잔여 권고:

1. **타임존/클럭 무결성 일반화.** 시스템 타임존을 `SYSTEM\...\TimeZoneInformation`에서 먼저 확정 →
   클럭 조작(EID 4616) 탐지 → 아티팩트별 타임존 매트릭스. 현재는 MPLog/setupapi만 device-local 경고.

2. **Impact·Privilege Escalation·Discovery lane.** Sufficiency Matrix에 독립 lane으로 승격 권고
   (룰은 일부 존재). 특히 Impact는 섀도 삭제 외 대량 파일 변조/랜섬노트/`bcdedit`·`wbadmin` 복구
   무력화를 포함.

3. **메모리 교차검증.** 노출 plugin 6개(pslist/pstree/cmdline/netscan/malfind) 외 `svcscan`·
   `dlllist`·`handles`는 커넥터에 존재하나 MCP 미노출. `vol_malfind`의 `injection_source`를 검증할
   교차 plugin을 노출하면 "주입 관찰 ≠ 악성" 원칙을 실증할 수 있다.

---

## 4. 우선순위 권고 (rev.2)

| 우선 | 항목 | 상태 |
| --- | --- | --- |
| ~~P0~~ | ~~hunt_evtx_rules 조용한 0건~~ | **철회 — 오탐(§1-A)** |
| P2 | raw 검색(`search_artifacts`)에 "미인덱스 EID/채널" 힌트 추가 | 잔존(경미) |
| P2 | 채널별 20K 캡 도달 여부를 결론 전 체크리스트화 | 잔존(§1-E) |
| P2 | Sufficiency Matrix에 `direct-parser`/`sidecar-indexed` 표기 구분 | 일부 해소(§1-C) |
| P2 | 클럭 무결성(4616/6005~6008)·Defender 1013 인덱싱 | 잔존(§2) |
| P3 | Impact/PrivEsc/Discovery lane 승격, 타임존 매트릭스, 메모리 교차검증 plugin 노출 | 잔존(§3) |
| 완료 | Sysmon/WinRM/DNS-Client/WMI-Activity/PCA/ShellBags/ActivitiesCache gap 명시 | 작성자 반영 |
| 완료 | CurrentControlSet 한정 정정 + service_persistence_gate 분리 | 작성자 반영 |
| 완료 | source 분리(parsed/raw sidecar/raw direct/VSS/memory) | 작성자 반영 |

---

## 5. 검증 근거 (재현용)

| 주장 | 근거 위치 | 검증 결과 |
| --- | --- | --- |
| raw-only에서 hunt_evtx_rules는 not_evaluable 단락 | `mcp_bridge.py:4440~4478` | **확인 — 조용한 0건 없음** |
| evtx_rules silent continue는 parsed 모드 전용 | `evtx_rules.py:471,481` | 확인 |
| query_event_logs는 AXIOM 커넥터에만 존재 | `axiom_artifact_queries.py:53` | 확인 (raw 구현 없음) |
| query_prefetch_files는 마운트 이미지 직접 parser | `mcp_bridge.py:7955`, `core/analysis/prefetch_semantic.py::parse_prefetch_bytes` | **확인 — AXIOM 전용 아님** |
| raw sidecar 수집 EID 48 / 채널 12 | `artifact_indexer.py:28,52` | 확인 |
| 채널당 20,000 레코드 캡 | `artifact_indexer.py:69` | 확인 |
| CurrentControlSet 한정 | `artifact_indexer.py` registry 파서 | 확인 (작성자 정정 완료) |
| rule_coverage는 find_suspicious용, family 단위, axiom 커넥터만 카운트 | `rule_coverage.py:40,240` | 확인 |
| 메모리 plugin 6개 노출, svcscan/dlllist/handles 미노출 | `volatility_connector.py`, `mcp_bridge.py` | 확인 |

---

## 6. 철회 경위 (lessons learned)

초판의 P0(§1-A)는 `evtx_rules.py`만 격리해 읽고 `aq`가 raw index에 바인딩된다고 **추정**한 데서
비롯됐다. 호출부인 `mcp_bridge.py`의 raw-only 가드를 추적하지 않았고, 서브에이전트의 "룰이 raw
index를 돈다"는 요약을 코드로 재확인하지 않은 채 최우선 결함으로 격상했다. 이는 이 도구가 경계하는
바로 그 실패 양식(상관/추정을 검증 없이 결론으로 승격)에 해당한다. 데이터 흐름 주장은 **호출 경로
끝까지(tool wrapper → connector method) 추적한 뒤** 확정해야 한다는 교훈을 기록한다.
