# MCP Disclosure Gate Spec

> **상태: 제안 (미구현)** — Phase 0 (정적 docstring 감사) 일부만 반영됨.
> Phase 1–4 (`backend/core/disclosure.py`, pending_disclosures 큐, UI
> DisclosurePanel) 는 미착수. 현재 MCP 응답은 마스킹(`enable_masking`)
> 외의 공개 게이트 없이 LLM 컨텍스트로 전달된다. (2026-06-12 기준)

## 목적

Forensic Workstation은 로컬 DFIR 도구지만, Claude Code/Codex MCP로 사용할 때 MCP 도구의 응답(`RES`)이 LLM 컨텍스트로 전달될 수 있다. 이때 파일 경로, 사용자명, 호스트명, IP, registry value, event detail, browser history, credential, secret이 클라우드 모델 쪽으로 올라갈 수 있다.

이 문서는 성능을 크게 해치지 않으면서 민감정보 노출을 줄이기 위한 **MCP Disclosure Gate** 설계안이다. 핵심은 모든 호출을 사람이 확인하는 것이 아니라, 위험도가 높은 요청/응답만 로컬에서 붙잡고 분석가가 release 여부를 결정하는 것이다.

## 설계 원칙

- 웹 UI의 로컬 분석과 MCP/LLM handoff를 명확히 분리한다.
- `REQ`만 보고 판단하지 않는다. 안전해 보이는 요청도 `RES`에 secret이 포함될 수 있으므로 `REQ + RES`를 함께 평가한다.
- 기본 경로는 빠른 자동 redaction이어야 한다. 모든 결과를 무조건 사람이 승인하게 만들면 분석 속도가 무너진다.
- full result는 로컬에 보관하고, LLM에는 승인된 projection만 전달한다.
- 파일 경로도 민감정보로 취급한다.
- `disable_masking`처럼 보호 정책을 낮추는 함수는 요청 단계에서 승인해야 한다.
- 0-result, coverage, runtime 같은 메타 응답은 분석 흐름을 막지 않는다.

## 위협 모델

### 보호 대상

- Windows/Linux/macOS 파일 경로
- 사용자명, 호스트명, 도메인명, 이메일
- 내부 IP, 외부 IP, URL query, cookie
- access key, secret key, bearer token, API key, private key
- registry value, browser history, shell history, command line
- event detail, log line, process command line
- extracted file content, strings output, report HTML

### 신뢰 경계

| 영역 | 신뢰도 | 설명 |
|---|---|---|
| Local UI | 높음 | 분석가 로컬 브라우저와 로컬 백엔드 |
| Local pending store | 높음 | full result를 로컬에 임시 저장하는 영역 |
| MCP response to LLM | 낮음 | 모델 컨텍스트로 전달될 수 있음 |
| `.mcp_events.jsonl` | 중간 | 로컬 파일이지만 장기 보관/공유/커밋 위험 있음 |
| Generated report/export | 중간 | 로컬 파일이지만 외부 공유 가능성 있음 |

## 정책 모드

### Strict

- LLM으로 전달되는 모든 MCP `RES`는 redacted projection만 허용한다.
- secret, credential, path, PII 감지 시 full result는 로컬 pending store에도 저장하지 않고 요약만 남긴다.
- 민감 사건이나 고객 데이터 분석 기본값으로 적합하다.

### Review

- 기본 권장 모드.
- 저위험 결과는 자동 redaction 후 즉시 반환한다.
- 고위험 결과나 secret/path/credential 감지 결과는 `approval_required` stub만 LLM에 반환한다.
- 분석가는 UI에서 원문을 확인한 뒤 `send_redacted`, `send_full`, `block` 중 선택한다.

### Full Local

- UI에는 원문을 표시할 수 있다.
- MCP/LLM에는 redacted projection만 전달한다.
- 분석가가 로컬 UI 중심으로 작업하면서 LLM에는 요약만 넘길 때 적합하다.

### Unsafe Full

- MCP/LLM에 원문 전달을 허용한다.
- 세션 단위 만료가 있어야 하며, 켤 때 명시적 경고와 audit event를 남긴다.
- 기본값으로 절대 사용하지 않는다.

## MCP 함수 위험 분류

분류는 함수명 기반 1차 라우팅이고, 최종 판단은 `RES` scan 결과로 보정한다.

### 고위험 함수

파일 내용, 상세 이벤트, registry value, log line, command line, browser/cache, strings, credential이 직접 나올 수 있다. 기본적으로 Review 대상이다.

```text
get_hit_detail
search_artifacts
search_by_hash
build_timeline
slice_timeline
correlate
pivot_across_cases
entity_story_pack
behavioral_delta_pack
temporal_anchor_correlation
auto_seed_entities_pack

list_files
extract_file
get_file_timestamps
compare_case_image_entity

query_evtx_file
query_prefetch_files
query_registry_hive
search_wer_reports
srum_by_process

vss_list_files
vss_extract_file
vss_get_file_timestamps
vss_query_evtx_file
vss_query_registry_hive

import_logs
search_logs
log_stats

inspect_pe_file
analyze_binary
ghidra_strings
ghidra_imports
ghidra_exports
ghidra_functions
ghidra_decompile
ghidra_suspicious_apis

vol_load_memory
vol_pslist
vol_pstree
vol_netscan
vol_cmdline
vol_malfind

extract_iocs
generate_report
auto_triage
```

아래 함수는 특히 즉시 Review로 승격한다.

```text
extract_file
get_hit_detail
query_registry_hive
query_evtx_file
search_logs
ghidra_strings
vol_cmdline
extract_iocs
generate_report
auto_triage
disable_masking
```

### 중위험 함수

원문 파일 내용은 덜 나오지만, 경로, 사용자, 호스트, IP, 프로세스, 서비스명, 시간대별 행위가 나올 수 있다. 기본은 자동 redaction 후 반환하고, scan 결과가 높으면 Review로 승격한다.

```text
find_suspicious
detect_anti_forensics
hunt_evtx_rules
map_to_mitre
baseline_diff
service_persistence_gate
raw_image_triage_gate
date_anchor_triage
initial_triage_pack
investigation_gap_report
hypothesis_refutation_pack
build_entity_graph
coverage_explainer
explain_zero_results
compare_cases
get_tagged_hits
get_bucket_hits
```

### 저위험/메타 함수

대체로 상태, 카운트, 커버리지, 런타임, 의존성, 룰 목록 중심이다. 바로 반환하되 경로와 사용자 식별자는 redaction 대상이다.

```text
server_runtime_info
dependency_health
get_evidence_context
case_health
get_summary
get_artifact_types
list_case_snapshots
load_case_snapshot
save_case_snapshot
list_suppressions
add_suppression
remove_suppression
list_hunt_packs
run_hunt_pack
set_timezone
enable_masking
list_vss_snapshots
mount_image
open_case
```

주의: `open_case`, `mount_image`, `get_evidence_context`는 메타 함수지만 증거 경로를 포함하므로 path redaction은 필요하다.

### 요청 단계 승인 함수

보안 정책이나 조사 상태를 바꾸는 함수다. `REQ` 단계에서 분석가 확인이 필요하다.

```text
disable_masking
enable_masking
add_suppression
remove_suppression
save_case_snapshot
add_hits_to_bucket
remove_hits_from_bucket
```

## 민감정보 탐지 규칙

### 경로

```text
C:\Users\<USER>\...
C:\Windows\...
D:\...
/Users/<USER>/...
/home/<USER>/...
/c:/Users/<USER>/...
\\server\share\...
G:\My_Project\...
```

경로는 다음 형태로 projection한다.

```text
C:\Users\<USER>\Downloads\rootkey.csv -> <WIN_USER_PATH>/Downloads/rootkey.csv
G:\My_Project\case\image.e01 -> <LOCAL_WORKSPACE_PATH>/image.e01
\\fileserver\share\secret.docx -> <UNC_PATH>/secret.docx
```

### Credential/secret

탐지 예:

```text
AKIA[0-9A-Z]{16}
ASIA[0-9A-Z]{16}
aws_secret_access_key
AWSSecretKey
password=
passwd=
pwd=
token=
api_key=
client_secret=
Bearer <token>
-----BEGIN PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
```

projection 예:

```text
AKIAJQCL74OG6U6JRXKQ -> <AWS_ACCESS_KEY:sha256:12>
aws_secret_access_key=... -> aws_secret_access_key=<SECRET:sha256:12>
Bearer eyJ... -> Bearer <TOKEN:sha256:12>
```

### URL/query/cookie

- URL host/path는 분석 가치가 있으므로 보존 가능.
- query string은 기본적으로 redaction한다.
- cookie/header는 high risk로 취급한다.

```text
https://example.com/path?token=abc&user=x -> https://example.com/path?[redacted-query]
Cookie: session=... -> Cookie: <COOKIE:sha256:12>
```

## 응답 흐름

### Low-risk flow

```text
MCP REQ
  -> tool runs locally
  -> fast disclosure scan
  -> redacted projection
  -> MCP RES to LLM
```

### Review flow

```text
MCP REQ
  -> tool runs locally
  -> disclosure scan detects high risk
  -> full result saved in local pending store
  -> LLM receives approval_required stub
  -> UI shows pending disclosure
  -> analyst chooses send_redacted / send_full / block / expire
```

LLM-facing stub:

```json
{
  "status": "approval_required",
  "risk": "secret_detected",
  "risk_labels": ["path", "aws_access_key", "secret_assignment"],
  "summary": "Registry query returned 3 values; 1 value appears to contain a cloud credential.",
  "local_result_id": "mcpres_20260427_001",
  "allowed_actions": ["send_redacted", "send_full", "block", "expire"],
  "default_action": "send_redacted"
}
```

## Pending store

Full result는 LLM에 보내지 않고 로컬에 임시 저장한다.

권장 위치:

```text
backend/state/pending_disclosures/
```

저장 항목:

```json
{
  "id": "mcpres_20260427_001",
  "created_at": "2026-04-27T12:00:00Z",
  "expires_at": "2026-04-27T13:00:00Z",
  "tool_name": "query_registry_hive",
  "risk_labels": ["path", "secret_assignment"],
  "request_preview": {},
  "redacted_result": {},
  "full_result_path": "backend/state/pending_disclosures/mcpres_20260427_001.json",
  "decision": "pending"
}
```

요구사항:

- 기본 TTL 1시간.
- 만료 시 full result 삭제.
- audit log에 decision만 남기고 full secret은 남기지 않는다.
- pending store는 gitignore 대상이어야 한다.

## UI 요구사항

### MCP Monitor

- `Pending Disclosure` 패널 추가.
- tool name, risk labels, redacted summary, blocked fields count 표시.
- 버튼:
  - `Send Redacted`
  - `Send Full`
  - `Block`
  - `Expire`
- `Send Full`은 확인 모달과 세션 audit event가 필요하다.

### Settings

- Disclosure mode 선택:
  - `Strict`
  - `Review`
  - `Full Local`
  - `Unsafe Full`
- 기본값은 `Review`.
- `Unsafe Full`은 세션 만료 시간과 명시적 경고 필요.

### Status bar/Header

- 현재 disclosure mode를 항상 표시.
- `Review` 이상에서 pending count 표시.

## API/MCP 추가안

REST:

```text
GET  /api/disclosure/policy
POST /api/disclosure/policy
GET  /api/disclosure/pending
GET  /api/disclosure/pending/{id}
POST /api/disclosure/pending/{id}/send-redacted
POST /api/disclosure/pending/{id}/send-full
POST /api/disclosure/pending/{id}/block
POST /api/disclosure/pending/{id}/expire
```

MCP:

```text
disclosure_policy
list_pending_disclosures
resolve_pending_disclosure
```

주의: MCP에서 `send-full`을 직접 허용하면 LLM이 스스로 full release를 유도할 수 있다. `send-full`은 UI 또는 로컬 분석가 명령에만 허용하는 것이 안전하다.

## 구현 위치

### Backend

- `backend/core/disclosure.py`
  - policy model
  - risk classifier
  - fast scanner
  - redaction projection
  - pending store helpers
- `backend/mcp_bridge.py`
  - `_traced()`에서 `_mask()` 이후 또는 이전의 정책 결정 지점 추가
  - 추천 순서:

```text
fn()
  -> disclosure_scan(full_result)
  -> if approval_required: persist full + return stub
  -> else: project/redact
  -> _localize_timestamps()
  -> runtime/dependency warning attach
  -> _log_event()
```

주의: 현재 `_log_event()`가 request/response를 `.mcp_events.jsonl`에 남긴다. disclosure gate는 event logging 이전에 적용되어야 한다.

### Frontend

- `frontend/src/components/DisclosurePanel.tsx`
- `CopilotPanel.tsx`에 pending disclosure block 추가
- `Settings.tsx`에 policy selector 추가
- `Header.tsx` 또는 status bar에 mode 표시

## 성능 전략

- scanner는 regex + key-name heuristic 중심으로 구현한다.
- JSON 전체 deep scan은 최대 depth/byte 제한을 둔다.
- 대용량 결과는 샘플 + 요약만 scan하고, full은 pending store에 저장한다.
- scan 결과는 `risk_labels`, `sensitive_count`, `sample_paths_count`처럼 카운트 중심으로 반환한다.
- LLM으로 전달되는 projection은 기존 `_truncate()`보다 먼저 적용한다.

## 테스트 계획

### Unit tests

- AWS access key/secret 탐지.
- Windows path, POSIX path, UNC path redaction.
- URL query redaction.
- low/medium/high function classification.
- `disable_masking` request-stage approval.
- pending store TTL deletion.

### Integration tests

- `query_registry_hive` 결과에 secret이 있으면 `approval_required`.
- `server_runtime_info`는 바로 반환.
- `mount_image`는 경로 redaction 후 반환.
- `.mcp_events.jsonl`에 full secret이 기록되지 않음.
- `send_redacted` 후 LLM-facing payload에 secret이 없음.

### Regression tests

- 기존 `dependency_health`, `case_health`, `coverage_explainer` 흐름은 지연 없이 동작.
- `find_suspicious` 결과가 중위험으로 redacted projection을 반환.
- `extract_file`은 full file content를 반환하지 않고 static metadata/handle 중심으로 유지.

## 단계별 구현안

### Phase 1: Passive redaction

- `backend/core/disclosure.py` 추가.
- function risk registry 추가.
- MCP `_traced()` response logging 전에 disclosure scan/redaction 적용.
- UI에는 mode 표시만 추가.

### Phase 2: Review gate

- pending store 추가.
- `approval_required` stub 반환.
- MCP Monitor Pending Disclosure 패널 추가.
- `send_redacted`, `block`, `expire` REST API 추가.

### Phase 3: Analyst-controlled full release

- `send_full` UI-only action 추가.
- 세션 만료와 audit event 추가.
- `Unsafe Full` mode 추가, 기본 비활성.

### Phase 4: Report/export hygiene

- `generate_report`가 disclosure policy를 존중하도록 변경.
- report 내 민감정보 배너와 demask/restore 정책 재검토.
- export 파일이 git에 올라가지 않도록 추가 guardrail 검토.

## Claude/Codex 사용 관점 결론

분석가 프록시 모델은 타당하다. 다만 `REQ`만 승인하는 방식은 부족하다. MCP 도구의 위험은 응답에 의해 결정되는 경우가 많으므로, 최종 구조는 다음 조합이어야 한다.

- 함수명 기반 1차 위험 분류
- `RES` 기반 fast sensitive scan
- 기본 redaction
- 고위험 결과의 로컬 pending store
- 분석가 승인 후 redacted/full/block 결정

이 방식은 성능을 유지하면서도 LLM 컨텍스트로 들어가는 민감정보를 통제할 수 있다.
