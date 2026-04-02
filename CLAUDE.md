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
