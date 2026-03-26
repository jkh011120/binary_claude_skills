---
name: binary-recon
description: "Stage 1-2: IDA Pro MCP를 사용하여 바이너리 정찰 및 함수 인덱스를 구축한다. 전체 함수 목록, import 테이블, 문자열을 수집하고, framework config의 indicator pattern으로 각 함수를 스코어링하여 index.json을 생성한다."
license: MIT
compatibility: "IDA Pro + ida-pro-mcp server 실행 필요. 분석할 바이너리가 IDA에 열려 있어야 함."
allowed-tools: >
  Bash Read Write Edit Glob Grep
  TaskCreate TaskUpdate TaskGet TaskList
  mcp__ida-pro-mcp__list_funcs
  mcp__ida-pro-mcp__imports
  mcp__ida-pro-mcp__find_regex
  mcp__ida-pro-mcp__find_bytes
  mcp__ida-pro-mcp__callgraph
  mcp__ida-pro-mcp__callees
  mcp__ida-pro-mcp__lookup_funcs
  mcp__ida-pro-mcp__list_globals
  mcp__ida-pro-mcp__get_string
  mcp__ida-pro-mcp__xrefs_to
  mcp__ida-pro-mcp__decompile
  mcp__ida-pro-mcp__disasm
metadata:
  user-invocable: "false"
---

# Binary Recon — 정찰 및 인덱스 구축

바이너리의 전체 지도를 만드는 단계. 이후 모든 분석 스테이지의 기반이 된다.

## 입력

- `framework`: configs/*.yaml 중 하나 (userspace, firmware, linux_kernel, windows_driver, generic)
- `session_id`: 세션 식별자 (없으면 자동 생성: `<framework>-<YYYYMMDD>-<HHMMSS>`)
- `goal`: (선택) 분석 목표 — 특정 기능에 집중할 경우

## 워크플로우

### Step 1: 세션 초기화

```
state/<session_id>/ 디렉토리 생성
configs/<framework>.yaml 로드
```

### Step 2: 전체 함수 수집

```
list_funcs(queries={"count": 0})
→ 전체 함수 목록 (이름, 주소, 크기)
→ state/<session>/raw_functions.json에 백업
```

### Step 3: Import 테이블 수집

```
imports(offset=0, count=0)
→ 외부 함수 목록
→ state/<session>/imports.json 저장
```

### Step 4: 문자열 탐색

framework config의 hardcoded 패턴 + 범용 패턴으로 탐색:

```
find_regex("password|secret|key|token|admin|root|backdoor")
find_regex("http://|https://|ftp://")
find_regex("/bin/sh|/bin/bash|cmd\\.exe")
find_regex("error|fail|assert|panic|abort")
→ state/<session>/strings.json 저장
```

### Step 5: Indicator Scoring

framework config의 `indicator_patterns`를 imports에 대해 매칭:

```python
for each function:
  score = 0
  for category, patterns in indicator_patterns:
    for pattern in patterns:
      if function imports/calls match pattern:
        score += score_weights[category]
  # guards 패턴 매칭 시 감점
  function.score = score
  function.tags = matched_categories
```

스코어링은 다음 정보를 조합:
1. **Import 기반**: 함수가 호출하는 외부 API (callees 확인)
2. **문자열 참조**: 함수가 참조하는 문자열 (xrefs_to)
3. **함수 크기**: 큰 함수일수록 복잡도 ↑
4. **이름 패턴**: framework의 entrypoint_patterns 매칭 시 보너스

### Step 6: Entrypoint 식별

framework config의 `entrypoint_patterns`로 진입점 함수 식별:

```
각 카테고리(ioctl, file_operations, interrupt 등)별로
함수 이름/주소 매칭 → entrypoints 목록
```

### Step 7: Call Graph 구축 (핵심 영역만)

```
entrypoints + 고스코어 상위 10개 함수를 root로:
callgraph(roots=[...], max_depth=3, max_nodes=500)
→ state/<session>/callgraph_cache/<root_addr>.json
```

### Step 8: Index 생성

모든 정보를 통합하여 index.json 생성:

```json
{
  "session_id": "<session-id>",
  "framework": "<framework>",
  "binary_info": {
    "total_functions": 4523,
    "named_functions": 342,
    "imports_count": 187
  },
  "analyzed_count": 0,
  "functions": {
    "0x401230": {
      "name": "sub_401230",
      "size": 342,
      "score": 12.3,
      "tags": ["user_control", "dangerous_api"],
      "status": "pending",
      "is_entrypoint": false,
      "entrypoint_category": null
    }
  },
  "entrypoints": {
    "ioctl": ["0x402000"],
    "file_operations": ["0x402100", "0x402200"]
  },
  "hot_functions": ["0x401230", "0x402100", ...],
  "framework_config_used": "<framework>"
}
```

`hot_functions`: score 내림차순 상위 30개. 다음 스테이지(triage)의 입력.

### Step 9: Framework 자동 감지 (generic 사용 시)

generic framework로 시작한 경우, imports/strings 분석 결과로 실제 유형을 추론:

| 감지 패턴 | 전환 대상 |
|-----------|-----------|
| DriverEntry, IoCreateDevice, IRP | windows_driver |
| copy_from_user, kmalloc, module_init | linux_kernel |
| IRQHandler, HAL_, MMIO | firmware |
| main, printf, socket | userspace |

추론 결과를 index.json의 `detected_framework` 필드에 기록하고 사용자에게 전환 제안.

## 출력

- `state/<session>/index.json` — 핵심 출력물
- `state/<session>/imports.json`
- `state/<session>/strings.json`
- `state/<session>/callgraph_cache/*.json`

## 재실행 시

이전 세션의 index.json이 존재하면:
- 새로 추가된 함수만 스코어링 (IDA가 추가 분석한 경우)
- 이전 어노테이션 반영된 이름으로 업데이트
- score 재계산
