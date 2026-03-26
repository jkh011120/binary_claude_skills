---
name: binary-deep
description: "Stage 4: candidates.json의 '위험' 함수들에 대해 xrefs, callgraph, 데이터 흐름을 추적하여 취약점을 검증한다. evidence packing과 함께 findings.json을 생성한다."
license: MIT
compatibility: "IDA Pro + ida-pro-mcp server 실행 필요."
allowed-tools: >
  Bash Read Write Edit Glob Grep
  TaskCreate TaskUpdate TaskGet TaskList
  mcp__ida-pro-mcp__decompile
  mcp__ida-pro-mcp__disasm
  mcp__ida-pro-mcp__xrefs_to
  mcp__ida-pro-mcp__callgraph
  mcp__ida-pro-mcp__callees
  mcp__ida-pro-mcp__lookup_funcs
  mcp__ida-pro-mcp__stack_frame
  mcp__ida-pro-mcp__basic_blocks
  mcp__ida-pro-mcp__get_bytes
  mcp__ida-pro-mcp__get_string
  mcp__ida-pro-mcp__get_int
  mcp__ida-pro-mcp__find_regex
  mcp__ida-pro-mcp__read_struct
  mcp__ida-pro-mcp__search_structs
  mcp__ida-pro-mcp__infer_types
  mcp__ida-pro-mcp__list_globals
metadata:
  user-invocable: "false"
---

# Binary Deep Dive — 심층 취약점 분석

triage에서 "위험"으로 판정된 함수들의 실제 exploitability를 검증한다.

## 입력

- `session_id`: 이전 스테이지의 세션
- `state/<session>/candidates.json` 필수
- `state/<session>/index.json` 필수
- `max_deep`: 심층 분석할 최대 함수 수 (기본: 8)

## 워크플로우

### Step 1: 대상 선정

```
candidates.json에서 verdict="dangerous" 함수를 priority 순 로드
최대 max_deep개 선택
```

### Step 2: 각 함수에 대해 심층 분석

함수 하나당 다음 과정을 수행:

#### 2a. 호출 컨텍스트 분석 (Reachability)

```
xrefs_to(addr) → 이 함수를 호출하는 곳
  각 caller를 decompile → 어떤 인자로 호출하는지 확인
  caller의 caller도 추적 (최대 3단계)

목표: 사용자 입력에서 이 함수까지 도달 가능한 경로 확인
```

**Attack Path 구성**:
```
[진입점] → [중간 함수 1] → [중간 함수 2] → [취약 함수]
   ↑            ↑              ↑              ↑
 recv()    parse_header()  validate()    sub_401230()
 (user      (인자 전달)     (검증 유무)   (strcpy 호출)
  input)
```

#### 2b. 피호출자 분석 (Impact)

```
callees(addr) → 이 함수가 호출하는 하위 함수
callgraph(addr, max_depth=2) → 하위 호출 체인

목표: 취약 동작의 실제 영향 범위 확인
- 위험 API 최종 도달 여부
- 시스템 호출까지의 경로
```

#### 2c. 데이터 흐름 추적

```
decompile 결과에서:
1. 입력 파라미터 → 어디서 사용되는가
2. 버퍼 할당 → 크기가 어떻게 결정되는가
3. 조건 분기 → 어떤 검증이 있는가
4. 출력/부작용 → 어디에 쓰는가

stack_frame(addr) → 스택 레이아웃, 로컬 버퍼 크기
```

#### 2d. Framework 특화 분석

**Linux Kernel**:
```
- copy_from_user 반환값 체크 여부
- mutex/spinlock 보호 범위 vs 공유 자원 접근
- capable() 체크 위치
```

**Windows Driver**:
```
- IOCTL dispatch: IoControlCode → CTL_CODE 매크로 해석
  * METHOD_BUFFERED / METHOD_NEITHER / METHOD_DIRECT 판별
- METHOD_NEITHER: ProbeForRead/ProbeForWrite + __try/__except 유무
- InputBufferLength 검증 vs 실제 구조체 크기
```

**Firmware**:
```
- 인터럽트 핸들러에서의 race condition (ISR vs main loop)
- DMA 버퍼 경계 조건
- 통신 프로토콜 파싱 (길이 필드 신뢰 여부)
```

**Userspace**:
```
- ASLR/PIE/NX/Canary 보호 기법 우회 가능성
- heap 메타데이터 조작 가능성
- format string: 사용자 입력이 몇 번째 인자인지
```

### Step 3: Evidence Packing

각 취약점 발견에 대해 evidence를 구조화:

```json
{
  "addr": "0x401230",
  "name": "sub_401230",
  "vuln_type": "stack buffer overflow",
  "severity": "high",
  "confidence": 0.85,
  "attack_path": [
    {"addr": "0x400100", "name": "main", "role": "entrypoint"},
    {"addr": "0x400500", "name": "handle_request", "role": "dispatcher"},
    {"addr": "0x401230", "name": "sub_401230", "role": "vulnerable"}
  ],
  "root_cause": "384바이트 스택 버퍼에 사용자 입력을 길이 검증 없이 strcpy",
  "impact": "스택 버퍼 오버플로우 → RIP 제어 → 코드 실행",
  "preconditions": [
    "공격자가 네트워크를 통해 handle_request에 도달 가능해야 함"
  ],
  "mitigations_present": [
    "스택 카나리 존재 여부 확인 필요"
  ],
  "evidence": {
    "decompiled_vuln_func": "(디컴파일 결과)",
    "decompiled_caller": "(호출자 디컴파일)",
    "stack_layout": "(stack_frame 결과)",
    "xrefs": ["0x400500 → 0x401230 (call)"],
    "callgraph_depth": 2
  },
  "next_questions": [
    "handle_request의 다른 코드 경로에서도 동일 취약점?",
    "스택 카나리가 활성화되어 있는가?"
  ]
}
```

### Step 4: findings.json 생성

```json
{
  "session_id": "<session-id>",
  "framework": "<framework>",
  "deep_dive_count": 8,
  "findings": [
    { ... finding 1 ... },
    { ... finding 2 ... }
  ],
  "summary": {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 2
  },
  "follow_up_targets": [
    {
      "addr": "0x400500",
      "reason": "handle_request의 다른 dispatch 경로 미분석"
    }
  ]
}
```

### Step 5: Index 업데이트

```
분석된 함수의 status → "analyzed"
follow_up_targets → index.json의 hot_functions에 추가 (다음 iteration용)
```

## 출력

- `state/<session>/findings.json`
- `state/<session>/decompile_cache/*.md` (추가 캐시)
- `state/<session>/callgraph_cache/*.json` (추가 캐시)
- `state/<session>/index.json` (status 업데이트)

## 반복 분석

findings.json의 `follow_up_targets`가 있으면, binary-analyze 오케스트레이터가 다시 triage → deep dive를 실행할 수 있다 (최대 2회 반복).
