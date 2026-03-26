---
name: binary-annotate
description: "Stage 5: 분석 결과를 IDA Pro 데이터베이스에 반영한다. 함수/변수 rename, 타입 적용, 코멘트 추가를 일괄 수행하여 디컴파일 품질을 향상시킨다."
license: MIT
compatibility: "IDA Pro + ida-pro-mcp server 실행 필요."
allowed-tools: >
  Bash Read Write Edit Glob Grep
  TaskCreate TaskUpdate TaskGet TaskList
  mcp__ida-pro-mcp__rename
  mcp__ida-pro-mcp__set_type
  mcp__ida-pro-mcp__set_comments
  mcp__ida-pro-mcp__declare_type
  mcp__ida-pro-mcp__declare_stack
  mcp__ida-pro-mcp__delete_stack
  mcp__ida-pro-mcp__decompile
  mcp__ida-pro-mcp__lookup_funcs
  mcp__ida-pro-mcp__stack_frame
  mcp__ida-pro-mcp__infer_types
  mcp__ida-pro-mcp__search_structs
metadata:
  user-invocable: "false"
---

# Binary Annotate — IDA DB 어노테이션

분석 결과를 IDA 데이터베이스에 반영한다. 이것이 반복 분석의 핵심이다.

## 왜 중요한가

```
분석 전: int sub_401230(int a1, int a2, int a3)
분석 후: int parse_user_command(int socket_fd, struct cmd_packet *pkt, size_t pkt_len)

→ 이 함수를 호출하는 다른 함수의 디컴파일도 자동으로 개선됨
→ 분석할수록 바이너리 전체가 읽기 쉬워짐 (propagation effect)
```

## 입력

- `session_id`: 이전 스테이지의 세션
- `state/<session>/findings.json`
- `state/<session>/candidates.json`
- `state/<session>/decompile_cache/*.md`

## 워크플로우

### Step 1: 어노테이션 계획 수립

findings.json과 candidates.json에서 분석된 모든 함수를 수집:

```
1. findings의 각 finding → 함수명, 변수명, 타입 추론
2. attack_path의 각 함수 → 역할 기반 이름 부여
3. candidates의 "interesting" 함수 → 추론된 이름 부여
```

### Step 2: Function Rename

**일괄 rename 실행**:

```
rename(batch={
  "func": [
    {"addr": "0x401230", "name": "parse_user_command"},
    {"addr": "0x400500", "name": "handle_network_input"},
    {"addr": "0x400100", "name": "server_main_loop"}
  ]
})
```

**명명 규칙**:
- 동사_목적어 형태: `parse_command`, `handle_request`, `validate_input`
- 취약 함수: `vuln_` prefix 사용하지 않음 (기능 기반 이름)
- 콜백: `on_` prefix — `on_data_received`, `on_timer_expired`
- 디스패치: `dispatch_` prefix — `dispatch_ioctl`

### Step 3: Variable/Stack Rename

```
rename(batch={
  "local": [
    {"func_addr": "0x401230", "old": "v3", "new": "input_buffer"},
    {"func_addr": "0x401230", "old": "a1", "new": "socket_fd"}
  ],
  "stack": [
    {"func_addr": "0x401230", "old": "var_180", "new": "input_buffer"}
  ]
})
```

### Step 4: Type 적용

```
set_type(edits=[
  {
    "addr": "0x401230",
    "kind": "function",
    "signature": "int parse_user_command(int socket_fd, char *buf, size_t buf_len)"
  },
  {
    "addr": "0x401230",
    "variable": "input_buffer",
    "ty": "char [384]"
  }
])
```

**구조체 선언이 필요한 경우**:

```
declare_type("struct cmd_packet { uint16_t opcode; uint16_t length; char payload[0]; };")

set_type(edits=[{
  "addr": "0x401230",
  "variable": "pkt",
  "ty": "struct cmd_packet *"
}])
```

### Step 5: Comment 추가

```
set_comments(items=[
  {
    "addr": "0x401230",
    "comment": "[ANALYZED] parse_user_command - 네트워크 패킷 명령 파싱"
  },
  {
    "addr": "0x401290",
    "comment": "[VULN:HIGH] stack BOF: input_buffer(384) <- strcpy(no length check)"
  },
  {
    "addr": "0x400500",
    "comment": "[ANALYZED] handle_network_input - recv() 결과를 parse_user_command로 전달"
  }
])
```

**Comment prefix 규칙**:
- `[ANALYZED]` — 분석 완료, 기능 설명
- `[VULN:HIGH]` / `[VULN:MED]` / `[VULN:LOW]` — 취약점 발견
- `[SUSPICIOUS]` — 추가 분석 필요
- `[SAFE]` — 검증 완료, 안전
- `[ENTRYPOINT]` — 진입점 함수
- `[TAINTED]` — 사용자 입력이 흐르는 경로

### Step 6: Index 업데이트

```
index.json의 각 어노테이션된 함수:
- status → "annotated"
- name → 새 이름으로 업데이트
```

### Step 7: 검증

어노테이션 후 주요 함수를 재 decompile하여 품질 확인:

```
decompile("0x401230")
→ 이름, 타입이 반영되었는지 확인
→ decompile_cache 갱신
```

## 출력

- IDA DB에 어노테이션 반영 (rename, type, comments)
- `state/<session>/index.json` (status, name 업데이트)
- `state/<session>/decompile_cache/*.md` (어노테이션 반영 후 재캐시)
- `state/<session>/annotations_log.json` — 수행한 모든 어노테이션 기록

```json
// annotations_log.json
{
  "session_id": "<session-id>",
  "timestamp": "2026-03-26T14:30:00",
  "renames": [
    {"addr": "0x401230", "old": "sub_401230", "new": "parse_user_command"}
  ],
  "types": [
    {"addr": "0x401230", "kind": "function", "signature": "..."}
  ],
  "comments": [
    {"addr": "0x401290", "comment": "[VULN:HIGH] ..."}
  ],
  "structs_declared": [
    "struct cmd_packet { ... }"
  ]
}
```

## 주의사항

- rename 실패 시 (이름 충돌 등): 로그에 기록하고 건너뜀
- IDA 자동 분석이 추가로 진행될 수 있음 — 잠시 대기 후 재확인 권장
- 어노테이션은 **되돌리기 어려움** — annotations_log.json으로 추적
