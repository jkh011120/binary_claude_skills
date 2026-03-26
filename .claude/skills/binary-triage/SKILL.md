---
name: binary-triage
description: "Stage 3: index.json의 고스코어 함수들을 decompile하여 빠르게 분류한다. 각 함수를 위험/관심/무해로 판정하고 candidates.json을 생성한다."
license: MIT
compatibility: "IDA Pro + ida-pro-mcp server 실행 필요."
allowed-tools: >
  Bash Read Write Edit Glob Grep
  TaskCreate TaskUpdate TaskGet TaskList
  mcp__ida-pro-mcp__decompile
  mcp__ida-pro-mcp__disasm
  mcp__ida-pro-mcp__lookup_funcs
  mcp__ida-pro-mcp__callees
  mcp__ida-pro-mcp__stack_frame
  mcp__ida-pro-mcp__get_string
  mcp__ida-pro-mcp__xrefs_to
  mcp__ida-pro-mcp__basic_blocks
metadata:
  user-invocable: "false"
---

# Binary Triage — 빠른 분류

고스코어 함수들을 실제로 decompile하여 위험도를 판정한다.

## 입력

- `session_id`: recon에서 생성된 세션
- `state/<session>/index.json` 필수
- `max_triage`: 분류할 최대 함수 수 (기본: 30)

## 워크플로우

### Step 1: 대상 선정

```
index.json 로드
hot_functions에서 status="pending"인 함수 선택 (최대 max_triage개)
entrypoints는 스코어 무관하게 항상 포함
```

### Step 2: Batch Decompile

각 대상 함수를 decompile하고 캐시에 저장:

```
for addr in targets:
  # 캐시 확인
  if decompile_cache/<addr>.md exists:
    load from cache
  else:
    result = decompile(addr)
    save to state/<session>/decompile_cache/<addr>.md
```

**캐시 파일 형식** (`decompile_cache/0x401230.md`):
```markdown
# 0x401230 (sub_401230)
## Metadata
- Size: 342 bytes
- Score: 12.3
- Tags: user_control, dangerous_api

## Pseudocode
```c
int sub_401230(int a1, char *a2) {
  char v3[256];
  strcpy(v3, a2);
  ...
}
```

## Triage Notes
(이 섹션은 triage 판정 후 추가됨)
```

### Step 3: 판정 기준

각 decompile 결과를 읽고 다음 기준으로 분류:

**위험 (dangerous)**:
- 사용자 입력이 검증 없이 위험 API로 전달
- 버퍼 크기 < 입력 크기 가능성
- 해제된 포인터 재사용 패턴
- 정수 오버플로우 → 크기 계산
- 권한 체크 누락 (커널/드라이버)
- METHOD_NEITHER + ProbeForRead 부재 (Windows 드라이버)

**관심 (interesting)**:
- 복잡한 파싱 로직 (다수 분기)
- 메모리 할당/해제 패턴 존재하나 즉각적 위험 불분명
- 콜백/함수 포인터 사용
- 크기 검증이 있으나 경계 조건 의심

**무해 (benign)**:
- 단순 getter/setter
- 로깅/디버그 출력만
- 상수 반환 함수
- 이미 안전한 API만 사용 (strncpy with sizeof 등)

**FP 자동 필터**: framework config의 `false_positive_rules` 적용.
매칭되면 자동으로 무해 또는 지정된 `target_risk`로 다운그레이드.

### Step 4: candidates.json 생성

```json
{
  "session_id": "<session-id>",
  "triage_count": 30,
  "results": {
    "dangerous": [
      {
        "addr": "0x401230",
        "name": "sub_401230",
        "score": 12.3,
        "verdict": "dangerous",
        "reason": "strcpy(stack_buf, user_input) — 256바이트 스택 버퍼, 길이 미검증",
        "vuln_hint": "stack buffer overflow",
        "priority": 1
      }
    ],
    "interesting": [...],
    "benign": [...]
  },
  "stats": {
    "dangerous": 8,
    "interesting": 12,
    "benign": 10
  }
}
```

### Step 5: Index 업데이트

```
index.json의 각 함수 status를 "triaged"로 업데이트
verdict를 함수 정보에 추가
```

## 출력

- `state/<session>/candidates.json`
- `state/<session>/decompile_cache/*.md` (캐시 축적)
- `state/<session>/index.json` (status 업데이트)

## 컨텍스트 효율화

- 한 번에 5개씩 batch로 decompile하여 판정
- 판정 완료된 함수는 즉시 컨텍스트에서 제거
- decompile 결과는 파일에 남으므로 deep dive에서 재사용
