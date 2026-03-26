---
name: binary-report
description: "Stage 6: findings.json과 분석 상태를 종합하여 마크다운 리포트를 생성한다."
license: MIT
compatibility: "파일 시스템 접근만 필요."
allowed-tools: >
  Bash Read Write Edit Glob Grep
  TaskCreate TaskUpdate TaskGet TaskList
metadata:
  user-invocable: "false"
---

# Binary Report — 리포트 생성

분석 결과를 구조화된 마크다운 리포트로 출력한다.

## 입력

- `session_id`
- `state/<session>/index.json`
- `state/<session>/findings.json`
- `state/<session>/candidates.json`
- `state/<session>/annotations_log.json` (있으면)

## 리포트 구조

```markdown
# Vulnerability Report: <binary_name>

**Session**: <session_id>
**Framework**: <framework>
**Date**: <timestamp>
**Analyzed**: <analyzed_count> / <total_functions> functions (<percentage>%)

---

## Executive Summary

- **Critical/High**: N findings
- **Medium**: N findings
- **Low/Info**: N findings
- **Top Risk**: <가장 위험한 finding 한 줄 요약>

---

## Findings

### [HIGH] #1: <취약점 제목>

| Field | Value |
|-------|-------|
| **Address** | 0x401230 (`parse_user_command`) |
| **Type** | Stack Buffer Overflow |
| **Severity** | High |
| **Confidence** | 85% |

**Attack Path**:
```
recv() [0x400050]
  → handle_network_input() [0x400500]
    → parse_user_command() [0x401230]
      → strcpy() ← OVERFLOW
```

**Root Cause**:
384바이트 스택 버퍼 `input_buffer`에 사용자 입력을 길이 검증 없이 `strcpy`로 복사.

**Impact**:
스택 버퍼 오버플로우로 리턴 주소 덮어쓰기 가능. RIP 제어 → 임의 코드 실행.

**Preconditions**:
- 공격자가 네트워크를 통해 `handle_network_input`에 도달 가능

**Evidence**:
```c
// 0x401230 - parse_user_command (decompiled)
int parse_user_command(int socket_fd, char *buf, size_t buf_len) {
  char input_buffer[384];
  strcpy(input_buffer, buf);  // ← VULN: no bounds check
  ...
}
```

**Recommendations**:
1. `strncpy(input_buffer, buf, sizeof(input_buffer) - 1)` 사용
2. 입력 길이 사전 검증

---

### [MEDIUM] #2: ...

---

## Analysis Coverage

| Category | Count | Percentage |
|----------|-------|------------|
| Total Functions | 4523 | 100% |
| Indexed | 4523 | 100% |
| Triaged | 30 | 0.7% |
| Deep Analyzed | 8 | 0.2% |
| Annotated | 45 | 1.0% |

### Entrypoints Identified

| Category | Functions |
|----------|-----------|
| ioctl | `dispatch_ioctl` (0x402000) |
| file_ops | `dev_read` (0x402100), `dev_write` (0x402200) |

### Unanalyzed High-Score Functions

다음 분석 세션에서 우선 검토 필요:

| Address | Name | Score | Tags |
|---------|------|-------|------|
| 0x403000 | sub_403000 | 11.2 | user_control, lifetime |
| ... | ... | ... | ... |

---

## Annotations Applied

- Functions renamed: N
- Types applied: N
- Comments added: N
- Structs declared: N

---

## Appendix: Configuration

- Framework: <framework> (<display_name>)
- Score Weights: user_control=3.0, dangerous_api=2.5, ...
- FP Rules Applied: N rules
```

## 출력

- `out/<session>/report.md` — 전체 리포트
- `out/<session>/report_high_only.md` — High 이상만
- `out/<session>/state_final.json` — 전체 상태 스냅샷 (index + findings + candidates 통합)
- `out/<session>/` 디렉토리에 심볼릭 링크: `out/latest/` → 최신 세션
