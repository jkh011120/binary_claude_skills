---
name: binary-analyze
description: "IDA Pro MCP 기반 바이너리 취약점 분석 오케스트레이터. framework config에 따라 recon → triage → deep dive → annotate → report 파이프라인을 실행한다. userspace, firmware, linux_kernel, windows_driver 바이너리를 지원한다."
license: MIT
compatibility: "IDA Pro + ida-pro-mcp server 실행 필요. 분석할 바이너리가 IDA에 열려 있어야 함."
allowed-tools: >
  Bash Read Write Edit Glob Grep Skill
  TaskCreate TaskUpdate TaskGet TaskList
  mcp__ida-pro-mcp__list_funcs
  mcp__ida-pro-mcp__imports
  mcp__ida-pro-mcp__find_regex
  mcp__ida-pro-mcp__decompile
  mcp__ida-pro-mcp__disasm
  mcp__ida-pro-mcp__xrefs_to
  mcp__ida-pro-mcp__callgraph
  mcp__ida-pro-mcp__callees
  mcp__ida-pro-mcp__lookup_funcs
  mcp__ida-pro-mcp__rename
  mcp__ida-pro-mcp__set_type
  mcp__ida-pro-mcp__set_comments
  mcp__ida-pro-mcp__declare_type
  mcp__ida-pro-mcp__declare_stack
  mcp__ida-pro-mcp__delete_stack
  mcp__ida-pro-mcp__stack_frame
  mcp__ida-pro-mcp__basic_blocks
  mcp__ida-pro-mcp__get_bytes
  mcp__ida-pro-mcp__get_string
  mcp__ida-pro-mcp__get_int
  mcp__ida-pro-mcp__find_bytes
  mcp__ida-pro-mcp__list_globals
  mcp__ida-pro-mcp__infer_types
  mcp__ida-pro-mcp__read_struct
  mcp__ida-pro-mcp__search_structs
metadata:
  user-invocable: "true"
  argument-hint: "[framework] [goal] [--session=<id>] [--stage=<stage>] [--max-triage=N] [--max-deep=N]"
---

# Binary Analyze — 바이너리 취약점 분석 오케스트레이터

IDA Pro MCP를 사용하여 바이너리를 체계적으로 분석하고, 취약점을 발견하며, IDA DB에 분석 결과를 축적한다.

## 사전 조건

1. IDA Pro에서 분석할 바이너리가 열려 있어야 함
2. ida-pro-mcp 서버가 실행 중이어야 함
3. 바이너리 유형에 맞는 framework config가 `configs/` 디렉토리에 존재해야 함

## 사용법

```
/binary-analyze                              # generic framework, 자동 감지
/binary-analyze userspace                    # userspace 바이너리
/binary-analyze windows_driver               # Windows 드라이버
/binary-analyze linux_kernel                 # Linux 커널 모듈
/binary-analyze firmware                     # 임베디드 펌웨어
/binary-analyze firmware "UART 명령 파싱 분석"  # 특정 목표
/binary-analyze --session=fw-20260326-142000   # 이전 세션 이어서
/binary-analyze --stage=deep                   # 특정 스테이지부터
```

## 파이프라인

```
┌─────────────────────────────────────────────────────────────┐
│                    /binary-analyze                           │
│                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐               │
│  │  RECON   │──▶│  TRIAGE  │──▶│   DEEP   │               │
│  │ Stage1-2 │   │  Stage3  │   │  Stage4  │               │
│  └──────────┘   └──────────┘   └────┬─────┘               │
│       │                              │                      │
│       │              ┌───────────────┘                      │
│       │              │  follow_up_targets?                  │
│       │              │  ├─ yes → TRIAGE로 돌아감 (max 2회)  │
│       │              │  └─ no  ↓                            │
│       │         ┌────▼─────┐   ┌──────────┐               │
│       │         │ ANNOTATE │──▶│  REPORT  │               │
│       │         │  Stage5  │   │  Stage6  │               │
│       │         └──────────┘   └──────────┘               │
│       │                                                     │
│       ▼                                                     │
│  state/<session>/          out/<session>/                   │
│  ├── index.json            ├── report.md                   │
│  ├── candidates.json       ├── report_high_only.md         │
│  ├── findings.json         └── state_final.json            │
│  ├── imports.json                                          │
│  ├── strings.json                                          │
│  ├── annotations_log.json                                  │
│  ├── decompile_cache/                                      │
│  └── callgraph_cache/                                      │
└─────────────────────────────────────────────────────────────┘
```

## 오케스트레이션 로직

### 1. 초기화

```python
# 인자 파싱
framework = args.framework or "generic"  # 기본값: generic
goal = args.goal or None
session_id = args.session or f"{framework}-{YYYYMMDD}-{HHMMSS}"
start_stage = args.stage or "recon"

# Framework config 로드
config = load_yaml(f"configs/{framework}.yaml")

# 세션 디렉토리 확인/생성
if session exists:
  load existing state (index.json, candidates.json, findings.json)
  determine resume point
else:
  create state/<session_id>/
```

### 2. 스테이지 실행

각 스테이지는 해당 서브 스킬을 호출:

```
if start_stage <= "recon":
  invoke Skill("binary-recon")
  → state/<session>/index.json 생성

if start_stage <= "triage":
  invoke Skill("binary-triage")
  → state/<session>/candidates.json 생성

if start_stage <= "deep":
  invoke Skill("binary-deep")
  → state/<session>/findings.json 생성

  # 반복 분석 체크
  if findings.follow_up_targets and iteration < 2:
    follow_up_targets → index.json의 hot_functions에 추가
    → triage로 돌아감

if start_stage <= "annotate":
  invoke Skill("binary-annotate")
  → IDA DB 업데이트

if start_stage <= "report":
  invoke Skill("binary-report")
  → out/<session>/report.md 생성
```

### 3. 세션 이어서 분석

이전 세션을 `--session`으로 지정하면:

```
1. index.json 로드 → 이전 분석 상태 확인
2. status="pending"인 함수들로 triage 재시작
3. 이전 decompile_cache 재사용 (IDA MCP 호출 절약)
4. 이전 findings에 새 findings 추가 (append)
5. 누적 어노테이션 반영
```

### 4. 목표 기반 분석

`goal`이 지정되면 분석 범위를 조정:

```
goal = "UART 명령 파싱 분석"
→ recon에서 find_regex("uart|UART|serial|command|cmd|parse")로 관련 함수 우선 탐색
→ 관련 함수의 스코어에 goal_bonus 추가
→ triage/deep에서 해당 함수 우선 분석
```

## 지원 Framework

| Framework | Config | 주요 진입점 | 핵심 분석 관점 |
|-----------|--------|-------------|----------------|
| `userspace` | configs/userspace.yaml | main, handlers | 입력 검증, 메모리 안전성 |
| `firmware` | configs/firmware.yaml | IRQ, 통신 함수 | 하드코딩, 프로토콜 파싱 |
| `linux_kernel` | configs/linux_kernel.yaml | ioctl, fops | copy_from_user, locking |
| `windows_driver` | configs/windows_driver.yaml | DriverEntry, IRP | METHOD_NEITHER, 풀 관리 |
| `generic` | configs/generic.yaml | exported, 큰 함수 | 자동 감지 → 전환 제안 |

## 상태 파일 요약

| 파일 | 생성 스테이지 | 용도 |
|------|-------------|------|
| `index.json` | recon | 함수 인덱스 + 스코어 + 상태 추적 |
| `imports.json` | recon | import 테이블 |
| `strings.json` | recon | 주요 문자열 |
| `candidates.json` | triage | 분류 결과 (dangerous/interesting/benign) |
| `findings.json` | deep | 취약점 상세 + evidence |
| `annotations_log.json` | annotate | 수행한 어노테이션 기록 |
| `decompile_cache/*.md` | triage/deep | 디컴파일 캐시 (컨텍스트 절약) |
| `callgraph_cache/*.json` | recon/deep | callgraph 캐시 |

## 핵심 원칙

1. **IDA MCP 호출 최소화**: 캐시를 적극 활용. 같은 함수를 두 번 decompile하지 않음.
2. **Progressive filtering**: 전체 함수 → 고스코어 → 위험 판정 → 심층 분석. 컨텍스트 윈도우를 효율적으로 사용.
3. **축적형 분석**: 어노테이션이 IDA DB에 쌓이면서 디컴파일 품질이 향상. 재분석 시 이전 결과 활용.
4. **Framework 적응**: 바이너리 유형에 따라 진입점, 위험 패턴, FP 규칙이 자동 조정.
5. **파일 기반 상태**: 모든 중간 결과가 파일로 저장되어 중단/재개, 수동 검토 가능.
