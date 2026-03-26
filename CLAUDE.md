# Binary Vulnerability Analysis Skills

IDA Pro MCP 기반 바이너리 취약점 분석 프레임워크.

## 프로젝트 구조

```
binary_claude_skills/
├── CLAUDE.md                    # 이 파일
├── configs/                     # Framework configs (바이너리 유형별)
│   ├── userspace.yaml
│   ├── firmware.yaml
│   ├── linux_kernel.yaml
│   ├── windows_driver.yaml
│   └── generic.yaml
├── .claude/skills/              # Claude Code 스킬
│   ├── binary-analyze/          # 오케스트레이터 (user-invocable)
│   ├── binary-recon/            # Stage 1-2: 정찰 + 인덱스 구축
│   ├── binary-triage/           # Stage 3: 빠른 분류
│   ├── binary-deep/             # Stage 4: 심층 분석
│   ├── binary-annotate/         # Stage 5: IDA DB 어노테이션
│   └── binary-report/           # Stage 6: 리포트 생성
├── state/                       # 분석 상태 (per-session)
│   └── <session-id>/
│       ├── index.json           # 함수 인덱스
│       ├── imports.json         # import 테이블
│       ├── strings.json         # 주요 문자열
│       ├── candidates.json      # 스코어링 결과
│       ├── findings.json        # 취약점 발견 (progressive)
│       ├── callgraph_cache/     # callgraph 캐시
│       └── decompile_cache/     # 디컴파일 캐시
└── out/                         # 최종 리포트
    └── <session-id>/
        ├── report.md
        └── state_final.json
```

## 분석 파이프라인

```
/binary-analyze [framework] [목표]
  ├─ Stage 1-2: /binary-recon    → index.json 생성
  ├─ Stage 3:   /binary-triage   → candidates.json 생성
  ├─ Stage 4:   /binary-deep     → findings.json 생성
  ├─ Stage 5:   /binary-annotate → IDA DB 업데이트
  └─ Stage 6:   /binary-report   → out/<session>/report.md
```

## Framework 선택

| Framework | 대상 | 진입점 패턴 |
|-----------|------|-------------|
| `userspace` | Linux/Windows 유저 앱 | main, exported functions |
| `firmware` | 임베디드 펌웨어 | IRQ handlers, app_main |
| `linux_kernel` | 리눅스 커널 모듈 (.ko) | module_init, ioctl, file_operations |
| `windows_driver` | Windows 드라이버 (.sys) | DriverEntry, IRP handlers, IOCTL dispatch |
| `generic` | 기타/자동감지 실패 시 | 모든 exported + 큰 함수 |

## IDA Pro MCP 도구 사용 규칙

1. **list_funcs**: 초기 인덱싱에만 사용. count=0으로 전체 수집.
2. **decompile**: 결과를 반드시 decompile_cache/에 저장. 같은 함수 재요청 금지.
3. **callgraph**: max_depth=3 기본. 필요시 증가.
4. **rename/set_type/set_comments**: annotate 스테이지에서 일괄 처리. 분석 중 즉시 반영하지 않음.
5. **xrefs_to**: deep dive에서 데이터 흐름 추적에 사용.

## 세션 관리

- 세션 ID 형식: `<framework>-<YYYYMMDD>-<HHMMSS>`
- 이전 세션 이어서 분석: `--session=<session-id>`
- index.json의 `status` 필드로 진행 상황 추적: pending → triaged → analyzed → annotated

## 스코어링 가중치

configs/*.yaml의 `score_weights`에 정의. 기본값:
- user_control: 3.0 (사용자 입력 처리)
- dangerous_api: 2.5 (위험 API 사용)
- lifetime: 2.0 (메모리 할당/해제)
- concurrency: 1.5 (동시성 패턴)
- hardcoded: 1.5 (하드코딩된 민감 값)
- guards: -0.35 (검증 로직 존재 시 감점)
