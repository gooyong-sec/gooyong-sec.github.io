---
title: "Hera — Frida 기반 동적 보안 분석 워크벤치를 직접 만들다"
tags:
  - Frida
  - 동적분석
  - 모바일진단
  - 프로토콜분석
  - MCP
  - 진단도구
  - Hera
---

> 🚧 **활발히 개발 중(Work in Progress)** — 테스트 단계이고 편의성 개선·버그 검증이 더 필요합니다. 안정 릴리즈가 아닙니다.

> ⚠️ 승인된 자산(자사 앱, 허가받은 진단 대상)에만 사용하세요. 보안 연구·진단 목적의 도구입니다.

진단을 하다 보면 Burp Suite류 프록시로는 손이 안 닿는 대상이 있습니다. raw TCP 위에 커스텀 프로토콜을 얹고, 전송 전에 네이티브 레이어에서 자체 암호화를 하는 앱입니다. 세션키·시퀀스·프레이밍을 모르면 와이어에서 잡은 패킷은 그냥 암호문 덩어리죠.

그래서 직접 만들기 시작한 게 **Hera**입니다. Frida 기반 런타임 계측, 패킷 캡처, 프로토콜 리플레이, 그리고 AI 에이전트(MCP) 연동을 하나의 GUI로 묶은 동적 보안 분석 워크벤치입니다.

## 왜 와이어가 아니라 메모리인가

Hera의 핵심 아이디어는 단순합니다. 암호화가 일어나기 직전의 평문 버퍼를 메모리에서 가로채는 것.

```
TARGET Start
  → FridaManager → FridaAdapter → frida로 agent.js를 대상 프로세스에 주입
  → agent.js: Interceptor.attach()로 암호화 함수 후킹
    호출 직전 평문 버퍼를 in-place로 치환(Replace) → send()로 이벤트 전달
  → GUI는 QTimer로 드레인해 Trace 테이블에 반영
```

소켓(와이어) 레벨이 아니라 암호화 함수 호출 지점을 잡기 때문에, 세션키·시퀀스·프레이밍을 재현할 필요가 없습니다. 평문만 바꿔치기하면 앱이 스스로 암호화·전송을 마저 처리하거든요.

## 워크스페이스

| 워크스페이스 | 기능 |
|---|---|
| **TARGET** | 프로세스 선택, 함수명 glob 후킹, module+offset 주소 후킹(IDA/Ghidra RVA), Replace 규칙(평문 변조 + 길이 변경 허용) |
| **FRIDA / Trace** | 실시간 이벤트 스트림, Type/Module/Function/Preview 통합 검색(정규식), Backtrace(콜스택 + 인자 출처 추적) |
| **FRIDA / Intercept** | Burp Intercept를 Frida 후킹에 적용 — 요청·응답 양방향 실시간 일시정지·수정 |
| **HEX** | 16바이트/행 정렬 hex 에디터 + offset·ASCII 동기 스크롤 |
| **REPLAY** | Web/TCP Repeater — length-prefix 자동 재계산, hex diff, Protocol Lab(여러 샘플 비교로 고정/가변 필드 자동 탐지), Mutation Lab(필드 하나씩 변조해 응답 diff) |
| **NET** | HTTP/HTTPS MITM 프록시, 내장 브라우저 연동 |
| **CAPTURE** | tshark/Npcap 실시간 캡처, 정규식 필터, `.pcapng` 동시 저장 |
| **TIMELINE** | Frida trace + 패킷 + 프록시 flow 통합 시간순 뷰, Correlate(평문 바이트를 실제 패킷과 매칭) |
| **ASSESSMENT** | CWE/CVSS까지 갖춘 구조화된 Finding + 증거 연계(원본 바이트·SHA-256·타임스탬프 보존), Markdown+JSON 리포트 export |
| **MCP** | Hera의 실시간 상태를 MCP 도구로 노출 — AI 에이전트가 진단 세션을 직접 조회·보조 |

![Hera TARGET 워크스페이스 — 프로세스 선택과 후킹 규칙 설정 화면](/도구/images/hera-target.png)

![Hera Trace 워크스페이스 — Frida 후킹으로 잡힌 실시간 이벤트 스트림](/도구/images/hera-trace.png)

TCP Repeater는 raw 소켓으로 직접 송수신하면서 length-prefix 필드를 자동으로 다시 계산해줍니다. 바이트 하나 바꾸면 전체 길이 필드가 깨지는 커스텀 프로토콜에서 이 자동 재계산이 없으면 매번 손으로 계산기를 두드려야 합니다.

![Hera TCP Repeater — hex 편집과 length-prefix 자동 재계산, 원본 대비 diff](/도구/images/hera-tcp-repeater.png)

## MCP 연동 — AI가 진단 세션을 직접 들여다본다

Hera는 로컬 HTTP 상태 스냅샷을 통해 별도 프로세스(`hera_mcp.py`)와 통신하고, 이걸 MCP 도구로 노출합니다. Claude 같은 AI 클라이언트가 지금 어떤 함수가 후킹됐는지, Trace에 뭐가 찍혔는지를 직접 조회할 수 있어요. [[취약점 진단 툴에 MCP 붙이기 Ghidra Burp jadx]]에서 다룬 "AI가 진단 도구를 직접 부리는" 패턴을 제가 쓰는 도구에도 그대로 적용한 셈입니다.

![Hera MCP 워크스페이스 — AI 에이전트 연동 상태 화면](/도구/images/hera-mcp.png)

## 코드 구조

```
hera/
├── core/     — 프레임워크 비의존 순수 로직
│               이벤트 모델·hexdump·length-field, Correlate, Protocol Lab, Mutation Lab,
│               구조화 Finding+Evidence — 전부 Qt 의존 없이 단위 테스트 가능
├── frida/    — 계측 엔진 (adapter=frida API 격리, agent.js=타깃 내부 JS, manager=오케스트레이션)
├── net/      — 네트워크 I/O (raw HTTP 클라이언트, tshark 캡처, MITM 프록시, CA)
└── ui/       — PySide6(Qt) 패널, 워크스페이스 1:1 대응

hera_mcp.py   — MCP stdio 서버 진입점 (별도 프로세스)
run.py        — GUI 진입점
```

`frida/adapter.py`가 frida 라이브러리를 직접 다루는 유일한 지점이라, frida 버전이 바뀌어도 영향이 한 파일로 격리됩니다. 실제로 frida 17.x에서 특정 anti-frida 보호 대상에 attach가 멈추는 문제를 겪고 16.5.1로 핀 고정했는데, 이 격리 덕분에 롤백이 한 파일 수정으로 끝났습니다.

## 만든 방식 — 솔직하게

설계·기능 우선순위·실제 타깃 검증은 직접 했고, 구현은 Claude Code와 페어 프로그래밍하면서 Codex 교차검토를 거쳤습니다. [[Claude 작업을 Codex로 교차검증하기 — MCP로 두 AI 붙이기]]에서 쓴 워크플로우를 이 프로젝트 전체에 실제로 적용한 결과물이 Hera입니다. 커밋 전에는 적대적 관점의 멀티에이전트 코드 리뷰도 한 번씩 거쳤고요.

다만 그래서 WIP 딱지를 붙여뒀습니다. 설계가 맞았는지는 실제 타깃에 써보면서 계속 검증 중이고, 편의성 이슈나 엣지 케이스 버그가 아직 남아있습니다. "AI랑 같이 만들었으니 다 됐다"가 아니라, 안정화는 계속 제가 써보면서 잡아나가는 단계예요.

## 요구 사항과 로드맵

Windows + Python 3.12+, CAPTURE 워크스페이스를 쓰려면 Wireshark(tshark+Npcap)가 별도로 필요합니다. 당장 남은 과제는 Protocol Lab의 TLV 재귀 파싱·CRC 추론, Mutation Lab의 알려진 인젝션 페이로드 사전, Evidence의 redaction 규칙과 HTML/PDF export입니다.

---

Burp가 못 보는 영역(raw TCP + 네이티브 암호화)을 다루려고 시작한 도구가, 결국 Frida 계측·패킷 분석·AI 연동까지 한 워크벤치로 커졌습니다. [[취약점 진단 툴에 MCP 붙이기 Ghidra Burp jadx]]와 [[Claude 작업을 Codex로 교차검증하기 — MCP로 두 AI 붙이기]]에서 다룬 두 가지(진단에 AI 도구 붙이기, AI 작업을 AI로 교차검증하기)를 실제 도구 하나에 전부 적용해본 경험이기도 합니다.
