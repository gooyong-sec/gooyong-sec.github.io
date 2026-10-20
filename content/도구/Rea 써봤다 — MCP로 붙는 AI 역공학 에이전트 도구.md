---
title: "Rea 써봤다 — MCP로 붙는 AI 역공학 에이전트 도구"
tags:
  - 도구
  - MCP
  - 리버싱
  - AI에이전트
---

[Rea](https://github.com/morluto/rea)는 npm 패키지 `rea-agents`로 배포되는 MCP 서버 + CLI입니다. README 기준으로 네이티브 바이너리(Ghidra/IDA/Hopper 오케스트레이션), JS/Electron 앱(실행 없이 정적 분석), .NET/Go/Rust/WASM/EVM 바이트코드, 안드로이드(JADX/apktool/adb), 게임 엔진 파일, 웹사이트/네트워크 캡처(HAR/pcap), 펌웨어, SQLite, 실행 중 프로세스 관찰까지 — 역공학 대상 거의 전부를 하나의 MCP 인터페이스로 묶겠다는 도구입니다. TypeScript 모노레포, MIT 라이선스, Node >=22.19/24.11/26 요구.

[[취약점 진단 툴에 MCP 붙이기 Ghidra Burp jadx]]에서 Ghidra·Burp·jadx를 각각 따로 MCP 브리지로 붙였는데, Rea는 그 역할을 한 패키지로 흡수하려는 시도처럼 보여서 직접 설치해보고 실제로 뭘 할 수 있는지 확인했습니다.

## 환경 확인

```bash
node --version
# v24.14.0

npm ping
# npm notice PING https://registry.npmjs.org/
# npm notice PONG 198ms
```

요구 버전(>=24.11) 충족, 레지스트리 접근도 정상.

## 설치 — npx로 바로 실행

Ghidra/IDA/JADX 같은 무거운 외부 도구는 이 환경에 없어서 설치하지 않았습니다. 그 전제하에, 외부 도구가 필요 없는 경로부터 테스트했습니다.

```bash
npx --yes rea-agents --help
```

로컬에 설치하지 않고 npx가 패키지를 받아서 바로 실행했습니다(테스트한 버전은 `rea-agents 6.7.0`). `prebuild-install@7.1.3` deprecated 경고 한 줄만 나왔고 에러는 없었습니다. `--help` 출력에 커맨드가 100개 넘게 나열됩니다 — `inspect-macho`, `decompile-jeb-item`, `capture-adb-screen`, `inspect-sqlite-database`, `inspect-pcap-capture`, `analyze-javascript-application` 등 README에서 말한 범위가 커맨드 이름 목록으로는 전부 존재합니다. 다만 이건 "메뉴에 있다"는 확인이고, 실제로 실행까지 확인한 건 아래 `analyze-javascript-application` 하나뿐입니다.

## doctor — 뭐가 없는지부터 솔직하게 보여줌

```bash
npx --yes rea-agents doctor
```

```
healthy: false
environment_healthy: false
scope_checks[14]:
  - name: node
    ok: true
    detail: 24.14.0
  - name: host
    ok: true
    detail: win32 x64
  - name: hopper
    ok: false
    classification: missing_analysis_engine
    remediation: "Run rea setup to install Hopper, or set HOPPER_LAUNCHER_PATH."
  - name: ghidra
    ok: false
    classification: missing_analysis_engine
    detail: GHIDRA_INSTALL_DIR is not set
  - name: ida-registration
    ok: false
    classification: missing_analysis_engine
    detail: IDA MCP registration is not configured.
  - name: jadx
    ok: false
    classification: missing_analysis_engine
    detail: Set REA_JADX_MCP_JAR to the absolute path of a caller-supplied jadx-headless-mcp 0.7.1 JAR. REA does not download or install it.
  ...
```

이 환경엔 Hopper, Ghidra, IDA, jadx, Kuna 모두 없어서(이 5개는 `doctor`와 아래 `setup --dry-run` 출력에서 직접 확인한 항목입니다) 전부 `missing_analysis_engine`으로 떴습니다. 다만 "설치를 전혀 안 해준다"는 아니었습니다 — `doctor`의 remediation 문구를 보면 Ghidra·jadx는 `GHIDRA_INSTALL_DIR`/`REA_JADX_MCP_JAR`처럼 사용자가 이미 가진 설치본의 경로를 환경변수로 넘기라고 하는 반면, Hopper는 "`Run rea setup to install Hopper, or set HOPPER_LAUNCHER_PATH`"라고 — 즉 `rea setup`이 Hopper 설치까지 대신 진행할 수 있다는 뜻입니다(`setup --help`에도 `--install-hopper` 옵션이 있었습니다). 저는 이 설치 경로를 직접 실행해보진 않았지만, Rea가 전부 "기존 설치본 연결"만 하는 건 아니라는 점은 출력에서 바로 보였습니다.

## setup — 일단 --dry-run만

`rea setup`은 Claude Code/Codex/Cursor/Gemini CLI 같은 에이전트 설정 파일에 MCP 서버를 등록합니다. 지금 세션에서 쓰고 있는 AI 클라이언트 설정을 실제로 건드리고 싶지 않아서, `--client`나 `--all-detected` 없이 `--dry-run`만 돌렸습니다.

```bash
npx --yes rea-agents setup --dry-run
```

```
status: planned
plannedActions: []
appliedActions: []
...
registrations[6]:
  - client: antigravity
    config_path: "C:\\Users\\yong\\.gemini\\config\\mcp_config.json"
    command: []
```

`--dry-run`이라 애초에 아무것도 쓰지 않는 모드였고, `--client`도 지정하지 않아서 `plannedActions`/`appliedActions` 둘 다 비어 있었습니다 — 즉 이 호출로는 실제 설정 파일을 건드릴 수조차 없는 조합이었습니다. 다만 이미 설치된 agentic CLI(여기선 antigravity/`agy`)의 설정 파일 경로(`C:\Users\yong\.gemini\config\mcp_config.json`)는 탐지해서 출력에 보여줬습니다. `rea mcp add`나 `setup --yes`로 실제 등록까지는 의도적으로 가지 않았습니다. 이 세션이 쓰는 도구 설정을 실험용으로 바꾸고 싶지 않아서입니다.

## analyze-javascript-application — 실제로 작동한 유일한 "진짜 분석"

외부 도구가 필요 없는 경로가 이거라서 직접 만든 미니 JS 앱으로 테스트했습니다. 3개 파일짜리 가짜 "라이선스 체크" 앱입니다.

```javascript
// index.js
const crypto = require("crypto");
const { checkLicense } = require("./license");

function main() {
  const key = "hardcoded-super-secret-key-123";
  ...
  if (checkLicense(key)) { ... }
  const hash = crypto.createHash("sha256").update(key).digest("hex");
  return hash;
}
main();

// license.js
function checkLicense(key) {
  return key.length > 10 && key.startsWith("hardcoded");
}
module.exports = { checkLicense };
```

```bash
npx --yes rea-agents analyze-javascript-application "/tmp/rea-test-app"
```

(Git Bash 환경이라 `/tmp`가 실제로는 `C:\Users\yong\AppData\Local\Temp`로 풀립니다 — 아래 출력의 `local_path`에 그대로 찍혀 있습니다.)

진행 로그가 단계별로 찍히면서(파싱 → 애플리케이션 그래프 구성 → semantic 그래프 구성 → sealing → hashing) 완료됩니다.

```
{"rea_progress":{"phase":"parse_javascript_source","message":"Parsing and projecting index.js (1/3)",...}}
{"rea_progress":{"phase":"parse_javascript_source","message":"Parsing and projecting license.js (2/3)",...}}
{"rea_progress":{"phase":"build_javascript_semantic_graph",...}}
{"rea_progress":{"phase":"analyze_javascript_application","terminal":true,...}}
evidence_id: ev_c88e17739f84701a75b926890fbc818ac0cebfb8ae0d400ccebe6cbee99a4d66
subject:
  name: rea-test-app
  digest:
    sha256: 354a14f9700ae33147f27688234788d97002702afcac51018a9a2facb873362d
```

결과물은 3파일짜리 토이 앱 기준으로 4943줄, `--token-count` 기준 35,808토큰짜리 evidence 그래프였습니다. `--filter-output`/`--token-limit` 같은 옵션이 따로 있는 걸 보면 사람이 전체를 눈으로 읽기보다 에이전트가 필요한 부분만 잘라서 쿼리하는 걸 염두에 둔 구조로 보입니다(MCP로 실제 연결해서 에이전트가 이 출력을 어떻게 소비하는지까지는 테스트하지 않았습니다). 그래도 CLI로 받은 결과 자체는 가짜가 아니었습니다 — grep해보면:

```
role_key: "literal:scope:function:82:409:binding:key:binding:\"hardcoded-super-secret-key-123\""
value: hardcoded-super-secret-key-123
```

하드코딩한 키 문자열을 그래프 노드의 `role_key`(스코프·바인딩 경로가 그대로 인코딩된 문자열)와 함께 복원했고, `index.js`가 `require("./license")`로 `license.js`의 `checkLicense`를 가져오는 CommonJS 관계, `checkLicense` 참조 지점들, `.startsWith` 속성 접근까지 — grep으로 확인 가능한 노드들로 그래프에 잡혀 있었습니다. 전부 실행 없이 AST 기반 정적 분석만으로 나온 결과입니다. 동시에 과장하지 않고 한계도 명시합니다 — `"Call target checkLicense has ambiguous or unsupported assignments."`, `"Own property checkLicense is unknown-coverage."` 같은 caveat이 결과 안에 박혀 있습니다. 동적 분석이 아니니 "이 함수가 실제로 호출됐다"는 보장은 하지 않는다는 뜻입니다.

## 뭐가 됐고 뭐가 안 됐나

- 됨: `npx rea-agents` 설치/실행, `--help`/`doctor`/`capabilities`/`setup --dry-run`, `analyze-javascript-application`으로 실제 정적 JS 분석(문자열 리터럴 위치 복원, import/참조 그래프 추적)까지 전부 실제로 확인했습니다.
- 안 함(환경 제약): Ghidra/IDA/Hopper/jadx가 이 환경에 없어서 네이티브 바이너리·안드로이드 분석 경로는 테스트 못 했습니다. doctor가 이걸 명확히 `missing_analysis_engine`으로 보고해줘서, 뭐가 빠졌는지는 바로 알 수 있었습니다.
- 안 함(의도적으로): `rea mcp add`로 실제 MCP 등록, `setup --yes`로 실제 설정 파일 변경은 하지 않았습니다. 이 세션이 쓰는 Claude Code/agentic CLI 설정을 실험용으로 건드리고 싶지 않아서입니다.
- 놀란 점: 3파일 토이 앱에 35,808토큰짜리 출력이 나온다는 것. 이건 사람이 읽는 리포트가 아니라 AI 에이전트가 `--token-limit`/`--filter-output`으로 잘라먹으면서 쓰라고 설계된 구조라는 걸 체감했습니다.

## Hera와 비교하면

[[Hera — Frida 기반 동적 보안 분석 워크벤치를 직접 만들다]]는 정확히 반대 극단입니다. Hera는 "raw TCP + 네이티브 암호화"라는 하나의 구체적 문제를 풀기 위해 Frida 메모리 레이어 후킹을 직접 만든 전용 도구입니다. MCP는 그 위에 얹은 보조 기능 하나일 뿐이고, 핵심은 제가 직접 설계한 암호화 함수 후킹·프로토콜 리플레이 로직입니다.

Rea는 반대로 범용 오케스트레이션 쪽입니다. 제가 실행까지 직접 확인한 건 외부 엔진이 필요 없는 JS/Electron 정적 분석 하나뿐이고, `--help` 커맨드 이름으로 미뤄보면 Ghidra·IDA·Hopper·jadx·adb·tshark·GDB·Rizin 같은 기존 도구를 호출하는 커맨드가 대부분입니다(SQLite·Go/Rust 메타데이터처럼 외부 엔진이 필요 없어 보이는 커맨드도 있었지만 이건 이름만 봤을 뿐 실행해보진 않았습니다). [[취약점 진단 툴에 MCP 붙이기 Ghidra Burp jadx]]에서 도구별로 따로 브리지를 붙이던 걸, Rea는 한 패키지·한 설정으로 수십 개 커맨드에 걸쳐 묶어주겠다는 쪽입니다.

## 솔직한 평가

JS/Electron 앱을 실행 없이 정적으로 빠르게 훑어야 할 때는 바로 쓸 만합니다. 외부 도구·라이선스 없이 `npx` 한 줄로 evidence 그래프(해시·위치·커버리지 정보 포함)가 나오는 건 실제로 확인했으니까요.

다만 네이티브/안드로이드/WASM 등 나머지 대부분 경로는 Rea가 분석을 "대신 해주는" 게 아니라 "이미 가진 도구를 AI가 부리게 해주는" 역할입니다. README도 명시하듯 Ghidra는 무료지만 IDA·Hopper·JEB는 각자 라이선스를 따로 사야 합니다. Rea를 설치했다고 역공학 능력이 생기는 게 아니라, 이미 Ghidra/IDA 라이선스와 숙련도가 있는 사람이 그 도구들을 AI 에이전트로 일괄 조작하는 레이어를 얻는 겁니다. doctor가 "뭐가 없는지"를 바로 알려주는 점은 신뢰할 만했습니다.

출력이 CLI만으로도 극단적으로 무겁다는 점도 염두에 둬야 합니다(토이 앱 하나에 3만 5천 토큰). 사람이 직접 읽는 용도로는 안 맞고, `--filter-output`/`--token-limit` 옵션 구성을 보면 Claude Code 같은 에이전트가 MCP로 붙어 필요한 조각만 꺼내 쓰는 용도로 설계된 것으로 보입니다 — 다만 이 문단은 CLI 옵션에서 유추한 것이고, MCP로 실제 연결해 에이전트가 이걸 어떻게 소비하는지는 테스트하지 않았습니다.

## 신뢰 관점 — MCP 서버를 설치한다는 것 자체가 결정이다

README는 공식 저장소(github.com/morluto/rea), rea.tools, npm 패키지명 `rea-agents`를 통해서만 설치하라고 명시합니다. 이건 가벼운 주의사항이 아닙니다. `capabilities` 출력을 직접 받아보면 Rea가 노출하는 operation들의 effect로 `launches_process`, `may_write_filesystem`, `may_access_network`, `may_show_ui`가 붙어 있고, adb push/install, GDB 콘솔 명령 실행 같은 커맨드도 CLI 표면에 그대로 있습니다 — 이건 제가 받은 출력에서 직접 확인한 거고, 이번 테스트에서 실제로 프로세스를 띄우거나 파일을 쓰거나 네트워크를 탄 건 아닙니다(그런 동작을 "할 수 있는" 커맨드가 존재한다는 것과 "실행됐다"는 건 다릅니다). MCP로 AI 에이전트를 붙이면 에이전트가 이런 동작을 요청할 수 있는 경로가 생기는데, 실제로 그게 승인 없이 실행되는지는 클라이언트의 MCP 승인 정책에 달려 있습니다. 출처를 확인하지 않은 채로 설치하는 건, 그 경로를 열어줄지 말지를 제대로 검토하지 않고 결정하는 셈입니다 — README의 출처 확인 경고는 과장이 아니라 타당한 조언입니다.

---

같은 "AI + 역공학" 맥락이라도 접근이 완전히 다릅니다. Rea는 넓게(모든 타깃 타입) + 얕게(기존 도구 오케스트레이션), Hera는 좁게(특정 프로토콜) + 깊게(직접 만든 메모리 후킹)입니다. 둘 다 MCP를 "AI가 도구를 직접 부린다"는 같은 패턴으로 쓰지만, Rea는 그 패턴을 범용 플랫폼으로 확장한 버전이라고 보면 됩니다.
