---
title: OSCP 추천 도구
tags:
  - OSCP
  - 침투테스트
  - 도구
---

> [!summary] ⏱️ 5초 핵심 요약
> - **한 줄 비유**: 24시간 제한 시간 안에 여러 대의 머신을 뚫어야 하는 OSCP 시험장에서 **수동 드라이버(`nc`, 수동 해시 검색, 단발성 `gobuster`) 대신 시간을 절반으로 줄여주는 4가지 전동 공구 세트**입니다.
> - **핵심 구성**: ① **Penelope**(자동 PTY 업그레이드 및 멀티 세션 리버스 셸 핸들러), ② **Name-That-Hash (`nth`)**(즉각적인 해시 포맷·Hashcat/John 모드 식별), ③ **Feroxbuster**(Rust 기반 초고속 재귀 웹 디렉터리 탐색), ④ **Remmina**(안정적인 RDP/VNC/SSH 통합 GUI 원격 클라이언트).
> - **시험장 실전 포인트**: 시험 중 `Ctrl+C` 실수로 셸이 날아가거나 엉뚱한 Hashcat 모드로 시간을 허비하는 사고를 막아주며, 모든 도구는 시험 전 칼리 리눅스에 미리 설치하고 단축 옵션까지 손에 익혀두어야 합니다.

OSCP 시험은 23시간 45분이라는 제한된 시간 안에 AD 세트 1개(3대)와 스탠드얼론 머신 3대를 공략하고, 이어서 24시간 안에 재현 가능한 보고서([[SysReptor로 OSCP 리포트 작성하기]])까지 제출해야 하는 시간 싸움입니다. 화려한 자동화 프레임워크보다 **반복 작업에서 잔실수를 없애고 시간을 극적으로 아껴주는 실전 도구 4가지**를 기본 도구와의 차이점, 실전 옵션과 함께 정리합니다.

```mermaid
flowchart LR
    Recon["🔍 1. 웹 경로 정찰<br/>Feroxbuster<br/>(초고속 자동 재귀 탐색)"] --> Shell["🐚 2. 초기 침투 및 셸 확보<br/>Penelope<br/>(자동 PTY 업그레이드 · 세션 로깅)"]
    Shell --> Hash["🔑 3. 자격증명·해시 식별<br/>Name-That-Hash (nth)<br/>(Hashcat · John 모드 즉시 매핑)"]
    Hash --> Pivot["🖥️ 4. 윈도우 GUI 피벗·후속 작업<br/>Remmina<br/>(RDP · 폴더 공유 · 클립보드 연동)"]
```

---

## 한눈에 보는 기본 도구 vs OSCP 추천 도구 비교

| 작업 영역 | 기존 기본 도구 (`nc`, `gobuster` 등)의 불편한 점 | 추천 도구 | 시험장에서 아껴주는 핵심 가치 |
|---|---|---|---|
| **리버스 셸 핸들링** | `nc -lvnp`는 받을 때마다 `python3 -c 'import pty...'` + `stty raw -echo; fg`를 수동 입력해야 하고, 실수로 `Ctrl+C`를 누르면 셸이 바로 끊김 | **Penelope** | 연결 즉시 **자동으로 완전한 대화형 PTY 셸로 업그레이드**, 멀티 세션 전환, **모든 입출력 로그 자동 파일 저장**(리포트 작성 시 효자) |
| **해시 타입 식별** | 낯선 해시 문자열을 볼 때마다 구글링하거나 `hashid`가 Hashcat 모드 번호를 바로 안 알려줘서 문서 검색에 시간 허비 | **Name-That-Hash (`nth`)** | 해시 길이·패턴 기반으로 **가장 확률 높은 해시 이름 + `Hashcat (-m)` 번호 + `John (--format)` 이름**을 1초 만에 출력 |
| **웹 디렉터리 탐색** | `dirb`는 느리고, `gobuster`/`ffuf`는 하위 폴더 발견 시 수동으로 다시 돌리거나 재귀 옵션을 세밀하게 챙겨야 함 | **Feroxbuster** | Rust 멀티스레드 기반 압도적 속도 + **기본 자동 재귀(Recursion) 탐색** + 실행 중 실시간 스레드·필터 조정 및 스캔 상태 저장/재개 |
| **원격 GUI 접속** | `xfreerdp` 명령줄 옵션을 매번 길게 치거나 해상도·클립보드·드라이브 마운트 설정이 번거로움 | **Remmina** | 직관적인 GUI 프로필 저장, **동적 해상도 조절, 양방향 클립보드 복사, 로컬 칼리 폴더 공유**를 클릭 몇 번으로 해결 |

---

## 1. Penelope — 리버스 셸 핸들러

**💡 한 줄 비유**: 일반 `netcat`(`nc`)이 **아무 안전장치 없는 낚싯줄**이라 손 한 번 잘못 놀리면(`Ctrl+C`) 물고기(셸)가 도망간다면, **Penelope는 물고기가 물자마자 자동으로 뜰채로 건져 수조(완전한 TTY 세션)에 넣고 녹화까지 켜주는 자동 낚시 장비**입니다.

### 왜 `nc -lvnp` 대신 써야 하는가?
1. **자동 PTY 업그레이드**: 리버스 셸이 연결되는 순간 타깃에 설치된 Python/script 등을 자동 감지해 `stty` 수동 작업 없이 즉시 **탭 자동완성, 화살표 히스토리, `Ctrl+C` 시그널 전달이 정상 작동하는 완전한 TTY 셸**로 만들어줍니다.
2. **멀티 세션 & 멀티 타깃 관리**: 포트 하나로 여러 호스트의 셸을 동시에 받아 세션을 오가며 관리하거나, 각 세션을 별도 터미널 탭/창으로 분리해 띄울 수 있습니다.
3. **자동 세션 로깅 (`~/.penelope/sessions/`)**: 각 타깃에서 실행한 모든 명령어와 출력 결과가 타임스탬프와 함께 자동 기록되어, 시험 후 리포트를 쓸 때 "아까 그 명령어 출력 안 찍어뒀는데!" 하는 아찔한 상황을 막아줍니다.

### 설치 및 실전 주요 명령어
```bash
# 설치 (Kali Linux / pipx 권장)
pipx install penelope-shell-handler
# 또는 단일 스크립트 다운로드 후 실행:
wget https://raw.githubusercontent.com/brightio/penelope/main/penelope.py && chmod +x penelope.py

# 1. 기본 리스너 실행 (포트 4444)
penelope 4444

# 2. 여러 포트 동시 리스닝
penelope 4444 8080 9001

# 3. SSH처럼 특정 타깃에 바인드 셸 연결할 때
penelope -c <target-ip> 4444
```

### 시험장 필수 단축키 & 메뉴 활용 팁
- 셸 내부에서 **`F12`** 키를 누르면 타깃 셸을 죽이지 않고 언제든 **Penelope 메인 메뉴 프롬프트**로 빠져나옵니다.
- 메인 메뉴에서 `sessions`로 연결된 세션 목록을 보고, `interact <ID>`로 원하는 셸로 들어가며, `spawn`을 치면 별도 터미널 창에 새 세션을 복제해 띄워줍니다.

---

## 2. Name-That-Hash (`nth`) — 해시 타입 식별

**💡 한 줄 비유**: 잠긴 자물쇠(해시값)를 부수기 전에 **"이 자물쇠가 몇 번 규격(Hashcat 모드 번호)인지" 1초 만에 판독해 주는 자물쇠 감정 돋보기**입니다.

### 왜 시험장에서 유용한가?
- DB 덤프나 설정 파일에서 해시 문자열을 주웠을 때, 이게 `MD5`인지 `NTLM`인지, 아니면 `bcrypt`나 `NetNTLMv2`인지 헷갈리면 크랙 자체가 시작되지 않습니다.
- 구형 `hash-identifier`와 달리 최신 해시 포맷까지 지원하며, 무엇보다 **`Hashcat` 모드 번호(예: `1000`, `1800`, `3200`)와 `John the Ripper` 포맷 이름을 가장 가능성 높은 순서(`Most Likely`)로 바로 찍어줍니다.**

### 설치 및 실전 주요 명령어
```bash
# 설치 (Kali 기본 저장소 또는 pipx)
sudo apt install name-that-hash
# 또는: pipx install name-that-hash

# 1. 단일 해시 문자열 즉시 식별 (-t / --text)
nth -t '5f4dcc3b5aa765d61d8327deb882cf99'

# 2. 여러 해시가 담긴 파일 일괄 식별 (-f / --file)
nth -f hashes.txt

# 3. 배너 없이 깔끔하게 핵심 결과만 볼 때 (--no-banner)
nth --no-banner -t '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
```

### 식별 직후 크랙 연동 치트시트
```bash
# nth 출력에서 확인한 모드로 곧바로 크랙 실행
# 예: NTLM (Hashcat 모드 1000 / John 포맷 NT)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --format=NT hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 3. Feroxbuster — 디렉터리/콘텐츠 탐색

**💡 한 줄 비유**: 일반 도구가 **건물 1층 방문만 두드려보고 끝내는 순찰대**라면, Feroxbuster는 **열린 방문을 발견하는 즉시 그 방 안의 안방과 다락방까지 자동으로 끝까지 파고드는 초고속 수색대**입니다.

### 왜 `dirb`/`gobuster` 대신 주력으로 쓰는가?
1. **자동 재귀 탐색(Auto-Recursion)**: `/admin`을 찾으면 사용자가 다시 명령을 칠 필요 없이 자동으로 `/admin/backup`, `/admin/backup/db`까지 깊이 파고듭니다. OSCP 머신은 2~3단계 하위 디렉터리에 결정적 힌트를 숨겨두는 경우가 많아 특히 강력합니다.
2. **런타임 인터랙티브 제어**: 스캔이 돌아가는 도중에도 **`Enter` 키**를 눌러 특정 하위 디렉터리 스캔을 도중에 취소하거나 필터를 실시간으로 추가할 수 있어, 쓸데없는 경로(예: `/assets/img/...`)에 갇혀 시간을 낭비하지 않습니다.
3. **자동 와일드카드·에러 페이지 필터링 (`--auto-bail`, `--auto-tune`)**: 존재하지 않는 경로에도 무조건 `200 OK`를 돌려주는 웹 서버를 만나면 알아서 응답 크기·단어 수를 분석해 가짜 응답을 걸러냅니다.

### 실전 주요 명령어 (OSCP 맞춤 옵션)
```bash
# 1. 가장 기본적인 빠른 탐색
feroxbuster -u http://<target> -w /usr/share/wordlists/dirb/common.txt

# 2. [실전 추천] PHP/TXT/BAK 확장자 포함 + 404/403 제외 + 인증서 오류 무시(-k)
feroxbuster -u http://<target> \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,bak,zip,conf \
  -C 404,403 \
  -k

# 3. 재귀 깊이를 2단계로 제한(--depth 2)하고 백업 파일 위주로 빠르게 훑을 때
feroxbuster -u http://<target> -w /usr/share/wordlists/dirb/common.txt -d 2 --collect-backups
```

---

## 4. Remmina — 원격 데스크톱 클라이언트

**💡 한 줄 비유**: 타깃 윈도우 서버의 열쇠(자격증명)를 얻었을 때, **복잡한 명령줄 옵션 씨름 없이 내 칼리 리눅스 폴더를 원격 서버에 외장하드처럼 꽂아 넣으며 편하게 조작하는 종합 원격 제어판**입니다.

### 왜 알아두어야 하는가?
- OSCP나 실무 AD 침투에서 윈도우 자격증명을 확보한 뒤 RDP(3389)나 VNC(5900)로 붙어야 할 때가 많습니다. 특히 타깃 내부에서만 접근 가능한 내부 웹 브라우저, 관리 콘솔(MMC), 또는 GUI 전용 애플리케이션을 건드려야 할 때 필수입니다.
- `xfreerdp`도 훌륭하지만, Remmina는 **연결 프로필 저장, 창 크기에 맞춘 동적 해상도 변경, 양방향 클립보드 복사/붙여넣기, 그리고 로컬 칼리 폴더를 윈도우 네트워크 드라이브로 마운트(파일 전송)**하는 설정이 UI 체크박스 하나로 끝나 실수가 없습니다.

### 설치 및 실전 활용 팁
```bash
# 칼리 리눅스에 기본 포함되어 있으며, 없을 경우 설치:
sudo apt update && sudo apt install -y remmina remmina-plugin-rdp remmina-plugin-vnc
```

### 시험장 Remmina 활용 3대 체크 포인트
1. **폴더 공유로 도구 반입 (`Share folder`)**: 새 연결 프로필을 만들 때 `Basic` 탭 하단의 **`Share folder`**를 켜고 칼리의 `/home/kali/tools` 폴더를 지정하면, 윈도우 탐색기 `내 PC` 안에 공유 드라이브가 바로 생겨 `PrintSpoofer.exe`, `SharpHound.exe`, `Mimikatz` 등을 `certutil`이나 웹 서버 없이 바로 실행·복사할 수 있습니다.
2. **TLS 보안 협상 실패 시 (`Security protocol negotiation`)**: 구형 윈도우 서버에 RDP가 안 붙을 때는 프로필 설정의 **`Security protocol negotiation`**을 `Automatic`에서 **`RDP` 또는 `TLS`/`NLA`**로 바꿔가며 테스트합니다.
3. **(보너스) 패스워드 대신 NTLM 해시로 RDP 붙기 (Restricted Admin Mode)**: Remmina는 평문 패스워드 중심이므로, 만약 크랙되지 않은 NTLM 해시로만 RDP를 뚫어야 한다면 그때는 `xfreerdp /v:<target> /u:<user> /pth:<ntlm-hash> /cert:ignore`를 병행하면 완벽합니다.

---

## 참고
- [Penelope 공식 GitHub (brightio)](https://github.com/brightio/penelope)
- [Name-That-Hash 공식 GitHub (HashPals)](https://github.com/HashPals/Name-That-Hash)
- [Feroxbuster 공식 문서 (epi052)](https://epi052.github.io/feroxbuster-docs/)
- [Remmina 공식 사이트](https://remmina.org/)
- 획득한 머신 권한과 캡처를 감점 없이 보고서로 완성하는 방법은 [[SysReptor로 OSCP 리포트 작성하기]] 글을 이어서 참고하세요.
