---
title: "윈도우 AD 침투: 자격증명 피벗·권한상승 3가지 기법"
tags:
  - OSCP
  - ActiveDirectory
  - 권한상승
  - 침투테스트
---

윈도우 액티브 디렉터리(AD) 환경 침투의 핵심은 한 문장으로 줄어듭니다. "이 호스트에서 주운 자격증명이 다음 호스트의 열쇠다." 화려한 익스플로잇보다, 자격증명을 모으고(harvest) 재사용해 옆으로 번지는(pivot) 흐름이 실전에서 훨씬 자주 통합니다.

여기서는 그 흐름에 자주 등장하는 보편 기법 3가지를 정리합니다. 셋 다 공개 자료에 이미 널린 기술이고, 아래 명령은 전부 플레이스홀더(`<target>`, `<user>`)로 일반화했습니다. 모든 기법은 본인 소유 랩이나 명시적으로 인가된 시스템에서만 재현하세요.

---

## 1. LSASS 메모리에서 자격증명 덤프 → 피벗

윈도우의 `lsass.exe`(Local Security Authority Subsystem)는 로그인 세션의 자격증명(NTLM 해시, 때로는 평문, 커버로스 티켓)을 메모리에 들고 있습니다. 어떤 호스트에 로컬 관리자 권한을 얻으면, LSASS 메모리를 덤프해 그 머신에 로그인했던 다른 계정의 자격증명을 주울 수 있습니다. 이게 다음 타깃으로 넘어가는 피벗의 출발점이에요.

[netexec(nxc)](https://www.netexec.wiki/)의 `lsassy` 모듈이면 원격에서 한 줄로 됩니다.

```bash
# 로컬 관리자 권한이 있는 계정으로 원격 호스트의 LSASS를 덤프·파싱
nxc smb <target> -u <admin_user> -p <password> -M lsassy
```

출력으로 그 호스트에 캐시된 다른 계정(서비스 계정 등)의 해시나 평문이 떨어지면, 그대로 다음 호스트 인증에 재사용합니다. 다만 로컬 관리자 권한이 이미 있어야 되는 후속 동작이고, LSASS 접근은 EDR이 가장 민감하게 보는 행위 중 하나라 탐지·차단되기 쉽습니다.

방어는 Credential Guard로 LSASS 비밀을 가상화 격리하고, `RunAsPPL`(LSA Protection)로 LSASS를 보호 프로세스화하고, 로컬 관리자 권한을 최소화하고, EDR로 LSASS 핸들 접근을 모니터링하는 것입니다.

## 2. 애플리케이션이 DB에 평문 자격증명을 저장

개발 편의용 스택(대표적으로 XAMPP)이 운영 서버에 그대로 남아 있는 경우가 많습니다. XAMPP의 MySQL은 root 계정이 비밀번호 없이 돌아가는 기본 상태가 흔하고, 애플리케이션이 사용자 비밀번호를 평문으로 `creds`/`users` 테이블에 저장해 두기도 합니다. 로컬 셸만 있으면 DB를 통째로 덤프해 관리자나 다른 사용자 자격증명을 회수할 수 있습니다.

```bash
# (윈도우 타깃 셸에서) 무인증 root로 전체 DB 덤프
C:\xampp\mysql\bin\mysqldump.exe --all-databases -u root > dump.sql
```

덤프한 `dump.sql`에서 평문 자격증명을 찾아 로컬 administrator나 다른 사용자로 재사용하면 또 한 단계 피벗할 수 있습니다. 침투 후에는 `C:\xampp`, `C:\wamp`, `inetpub`, 웹 루트의 설정 파일(`config.php`, `.env`, `web.config`), 로컬에서 열려 있는 DB 포트(MySQL 3306 등)를 먼저 확인하는 게 좋습니다. 개발 잔재가 평문 비밀의 보고인 경우가 많거든요.

방어는 DB에 평문 자격증명을 저장하지 않고(솔트 적용 해싱), MySQL root 비밀번호를 설정하고 로컬로 바인딩하고, 서비스는 최소 권한 계정으로 실행하고, 개발용 스택을 운영에 배포하지 않는 것입니다.

## 3. SeImpersonatePrivilege → PrintSpoofer로 SYSTEM 상승

웹·DB 같은 서비스 계정은 종종 `SeImpersonatePrivilege`(다른 토큰을 가장할 수 있는 권한)를 갖고 있습니다. 이 권한이 있으면 PrintSpoofer나 Potato 계열 도구로 `NT AUTHORITY\SYSTEM` 토큰을 가장해 로컬 최고 권한까지 상승할 수 있습니다. OSCP·실무에서 가장 자주 보는 윈도우 로컬 권한상승 패턴 중 하나예요.

```powershell
# 1) 현재 계정 권한 확인 — SeImpersonatePrivilege 가 Enabled 인지
whoami /priv

# 2) PrintSpoofer 로 SYSTEM 컨텍스트에서 명령 실행
.\PrintSpoofer64.exe -c "<SYSTEM 권한으로 실행할 명령>"
```

`whoami /priv` 결과에 `SeImpersonatePrivilege`가 보이면 거의 성공 신호입니다. IIS/Apache/MSSQL 같은 서비스 계정(`iis apppool\...`, `mssql$...` 등)으로 셸을 잡았을 때 특히 자주 충족되고, 일반 사용자 계정에는 보통 없습니다.

방어는 불필요한 계정·서비스에서 `SeImpersonatePrivilege`를 회수하고, 최신 OS 패치를 적용하고, 서비스 계정을 gMSA 등으로 관리하며 권한을 최소화하는 것입니다.

---

## 세 기법은 어떻게 이어지나

따로 보면 단편 기술이지만, AD 세트에서는 체인으로 엮입니다.

```
초기 발판(가정된 침해/약한 자격증명)
        │
        ▼
[1] 호스트 A 장악 → LSASS 덤프로 서비스 계정 자격증명 회수
        │  (자격증명 재사용)
        ▼
[2] 호스트 B 접근 → 남아있는 XAMPP MySQL 덤프로 관리자/다른 사용자 평문 회수
        │  (자격증명 재사용)
        ▼
[3] 호스트 C(DC 등) 접근 → SeImpersonate + PrintSpoofer 로 SYSTEM 상승
```

핵심은 자격증명을 줍고 재사용하는 흐름의 반복입니다. 익스플로잇 하나하나보다 이 수집·재사용 루프를 몸에 익히는 게 AD 침투의 본질이에요.

AD 침투는 자격증명 피벗 게임입니다. LSASS 덤프(메모리 속 자격증명), 앱이 흘린 평문 자격증명(XAMPP MySQL 등 개발 잔재), SeImpersonate→PrintSpoofer(서비스 계정의 SYSTEM 상승) 세 가지가 반복해서 쓰이고, 방어는 공통적으로 자격증명을 평문·메모리에 남기지 말고 권한을 최소로 좁히는 것입니다.

이 글은 공개 자료에 보편적으로 존재하는 일반 기법을, 특정 머신·자격증명·플래그 없이 추상화해 정리한 것입니다. 특정 코스/챌린지의 풀이 원문은 해당 제공자의 정책에 따라 비공개로 보관하세요.

## 참고

- [NetExec(nxc) 공식 위키](https://www.netexec.wiki/)
- [PrintSpoofer (itm4n)](https://github.com/itm4n/PrintSpoofer)
- [lsassy (Hackndo)](https://github.com/Hackndo/lsassy)
