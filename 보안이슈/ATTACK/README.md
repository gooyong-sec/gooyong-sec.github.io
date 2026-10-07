# MITRE ATT&CK 전술별 누적 정리

기준: **ATT&CK Enterprise v19.2**. v19에서 TA0005는 *Defense Evasion*에서 **Stealth**로 개칭됐고 **Defense Impairment(TA0112)** 가 신설됐다. 과거 자료와 전술명이 다를 수 있으니 기법 ID로 비교한다.

> 이 폴더의 `NN-*.md`와 이 파일은 `node build.mjs`가 생성한다. **원본은 `매핑.psv`** (사건-기법 매핑)와 `_catalog.psv`(공식 기법 목록)다. 쉬운 한국어 해설은 `기법해설.psv`·`전술해설.psv`.

| 파일 | 전술 | ID | 사례 있는 기법 / 공식 기법 |
|------|------|----|------|
| [01-정찰.md](01-정찰.md) | 정찰 (Reconnaissance) | TA0043 | 0 / 12 |
| [02-자원개발.md](02-자원개발.md) | 자원개발 (Resource Development) | TA0042 | 3 / 9 |
| [03-초기접근.md](03-초기접근.md) | 초기접근 (Initial Access) | TA0001 | 7 / 11 |
| [04-실행.md](04-실행.md) | 실행 (Execution) | TA0002 | 4 / 20 |
| [05-지속성.md](05-지속성.md) | 지속성 (Persistence) | TA0003 | 7 / 22 |
| [06-권한상승.md](06-권한상승.md) | 권한상승 (Privilege Escalation) | TA0004 | 1 / 13 |
| [07-스텔스.md](07-스텔스.md) | 스텔스 (Stealth (구 Defense Evasion)) | TA0005 | 4 / 30 |
| [08-방어약화.md](08-방어약화.md) | 방어약화 (Defense Impairment) | TA0112 | 1 / 18 |
| [09-자격증명접근.md](09-자격증명접근.md) | 자격증명접근 (Credential Access) | TA0006 | 12 / 17 |
| [10-탐색.md](10-탐색.md) | 탐색 (Discovery) | TA0007 | 0 / 34 |
| [11-횡적이동.md](11-횡적이동.md) | 횡적이동 (Lateral Movement) | TA0008 | 2 / 9 |
| [12-수집.md](12-수집.md) | 수집 (Collection) | TA0009 | 5 / 17 |
| [13-C2.md](13-C2.md) | C2 (Command and Control) | TA0011 | 6 / 18 |
| [14-유출.md](14-유출.md) | 유출 (Exfiltration) | TA0010 | 2 / 9 |
| [15-영향.md](15-영향.md) | 영향 (Impact) | TA0040 | 6 / 15 |

전체: 서로 다른 상위 기법 60개에서 사례가 관측됨 (공식 222개). 사건 51건, 매핑 168행.

근거 수준: **확인**(벤더·CISA·연구기관 직접 확인) / **추정**(공개 자료에 없어 분석상 추정) / **후보**(조건이 확인되면 적용). 공격자 일방 주장은 표에 넣지 않고 일일 보고서에만 적는다.

## 매일 갱신하는 법

1. `일일/YYYY-MM-DD.md`에 사건을 `### [D<날짜>-<이름>]` 제목과 `> 날짜: … · 유형: … · 행위자: … · 지역: … · 근거: …` 메타 줄로 쓴다.
2. `ATTACK/매핑.psv`에 `사건ID|전술|기법|근거|설명` 행을 추가한다.
3. `node build.mjs`를 실행하면 전술별 파일, 타임라인, `index.html`이 갱신된다.
