import { FileTrieNode } from "./util/fileTrie"

export type LearningOrderItem = Pick<FileTrieNode, "displayName" | "isFolder">

// Keep every dependency inside this function: Explorer serializes it with toString().
export const learningOrderSort = (a: LearningOrderItem, b: LearningOrderItem) => {
  const folderOrder = [
    "모의해킹 기초",
    "웹취약점",
    "시큐어코딩",
    "모바일취약점",
    "클라우드인프라",
    "OSCP",
    "LLM",
    "도구",
  ]

  const fileOrder = [
    // 0. 모의해킹 기초 (IT 기초 3부작 → 핵심 용어집 → 역할·범위·방법론 → 서비스 열거·피벗팅·OS 권한상승 → 리포트 작성)
    "모의해킹 전에 알아야 할 IT 기초 — 클라이언트-서버, IP·포트, HTTP",
    "모의해킹 전에 알아야 할 IT 기초 — 운영체제, 파일과 권한, 터미널",
    "모의해킹 전에 알아야 할 IT 기초 — 인증과 인가, 세션과 토큰",
    "모의해킹 핵심 용어집",
    "모의해킹 vs 레드팀 vs 퍼플팀",
    "스코프와 교전규칙(RoE)",
    "모의해킹 방법론 총정리",
    "체계적 서비스 열거 플레이북",
    "펜테스터를 위한 네트워크 피벗팅과 터널링",
    "Linux 권한상승을 위한 OS 내부구조",
    "Windows 권한상승을 위한 OS 내부구조",
    "모의해킹 리포트 작성법",
    // 1. 웹취약점 — Java 웹 아키텍처 선수지식 (요청 흐름 → 실행 모델 → 화면 → 보안 경계 → 프레임워크)
    "Java 웹 기초 1",
    "Java 웹 기초 2",
    "Java 웹 기초 3",
    "Java 웹 기초 4",
    "Java 웹 기초 5",
    // 1. 웹취약점 — 취약점 진단 본편 (입문·XSS 페이로드 → 정찰·API9 → 설정 → 인증·SSO → 인가·BOPLA → 로직·API6·API4 → 웹훅·WebSocket → 심화·인프라·공급망)
    "웹 취약점 진단 기법 입문",
    "웹 취약점 진단 — XSS 페이로드별 사용처와 목적",
    "웹 취약점 진단 정찰편",
    "웹 취약점 진단 — 레거시·섀도우 API 자산 인벤토리(API9)",
    "웹 취약점 진단 설정편",
    "웹 취약점 진단 인증편",
    "웹 취약점 진단 SSO편",
    "웹 취약점 진단 인가편",
    "웹 취약점 진단 API편 — Mass Assignment와 필드 단위 인가(BOPLA)",
    "웹 취약점 진단 로직편",
    "웹 취약점 진단 — 비즈니스 플로우 남용과 봇 방어 우회(API6)",
    "웹 취약점 진단 — API 자원 소비 진단(Unrestricted Resource Consumption, API4)",
    "웹 취약점 진단 — 서드파티 연동·웹훅 신뢰 공격(API7·API10)",
    "웹 취약점 진단 — WebSocket·실시간 통신 보안",
    "웹 취약점 진단 심화",
    "웹 취약점 진단 인프라편",
    "웹 취약점 진단 — 공급망·의존성 보안(SCA와 악성 패키지)",
    // 2. 시큐어코딩
    "Java Properties 파일 AES 암호화",
    // 3. 모바일취약점 (입문·MASVS → 정적분석·API 추출 → 로컬 포렌식 → IPC·딥링크·WebView → Frida 동적분석·기기 신뢰 → OAuth/PKCE·토큰 바인딩)
    "모바일 모의해킹 입문",
    "모바일 취약점 진단 — 안드로이드 정적분석",
    "모바일 취약점 진단 — iOS 정적분석",
    "모바일 취약점 진단 — 앱 바이너리에서 API 계약 추출하기",
    "모바일 취약점 진단 — 로컬 저장소 포렌식",
    "모바일 취약점 진단 — 안드로이드 IPC 공격면",
    "모바일 취약점 진단 — 딥링크·앱링크 공격표면",
    "모바일 취약점 진단 — WebView와 파일 접근 취약점",
    "모바일 취약점 진단 — Frida 동적분석과 네트워크",
    "모바일 취약점 진단 — 기기 신뢰 공격(Device Attestation 우회)",
    "모바일 취약점 진단 — OAuth·PKCE 네이티브 플로우 공격",
    "모바일 취약점 진단 — 백엔드 API 토큰 갱신과 디바이스 바인딩",
    // 4. 클라우드인프라 (IaC 사전 스캔 → IAM 권한상승 → IMDS 자격증명 탈취 → S3 데이터 유출 → K8s 탈출)
    "클라우드 인프라 진단 — IaC 보안 스캐닝(Terraform·K8s manifest)",
    "클라우드 인프라 진단 — AWS IAM 권한상승 체인",
    "클라우드 인프라 진단 — IMDS SSRF로 자격증명 탈취",
    "클라우드 인프라 진단 — S3·스토리지 오남용과 데이터 유출 체인",
    "클라우드 인프라 진단 — 컨테이너·Kubernetes 탈출",
    // 5. OSCP (시험 전 추천 도구 준비 → AD 아키텍처 기초 → AD 자격증명 피벗·권한상승 → Kerberos 위임 체인 → SysReptor 리포트 작성)
    "OSCP 추천 도구",
    "공격 체인 이전의 AD 아키텍처 기초",
    "윈도우 AD 침투",
    "AD 환경 Kerberos 체인 공격",
    "SysReptor로 OSCP 리포트 작성하기",
    // 6. LLM (개념 입문 → OWASP Top 10 → 14개 취약점 진단 → PortSwigger 랩 실습 → 클라우드 공격 경로 → CVE·PoC 카탈로그 → 학습 자료실)
    "LLM 입문",
    "OWASP Top 10 for LLM",
    "LLM 애플리케이션 모의해킹",
    "PortSwigger Web LLM Attacks",
    "LLM 서비스와 클라우드 공격 경로",
    "LLM·AI 서비스 CVE",
    "보안 진단 학습 자료실",
    // 7. 도구 (진단 툴 MCP 연동 → Rea 역공학 → Hera 동적분석 제작 → Claude×Codex 교차검증 → Gemini CLI 개발·보안감사 → 트래커 빌드 → 블로그 인프라 자동화)
    "취약점 진단 툴에 MCP 붙이기",
    "Rea 써봤다",
    "Hera — Frida 기반 동적 보안 분석 워크벤치를 직접 만들다",
    "Claude 작업을 Codex로 교차검증하기",
    "AI한테 윈도우용 프로그램 개발을 통째로 맡겨보았다",
    "보안이슈 트래커 빌드 후기",
    "블로그 인프라 자동화",
  ]

  if (a.isFolder && b.isFolder) {
    const aFolder = a.displayName.replace(/-/g, " ")
    const bFolder = b.displayName.replace(/-/g, " ")
    const ai = folderOrder.findIndex((prefix) => aFolder.startsWith(prefix))
    const bi = folderOrder.findIndex((prefix) => bFolder.startsWith(prefix))
    const diff = (ai === -1 ? folderOrder.length : ai) - (bi === -1 ? folderOrder.length : bi)
    if (diff !== 0) return diff
  } else if (!a.isFolder && !b.isFolder) {
    const ai = fileOrder.findIndex((prefix) => a.displayName.startsWith(prefix))
    const bi = fileOrder.findIndex((prefix) => b.displayName.startsWith(prefix))
    const diff = (ai === -1 ? fileOrder.length : ai) - (bi === -1 ? fileOrder.length : bi)
    if (diff !== 0) return diff
  } else {
    return a.isFolder ? -1 : 1
  }

  return a.displayName.localeCompare(b.displayName, undefined, {
    numeric: true,
    sensitivity: "base",
  })
}
