import { PageLayout, SharedLayout } from "./quartz/cfg"
import * as Component from "./quartz/components"
import { FileTrieNode } from "./quartz/util/fileTrie"

// 탐색기 정렬: 폴더는 아래 순서대로, 각 폴더 안의 글은 지정된 제목 접두사 순서대로
// (목록에 없는 폴더/글은 기존처럼 알파벳순으로 뒤에 붙는다)
//
// 주의: Explorer 컴포넌트는 이 함수를 .toString()으로 직렬화해 브라우저에서
// `new Function("return " + str)()`로 다시 만든다 — 바깥 스코프(클로저)를 전혀
// 가져가지 못하므로, 참조하는 배열·헬퍼는 전부 함수 "안에" 정의해야 한다.
const explorerSortFn = (a: FileTrieNode, b: FileTrieNode) => {
  const folderOrder = ["모의해킹 기초", "웹취약점", "시큐어코딩", "모바일취약점", "클라우드인프라", "OSCP", "LLM", "도구"]

  const fileOrder = [
    // 모의해킹 기초 (역할 이해 → 범위 합의 → 방법론 → 열거·피벗팅 → OS 내부구조 → 보고)
    "모의해킹 vs 레드팀 vs 퍼플팀",
    "스코프와 교전규칙(RoE)",
    "모의해킹 방법론 총정리",
    "체계적 서비스 열거 플레이북",
    "펜테스터를 위한 네트워크 피벗팅과 터널링",
    "Linux 권한상승을 위한 OS 내부구조",
    "Windows 권한상승을 위한 OS 내부구조",
    "모의해킹 리포트 작성법",
    // Java 웹 선수지식 (요청 흐름 → 실행 모델 → 화면 → 보안 경계 → 프레임워크)
    "Java 웹 기초 1",
    "Java 웹 기초 2",
    "Java 웹 기초 3",
    "Java 웹 기초 4",
    "Java 웹 기초 5",
    // 웹취약점 시리즈 (읽는 순서)
    "웹 취약점 진단 기법 입문",
    "웹 취약점 진단 정찰편",
    "웹 취약점 진단 설정편",
    "웹 취약점 진단 인증편",
    "웹 취약점 진단 인가편",
    "웹 취약점 진단 로직편",
    "웹 취약점 진단 SSO편",
    "웹 취약점 진단 API편 — Mass Assignment와 필드 단위 인가(BOPLA)",
    "웹 취약점 진단 — API 자원 소비 진단(Unrestricted Resource Consumption, API4)",
    "웹 취약점 진단 — 비즈니스 플로우 남용과 봇 방어 우회(API6)",
    "웹 취약점 진단 — 서드파티 연동·웹훅 신뢰 공격(API7·API10)",
    "웹 취약점 진단 — 레거시·섀도우 API 자산 인벤토리(API9)",
    "웹 취약점 진단 — WebSocket·실시간 통신 보안",
    "웹 취약점 진단 — XSS 페이로드별 사용처와 목적",
    "웹 취약점 진단 심화",
    "웹 취약점 진단 인프라편",
    "웹 취약점 진단 — 공급망·의존성 보안(SCA와 악성 패키지)",
    // 모바일취약점 시리즈 (읽는 순서)
    "모바일 모의해킹 입문",
    "모바일 취약점 진단 — 안드로이드 정적분석",
    "모바일 취약점 진단 — iOS 정적분석",
    "모바일 취약점 진단 — 앱 바이너리에서 API 계약 추출하기",
    "모바일 취약점 진단 — Frida 동적분석과 네트워크",
    "모바일 취약점 진단 — 로컬 저장소 포렌식",
    "모바일 취약점 진단 — 안드로이드 IPC 공격면",
    "모바일 취약점 진단 — WebView와 파일 접근 취약점",
    "모바일 취약점 진단 — 딥링크·앱링크 공격표면",
    "모바일 취약점 진단 — OAuth·PKCE 네이티브 플로우 공격",
    "모바일 취약점 진단 — 백엔드 API 토큰 갱신과 디바이스 바인딩",
    "모바일 취약점 진단 — 기기 신뢰 공격(Device Attestation 우회)",
    // 클라우드인프라 시리즈 (읽는 순서)
    "클라우드 인프라 진단 — IaC 보안 스캐닝(Terraform·K8s manifest)",
    "클라우드 인프라 진단 — AWS IAM 권한상승 체인",
    "클라우드 인프라 진단 — S3·스토리지 오남용과 데이터 유출 체인",
    "클라우드 인프라 진단 — IMDS SSRF로 자격증명 탈취",
    "클라우드 인프라 진단 — 컨테이너·Kubernetes 탈출",
    // LLM (개념 입문 → 학습 자료 → 심화 → 실습 → 카탈로그)
    "LLM 입문",
    "보안 진단 학습 자료실",
    "OWASP Top 10 for LLM",
    "LLM 애플리케이션 모의해킹",
    "PortSwigger Web LLM Attacks",
    "LLM 서비스와 클라우드 공격 경로",
    "LLM·AI 서비스 CVE",
    // OSCP (기초 구조 → 도구 → 공격 체인 → 보고)
    "공격 체인 이전의 AD 아키텍처 기초",
    "OSCP 추천 도구",
    "윈도우 AD 침투",
    "AD 환경 Kerberos 체인 공격",
    "SysReptor로 OSCP 리포트 작성하기",
    // 시큐어코딩
    "Java Properties 파일 AES 암호화",
    // 도구 (일반 AI 활용 → 보안 도구 연동 → 제작 사례 → 운영 자동화)
    "AI한테 윈도우용 프로그램 개발을 통째로 맡겨보았다",
    "Claude 작업을 Codex로 교차검증하기",
    "취약점 진단 툴에 MCP 붙이기",
    "Rea 써봤다",
    "Hera — Frida 기반 동적 보안 분석 워크벤치를 직접 만들다",
    "보안이슈 트래커 빌드 후기",
    "블로그 인프라 자동화",
  ]

  // 주의 2: 이 안에서 `const foo = (..) => {}` 같은 이름 있는 헬퍼를 또 만들면,
  // esbuild가 디버깅용으로 `__name(..., "foo")`로 감싸버린다. `__name`은 번들
  // 전역 헬퍼라 격리 실행 시 ReferenceError가 나므로, 헬퍼 없이 전부 인라인한다.
  if (a.isFolder && b.isFolder) {
    const ai = folderOrder.findIndex((p) => a.displayName.startsWith(p))
    const bi = folderOrder.findIndex((p) => b.displayName.startsWith(p))
    const diff = (ai === -1 ? folderOrder.length : ai) - (bi === -1 ? folderOrder.length : bi)
    if (diff !== 0) return diff
    return a.displayName.localeCompare(b.displayName, undefined, { numeric: true, sensitivity: "base" })
  }
  if (!a.isFolder && !b.isFolder) {
    const ai = fileOrder.findIndex((p) => a.displayName.startsWith(p))
    const bi = fileOrder.findIndex((p) => b.displayName.startsWith(p))
    const diff = (ai === -1 ? fileOrder.length : ai) - (bi === -1 ? fileOrder.length : bi)
    if (diff !== 0) return diff
    return a.displayName.localeCompare(b.displayName, undefined, { numeric: true, sensitivity: "base" })
  }
  return a.isFolder ? -1 : 1
}

// components shared across all pages
export const sharedPageComponents: SharedLayout = {
  head: Component.Head(),
  header: [],
  afterBody: [
    Component.PageNavigation(),
    Component.ConditionalRender({
      component: Component.RecentNotes({
        title: "최근 글",
        limit: 5,
        showTags: false,
        filter: (page) => page.slug !== "index",
      }),
      condition: (page) => page.fileData.slug === "index",
    }),
  ],
  footer: Component.Footer({
    links: {
      GitHub: "https://github.com/jackyzha0/quartz",
      "Discord Community": "https://discord.gg/cRFFHYye7t",
    },
  }),
}

// components for pages that display a single page (e.g. a single note)
export const defaultContentPageLayout: PageLayout = {
  beforeBody: [
    Component.ConditionalRender({
      component: Component.Breadcrumbs(),
      condition: (page) => page.fileData.slug !== "index",
    }),
    Component.ArticleTitle(),
    Component.ContentMeta(),
    Component.TagList(),
    Component.MobileOnly(Component.TableOfContents({ layout: "legacy", defaultOpen: false })),
  ],
  left: [
    Component.PageTitle(),
    Component.SecurityIssuesLink(),
    Component.CvePocLink(),
    Component.MobileOnly(Component.Spacer()),
    Component.Flex({
      components: [
        {
          Component: Component.Search(),
          grow: true,
        },
        { Component: Component.Darkmode() },
        { Component: Component.ReaderMode() },
      ],
    }),
    Component.Explorer({ sortFn: explorerSortFn }),
  ],
  right: [
    Component.DesktopOnly(Component.TableOfContents()),
    Component.Graph(),
    Component.Backlinks(),
  ],
}

// components for pages that display lists of pages  (e.g. tags or folders)
export const defaultListPageLayout: PageLayout = {
  beforeBody: [Component.Breadcrumbs(), Component.ArticleTitle(), Component.ContentMeta()],
  left: [
    Component.PageTitle(),
    Component.SecurityIssuesLink(),
    Component.CvePocLink(),
    Component.MobileOnly(Component.Spacer()),
    Component.Flex({
      components: [
        {
          Component: Component.Search(),
          grow: true,
        },
        { Component: Component.Darkmode() },
      ],
    }),
    Component.Explorer({ sortFn: explorerSortFn }),
  ],
  right: [],
}
