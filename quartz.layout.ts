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
  const folderOrder = ["웹취약점", "모바일취약점", "LLM", "OSCP", "도구", "시큐어코딩"]

  const fileOrder = [
    // 웹취약점 시리즈 (읽는 순서)
    "웹 취약점 진단 기법 입문",
    "웹 취약점 진단 심화",
    "웹 취약점 진단 설정편",
    "웹 취약점 진단 정찰편",
    "웹 취약점 진단 인증편",
    "웹 취약점 진단 인가편",
    "웹 취약점 진단 SSO편",
    "웹 취약점 진단 로직편",
    "웹 취약점 진단 인프라편",
    // 모바일취약점 시리즈 (읽는 순서)
    "모바일 모의해킹 입문",
    "모바일 취약점 진단 — 안드로이드 정적분석",
    "모바일 취약점 진단 — iOS 정적분석",
    "모바일 취약점 진단 — Frida 동적분석과 네트워크",
    "모바일 취약점 진단 — 로컬 저장소 포렌식",
    "모바일 취약점 진단 — 안드로이드 IPC 공격면",
    "모바일 취약점 진단 — WebView와 파일 접근 취약점",
    // LLM (개념 입문 → 학습 자료 → 심화 → 실습 → 카탈로그)
    "LLM 입문",
    "보안 진단 학습 자료실",
    "OWASP Top 10 for LLM",
    "LLM 애플리케이션 모의해킹",
    "PortSwigger Web LLM Attacks",
    "LLM 서비스와 클라우드 공격 경로",
    "LLM·AI 서비스 CVE",
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
  afterBody: [],
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
    Component.Graph(),
    Component.DesktopOnly(Component.TableOfContents()),
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
