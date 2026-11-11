import { PageLayout, SharedLayout } from "./quartz/cfg"
import * as Component from "./quartz/components"
import { learningOrderSort } from "./quartz/learningOrder"

const explorerSortFn = learningOrderSort

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
