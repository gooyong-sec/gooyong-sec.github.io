import { learningOrderSort } from "../learningOrder"
import { resolveRelative, simplifySlug } from "../util/path"
import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import style from "./styles/pageNavigation.scss"

const PageNavigation: QuartzComponent = ({ fileData, allFiles }: QuartzComponentProps) => {
  const currentSlug = fileData.slug ? simplifySlug(fileData.slug) : undefined
  if (!currentSlug || currentSlug === "index") return null

  const pages = allFiles
    .filter((page) => page.slug && page.frontmatter?.title && page.slug !== "index")
    .sort((a, b) => {
      const aSlug = simplifySlug(a.slug!)
      const bSlug = simplifySlug(b.slug!)
      const folderDiff = learningOrderSort(
        { displayName: aSlug.split("/")[0], isFolder: true },
        { displayName: bSlug.split("/")[0], isFolder: true },
      )
      if (folderDiff !== 0) return folderDiff

      const titleDiff = learningOrderSort(
        { displayName: a.frontmatter!.title!, isFolder: false },
        { displayName: b.frontmatter!.title!, isFolder: false },
      )
      if (titleDiff !== 0) return titleDiff
      return aSlug.localeCompare(bSlug, undefined, { numeric: true, sensitivity: "base" })
    })

  const currentIndex = pages.findIndex((page) => simplifySlug(page.slug!) === currentSlug)
  if (currentIndex === -1) return null

  const previous = pages[currentIndex - 1]
  const next = pages[currentIndex + 1]
  if (!previous && !next) return null

  return (
    <nav class="page-navigation" aria-label="글 탐색">
      {previous && (
        <a
          class="page-navigation-link previous internal"
          href={resolveRelative(fileData.slug!, previous.slug!)}
          aria-label={`이전 글: ${previous.frontmatter!.title}`}
        >
          <span class="page-navigation-direction">← 이전 글</span>
          <span>{previous.frontmatter!.title}</span>
        </a>
      )}
      {next && (
        <a
          class="page-navigation-link next internal"
          href={resolveRelative(fileData.slug!, next.slug!)}
          aria-label={`다음 글: ${next.frontmatter!.title}`}
        >
          <span class="page-navigation-direction">다음 글 →</span>
          <span>{next.frontmatter!.title}</span>
        </a>
      )}
    </nav>
  )
}

PageNavigation.css = style

export default (() => PageNavigation) satisfies QuartzComponentConstructor
