import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"

const SecurityIssuesLink: QuartzComponent = ({ displayClass }: QuartzComponentProps) => {
  return (
    <a
      href="/security-issues/"
      data-router-ignore
      class={classNames(displayClass, "security-issues-link")}
    >
      보안 이슈 · ATT&amp;CK 정리
    </a>
  )
}

SecurityIssuesLink.css = `
a.security-issues-link,
a.security-issues-link.internal {
  display: inline-block;
  margin: 0.25rem 0 1rem 0;
  padding: 0 !important;
  background: none !important;
  border: none;
  color: var(--gray) !important;
  font-size: 0.8rem;
  font-weight: 600;
  text-decoration: underline;
  text-decoration-color: var(--lightgray);
  text-underline-offset: 3px;
}

a.security-issues-link:hover,
a.security-issues-link.internal:hover {
  color: var(--tertiary) !important;
  text-decoration-color: var(--tertiary);
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
