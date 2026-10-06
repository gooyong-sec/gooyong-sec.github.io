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
  display: block;
  margin: 0.5rem 0 1rem 0;
  padding: 0.3rem 0 0.3rem 0.6rem !important;
  background: none !important;
  border: none;
  border-left: 3px solid #1e40af;
  color: #1e40af !important;
  font-size: 0.95rem;
  font-weight: 700;
  text-decoration: none;
  line-height: 1.3;
}

html[saved-theme="dark"] a.security-issues-link,
html[saved-theme="dark"] a.security-issues-link.internal {
  border-left-color: #60a5fa;
  color: #60a5fa !important;
}

a.security-issues-link:hover,
a.security-issues-link.internal:hover {
  color: var(--secondary) !important;
  border-left-color: var(--secondary);
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
