import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"

const SecurityIssuesLink: QuartzComponent = ({ displayClass }: QuartzComponentProps) => {
  return (
    <a
      href="/security-issues/"
      data-router-ignore
      class={classNames(displayClass, "security-issues-link")}
    >
      보안 이슈 · ATT&CK 정리 ↗
    </a>
  )
}

SecurityIssuesLink.css = `
a.security-issues-link,
a.security-issues-link.internal {
  display: block;
  margin: 0.75rem 0 1.25rem 0;
  padding: 0.5rem 0.75rem !important;
  border-radius: 5px;
  border: 1px solid var(--tertiary);
  background: transparent !important;
  background-color: transparent !important;
  color: var(--secondary) !important;
  font-size: 0.9rem;
  font-weight: 600;
  text-decoration: none;
  text-align: left;
  line-height: 1.4;
  transition: background-color 0.15s ease, color 0.15s ease;
}
a.security-issues-link:hover,
a.security-issues-link.internal:hover {
  background: var(--tertiary) !important;
  background-color: var(--tertiary) !important;
  color: var(--light) !important;
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
