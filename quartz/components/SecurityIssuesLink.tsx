import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"

const SecurityIssuesLink: QuartzComponent = ({ displayClass }: QuartzComponentProps) => {
  return (
    <a
      href="/security-issues/"
      data-router-ignore
      class={classNames(displayClass, "security-issues-link")}
    >
      🛡️ 보안 이슈 · ATT&CK 정리
    </a>
  )
}

SecurityIssuesLink.css = `
.security-issues-link {
  display: block;
  margin: 0.5rem 0 1rem 0;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  background: var(--highlight);
  color: var(--secondary);
  font-size: 0.85rem;
  font-weight: 600;
  text-decoration: none;
  text-align: center;
  transition: background 0.2s ease, color 0.2s ease;
}
.security-issues-link:hover {
  background: var(--tertiary);
  color: var(--light);
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
