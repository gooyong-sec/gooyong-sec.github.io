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
a.security-issues-link,
a.security-issues-link.internal {
  display: block;
  margin: 0.75rem 0 1.25rem 0;
  padding: 0.65rem 1rem !important;
  border-radius: 8px;
  background: var(--tertiary) !important;
  background-color: var(--tertiary) !important;
  color: var(--light) !important;
  font-size: 1rem;
  font-weight: 700;
  text-decoration: none;
  text-align: center;
  line-height: 1.4;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15);
  transition: filter 0.2s ease, transform 0.1s ease;
}
a.security-issues-link:hover,
a.security-issues-link.internal:hover {
  filter: brightness(1.1);
  transform: translateY(-1px);
  color: var(--light) !important;
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
