import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"

const ShieldIcon = () => (
  <svg
    class="security-badge-icon"
    width="15"
    height="15"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="2"
    stroke-linecap="round"
    stroke-linejoin="round"
  >
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
)

const SecurityIssuesLink: QuartzComponent = ({ displayClass }: QuartzComponentProps) => {
  return (
    <a
      href="/security-issues/"
      data-router-ignore
      class={classNames(displayClass, "security-badge-btn")}
    >
      <ShieldIcon />
      <span class="security-badge-label">보안 이슈 · ATT&amp;CK 정리</span>
      <span class="security-badge-arrow">↗</span>
    </a>
  )
}

SecurityIssuesLink.css = `
a.security-badge-btn,
a.security-badge-btn.internal {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin: 0.75rem 0 1.25rem 0;
  padding: 0.5rem 0.75rem !important;
  border-radius: 7px;
  border: 1px solid rgba(56, 189, 248, 0.25);
  background: linear-gradient(135deg, var(--highlight) 0%, transparent 100%) !important;
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
  color: var(--secondary) !important;
  font-size: 0.85rem;
  font-weight: 600;
  text-decoration: none;
  line-height: 1.3;
  transition: all 0.2s ease;
}

a.security-badge-btn .security-badge-icon {
  flex-shrink: 0;
  color: rgb(56, 189, 248);
  opacity: 0.9;
  transition: all 0.2s ease;
}

a.security-badge-btn .security-badge-label {
  flex: 1 1 auto;
}

a.security-badge-btn .security-badge-arrow {
  flex-shrink: 0;
  opacity: 0.6;
  font-size: 0.8rem;
  transition: transform 0.2s ease;
}

a.security-badge-btn:hover,
a.security-badge-btn.internal:hover {
  border-color: rgba(56, 189, 248, 0.6);
  color: rgb(56, 189, 248) !important;
  background: linear-gradient(135deg, rgba(56, 189, 248, 0.12) 0%, transparent 100%) !important;
  box-shadow: 0 2px 12px rgba(56, 189, 248, 0.25);
  transform: translateY(-1px);
}

a.security-badge-btn:hover .security-badge-icon {
  color: rgb(56, 189, 248);
  opacity: 1;
}

a.security-badge-btn:hover .security-badge-arrow {
  transform: translate(1px, -1px);
}
`

export default (() => SecurityIssuesLink) satisfies QuartzComponentConstructor
