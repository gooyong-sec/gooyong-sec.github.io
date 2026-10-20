import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"

const CvePocLink: QuartzComponent = ({ displayClass }: QuartzComponentProps) => {
  return (
    <a
      href="/CVE-PoC/"
      data-router-ignore
      class={classNames(displayClass, "cve-poc-link")}
    >
      CVE · PoC 트래커
    </a>
  )
}

CvePocLink.css = `
a.cve-poc-link,
a.cve-poc-link.internal {
  display: block;
  margin: 0 0 1rem 0;
  padding: 0.3rem 0 0.3rem 0.6rem !important;
  background: none !important;
  border: none;
  border-left: 3px solid #b45309;
  color: #b45309 !important;
  font-size: 0.95rem;
  font-weight: 700;
  text-decoration: none;
  line-height: 1.3;
}

html[saved-theme="dark"] a.cve-poc-link,
html[saved-theme="dark"] a.cve-poc-link.internal {
  border-left-color: #fbbf24;
  color: #fbbf24 !important;
}

a.cve-poc-link:hover,
a.cve-poc-link.internal:hover {
  color: var(--secondary) !important;
  border-left-color: var(--secondary);
}

@media (max-width: 800px) {
  a.cve-poc-link,
  a.cve-poc-link.internal {
    display: inline-block;
    margin: 0.3rem 0.2rem;
    padding: 0.2rem 0.55rem !important;
    border: 1px solid currentColor;
    border-radius: 999px;
    font-size: 0.78rem;
    white-space: nowrap;
    box-sizing: border-box;
    max-width: 100%;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
}
`

export default (() => CvePocLink) satisfies QuartzComponentConstructor
