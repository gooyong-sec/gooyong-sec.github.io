function toggleToc(this: HTMLElement) {
  this.classList.toggle("collapsed")
  this.setAttribute(
    "aria-expanded",
    this.getAttribute("aria-expanded") === "true" ? "false" : "true",
  )
  const content = this.nextElementSibling as HTMLElement | undefined
  if (!content) return
  content.classList.toggle("collapsed")
}

function setupToc() {
  for (const toc of document.getElementsByClassName("toc")) {
    const button = toc.querySelector(".toc-header")
    const content = toc.querySelector(".toc-content")
    if (!button || !content) continue
    button.addEventListener("click", toggleToc)
    window.addCleanup(() => button.removeEventListener("click", toggleToc))
  }

  const links = Array.from(document.querySelectorAll<HTMLAnchorElement>(".toc-content a[data-for]"))
  const headings = links
    .map((link) => ({ link, heading: document.getElementById(link.dataset.for ?? "") }))
    .filter((entry): entry is { link: HTMLAnchorElement; heading: HTMLElement } =>
      entry.heading !== null,
    )

  let activeLink: HTMLAnchorElement | undefined
  const updateActiveHeading = () => {
    const readingLine = window.innerHeight * 0.25
    const scrollable = document.documentElement.scrollHeight > window.innerHeight + 2
    const atBottom =
      scrollable && window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2
    const current = atBottom
      ? headings.at(-1)
      : ([...headings].reverse().find(({ heading }) =>
          heading.getBoundingClientRect().top <= readingLine,
        ) ?? headings[0])
    if (current?.link === activeLink) return
    activeLink?.classList.remove("active")
    activeLink?.removeAttribute("aria-current")
    activeLink = current?.link
    activeLink?.classList.add("active")
    activeLink?.setAttribute("aria-current", "location")
  }

  updateActiveHeading()
  window.addEventListener("scroll", updateActiveHeading, { passive: true })
  window.addEventListener("resize", updateActiveHeading)
  window.addCleanup(() => {
    window.removeEventListener("scroll", updateActiveHeading)
    window.removeEventListener("resize", updateActiveHeading)
  })
}

document.addEventListener("nav", setupToc)
