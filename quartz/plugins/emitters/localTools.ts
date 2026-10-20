import { FilePath, joinSegments } from "../../util/path"
import { QuartzEmitterPlugin } from "../types"
import fs from "fs"
import path from "path"
import { dirname } from "path"

// 로컬 전용 정적 도구(보안이슈 트래커, CVE·PoC 트래커)를 빌드마다 public/ 아래로 복사한다.
// GitHub Actions 배포 워크플로가 하던 복사 단계를 로컬 서빙에서도 그대로 재현한다.
// (GitHub push는 닫혀 있고 이 사이트는 로컬 전용이다.)
const TOOLS: { src: string; dest: string }[] = [
  { src: "보안이슈/index.html", dest: "security-issues/index.html" },
  { src: "CVE-PoC/index.html", dest: "CVE-PoC/index.html" },
]

export const LocalTools: QuartzEmitterPlugin = () => ({
  name: "LocalTools",
  async *emit({ argv }) {
    for (const tool of TOOLS) {
      const src = path.join(process.cwd(), tool.src)
      if (!fs.existsSync(src)) continue
      const dest = joinSegments(argv.output, tool.dest) as FilePath
      await fs.promises.mkdir(dirname(dest), { recursive: true })
      await fs.promises.copyFile(src, dest)
      yield dest
    }
  },
  async *partialEmit() {},
})
