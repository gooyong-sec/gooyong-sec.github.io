import assert from "node:assert"
import test, { describe } from "node:test"
import { learningOrderSort } from "./learningOrder"

describe("learningOrderSort", () => {
  test("orders learning folders before tooling", () => {
    const folders = ["도구", "웹취약점", "모의해킹 기초"].map((displayName) => ({
      displayName,
      isFolder: true,
    }))

    folders.sort(learningOrderSort)

    assert.deepStrictEqual(
      folders.map((folder) => folder.displayName),
      ["모의해킹 기초", "웹취약점", "도구"],
    )
  })

  test("orders the Java web series numerically", () => {
    const files = ["Java 웹 기초 3", "Java 웹 기초 1", "Java 웹 기초 2"].map(
      (displayName) => ({ displayName, isFolder: false }),
    )

    files.sort(learningOrderSort)

    assert.deepStrictEqual(
      files.map((file) => file.displayName),
      ["Java 웹 기초 1", "Java 웹 기초 2", "Java 웹 기초 3"],
    )
  })
})
