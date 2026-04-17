import { describe, expect, test } from "bun:test"
import { resolveSlashCommand } from "../../src/command/resolve"

describe("resolveSlashCommand", () => {
  test("matches the longest command prefix", () => {
    const value = resolveSlashCommand("/report generate html", ["report", "report generate"])
    expect(value).toEqual({
      command: "report generate",
      arguments: "html",
    })
  })

  test("matches nested finalize commands before shorter report prefixes", () => {
    const value = resolveSlashCommand("/report finalize markdown --out report.md", [
      "report",
      "report generate",
      "report finalize",
    ])
    expect(value).toEqual({
      command: "report finalize",
      arguments: "markdown --out report.md",
    })
  })

  test("keeps multiline arguments after command match", () => {
    const value = resolveSlashCommand("/scope set https://example.com\nnotes line", ["scope set"])
    expect(value).toEqual({
      command: "scope set",
      arguments: "https://example.com\nnotes line",
    })
  })

  test("supports legacy evidence command and v2 subcommands", () => {
    const commands = ["evidence", "evidence list", "evidence show"]
    expect(resolveSlashCommand("/evidence", commands)).toEqual({
      command: "evidence",
      arguments: "",
    })
    expect(resolveSlashCommand("/evidence show SSEC-1", commands)).toEqual({
      command: "evidence show",
      arguments: "SSEC-1",
    })
    expect(resolveSlashCommand("/evidence SSEC-1", commands)).toEqual({
      command: "evidence",
      arguments: "SSEC-1",
    })
  })
})
