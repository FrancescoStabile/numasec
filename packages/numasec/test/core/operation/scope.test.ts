import { describe, expect, it } from "bun:test"
import { parseScope } from "@/core/operation/scope"

describe("Operation.scope parser", () => {
  it("returns default allow when no scope section", () => {
    const b = parseScope("# Operation: foo\n\n## Findings\n")
    expect(b.default).toBe("allow")
    expect(b.in_scope).toEqual([])
    expect(b.out_of_scope).toEqual([])
  })

  it("parses in/out bullets and stops at next heading", () => {
    const md = [
      "# Operation: x",
      "",
      "## Scope",
      "- in: https://example.com/*",
      "- out: https://example.com/admin/*",
      "- in:  ",
      "",
      "## Stack",
      "- in: https://other.com/* (should not be parsed)",
    ].join("\n")
    const b = parseScope(md)
    expect(b.default).toBe("ask")
    expect(b.in_scope).toEqual(["https://example.com/*"])
    expect(b.out_of_scope).toEqual(["https://example.com/admin/*"])
  })
})
