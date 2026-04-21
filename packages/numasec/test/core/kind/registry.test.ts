import { describe, expect, test } from "bun:test"
import { Kind } from "../../../src/core/kind"

describe("Kind registry", () => {
  test("exposes all 5 kinds", () => {
    expect(Kind.ALL.map((k) => k.id).sort()).toEqual([
      "appsec",
      "hacking",
      "osint",
      "pentest",
      "security",
    ])
  })

  test("byId round-trip", () => {
    for (const pack of Kind.ALL) {
      expect(Kind.byId(pack.id)?.id).toBe(pack.id)
    }
  })

  test("byAgent maps agent name → pack", () => {
    expect(Kind.byAgent("pentest")?.id).toBe("pentest")
    expect(Kind.byAgent("nope")).toBeUndefined()
  })

  test("resolve falls back to security", () => {
    expect(Kind.resolve("nope").id).toBe("security")
    expect(Kind.resolve(null).id).toBe("security")
    expect(Kind.resolve(undefined, "osint").id).toBe("osint")
  })

  test("each pack has placeholders and thinking phrases", () => {
    for (const pack of Kind.ALL) {
      expect(pack.placeholders.normal.length).toBeGreaterThan(0)
      expect(pack.placeholders.shell.length).toBeGreaterThan(0)
      expect(pack.thinking.length).toBeGreaterThan(0)
      expect(pack.glyph.length).toBeGreaterThan(0)
    }
  })
})
