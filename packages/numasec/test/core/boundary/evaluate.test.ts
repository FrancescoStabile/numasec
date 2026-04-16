import { describe, expect, test } from "bun:test"
import { evaluate } from "../../../src/core/boundary"

describe("Boundary.evaluate", () => {
  test("empty boundary falls back to default mode", () => {
    expect(evaluate({}, { kind: "url", value: "http://x.y" }).mode).toBe("ask")
    expect(
      evaluate({ default: "deny" }, { kind: "path", value: "/etc/hosts" }).mode,
    ).toBe("deny")
  })

  test("out_of_scope wins over in_scope", () => {
    const b = { in_scope: ["*.example.com"], out_of_scope: ["admin.example.com"] }
    expect(evaluate(b, { kind: "host", value: "admin.example.com" }).mode).toBe("deny")
    expect(evaluate(b, { kind: "host", value: "api.example.com" }).mode).toBe("allow")
  })

  test("url host match + wildcard subdomain", () => {
    const b = { in_scope: ["*.target.dev", "http://localhost:3000"] }
    expect(evaluate(b, { kind: "url", value: "https://api.target.dev/x" }).mode).toBe("allow")
    expect(evaluate(b, { kind: "url", value: "http://localhost:3000/login" }).mode).toBe("allow")
    expect(evaluate(b, { kind: "url", value: "http://evil.com" }).mode).toBe("ask")
  })

  test("path glob", () => {
    const b = { in_scope: ["src/**/*.ts"], out_of_scope: ["src/secrets/**"] }
    expect(evaluate(b, { kind: "path", value: "src/app/index.ts" }).mode).toBe("allow")
    expect(evaluate(b, { kind: "path", value: "src/secrets/key.ts" }).mode).toBe("deny")
    expect(evaluate(b, { kind: "path", value: "dist/app.js" }).mode).toBe("ask")
  })

  test("decision carries matched pattern", () => {
    const d = evaluate({ in_scope: ["*.x.y"] }, { kind: "host", value: "a.x.y" })
    expect(d.mode).toBe("allow")
    expect(d.matched).toBe("*.x.y")
  })
})
