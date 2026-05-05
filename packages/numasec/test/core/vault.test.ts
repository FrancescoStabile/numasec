import { describe, expect, test } from "bun:test"
import { resolveIdentityValue } from "../../src/core/vault"

describe("core/vault", () => {
  test("parses cookie-shaped active identities", () => {
    const resolved = resolveIdentityValue("alice", "session=abc123; tenant=red")
    expect(resolved.mode).toBe("cookies")
    expect(resolved.cookies).toBe("session=abc123; tenant=red")
  })

  test("parses explicit authorization headers", () => {
    const resolved = resolveIdentityValue("bob", "Authorization: Bearer token-123")
    expect(resolved.mode).toBe("headers")
    expect(resolved.headers?.Authorization).toBe("Bearer token-123")
  })

  test("parses structured identity objects", () => {
    const resolved = resolveIdentityValue(
      "carol",
      JSON.stringify({
        headers: { "X-Tenant": "blue" },
        cookies: "session=xyz",
      }),
    )
    expect(resolved.headers?.["X-Tenant"]).toBe("blue")
    expect(resolved.cookies).toBe("session=xyz")
  })
})
