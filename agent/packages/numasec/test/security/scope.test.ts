import { beforeEach, describe, expect, test } from "bun:test"
import type { SessionID } from "../../src/session/schema"
import { Scope } from "../../src/security/scope"

const SESSION_ID = "sess-scope" as SessionID
const OTHER_SESSION_ID = "sess-scope-other" as SessionID

beforeEach(() => {
  Scope.clear()
})

describe("Scope", () => {
  test("check fails when no scope is set", () => {
    const result = Scope.check(SESSION_ID, "http://example.com")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("No scope defined")
  })

  test("allows URL within scope", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://example.com/api").allowed).toBe(true)
  })

  test("blocks URL outside scope", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    const result = Scope.check(SESSION_ID, "http://evil.com/api")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("not in scope")
  })

  test("glob matching: *.example.com matches subdomains", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["*.example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://api.example.com").allowed).toBe(true)
    expect(Scope.check(SESSION_ID, "http://dev.example.com").allowed).toBe(true)
    expect(Scope.check(SESSION_ID, "http://example.com").allowed).toBe(false)
  })

  test("blocked patterns take priority over allowed", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["*.example.com"],
      blockedPatterns: ["admin.example.com"],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://api.example.com").allowed).toBe(true)
    const result = Scope.check(SESSION_ID, "http://admin.example.com")
    expect(result.allowed).toBe(false)
    expect(result.reason).toContain("Blocked")
  })

  test("blocks private IPs by default", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://127.0.0.1").allowed).toBe(false)
    expect(Scope.check(SESSION_ID, "http://10.0.0.1").allowed).toBe(false)
    expect(Scope.check(SESSION_ID, "http://192.168.1.1").allowed).toBe(false)
    expect(Scope.check(SESSION_ID, "http://172.16.0.1").allowed).toBe(false)
    expect(Scope.check(SESSION_ID, "http://localhost").allowed).toBe(false)
  })

  test("allows private IPs when allowInternal=true", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: true,
    })

    expect(Scope.check(SESSION_ID, "http://127.0.0.1:3000").allowed).toBe(true)
    expect(Scope.check(SESSION_ID, "http://localhost:8080").allowed).toBe(true)
    expect(Scope.check(SESSION_ID, "http://192.168.1.1").allowed).toBe(true)
  })

  test("handles host with port", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["example.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://example.com:8080/api").allowed).toBe(true)
  })

  test("set/get/clear lifecycle", () => {
    expect(Scope.get(SESSION_ID)).toBeNull()

    Scope.set(SESSION_ID, {
      allowedPatterns: ["test.com"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.get(SESSION_ID)).toBeDefined()
    expect(Scope.get(SESSION_ID)!.allowedPatterns).toContain("test.com")

    Scope.clear(SESSION_ID)
    expect(Scope.get(SESSION_ID)).toBeNull()
  })

  test("0.0.0.0 blocked as private", () => {
    Scope.set(SESSION_ID, {
      allowedPatterns: ["*"],
      blockedPatterns: [],
      allowInternal: false,
    })

    expect(Scope.check(SESSION_ID, "http://0.0.0.0").allowed).toBe(false)
  })

  test("ensure seeds scope from the first explicit target and isolates sessions", () => {
    const seeded = Scope.ensure(SESSION_ID, "http://localhost:3000")

    expect(seeded.allowInternal).toBe(true)
    expect(Scope.check(SESSION_ID, "http://localhost:3000").allowed).toBe(true)
    expect(Scope.check(OTHER_SESSION_ID, "http://localhost:3000").allowed).toBe(false)
  })
})
