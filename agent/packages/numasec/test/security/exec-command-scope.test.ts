import { beforeEach, describe, expect, test } from "bun:test"
import type { SessionID } from "../../src/session/schema"
import { Scope } from "../../src/security/scope"
import { enforceExecCommandScope } from "../../src/security/tool/exec-command"

const SESSION_ID = "sess-exec-command-scope" as SessionID

beforeEach(() => {
  Scope.clear()
})

describe("exec_command scope enforcement", () => {
  test("seeds scope from literal command URLs", () => {
    const targets = enforceExecCommandScope(SESSION_ID, {
      argv: ["curl", "https://example.com/api"],
    })

    expect(targets).toEqual(["https://example.com/api"])
    expect(Scope.check(SESSION_ID, "https://example.com/api").allowed).toBe(true)
  })

  test("requires scope_targets for network commands without literal URLs", () => {
    expect(() =>
      enforceExecCommandScope(SESSION_ID, {
        argv: ["nmap", "example.com"],
      }),
    ).toThrow("scope_targets")
  })

  test("accepts explicit scope_targets for network commands without literal URLs", () => {
    const targets = enforceExecCommandScope(SESSION_ID, {
      argv: ["nmap", "example.com"],
      scope_targets: ["example.com"],
    })

    expect(targets).toEqual(["example.com"])
    expect(Scope.check(SESSION_ID, "https://example.com").allowed).toBe(true)
  })
})
