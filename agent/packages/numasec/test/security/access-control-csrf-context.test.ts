import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"

let server: ReturnType<typeof Bun.serve>
let base = ""

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)

      if (url.pathname === "/register" && req.method === "POST") {
        return Response.json({ status: "success" }, { status: 201 })
      }

      if (url.pathname === "/profile" && req.method === "POST") {
        if (!(req.headers.get("cookie") ?? "").includes("session=auth")) {
          return new Response("unauthorized", { status: 401 })
        }
        return Response.json({ status: "updated" })
      }

      return new Response("not-found", { status: 404 })
    },
  })
  base = server.url.origin
})

afterAll(() => {
  server.stop()
})

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-access-control-csrf-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await AccessControlTestTool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("access_control_test CSRF context", () => {
  test("does not count anonymous registration as a CSRF finding", async () => {
    const out = await runTool(
      {
        url: `${base}/register`,
        test_type: "csrf",
        method: "POST",
      },
      "sess-access-csrf-register" as SessionID,
    )

    expect((out.metadata as any).findings).toBe(0)
    expect(out.output).toContain("unauthenticated state change")
  })

  test("still flags authenticated state changes as CSRF findings", async () => {
    const out = await runTool(
      {
        url: `${base}/profile`,
        test_type: "csrf",
        method: "POST",
        cookies: "session=auth",
      },
      "sess-access-csrf-profile" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("Potential CSRF")
  })
})
