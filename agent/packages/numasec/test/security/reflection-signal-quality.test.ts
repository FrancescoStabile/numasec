import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { InjectionTestTool } from "../../src/security/tool/injection-test"
import { SsrfTestTool } from "../../src/security/tool/ssrf-test"
import { XssTestTool } from "../../src/security/tool/xss-test"

let server: ReturnType<typeof Bun.serve>
let base = ""

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)

      if (url.pathname === "/xss-error") {
        return new Response("captchaId undefined", { status: 500 })
      }

      if (url.pathname === "/redirect") {
        return new Response(`Unrecognized target URL for redirect: ${url.searchParams.get("to") ?? ""}`, { status: 406 })
      }

      if (url.pathname === "/search") {
        const q =
          req.method === "POST"
            ? new URLSearchParams(await req.text()).get("q") ?? ""
            : url.searchParams.get("q") ?? ""
        if (q.includes("'")) {
          return new Response("SQLITE_ERROR: incomplete input", { status: 500 })
        }
        return Response.json({ data: [] })
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
    callID: "call-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("reflection signal quality", () => {
  test("xss_test does not treat generic 5xx validation errors as XSS", async () => {
    const out = await runTool(
      XssTestTool,
      {
        url: `${base}/xss-error`,
        parameter: "name",
      },
      "sess-xss-signal" as SessionID,
    )

    expect((out.metadata as any).vulnerable).toBe(false)
    expect(out.output).toContain("No reflected XSS found")
  })

  test("ssrf_test ignores reflected redirect validation errors", async () => {
    const out = await runTool(
      SsrfTestTool,
      {
        url: `${base}/redirect`,
        parameter: "to",
      },
      "sess-ssrf-signal" as SessionID,
    )

    expect((out.metadata as any).vulnerable).toBe(false)
    expect(out.output).toContain("No SSRF found")
  })

  test("injection_test still uses 5xx as a SQLi signal", async () => {
    const out = await runTool(
      InjectionTestTool,
      {
        url: `${base}/search`,
        parameter: "q",
        position: "body",
        method: "POST",
        types: ["sqli"],
      },
      "sess-sqli-signal" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThan(0)
    expect(out.output).toContain("SQL Injection: VULNERABLE")
  })
})
