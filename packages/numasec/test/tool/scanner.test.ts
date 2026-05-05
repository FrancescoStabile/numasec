import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import * as net from "node:net"
import { ScannerTool } from "../../src/tool/scanner"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
  ),
)

const baseCtx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make(""),
  callID: "",
  agent: "security",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  extra: {},
  ask: () => Effect.succeed(undefined as any),
} as any

async function exec(params: any) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* ScannerTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

function withFetchMock<T>(handler: (url: string) => Response | Promise<Response>, fn: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    return await handler(url)
  }) as typeof fetch
  return fn().finally(() => {
    globalThis.fetch = original
  })
}

function scannerResponse(url: string) {
  const u = new URL(url)
  if (u.pathname === "/") {
    return new Response(
      `<html><head><title>t</title><script src="/app.js"></script></head>
<body>
<a href="/about">about</a>
<a href="/contact">contact</a>
<form action="/login" method="POST"><input name="user" type="text"/><input name="pw" type="password"/></form>
<a href="/hidden">hidden</a>
</body></html>`,
      { status: 200, headers: { "content-type": "text/html", "x-powered-by": "Express" } },
    )
  }
  if (u.pathname === "/app.js") {
    return new Response(
      `const API = "/api/v1/users"; fetch("/api/v1/orders"); const key = "AIzaSyA1234567890abcdef1234567890abcdef12";`,
      { status: 200, headers: { "content-type": "application/javascript" } },
    )
  }
  if (u.pathname === "/about" || u.pathname === "/contact" || u.pathname === "/hidden") {
    return new Response("<html><body>page</body></html>", { status: 200, headers: { "content-type": "text/html" } })
  }
  if (u.pathname === "/robots.txt") {
    return new Response("User-agent: *\nDisallow: /admin\n", { status: 200, headers: { "content-type": "text/plain" } })
  }
  if (u.pathname === "/sitemap.xml") {
    return new Response(
      `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>${u.origin}/hidden</loc></url></urlset>`,
      { status: 200, headers: { "content-type": "application/xml" } },
    )
  }
  if (u.pathname === "/openapi.json") {
    return new Response(JSON.stringify({ openapi: "3.1.0", info: { title: "demo", version: "1.0.0" } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  }
  if (u.pathname === "/admin") {
    return new Response("forbidden", { status: 403, headers: { "content-type": "text/plain" } })
  }
  if (u.pathname.includes("numasec_404_check_")) {
    return new Response("nf", { status: 404, headers: { "content-type": "text/plain" } })
  }
  return new Response("nf", { status: 404, headers: { "content-type": "text/plain" } })
}

async function canBindLocalhost() {
  return await new Promise<boolean>((resolve) => {
    const server = net.createServer()
    server.once("error", () => resolve(false))
    server.listen(0, "127.0.0.1", () => {
      server.close(() => resolve(true))
    })
  })
}

describe("tool/scanner", () => {
  test("crawl enumerates same-origin links, forms, robots, sitemap, and openapi", async () => {
    await using fixture = await tmpdir()
    await withFetchMock(async (url) => scannerResponse(url), async () => {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "crawl",
            target: "https://scanner.test",
            options: { maxUrls: 10, maxDepth: 2, timeout: 3000 },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("crawl")
          expect(Array.isArray(data.urls)).toBe(true)
          expect(data.urls).toContain("https://scanner.test")
          expect(data.urls).toContain("https://scanner.test/about")
          expect(data.forms.length).toBeGreaterThanOrEqual(1)
          expect(data.technologies).toContain("Express")
          expect(data.robotsDisallowed).toContain("/admin")
          expect(data.sitemap).toContain("https://scanner.test/hidden")
          expect(data.openapi).toBe("https://scanner.test/openapi.json")
          expect(r.metadata.mode).toBe("crawl")
        },
      })
    })
  })

  test("js extracts endpoints and secrets from bundles", async () => {
    await using fixture = await tmpdir()
    await withFetchMock(async (url) => scannerResponse(url), async () => {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "js",
            target: "https://scanner.test/",
            options: { maxFiles: 5, timeout: 3000 },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("js")
          expect(data.jsFiles).toContain("https://scanner.test/app.js")
          expect(data.endpoints.join(" ")).toContain("/api/v1/")
          expect(data.secrets.length).toBeGreaterThanOrEqual(1)
          expect(data.secrets.some((s: any) => s.type === "Google API Key")).toBe(true)
        },
      })
    })
  })

  test("dir-fuzz finds filtered paths from the target surface", async () => {
    await using fixture = await tmpdir()
    await withFetchMock(async (url) => scannerResponse(url), async () => {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "dir-fuzz",
            target: "https://scanner.test",
            options: { wordlist: ["admin"], timeout: 3000, concurrency: 1, filterStatus: [403] },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("dir-fuzz")
          expect(data.found).toHaveLength(1)
          expect(data.found[0].path).toBe("/admin")
          expect(data.found[0].status).toBe(403)
          expect(r.metadata.mode).toBe("dir-fuzz")
        },
      })
    })
  })

  test("ports detects the open port when local listeners are available", async () => {
    if (!(await canBindLocalhost())) return
    await using fixture = await tmpdir()
    const server = net.createServer((sock) => {
      sock.write("HELLO\r\n")
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    const port = (server.address() as net.AddressInfo).port
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "ports",
            target: "127.0.0.1",
            options: { ports: [port, port + 1], timeout: 2000, concurrency: 2 },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("ports")
          expect(data.openPorts.some((p: any) => p.port === port && p.open)).toBe(true)
          expect(r.metadata.mode).toBe("ports")
        },
      })
    } finally {
      server.close()
    }
  })
})
