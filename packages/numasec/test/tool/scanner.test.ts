import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
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

function startServer(): Promise<{ port: number; stop: () => void }> {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const u = new URL(req.url)
      if (u.pathname === "/") {
        return new Response(
          `<html><head><title>t</title><script src="/app.js"></script></head>
<body>
<a href="/about">about</a>
<a href="/contact">contact</a>
<form action="/login" method="POST"><input name="user" type="text"/><input name="pw" type="password"/></form>
</body></html>`,
          { headers: { "content-type": "text/html", "x-powered-by": "Express" } },
        )
      }
      if (u.pathname === "/app.js") {
        return new Response(
          `const API = "/api/v1/users"; fetch("/api/v1/orders"); const key = "AIzaSyA1234567890abcdef1234567890abcdef12";`,
          { headers: { "content-type": "application/javascript" } },
        )
      }
      if (u.pathname === "/about" || u.pathname === "/contact") {
        return new Response("<html><body>page</body></html>", { headers: { "content-type": "text/html" } })
      }
      if (u.pathname === "/robots.txt") {
        return new Response("User-agent: *\nDisallow: /admin\n", { headers: { "content-type": "text/plain" } })
      }
      return new Response("nf", { status: 404 })
    },
  })
  return Promise.resolve({
    port: server.port!,
    stop: () => server.stop(true),
  })
}

describe("tool/scanner", () => {
  test("crawl enumerates same-origin links and forms", async () => {
    await using fixture = await tmpdir()
    const { port, stop } = await startServer()
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "crawl",
            target: `http://127.0.0.1:${port}`,
            options: { maxUrls: 10, maxDepth: 2, timeout: 3000 },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("crawl")
          expect(Array.isArray(data.urls)).toBe(true)
          expect(data.urls.length).toBeGreaterThanOrEqual(1)
          expect(data.forms.length).toBeGreaterThanOrEqual(1)
          expect(data.technologies).toContain("Express")
          expect(data.robotsDisallowed).toContain("/admin")
          expect(r.metadata.mode).toBe("crawl")
        },
      })
    } finally {
      stop()
    }
  })

  test("js extracts endpoints and secrets from bundles", async () => {
    await using fixture = await tmpdir()
    const { port, stop } = await startServer()
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            mode: "js",
            target: `http://127.0.0.1:${port}/`,
            options: { maxFiles: 5, timeout: 3000 },
          })
          const data = JSON.parse(r.output)
          expect(data.mode).toBe("js")
          expect(data.jsFiles.length).toBeGreaterThanOrEqual(1)
          const joined = data.endpoints.join(" ")
          expect(joined).toContain("/api/v1/")
          expect(data.secrets.length).toBeGreaterThanOrEqual(1)
          expect(data.secrets.some((s: any) => s.type === "Google API Key")).toBe(true)
        },
      })
    } finally {
      stop()
    }
  })

  test("ports detects the open port", async () => {
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
