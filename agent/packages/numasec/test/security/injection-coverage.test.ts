import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { testNoSql } from "../../src/security/scanner/nosql-tester"
import { testPayloads } from "../../src/security/scanner/test-payloads"

let server: ReturnType<typeof Bun.serve>
let baseUrl = ""

async function json(req: Request) {
  const text = await req.text()
  if (!text) return {}
  return JSON.parse(text) as Record<string, unknown>
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)
      if (url.pathname === "/api/search" && req.method === "POST") {
        const body = await json(req)
        const filters = body.filters as Record<string, unknown> | undefined
        const user = filters?.user as Record<string, unknown> | undefined
        if (user?.name === "' OR 1=1 --") {
          return new Response("SequelizeDatabaseError: near \"OR\": syntax error", { status: 500 })
        }
        return Response.json({ ok: true })
      }
      if (url.pathname === "/api/login" && req.method === "POST") {
        if (req.headers.get("x-mode") !== "json") {
          return Response.json({ error: "missing client mode" }, { status: 400 })
        }
        const body = await json(req)
        const credentials = body.credentials as Record<string, unknown> | undefined
        const username = credentials?.username
        if (username && typeof username === "object" && "$ne" in username) {
          return Response.json({ token: "bypassed-token", role: "admin" })
        }
        return Response.json({ error: "admin login denied" }, { status: 401 })
      }
      if (url.pathname === "/api/query" && req.method === "GET") {
        return Response.json({ note: "admin help", items: [] })
      }
      return new Response("not-found", { status: 404 })
    },
  })
  baseUrl = server.url.origin
})

afterAll(() => {
  server.stop()
})

describe("injection coverage", () => {
  test("injects payloads into nested JSON fields", async () => {
    const result = await testPayloads({
      url: `${baseUrl}/api/search`,
      method: "POST",
      parameter: "filters.user.name",
      position: "json",
      baseBody: JSON.stringify({
        filters: {
          user: {
            name: "guest",
          },
        },
      }),
      payloads: ["' OR 1=1 --"],
      successIndicators: ["SequelizeDatabaseError"],
    })

    expect(result.vulnerable).toBe(true)
    expect(result.results[0]?.matchType).toBe("content")
  })

  test("reuses original method, headers, and nested body paths for NoSQL tests", async () => {
    const result = await testNoSql(`${baseUrl}/api/login`, {
      position: "json",
      method: "POST",
      headers: {
        "x-mode": "json",
      },
      jsonBody: {
        credentials: {
          username: "guest",
          password: "guest",
        },
      },
    })

    expect(result.vulnerable).toBe(true)
    expect(result.findings.some((item) => item.parameter === "credentials.username")).toBe(true)
    expect(result.findings.some((item) => item.evidence.includes("Status changed from 401 to 200"))).toBe(true)
  })

  test("does not treat unchanged baseline indicator text as a NoSQL finding", async () => {
    const result = await testNoSql(`${baseUrl}/api/query?name=guest`, {
      position: "query",
    })

    expect(result.vulnerable).toBe(false)
    expect(result.findings).toHaveLength(0)
  })
})
