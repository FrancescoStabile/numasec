import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database } from "../../src/storage/db"
import { ingestToolEnvelope } from "../../src/security/envelope-ingestor"
import { AuthTestTool } from "../../src/security/tool/auth-test"

let server: ReturnType<typeof Bun.serve>
let baseUrl = ""

function jwt(payload: Record<string, unknown>) {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url")
  return `${header}.${body}.`
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url)
      if (url.pathname === "/api/Users" && req.method === "POST") {
        const body = await req.json() as Record<string, unknown>
        return Response.json(
          {
            status: "success",
            data: {
              id: 7,
              email: String(body.email ?? ""),
              role: "customer",
            },
          },
          { status: 201 },
        )
      }

      if (url.pathname === "/rest/user/login" && req.method === "POST") {
        const body = await req.json() as Record<string, unknown>
        if (body.email !== "admin" || body.password !== "admin") {
          return new Response("Invalid email or password.", { status: 401 })
        }
        return Response.json({
          authentication: {
            token: jwt({
              id: 1,
              email: "admin",
              role: "admin",
            }),
          },
          data: {
            id: 1,
            email: "admin",
            role: "admin",
          },
        })
      }

      if (url.pathname === "/cookie-login" && req.method === "POST") {
        if (!(req.headers.get("cookie") ?? "").includes("session=seeded")) {
          return new Response("Invalid email or password.", { status: 401 })
        }
        return Response.json({
          status: "success",
        })
      }

      return new Response("not-found", { status: 404 })
    },
  })
  baseUrl = server.url.origin
})

afterAll(() => {
  server.stop()
})

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make(`project-${sessionID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/tmp",
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values({
        id: sessionID,
        project_id: projectID,
        slug: "auth-default-tests",
        directory: "/tmp",
        title: "auth-default-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

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

async function runTool(args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await AuthTestTool.init()
  const out = await impl.execute(args as never, toolContext(sessionID))
  if (out.envelope) {
    await ingestToolEnvelope({
      sessionID,
      tool: AuthTestTool.id,
      title: out.title,
      metadata: typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata) ? out.metadata as Record<string, unknown> : {},
      envelope: out.envelope as any,
    })
  }
  return out
}

describe("auth default credential detection", () => {
  test("does not treat account creation as common/default credentials", async () => {
    const sessionID = "sess-auth-default-register" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      {
        url: `${baseUrl}/api/Users`,
      },
      sessionID,
    )

    expect((out.metadata as any).findings).toBe(0)
    expect(out.output).toContain("Skipped common/default credential checks")
    expect(out.output).not.toContain("COMMON CREDENTIALS WORK")
  })

  test("reports successful generic credential sweeps as common credentials, not defaults", async () => {
    const sessionID = "sess-auth-default-login" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      {
        url: `${baseUrl}/rest/user/login`,
      },
      sessionID,
    )

    expect((out.metadata as any).findings).toBe(1)
    expect(out.output).toContain("COMMON CREDENTIALS WORK: admin:admin")
    expect(out.output).not.toContain("DEFAULT CREDENTIALS WORK")
    expect(JSON.stringify(out.envelope)).toContain("\"actor_role\":\"admin\"")
  })

  test("does not treat pre-existing cookies as common credential proof", async () => {
    const sessionID = "sess-auth-default-cookie" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      {
        url: `${baseUrl}/cookie-login`,
        cookies: "session=seeded",
      },
      sessionID,
    )

    expect((out.metadata as any).findings).toBe(0)
    expect(out.output).not.toContain("COMMON CREDENTIALS WORK")
  })
})
