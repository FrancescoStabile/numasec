import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { SecurityActorSessionTable } from "../../src/security/runtime/runtime.sql"
import {
  ACTOR_SESSION_TTL_MS,
  actorSessionRequest,
  browserAuthMaterial,
  mergeActorSession,
  readActorSession,
} from "../../src/security/runtime/actor-session-store"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"
import { AuthTestTool } from "../../src/security/tool/auth-test"
import { HttpRequestTool } from "../../src/security/tool/http-request"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

function encode(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url")
}

function token(id: number, email: string, role: string) {
  return `${encode({ alg: "none", typ: "JWT" })}.${encode({
    data: {
      id,
      email,
      role,
    },
  })}.`
}

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
        slug: "auth-fabric-tests",
        directory: "/tmp",
        title: "auth-fabric-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

function context(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-auth-fabric-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  return impl.execute(args as never, context(sessionID))
}

describe("auth fabric unification", () => {
  test("http_request captures login auth material and reuses it across cookie and bearer flows", async () => {
    const sessionID = "sess-auth-fabric-http" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fabric-http@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)

    const login = await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
        method: "POST",
        actor_label: "fabric-http",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "fabric-http@example.com",
          password: "Test12345!",
        }),
      },
      sessionID,
    )
    expect((login.metadata as any).status).toBe(200)

    const cookie = await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/api/private/profile`,
        method: "GET",
        actor_label: "fabric-http",
      },
      sessionID,
    )
    expect((cookie.metadata as any).status).toBe(200)
    expect(cookie.output).toContain("private-")

    const bearer = await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/api/Projects`,
        method: "GET",
        actor_label: "fabric-http",
      },
      sessionID,
    )
    expect((bearer.metadata as any).status).toBe(200)
    expect(bearer.output).toContain('"data"')

    const row = Database.use((db) =>
      db
        .select()
        .from(SecurityActorSessionTable)
        .where(eq(SecurityActorSessionTable.session_id, sessionID))
        .get(),
    )
    expect(row?.material_summary).toBeDefined()
    expect((row?.material_summary as Record<string, unknown>).header_keys).toContain("authorization")
    expect((row?.material_summary as Record<string, unknown>).cookie_names).toContain("session")
  })

  test("http_request preserves explicit non-auth request headers while reusing actor sessions", async () => {
    const sessionID = "sess-auth-fabric-headers" as SessionID
    seedSession(sessionID)

    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        if (req.headers.get("content-type") !== "application/json") {
          return Response.json(
            {
              status: "error",
              content_type: req.headers.get("content-type") ?? "",
            },
            { status: 415 },
          )
        }
        const body = await req.json()
        return Response.json({
          status: "success",
          data: body,
        })
      },
    })

    try {
      const out = await runTool(
        HttpRequestTool,
        {
          url: `http://127.0.0.1:${server.port}/echo`,
          method: "POST",
          actor_label: "header-user",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            email: "headers@example.com",
          }),
        },
        sessionID,
      )

      expect((out.metadata as any).status).toBe(200)
      expect(out.output).toContain('"email":"headers@example.com"')
    } finally {
      server.stop()
    }
  })

  test("auth_test seeds actor sessions that access_control_test reuses without manual headers", async () => {
    const sessionID = "sess-auth-fabric-access" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fabric-left@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const left = (await reg.json()) as {
      data: {
        id: number
      }
    }

    const regTwo = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "fabric-right@example.com",
        password: "Test12345!",
      }),
    })
    expect(regTwo.status).toBe(201)
    const right = (await regTwo.json()) as {
      data: {
        id: number
      }
    }

    const leftToken = app.tokenFor(left.data.id)
    const rightToken = app.tokenFor(right.data.id)

    const leftOut = await runTool(
      AuthTestTool,
      {
        url: `${app.baseUrl}/api/profile`,
        jwt: leftToken,
        test_defaults: false,
        actor_label: "left",
      },
      sessionID,
    )
    expect((leftOut.metadata as any).findings).toBeGreaterThanOrEqual(1)

    const rightOut = await runTool(
      AuthTestTool,
      {
        url: `${app.baseUrl}/api/profile`,
        jwt: rightToken,
        test_defaults: false,
        actor_label: "right",
      },
      sessionID,
    )
    expect((rightOut.metadata as any).findings).toBeGreaterThanOrEqual(1)

    const out = await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Users/{id}`,
        test_type: "idor",
        parameter: "id",
        actor_label: "left",
        secondary_actor_label: "right",
        id_values: [String(left.data.id), String(right.data.id)],
      },
      sessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("cross-actor access confirmed")
    expect(JSON.stringify(out.envelope)).toContain("cross_actor_access")
  })

  test("browser session material can hydrate shared HTTP auth state", async () => {
    const sessionID = "sess-auth-fabric-browser" as SessionID
    seedSession(sessionID)

    const stored = await mergeActorSession({
      sessionID,
      actorLabel: "browser-user",
      material: browserAuthMaterial({
        actorLabel: "browser-user",
        pageURL: "https://app.example.com/dashboard",
        headers: {},
        cookies: [
          {
            name: "session",
            value: "auth-7",
            domain: "app.example.com",
            path: "/",
          },
        ],
        localStorage: {
          idToken: token(7, "browser-user@example.com", "customer"),
        },
        sessionStorage: {
          profile: JSON.stringify({
            user: {
              id: 7,
              email: "browser-user@example.com",
              role: "customer",
            },
          }),
        },
      }),
    })

    const request = actorSessionRequest(stored)
    expect(request.headers.authorization).toContain("Bearer ")
    expect(request.cookies).toContain("session=auth-7")
    expect(stored.actorEmail).toBe("browser-user@example.com")
    expect(stored.actorRole).toBe("customer")
  })

  test("evicts actor session material after the backing session is deleted", async () => {
    const sessionID = "sess-auth-fabric-evict-deleted" as SessionID
    seedSession(sessionID)

    await mergeActorSession({
      sessionID,
      actorLabel: "cleanup-user",
      material: browserAuthMaterial({
        actorLabel: "cleanup-user",
        pageURL: "https://app.example.com/profile",
        cookies: [],
      }),
    })

    expect(
      await readActorSession({
        sessionID,
        actorLabel: "cleanup-user",
      }),
    ).toBeDefined()

    Database.use((db) => db.delete(SessionTable).where(eq(SessionTable.id, sessionID)).run())

    expect(
      await readActorSession({
        sessionID,
        actorLabel: "cleanup-user",
      }),
    ).toBeUndefined()
  })

  test("evicts stale actor session material after the TTL window", async () => {
    const sessionID = "sess-auth-fabric-evict-ttl" as SessionID
    seedSession(sessionID)
    const prev = Date.now
    let now = 1_000_000
    Date.now = () => now

    try {
      await mergeActorSession({
        sessionID,
        actorLabel: "ttl-user",
        material: browserAuthMaterial({
          actorLabel: "ttl-user",
          pageURL: "https://app.example.com/dashboard",
          cookies: [],
        }),
      })

      expect(
        await readActorSession({
          sessionID,
          actorLabel: "ttl-user",
        }),
      ).toBeDefined()

      now += ACTOR_SESSION_TTL_MS + 1

      expect(
        await readActorSession({
          sessionID,
          actorLabel: "ttl-user",
        }),
      ).toBeUndefined()
    } finally {
      Date.now = prev
    }
  })
})
