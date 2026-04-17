import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { FindingTable } from "../../src/security/security.sql"
import { AuthTestTool } from "../../src/security/tool/auth-test"
import { HttpRequestTool } from "../../src/security/tool/http-request"
import { ProjectFindingsTool } from "../../src/security/tool/project-findings"
import { ingestToolEnvelope } from "../../src/security/envelope-ingestor"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
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
        slug: "phase0-floor-tests",
        directory: "/tmp",
        title: "phase0-floor-tests",
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

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  const out = await impl.execute(args as never, toolContext(sessionID))
  const envelope = out.envelope as Record<string, unknown> | undefined
  if (envelope) {
    await ingestToolEnvelope({
      sessionID,
      tool: tool.id,
      title: out.title,
      metadata: typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata) ? out.metadata as Record<string, unknown> : {},
      envelope: envelope as any,
    })
  }
  return out
}

describe("phase zero floor regressions", () => {
  test("projector promotes common credentials, SQLi auth bypass, and verbose error disclosure", async () => {
    const sessionID = "sess-phase0-floor-regression" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "admin@admin.com",
        password: "admin",
        passwordRepeat: "admin",
      }),
    })
    expect(reg.status).toBe(201)

    await runTool(
      AuthTestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
      },
      sessionID,
    )

    await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: `${app.admin.email}'--`,
          password: "x",
        }),
      },
      sessionID,
    )

    await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: "' UNION SELECT NULL--",
          password: "x",
        }),
      },
      sessionID,
    )

    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )

    const verified = rows.filter((item) => item.tool_used === "finding_projector" && item.state === "verified")
    expect(verified.some((item) => item.family === "auth" && item.title.toLowerCase().includes("common credentials"))).toBe(true)
    expect(verified.some((item) => item.family === "sql_injection" && item.title.toLowerCase().includes("authentication success"))).toBe(true)
    expect(verified.some((item) => item.family === "error_disclosure")).toBe(true)
  })

  test("projector does not promote SQLi auth bypass on successful login with harmless apostrophe text", async () => {
    const sessionID = "sess-phase0-floor-legit-login" as SessionID
    seedSession(sessionID)

    const out = await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: app.admin.email,
          password: app.admin.password,
          note: "owner's profile",
        }),
      },
      sessionID,
    )

    expect(out.output).toContain("HTTP 200")

    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )

    const verified = rows.filter((item) => item.tool_used === "finding_projector" && item.state === "verified")
    expect(verified.some((item) => item.family === "sql_injection" && item.title.toLowerCase().includes("authentication success"))).toBe(false)
  })
})
