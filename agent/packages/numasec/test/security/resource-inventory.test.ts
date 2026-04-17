import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { ingestToolEnvelope } from "../../src/security/envelope-ingestor"
import { AuthTestTool } from "../../src/security/tool/auth-test"
import { HttpRequestTool } from "../../src/security/tool/http-request"
import { QueryResourceInventoryTool } from "../../src/security/tool/query-resource-inventory"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"
import { Database } from "../../src/storage/db"

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
        slug: "resource-inventory-tests",
        directory: "/tmp",
        title: "resource-inventory-tests",
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
  if (out.envelope) {
    await ingestToolEnvelope({
      sessionID,
      tool: tool.id,
      title: out.title,
      metadata: typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata) ? out.metadata as Record<string, unknown> : {},
      envelope: out.envelope as any,
    })
  }
  return out
}

describe("shared resource inventory", () => {
  test("aggregates actor and own/foreign resource candidates across auth and http tools", async () => {
    const sessionID = "sess-resource-inventory" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "inventory-user@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const user = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(user.data.id)

    await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "inventory-project",
      }),
    })

    await runTool(
      AuthTestTool,
      {
        url: `${app.baseUrl}/rest/user/login`,
        jwt: token,
        test_defaults: false,
      },
      sessionID,
    )

    await runTool(
      HttpRequestTool,
      {
        url: `${app.baseUrl}/api/Projects`,
        method: "GET",
        headers: {
          authorization: `Bearer ${token}`,
        },
      },
      sessionID,
    )

    const result = await runTool(
      QueryResourceInventoryTool,
      {
        exposure: "all",
      },
      sessionID,
    )
    expect((result.metadata as any).actorCount).toBeGreaterThanOrEqual(1)
    expect((result.metadata as any).resourceCount).toBeGreaterThanOrEqual(2)
    const summary = JSON.parse(result.output.split("\n\n").slice(1).join("\n\n"))
    const group = summary.by_actor.find((item: Record<string, any>) => item.actor_id === String(user.data.id))
    expect(group).toBeDefined()
    expect(group.own_values.length).toBeGreaterThanOrEqual(1)
    expect(group.foreign_values).toContain("1")
  })

  test("ingestToolEnvelope returns canonical node ids keyed for reuse", async () => {
    const sessionID = "sess-envelope-node-ids" as SessionID
    seedSession(sessionID)

    const impl = await HttpRequestTool.init()
    const out = await impl.execute(
      {
        url: `${app.baseUrl}/api/Products`,
        method: "GET",
      } as never,
      toolContext(sessionID),
    )

    const ingest = await ingestToolEnvelope({
      sessionID,
      tool: HttpRequestTool.id,
      title: out.title,
      metadata: typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata) ? (out.metadata as Record<string, unknown>) : {},
      envelope: out.envelope as any,
    })

    expect(ingest.artifactNodeIDs.length).toBeGreaterThan(0)
    expect(ingest.nodeIDsByKey.exchange).toBeString()
  })
})
