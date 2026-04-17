import { describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database } from "../../src/storage/db"
import { ingestToolEnvelope } from "../../src/security/envelope-ingestor"
import {
  buildBrowserInventoryEnvelope,
  shouldResetBrowserSessionAfterFailure,
  type BrowserInventorySnapshot,
} from "../../src/security/tool/browser"
import { browserActorSessionID, browserPageID, browserSessionID } from "../../src/security/runtime/browser-runtime"
import { QueryResourceInventoryTool } from "../../src/security/tool/query-resource-inventory"

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
        slug: "browser-inventory-tests",
        directory: "/tmp",
        title: "browser-inventory-tests",
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
    callID: "call-browser-inventory-test",
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

function snapshot(): BrowserInventorySnapshot {
  const sessionID = "sess-browser-inventory-shared" as SessionID
  const actorSessionID = browserActorSessionID(sessionID, "browser")
  return {
    page_url: "https://app.example.com/dashboard",
    page_title: "Dashboard",
    actor_session_id: actorSessionID,
    browser_session_id: browserSessionID(sessionID, actorSessionID),
    page_id: browserPageID(sessionID, actorSessionID),
    navigation_index: 2,
    actor_label: "browser",
    cookies: [
      {
        name: "session",
        value: "auth-7",
        domain: "app.example.com",
        path: "/",
      },
    ],
    local_storage: {
      idToken: token(7, "spa-user@example.com", "customer"),
    },
    session_storage: {
      profile: JSON.stringify({
        user: {
          id: 7,
          email: "spa-user@example.com",
          role: "customer",
        },
      }),
    },
    links: [
      "/app/users/7",
      "/app/projects/11",
      "https://evil.example/offsite",
    ],
    forms: [
      {
        action: "/api/Projects/11/approve",
        method: "POST",
        fields: [
          {
            name: "confirm",
            value: "1",
            type: "hidden",
          },
        ],
        submit_label: "Approve project",
      },
    ],
    actions: [
      {
        url: "/api/Projects/11/archive",
        method: "POST",
        source_kind: "browser_button",
        content_type: "application/json",
        body: JSON.stringify({
          confirm: "1",
          filters: {
            owner: {
              id: "7",
            },
          },
        }),
        label: "Archive project",
      },
    ],
    network: [
      {
        url: "https://app.example.com/api/Projects/11/verify",
        method: "POST",
        status: 200,
        initiator_url: "https://app.example.com/dashboard",
        resource_type: "fetch",
        content_type: "application/json",
        body: '{"confirm":"1","filters":{"owner":{"id":"7"}}}',
      },
      {
        url: "https://evil.example/api/leak",
        method: "POST",
        status: 200,
        initiator_url: "https://app.example.com/dashboard",
        resource_type: "xhr",
        content_type: "application/json",
        body: '{"token":"secret"}',
      },
    ],
    resources: [
      "https://app.example.com/api/Projects/11",
      "https://cdn.example.com/app.js",
    ],
  }
}

describe("browser inventory", () => {
  test("resets poisoned browser sessions after retryable failures", () => {
    expect(
      shouldResetBrowserSessionAfterFailure({
        code: "transient_network",
        retryable: true,
      }),
    ).toBe(true)
    expect(
      shouldResetBrowserSessionAfterFailure({
        code: "origin_uninitialized",
        retryable: true,
      }),
    ).toBe(true)
    expect(
      shouldResetBrowserSessionAfterFailure({
        code: "page_crashed",
        retryable: false,
      }),
    ).toBe(true)
    expect(
      shouldResetBrowserSessionAfterFailure({
        code: "selector_missing",
        retryable: false,
      }),
    ).toBe(false)
  })

  test("builds actor and same-origin route observations from browser snapshot", () => {
    const envelope = buildBrowserInventoryEnvelope(snapshot())
    const trace = envelope.artifacts.find((item) => item.key === "browser-network")
    expect(trace).toBeDefined()
    const actor = envelope.observations.find((item) => item.family === "actor_inventory")
    expect(actor).toBeDefined()
    expect(actor?.actor_id).toBe("7")
    expect(actor?.actor_email).toBe("spa-user@example.com")
    expect(actor?.actor_session_id).toBeTruthy()
    expect(actor?.browser_session_id).toBeTruthy()
    expect(actor?.page_id).toBeTruthy()
    expect(actor?.navigation_index).toBe(2)
    const routes = envelope.observations.filter((item) => item.family === "resource_inventory")
    expect(routes.some((item) => item.url === "https://app.example.com/app/users/7" && item.exposure === "self")).toBe(true)
    const action = routes.find((item) => item.url === "https://app.example.com/api/Projects/11/approve" && item.source_kind === "browser_form")
    expect(action).toBeDefined()
    expect(action?.action_kind).toBe("approve")
    expect(action?.action_target_state).toBe("approved")
    expect(action?.resource_url).toBe("https://app.example.com/api/Projects/11")
    expect(action?.form_body).toBe("confirm=1")
    expect(action?.actor_session_id).toBeTruthy()
    expect(action?.browser_session_id).toBeTruthy()
    expect(action?.page_id).toBeTruthy()
    expect(action?.navigation_index).toBe(2)
    const archive = routes.find((item) => item.url === "https://app.example.com/api/Projects/11/archive" && item.source_kind === "browser_button")
    expect(archive).toBeDefined()
    expect(archive?.action_kind).toBe("archive")
    expect(archive?.action_target_state).toBe("archived")
    expect(archive?.request_content_type).toBe("application/json")
    expect(archive?.request_body).toBe('{"confirm":"1","filters":{"owner":{"id":"7"}}}')
    expect(archive?.parameter_names).toEqual(expect.arrayContaining(["confirm", "filters.owner.id"]))
    const verify = routes.find((item) => item.url === "https://app.example.com/api/Projects/11/verify" && item.source_kind === "browser_network")
    expect(verify).toBeDefined()
    expect(verify?.action_kind).toBe("verify")
    expect(verify?.action_target_state).toBe("verified")
    expect(verify?.resource_url).toBe("https://app.example.com/api/Projects/11")
    expect(verify?.response_status).toBe(200)
    expect(verify?.request_body).toBe('{"confirm":"1","filters":{"owner":{"id":"7"}}}')
    expect(verify?.parameter_names).toEqual(expect.arrayContaining(["confirm", "filters.owner.id"]))
    expect(routes.some((item) => String(item.url).includes("evil.example"))).toBe(false)
  })

  test("browser envelope feeds the shared resource inventory query surface", async () => {
    const sessionID = "sess-browser-inventory" as SessionID
    seedSession(sessionID)

    await ingestToolEnvelope({
      sessionID,
      tool: "browser",
      title: "Navigate dashboard",
      metadata: {},
      envelope: buildBrowserInventoryEnvelope(snapshot()),
    })

    const out = await runTool(
      QueryResourceInventoryTool,
      {
        exposure: "all",
      },
      sessionID,
    )

    expect((out.metadata as any).actorCount).toBeGreaterThanOrEqual(1)
    expect((out.metadata as any).resourceCount).toBeGreaterThanOrEqual(5)
    expect((out.metadata as any).actionCount).toBeGreaterThanOrEqual(3)
    const body = JSON.parse(out.output.split("\n\n").slice(1).join("\n\n")) as {
      by_actor: Array<{
        actor_email: string
        own_values: string[]
        unknown_values: string[]
        endpoints: string[]
        actions: Array<{
          url: string
          action_kind: string
          resource_url: string
          request_content_type: string
          parameter_names: string[]
        }>
      }>
      resources: Array<{
        source_kind: string
        url: string
        action_kind: string
        parameter_names: string[]
      }>
    }
    const actor = body.by_actor.find((item) => item.actor_email === "spa-user@example.com")
    expect(actor).toBeDefined()
    expect(actor?.own_values).toContain("7")
    expect(actor?.unknown_values).toContain("11")
    expect(actor?.actions.some((item) => item.action_kind === "approve" && item.resource_url === "https://app.example.com/api/Projects/11")).toBe(true)
    expect(
      actor?.actions.some(
        (item) =>
          item.action_kind === "archive" &&
          item.request_content_type === "application/json" &&
          item.parameter_names.includes("filters.owner.id"),
      ),
    ).toBe(true)
    expect(actor?.actions.some((item) => item.action_kind === "verify" && item.resource_url === "https://app.example.com/api/Projects/11")).toBe(true)
    expect(body.resources.some((item) => item.source_kind === "browser_form" && item.url === "https://app.example.com/api/Projects/11/approve")).toBe(true)
    expect(body.resources.some((item) => item.source_kind === "browser_button" && item.url === "https://app.example.com/api/Projects/11/archive")).toBe(true)
    expect(
      body.resources.some(
        (item) =>
          item.source_kind === "browser_network" &&
          item.url === "https://app.example.com/api/Projects/11/verify" &&
          item.parameter_names.includes("filters.owner.id"),
      ),
    ).toBe(true)
  })

  test("skips disabled actions while retaining generic state-changing labels", () => {
    const base = snapshot()
    const envelope = buildBrowserInventoryEnvelope({
      ...base,
      actions: [
        {
          url: "/api/Profile",
          method: "POST",
          source_kind: "browser_button",
          label: "Save profile",
        },
        {
          url: "/api/Reviews",
          method: "POST",
          source_kind: "browser_button",
          label: "Send the review",
        },
        {
          url: "/api/Reviews",
          method: "POST",
          source_kind: "browser_button",
          label: "Send the review",
          disabled: true,
        },
      ],
      forms: [],
      network: [],
      resources: [],
    })
    const routes = envelope.observations.filter((item) => item.family === "resource_inventory")
    const save = routes.find((item) => item.url === "https://app.example.com/api/Profile")
    const send = routes.find((item) => item.url === "https://app.example.com/api/Reviews")
    expect(save?.action_kind).toBe("save")
    expect(save?.action_target_state).toBe("saved")
    expect(send?.action_kind).toBe("send")
    expect(send?.action_target_state).toBe("sent")
    expect(routes.filter((item) => item.url === "https://app.example.com/api/Reviews")).toHaveLength(1)
  })

  test("does not treat JSON bodies with equals signs as form payloads", () => {
    const base = snapshot()
    const envelope = buildBrowserInventoryEnvelope({
      ...base,
      actions: [
        {
          url: "/api/Notes",
          method: "POST",
          source_kind: "browser_button",
          label: "Save note",
          body: '{"note":"value=123"}',
        },
      ],
      forms: [],
      network: [],
      resources: [],
    })
    const note = envelope.observations.find((item) => item.family === "resource_inventory" && item.url === "https://app.example.com/api/Notes")
    expect(note?.parameter_names).toEqual(["note"])
  })
})
