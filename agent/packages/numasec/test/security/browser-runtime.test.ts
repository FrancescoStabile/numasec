import { describe, expect, test } from "bun:test"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import {
  ACTIVE_TTL_MS,
  browserContextConfig,
  browserActorSessionID,
  browserLaunchArgs,
  browserPageID,
  browserSessionID,
  cleanupBrowserSessions,
} from "../../src/security/runtime/browser-runtime"
import {
  SecurityActorSessionTable,
  SecurityBrowserPageTable,
  SecurityBrowserSessionTable,
  SecurityExecutionAttemptTable,
  SecurityTargetProfileTable,
} from "../../src/security/runtime/runtime.sql"
import { SessionTable } from "../../src/session/session.sql"
import type { SessionID } from "../../src/session/schema"
import { Database, eq } from "../../src/storage/db"

function withEnv(values: Record<string, string | undefined>, fn: () => void) {
  const prev = new Map<string, string | undefined>()
  for (const key of Object.keys(values)) {
    prev.set(key, process.env[key])
    const value = values[key]
    if (value === undefined) {
      delete process.env[key]
      continue
    }
    process.env[key] = value
  }
  try {
    fn()
  } finally {
    for (const [key, value] of prev) {
      if (value === undefined) {
        delete process.env[key]
        continue
      }
      process.env[key] = value
    }
  }
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
        slug: "browser-runtime-tests",
        directory: "/tmp",
        title: "browser-runtime-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

describe("browser runtime substrate", () => {
  test("keeps browser sandbox and TLS verification on by default", () => {
    withEnv(
      {
        NUMASEC_SECURITY_BROWSER_NO_SANDBOX: undefined,
        NUMASEC_SECURITY_INSECURE_TLS: undefined,
      },
      () => {
        expect(browserLaunchArgs()).toEqual([])
        expect(browserContextConfig()).toEqual({
          ignoreHTTPSErrors: false,
          userAgent: "Mozilla/5.0 (compatible; numasec/4.2)",
        })
      },
    )
  })

  test("opts into unsafe browser flags only when explicit flags are set", () => {
    withEnv(
      {
        NUMASEC_SECURITY_BROWSER_NO_SANDBOX: "1",
        NUMASEC_SECURITY_INSECURE_TLS: "1",
      },
      () => {
        expect(browserLaunchArgs()).toEqual([
          "--no-sandbox",
          "--disable-setuid-sandbox",
          "--ignore-certificate-errors",
        ])
        expect(browserContextConfig()).toEqual({
          ignoreHTTPSErrors: true,
          userAgent: "Mozilla/5.0 (compatible; numasec/4.2)",
        })
      },
    )
  })

  test("derives deterministic actor, browser, and page identifiers", () => {
    const sessionID = "sess-browser-runtime-ids" as SessionID
    const left = browserActorSessionID(sessionID, "admin")
    const right = browserActorSessionID(sessionID, "admin")
    const other = browserActorSessionID(sessionID, "user")

    expect(left).toBe(right)
    expect(left).not.toBe(other)
    expect(browserSessionID(sessionID, left)).toBe(browserSessionID(sessionID, left))
    expect(browserPageID(sessionID, left)).toBe(browserPageID(sessionID, left))
  })

  test("persists runtime descriptor tables", () => {
    const sessionID = "sess-browser-runtime-schema" as SessionID
    seedSession(sessionID)

    const actorSessionID = browserActorSessionID(sessionID, "admin")
    const browserID = browserSessionID(sessionID, actorSessionID)
    const pageID = browserPageID(sessionID, actorSessionID)

    Database.use((db) =>
      db
        .insert(SecurityActorSessionTable)
        .values({
          id: actorSessionID,
          session_id: sessionID,
          actor_label: "admin",
          browser_session_id: browserID,
          status: "active",
          last_origin: "https://app.example.com",
          last_url: "https://app.example.com/dashboard",
          material_summary: {
            header_keys: ["authorization"],
          },
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(SecurityBrowserSessionTable)
        .values({
          id: browserID,
          session_id: sessionID,
          actor_session_id: actorSessionID,
          status: "active",
          headless: true,
          user_agent: "Mozilla/5.0 (compatible; numasec/4.2)",
          navigation_index: 3,
          last_origin: "https://app.example.com",
          last_url: "https://app.example.com/dashboard",
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(SecurityBrowserPageTable)
        .values({
          id: pageID,
          session_id: sessionID,
          browser_session_id: browserID,
          page_role: "primary",
          status: "active",
          last_url: "https://app.example.com/dashboard",
          title: "Dashboard",
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(SecurityExecutionAttemptTable)
        .values({
          id: "EATT-runtime-test" as any,
          session_id: sessionID,
          actor_session_id: actorSessionID,
          browser_session_id: browserID,
          page_id: pageID,
          tool_name: "browser",
          action: "navigate",
          status: "ok",
          error_code: "",
          notes: {
            response_status: 200,
          },
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(SecurityTargetProfileTable)
        .values({
          id: "TPRF-runtime-test" as any,
          session_id: sessionID,
          origin: "https://app.example.com",
          status: "baseline",
          concurrency_budget: 1,
          pacing_ms: 250,
          jitter_ms: 50,
          retry_budget: 2,
          browser_preferred: true,
          last_signal: "warm",
          notes: {
            source: "test",
          },
        })
        .run(),
    )

    const actor = Database.use((db) =>
      db.select().from(SecurityActorSessionTable).where(eq(SecurityActorSessionTable.id, actorSessionID)).get(),
    )
    const browser = Database.use((db) =>
      db.select().from(SecurityBrowserSessionTable).where(eq(SecurityBrowserSessionTable.id, browserID)).get(),
    )
    const page = Database.use((db) =>
      db.select().from(SecurityBrowserPageTable).where(eq(SecurityBrowserPageTable.id, pageID)).get(),
    )
    const attempt = Database.use((db) =>
      db.select().from(SecurityExecutionAttemptTable).where(eq(SecurityExecutionAttemptTable.id, "EATT-runtime-test" as any)).get(),
    )
    const profile = Database.use((db) =>
      db
        .select()
        .from(SecurityTargetProfileTable)
        .where(eq(SecurityTargetProfileTable.id, "TPRF-runtime-test" as any))
        .get(),
    )

    expect(actor?.actor_label).toBe("admin")
    expect(browser?.navigation_index).toBe(3)
    expect(page?.title).toBe("Dashboard")
    expect(attempt?.action).toBe("navigate")
    expect(profile?.browser_preferred).toBe(true)
  })

  test("expires stale browser sessions without waiting for a new prepare call", async () => {
    const sessionID = "sess-browser-runtime-expire" as SessionID
    seedSession(sessionID)

    const actorSessionID = browserActorSessionID(sessionID, "admin")
    const browserID = browserSessionID(sessionID, actorSessionID)
    const pageID = browserPageID(sessionID, actorSessionID)
    let closed = 0

    const state = {
      sessions: new Map([
        [
          `${sessionID}:${actorSessionID}`,
          {
            sessionID,
            actorSessionID,
            browserSessionID: browserID,
            pageID,
            actorLabel: "admin",
            context: {
              close: async () => {
                closed += 1
              },
            },
            page: {
              url: () => "https://app.example.com/dashboard",
              isClosed: () => false,
            },
            navigationIndex: 0,
            title: "Dashboard",
            materialSummary: {},
            network: [],
            pending: new Map(),
            timeUpdated: 0,
          },
        ],
      ]),
    }

    await cleanupBrowserSessions(state as any, ACTIVE_TTL_MS + 1)

    expect(closed).toBe(1)
    expect(state.sessions.size).toBe(0)

    const row = Database.use((db) =>
      db.select().from(SecurityBrowserSessionTable).where(eq(SecurityBrowserSessionTable.id, browserID)).get(),
    )
    expect(row?.status).toBe("expired")
  })

  test("closes browser sessions whose backing session row is gone", async () => {
    const sessionID = "sess-browser-runtime-deleted" as SessionID
    seedSession(sessionID)

    const actorSessionID = browserActorSessionID(sessionID, "user")
    const browserID = browserSessionID(sessionID, actorSessionID)
    let closed = 0

    const state = {
      sessions: new Map([
        [
          `${sessionID}:${actorSessionID}`,
          {
            sessionID,
            actorSessionID,
            browserSessionID: browserID,
            pageID: browserPageID(sessionID, actorSessionID),
            actorLabel: "user",
            context: {
              close: async () => {
                closed += 1
              },
            },
            page: {
              url: () => "https://app.example.com/profile",
              isClosed: () => false,
            },
            navigationIndex: 0,
            title: "Profile",
            materialSummary: {},
            network: [],
            pending: new Map(),
            timeUpdated: Date.now(),
          },
        ],
      ]),
    }

    Database.use((db) => db.delete(SessionTable).where(eq(SessionTable.id, sessionID)).run())
    await cleanupBrowserSessions(state as any)

    expect(closed).toBe(1)
    expect(state.sessions.size).toBe(0)
    const row = Database.use((db) =>
      db.select().from(SecurityBrowserSessionTable).where(eq(SecurityBrowserSessionTable.id, browserID)).get(),
    )
    expect(row).toBeUndefined()
  })
})
