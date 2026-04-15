import { describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { EvidenceNodeTable, EvidenceRunTable } from "../../src/security/evidence.sql"
import { CoverageTable, FindingTable } from "../../src/security/security.sql"
import { SecurityActorSessionTable, SecurityTargetProfileTable } from "../../src/security/runtime/runtime.sql"
import { mergeActorSession, readActorSession } from "../../src/security/runtime/actor-session-store"
import { noteTargetSignal } from "../../src/security/runtime/target-profile-store"
import { canonicalSecuritySessionID } from "../../src/security/security-session"
import { RecordEvidenceTool } from "../../src/security/tool/record-evidence"
import { QueryGraphTool } from "../../src/security/tool/query-graph"
import { PlanNextTool } from "../../src/security/tool/plan-next"
import { GenerateReportTool } from "../../src/security/tool/generate-report"

function seedLineage(rootID: SessionID, childID: SessionID) {
  const projectID = ProjectID.make(`project-${rootID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/workspace",
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values([
        {
          id: rootID,
          project_id: projectID,
          slug: `root-${rootID}`,
          directory: "/workspace",
          title: `root-${rootID}`,
          version: "1",
        },
        {
          id: childID,
          project_id: projectID,
          parent_id: rootID,
          slug: `child-${childID}`,
          directory: "/workspace",
          title: `child-${childID}`,
          version: "1",
        },
      ])
      .onConflictDoNothing()
      .run(),
  )
}

function seedCycle(aID: SessionID, bID: SessionID, cID: SessionID, dID: SessionID) {
  const projectID = ProjectID.make(`project-${aID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/workspace",
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values([
        {
          id: aID,
          project_id: projectID,
          slug: `a-${aID}`,
          directory: "/workspace",
          title: `a-${aID}`,
          version: "1",
        },
        {
          id: bID,
          project_id: projectID,
          slug: `b-${bID}`,
          directory: "/workspace",
          title: `b-${bID}`,
          version: "1",
        },
        {
          id: cID,
          project_id: projectID,
          slug: `c-${cID}`,
          directory: "/workspace",
          title: `c-${cID}`,
          version: "1",
        },
        {
          id: dID,
          project_id: projectID,
          slug: `d-${dID}`,
          directory: "/workspace",
          title: `d-${dID}`,
          version: "1",
        },
      ])
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .update(SessionTable)
      .set({ parent_id: cID })
      .where(eq(SessionTable.id, aID))
      .run(),
  )
  Database.use((db) =>
    db
      .update(SessionTable)
      .set({ parent_id: aID })
      .where(eq(SessionTable.id, bID))
      .run(),
  )
  Database.use((db) =>
    db
      .update(SessionTable)
      .set({ parent_id: bID })
      .where(eq(SessionTable.id, cID))
      .run(),
  )
  Database.use((db) =>
    db
      .update(SessionTable)
      .set({ parent_id: aID })
      .where(eq(SessionTable.id, dID))
      .run(),
  )
}

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-security-session-lineage",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

function insertReportFindings(sessionID: SessionID) {
  const suffix = sessionID.replace(/[^a-zA-Z0-9]/g, "").slice(-8).toUpperCase()
  Database.use((db) =>
    db
      .insert(FindingTable)
      .values([
        {
          id: `SSEC-LIN${suffix}01` as any,
          session_id: sessionID,
          title: "IDOR in user profile endpoint",
          severity: "high",
          description: "User profile endpoint leaks other user records",
          url: "https://example.com/api/users/1",
          method: "GET",
          confidence: 0.9,
          reportable: true,
          manual_override: true,
          state: "verified",
          tool_used: "test",
          owasp_category: "A01:2021 - Broken Access Control",
          remediation_summary: "Enforce ownership checks for profile reads",
        },
        {
          id: `SSEC-LIN${suffix}02` as any,
          session_id: sessionID,
          title: "Privilege escalation in user update endpoint",
          severity: "medium",
          description: "Role field can be updated without authorization",
          url: "https://example.com/api/users/2",
          method: "PUT",
          confidence: 0.8,
          reportable: true,
          manual_override: true,
          state: "verified",
          tool_used: "test",
          owasp_category: "A01:2021 - Broken Access Control",
          remediation_summary: "Apply server-side authorization on role changes",
        },
      ])
      .onConflictDoNothing()
      .run(),
  )
}

describe("security session lineage", () => {
  test("canonical security session ids stay stable when session parent links are cyclic", () => {
    const aID = "sess-cycle-a" as SessionID
    const bID = "sess-cycle-b" as SessionID
    const cID = "sess-cycle-c" as SessionID
    const dID = "sess-cycle-d" as SessionID
    seedCycle(aID, bID, cID, dID)

    const canonical = canonicalSecuritySessionID(aID)
    expect(canonical).toBe(aID)
    expect(canonicalSecuritySessionID(bID)).toBe(canonical)
    expect(canonicalSecuritySessionID(cID)).toBe(canonical)
    expect(canonicalSecuritySessionID(dID)).toBe(canonical)
  })

  test("records graph evidence in the root session and exposes it from child queries", async () => {
    const rootID = "sess-lineage-root-graph" as SessionID
    const childID = "sess-lineage-child-graph" as SessionID
    seedLineage(rootID, childID)

    const record = await (await RecordEvidenceTool.init()).execute(
      {
        type: "observation",
        payload: {
          url: "https://example.com/admin",
          method: "GET",
          body: "sensitive content",
        },
      },
      toolContext(childID),
    )
    expect(record.title).toContain("Evidence")

    const graph = await (await QueryGraphTool.init()).execute(
      {
        include_edges: true,
      },
      toolContext(childID),
    )
    expect((graph.metadata as any).nodeCount).toBe(1)

    const rootRows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, rootID))
        .all(),
    )
    const childRows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, childID))
        .all(),
    )
    expect(rootRows).toHaveLength(1)
    expect(childRows).toHaveLength(0)
  })

  test("shares actor sessions, target profiles, and planner runtime state across child sessions", async () => {
    const rootID = "sess-lineage-root-runtime" as SessionID
    const childID = "sess-lineage-child-runtime" as SessionID
    seedLineage(rootID, childID)

    const merged = await mergeActorSession({
      sessionID: childID,
      actorLabel: "admin",
      material: {
        actorEmail: "admin@example.com",
        actorRole: "admin",
        headers: {
          authorization: "Bearer test-token",
        },
        cookies: [{ name: "session", value: "abc123" }],
        lastOrigin: "https://example.com",
        lastURL: "https://example.com/app",
      },
    })
    const rootMaterial = await readActorSession({
      sessionID: rootID,
      actorLabel: "admin",
    })
    expect(rootMaterial?.actorSessionID).toBe(merged.actorSessionID)

    await noteTargetSignal(childID, "https://example.com/api/users", "rate_limited")

    const plan = await (await PlanNextTool.init()).execute(
      {
        state: "scope_defined",
        target: "https://example.com",
        scope: "deep",
      },
      toolContext(childID),
    )
    expect((plan.metadata as any).runtimeActorSessions).toBeGreaterThanOrEqual(1)
    expect((plan.metadata as any).runtimeTargetProfiles).toBeGreaterThanOrEqual(1)

    const actorRow = Database.use((db) =>
      db
        .select()
        .from(SecurityActorSessionTable)
        .where(eq(SecurityActorSessionTable.id, merged.actorSessionID))
        .get(),
    )
    expect(actorRow?.session_id).toBe(rootID)

    const profiles = Database.use((db) =>
      db
        .select()
        .from(SecurityTargetProfileTable)
        .where(eq(SecurityTargetProfileTable.session_id, rootID))
        .all(),
    )
    expect(profiles.some((item) => item.origin === "https://example.com" && item.status === "throttled")).toBe(true)

    const run = Database.use((db) =>
      db
        .select()
        .from(EvidenceRunTable)
        .where(eq(EvidenceRunTable.session_id, rootID))
        .get(),
    )
    expect(run?.session_id).toBe(rootID)
  })

  test("generates reports from root findings when invoked from a child session", async () => {
    const rootID = "sess-lineage-root-report" as SessionID
    const childID = "sess-lineage-child-report" as SessionID
    seedLineage(rootID, childID)
    insertReportFindings(rootID)

    const report = await (await GenerateReportTool.init()).execute(
      {
        format: "markdown",
        mode: "working",
      },
      toolContext(childID),
    )
    expect(report.title).toContain("Report (markdown)")
    expect(report.output).toContain("# Security Assessment Report")

    const rootCoverage = Database.use((db) =>
      db
        .select()
        .from(CoverageTable)
        .where(eq(CoverageTable.session_id, rootID))
        .all(),
    )
    const childCoverage = Database.use((db) =>
      db
        .select()
        .from(CoverageTable)
        .where(eq(CoverageTable.session_id, childID))
        .all(),
    )
    expect(rootCoverage.length).toBeGreaterThan(0)
    expect(childCoverage).toHaveLength(0)
  })
})
