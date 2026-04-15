import { describe, expect, test } from "bun:test"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import type { SessionID } from "../../src/session/schema"
import { SessionTable } from "../../src/session/session.sql"
import { EvidenceNodeTable } from "../../src/security/evidence.sql"
import { projectFindings } from "../../src/security/finding-projector"
import { FindingTable } from "../../src/security/security.sql"
import { Database, eq } from "../../src/storage/db"

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
        slug: "finding-projector-tests",
        directory: "/tmp",
        title: "finding-projector-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

describe("finding projector", () => {
  test("keeps projected findings isolated per session for identical candidates", () => {
    const firstSession = "sess-finding-projector-a" as SessionID
    const secondSession = "sess-finding-projector-b" as SessionID
    seedSession(firstSession)
    seedSession(secondSession)

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-METRICS-A" as any,
            session_id: firstSession,
            type: "verification",
            fingerprint: "metrics-a",
            status: "confirmed",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              family: "metrics",
              passed: true,
              title: "Metrics endpoint exposed without authentication",
              technical_severity: "medium",
              url: "https://example.com/metrics",
              method: "GET",
            },
          },
          {
            id: "ENOD-METRICS-B" as any,
            session_id: secondSession,
            type: "verification",
            fingerprint: "metrics-b",
            status: "confirmed",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              family: "metrics",
              passed: true,
              title: "Metrics endpoint exposed without authentication",
              technical_severity: "medium",
              url: "https://example.com/metrics",
              method: "GET",
            },
          },
        ])
        .run(),
    )

    const first = projectFindings(firstSession)
    const second = projectFindings(secondSession)
    expect(first.counts.raw).toBe(1)
    expect(second.counts.raw).toBe(1)

    const firstRows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, firstSession))
        .all(),
    )
    const secondRows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, secondSession))
        .all(),
    )

    expect(firstRows).toHaveLength(1)
    expect(secondRows).toHaveLength(1)
    expect(firstRows[0]?.title).toBe(secondRows[0]?.title)
    expect(firstRows[0]?.id).not.toBe(secondRows[0]?.id)
  })
})
