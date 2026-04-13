import { describe, expect, test } from "bun:test"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import type { SessionID } from "../../src/session/schema"
import { SessionTable } from "../../src/session/session.sql"
import { deriveAttackPathProjection } from "../../src/security/chain-projection"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../../src/security/evidence.sql"
import { FindingTable } from "../../src/security/security.sql"
import { Database } from "../../src/storage/db"

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
        slug: "chain-derivation-tests",
        directory: "/tmp",
        title: "chain-derivation-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

describe("chain derivation", () => {
  test("requires strong graph signals when finding nodes exist", () => {
    const sessionID = "sess-chain-derivation-graph" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(FindingTable)
        .values([
          {
            id: "SSEC-CHAIN-001" as any,
            session_id: sessionID,
            title: "IDOR read exposure",
            severity: "high",
            description: "Cross-user profile read",
            url: "https://example.com/api/users/1",
            method: "GET",
            confidence: 0.9,
          },
          {
            id: "SSEC-CHAIN-002" as any,
            session_id: sessionID,
            title: "IDOR write exposure",
            severity: "medium",
            description: "Cross-user profile write",
            url: "https://example.com/api/users/2",
            method: "PUT",
            confidence: 0.8,
          },
        ])
        .run(),
    )

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-HYP-CHAIN-001" as any,
            session_id: sessionID,
            type: "hypothesis",
            fingerprint: "hyp-chain-001",
            status: "open",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              statement: "Linked IDOR hypothesis",
            },
          },
          {
            id: "ENOD-FINDING-001" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "finding-001",
            status: "active",
            confidence: 0.9,
            source_tool: "test",
            payload: {
              finding_id: "SSEC-CHAIN-001",
            },
          },
          {
            id: "ENOD-FINDING-002" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "finding-002",
            status: "active",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              finding_id: "SSEC-CHAIN-002",
            },
          },
        ])
        .run(),
    )

    const first = deriveAttackPathProjection({
      sessionID,
    })
    expect(first.chains.length).toBe(0)

    Database.use((db) =>
      db
        .insert(EvidenceEdgeTable)
        .values([
          {
            id: "EEDG-CHAIN-001" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-CHAIN-001" as any,
            to_node_id: "ENOD-FINDING-001" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
          {
            id: "EEDG-CHAIN-002" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-CHAIN-001" as any,
            to_node_id: "ENOD-FINDING-002" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
        ])
        .run(),
    )

    const second = deriveAttackPathProjection({
      sessionID,
    })
    const third = deriveAttackPathProjection({
      sessionID,
    })

    expect(second.chains.length).toBe(1)
    expect(second.chains[0]?.id).toContain("CHAIN-")
    expect(second.chains[0]?.id).toBe(third.chains[0]?.id)
  })

  test("does not chain findings across different hosts even with shared hypothesis", () => {
    const sessionID = "sess-chain-derivation-host-guardrail" as SessionID
    seedSession(sessionID)

    Database.use((db) =>
      db
        .insert(FindingTable)
        .values([
          {
            id: "SSEC-HOST-001" as any,
            session_id: sessionID,
            title: "Anonymous signup open",
            severity: "high",
            description: "project A",
            url: "https://myadjrank.web.app/api/auth",
            method: "POST",
            confidence: 0.9,
          },
          {
            id: "SSEC-HOST-002" as any,
            session_id: sessionID,
            title: "Anonymous signup open",
            severity: "high",
            description: "project B",
            url: "https://musketier.web.app/api/auth",
            method: "POST",
            confidence: 0.9,
          },
        ])
        .run(),
    )

    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-HYP-HOST-001" as any,
            session_id: sessionID,
            type: "hypothesis",
            fingerprint: "hyp-host-001",
            status: "confirmed",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              statement: "shared root cause",
            },
          },
          {
            id: "ENOD-FIND-HOST-001" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "find-host-001",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: {
              finding_id: "SSEC-HOST-001",
            },
          },
          {
            id: "ENOD-FIND-HOST-002" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "find-host-002",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: {
              finding_id: "SSEC-HOST-002",
            },
          },
        ])
        .run(),
    )

    Database.use((db) =>
      db
        .insert(EvidenceEdgeTable)
        .values([
          {
            id: "EEDG-HOST-001" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-HOST-001" as any,
            to_node_id: "ENOD-FIND-HOST-001" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
          {
            id: "EEDG-HOST-002" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-HOST-001" as any,
            to_node_id: "ENOD-FIND-HOST-002" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
        ])
        .run(),
    )

    const result = deriveAttackPathProjection({
      sessionID,
    })
    expect(result.chains.length).toBe(0)
  })
})
