import { describe, expect, test, spyOn } from "bun:test"
import path from "path"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../../src/security/evidence.sql"
import { CoverageTable, FindingTable } from "../../src/security/security.sql"
import * as ChainProjection from "../../src/security/chain-projection"
import { GenerateReportTool } from "../../src/security/tool/generate-report"

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make(`project-${sessionID}`)
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
      .values({
        id: sessionID,
        project_id: projectID,
        slug: "report-projection-tests",
        directory: "/workspace",
        title: "report-projection-tests",
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

async function runReport(
  sessionID: SessionID,
  format: "sarif" | "markdown" | "html",
  extra?: {
    output_path?: string
  },
) {
  const impl = await GenerateReportTool.init()
  return impl.execute({ format, ...(extra ?? {}) }, toolContext(sessionID))
}

function insertReportFindings(sessionID: SessionID) {
  const suffix = sessionID.replace(/[^a-zA-Z0-9]/g, "").slice(-8).toUpperCase()
  Database.use((db) =>
    db
      .insert(FindingTable)
      .values([
        {
          id: `SSEC-RPT${suffix}01` as any,
          session_id: sessionID,
          title: "IDOR in user profile endpoint",
          severity: "high",
          description: "User profile endpoint leaks other user records",
          url: "https://example.com/api/users/1",
          method: "GET",
          confidence: 0.9,
          owasp_category: "A01:2021 - Broken Access Control",
          remediation_summary: "Enforce ownership checks for profile reads",
        },
        {
          id: `SSEC-RPT${suffix}02` as any,
          session_id: sessionID,
          title: "Privilege escalation in user update endpoint",
          severity: "medium",
          description: "Role field can be updated without authorization",
          url: "https://example.com/api/users/2",
          method: "PUT",
          confidence: 0.8,
          owasp_category: "A01:2021 - Broken Access Control",
          remediation_summary: "Apply server-side authorization on role changes",
        },
      ])
      .onConflictDoNothing()
      .run(),
  )
}

describe("generate_report projection path", () => {
  test("uses canonical projection and persists chain coverage projection", async () => {
    const sessionID = "sess-report-projection-markdown" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)

    const result = await runReport(sessionID, "markdown")

    expect(result.title).toContain("Report (markdown)")
    expect(result.output).toContain("## Attack Paths")
    expect((result.envelope as any).metrics.chain_count).toBeGreaterThanOrEqual(1)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    expect(rows.some((item) => item.chain_id.startsWith("CHAIN-"))).toBe(true)

    const coverage = Database.use((db) =>
      db
        .select()
        .from(CoverageTable)
        .where(eq(CoverageTable.session_id, sessionID))
        .all(),
    )
    expect(coverage.length).toBeGreaterThan(0)
  })

  test("keeps SARIF and HTML output contracts stable", async () => {
    const sessionID = "sess-report-projection-formats" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)

    const sarif = await runReport(sessionID, "sarif")
    const parsed = JSON.parse(sarif.output)
    expect(parsed.version).toBe("2.1.0")
    expect(parsed.runs[0].results.length).toBe(2)

    const html = await runReport(sessionID, "html")
    expect(html.output.startsWith("<!DOCTYPE html>")).toBe(true)
    expect(html.output).toContain("<h2>Findings</h2>")
  })

  test("falls back to legacy report reads when projection helper fails", async () => {
    const sessionID = "sess-report-projection-fallback" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)

    const mocked = spyOn(ChainProjection, "deriveAttackPathProjection").mockImplementation(() => {
      throw new Error("projection unavailable")
    })

    try {
      const result = await runReport(sessionID, "markdown")
      expect(result.title).toContain("Report (markdown)")
      expect(result.output).toContain("## Findings")

      const rows = Database.use((db) =>
        db
          .select()
          .from(FindingTable)
          .where(eq(FindingTable.session_id, sessionID))
          .all(),
      )
      expect(rows.every((item) => item.chain_id === "")).toBe(true)
    } finally {
      mocked.mockRestore()
    }
  })

  test("blocks report generation when critical hypotheses remain open", async () => {
    const sessionID = "sess-report-closure-block" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-001" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-001",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: {
            statement: "Critical auth bypass hypothesis still open",
          },
        })
        .run(),
    )

    const impl = await GenerateReportTool.init()
    const result = await impl.execute({ format: "markdown" }, toolContext(sessionID))
    expect(result.title).toBe("Report blocked: closure incomplete")
    expect((result.envelope as any).status).toBe("inconclusive")
    expect(result.output).toContain("closure policy")
  })

  test("allows incomplete report only with explicit override reason", async () => {
    const sessionID = "sess-report-closure-override" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-002" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-002",
          status: "open",
          confidence: 0.85,
          source_tool: "test",
          payload: {
            statement: "Open critical chain hypothesis",
          },
        })
        .run(),
    )

    const impl = await GenerateReportTool.init()
    await expect(impl.execute({ format: "markdown", allow_incomplete: true }, toolContext(sessionID))).rejects.toThrow(
      "incomplete_reason",
    )

    const result = await impl.execute(
      {
        format: "markdown",
        allow_incomplete: true,
        incomplete_reason: "Manual triage accepted for this run",
      },
      toolContext(sessionID),
    )
    expect(result.title).toContain("[INCOMPLETE]")
    expect((result.envelope as any).status).toBe("inconclusive")
    expect((result.metadata as any).override).toBe(true)
  })

  test("writes report file when output_path is provided", async () => {
    const sessionID = "sess-report-output-path" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    const outPath = path.join("/tmp", `numasec-report-${sessionID}.md`)

    const result = await runReport(sessionID, "markdown", {
      output_path: outPath,
    })

    const file = Bun.file(outPath)
    expect(await file.exists()).toBe(true)
    const text = await file.text()
    expect(text).toContain("# Security Assessment Report")
    expect((result.metadata as any).outputPath).toBe(outPath)
  })

  test("drops findings tied only to superseded hypotheses from canonical projection", async () => {
    const sessionID = "sess-report-canonical-superseded" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)

    Database.use((db) =>
      db
        .insert(FindingTable)
        .values([
          {
            id: "SSEC-CANON-OLD" as any,
            session_id: sessionID,
            title: "Duplicate root cause old",
            severity: "high",
            description: "old",
            url: "https://example.com/api/signUp",
            method: "POST",
            parameter: "key",
            confidence: 0.9,
          },
          {
            id: "SSEC-CANON-NEW" as any,
            session_id: sessionID,
            title: "Duplicate root cause old",
            severity: "high",
            description: "new",
            url: "https://example.com/api/signUp",
            method: "POST",
            parameter: "key",
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
            id: "ENOD-HYP-OLD" as any,
            session_id: sessionID,
            type: "hypothesis",
            fingerprint: "hyp-old",
            status: "superseded",
            confidence: 0.9,
            source_tool: "test",
            payload: { statement: "old" },
          },
          {
            id: "ENOD-HYP-NEW" as any,
            session_id: sessionID,
            type: "hypothesis",
            fingerprint: "hyp-new",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: { statement: "new" },
          },
          {
            id: "ENOD-FIND-OLD" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "find-old",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: { finding_id: "SSEC-CANON-OLD" },
          },
          {
            id: "ENOD-FIND-NEW" as any,
            session_id: sessionID,
            type: "finding",
            fingerprint: "find-new",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: { finding_id: "SSEC-CANON-NEW" },
          },
        ])
        .run(),
    )
    Database.use((db) =>
      db
        .insert(EvidenceEdgeTable)
        .values([
          {
            id: "EEDG-OLD" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-OLD" as any,
            to_node_id: "ENOD-FIND-OLD" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
          {
            id: "EEDG-NEW" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-NEW" as any,
            to_node_id: "ENOD-FIND-NEW" as any,
            relation: "establishes",
            weight: 1,
            metadata: {},
          },
        ])
        .run(),
    )

    const result = await runReport(sessionID, "markdown")
    expect((result.metadata as any).canonical.dropped_superseded_ids).toContain("SSEC-CANON-OLD")
    expect((result.metadata as any).canonical.canonical_count).toBeGreaterThanOrEqual(3)
    expect(result.output).not.toContain("SSEC-CANON-OLD")
  })
})
