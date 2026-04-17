import { describe, expect, test, spyOn } from "bun:test"
import path from "path"
import type { Tool } from "../../src/tool/tool"
import type { MessageV2 } from "../../src/session/message-v2"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../../src/security/evidence.sql"
import { CoverageTable, FindingTable } from "../../src/security/security.sql"
import * as ChainProjection from "../../src/security/chain-projection"
import { readOperationalPhase } from "../../src/security/report/readiness"
import { GenerateReportTool } from "../../src/security/tool/generate-report"
import { ReportStatusTool } from "../../src/security/tool/report-status"
import { FinalizeReportTool } from "../../src/security/tool/finalize-report"

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
  return toolContextWithUser(sessionID)
}

function toolContextWithMessages(sessionID: SessionID, messages: MessageV2.WithParts[]): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-test",
    extra: {},
    messages,
    metadata() {},
    ask: async () => {},
  }
}

function toolContextWithUser(sessionID: SessionID, text?: string): Tool.Context {
  return toolContextWithMessages(sessionID, text ? [userMessage(sessionID, text)] : [])
}

function userMessage(sessionID: SessionID, text: string): MessageV2.WithParts {
  const messageID = `user-${sessionID}` as MessageID
  return {
    info: {
      id: messageID,
      sessionID,
      role: "user",
      time: {
        created: Date.now(),
      },
      agent: "test",
      model: {
        providerID: "test" as any,
        modelID: "test" as any,
      },
    } as any,
    parts: [
      {
        id: `part-${sessionID}` as any,
        sessionID,
        messageID,
        type: "text",
        text,
      },
    ],
  }
}

async function runReport(
  sessionID: SessionID,
  format: "sarif" | "markdown" | "html",
  extra?: {
    mode?: "working" | "final"
    output_path?: string
  },
) {
  const impl = await GenerateReportTool.init()
  return impl.execute({ format, mode: "working", ...(extra ?? {}) }, toolContext(sessionID))
}

async function runStatus(sessionID: SessionID, extra?: { include_ids?: boolean }) {
  const impl = await ReportStatusTool.init()
  return impl.execute({ ...(extra ?? {}) }, toolContext(sessionID))
}

async function runFinalizeReport(
  sessionID: SessionID,
  extra?: {
    format?: "sarif" | "markdown" | "html"
    mode?: "working" | "final"
    include_ids?: boolean
    output_path?: string
    note?: string
  },
) {
  const impl = await FinalizeReportTool.init()
  return impl.execute({ format: "markdown", mode: "final", ...(extra ?? {}) }, toolContext(sessionID))
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
    expect(typeof (result.metadata as any).engagementRevision).toBe("number")
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

  test("fails closed when projection helper fails", async () => {
    const sessionID = "sess-report-projection-fallback" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)

    const mocked = spyOn(ChainProjection, "deriveAttackPathProjection").mockImplementation(() => {
      throw new Error("projection unavailable")
    })

    try {
      await expect(runReport(sessionID, "markdown")).rejects.toThrow("projection unavailable")

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

  test("renders a working report by default when readiness is incomplete", async () => {
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
    const result = await impl.execute({ format: "markdown", mode: "working" }, toolContext(sessionID))
    expect(result.title).toContain("[WORKING] Report (markdown)")
    expect((result.metadata as any).reportRendered).toBe("working")
    expect((result.envelope as any).status).toBe("inconclusive")
    expect(result.output).toContain("REPORT_WORKING_DRAFT")
    expect(result.output).toContain("Truthfulness Notice")
  })

  test("blocks final report generation when critical hypotheses remain open", async () => {
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
    const result = await impl.execute(
      {
        format: "markdown",
        mode: "final",
      },
      toolContext(sessionID),
    )
    expect(result.title).toContain("Final report blocked")
    expect((result.envelope as any).status).toBe("inconclusive")
    expect(result.output).toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(result.output).toContain("Working report generation is still available")
  })

  test("keeps allow_incomplete as a working-mode compatibility flag", async () => {
    const sessionID = "sess-report-working-compat" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-COMPAT" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-compat",
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
    const result = await impl.execute(
      {
        format: "markdown",
        mode: "working",
        allow_incomplete: true,
        note: "compatibility path",
      },
      toolContextWithUser(sessionID, "generate the report"),
    )

    expect(result.title).toContain("[WORKING] Report (markdown)")
    expect((result.metadata as any).reportRendered).toBe("working")
    expect(result.output).toContain("REPORT_WORKING_DRAFT")
  })

  test("report_status exposes readiness separately from rendering", async () => {
    const sessionID = "sess-report-status-working" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-STATUS" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-status",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: {
            statement: "Critical auth bypass hypothesis still open",
          },
        })
        .run(),
    )

    const result = await runStatus(sessionID, { include_ids: true })
    expect(result.title).toContain("working_draft")
    expect(result.output).toContain("Report readiness: WORKING_DRAFT")
    expect(result.output).toContain("Recommended command: /report generate markdown (working)")
    expect((result.metadata as any).operationalPhase).toBe("close")
    expect((result.metadata as any).finalSnapshot.state).toBe("absent")
    expect((result.metadata as any).blockers[0].kind).toBe("open_hypothesis")
    expect((result.metadata as any).blockers[0].next_minimal_action).toContain("Resolve or confirm hypothesis")
    expect((result.metadata as any).blockers[0].next_operator_command).toContain("/verify next")
  })

  test("finalize_report returns a structured blocker in one call when final readiness is incomplete", async () => {
    const sessionID = "sess-finalize-report-blocked" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-FINALIZE" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-finalize",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: {
            statement: "Critical auth bypass hypothesis still open",
          },
        })
        .run(),
    )

    const result = await runFinalizeReport(sessionID, { include_ids: true })
    const body = JSON.parse(result.output)

    expect(result.title).toBe("Final report blocked")
    expect((result.metadata as any).blocked_code).toBe("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(body.blocked).toBe(true)
    expect(body.blocked_code).toBe("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(body.next_action).toContain("mode=working")
    expect(body.promotion_gap_ids).toBeArray()
  })

  test("finalize_report preserves canonical render metadata for working drafts", async () => {
    const sessionID = "sess-finalize-report-working" as SessionID
    seedSession(sessionID)
    insertReportFindings(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-OPEN-FINALIZE-WORKING" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-open-finalize-working",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: {
            statement: "Critical auth bypass hypothesis still open",
          },
        })
        .run(),
    )

    const result = await runFinalizeReport(sessionID, { mode: "working" })

    expect((result.metadata as any).reportRendered).toBe("working")
    expect((result.metadata as any).readiness.finalReady).toBe(false)
    expect(result.output).toContain("REPORT_WORKING_DRAFT")
  })

  test("does not treat an open hypothesis with an established finding as closure-open", async () => {
    const sessionID = "sess-report-hypothesis-established" as SessionID
    seedSession(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-ESTABLISHED" as any,
          session_id: sessionID,
          type: "hypothesis",
          fingerprint: "hyp-established",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: {
            statement: "Foreign profile read is possible",
          },
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(FindingTable)
        .values({
          id: "SSEC-HYP-ESTABLISHED" as any,
          session_id: sessionID,
          title: "Foreign profile read",
          severity: "high",
          description: "Victim profile data is readable",
          evidence: "",
          confirmed: true,
          state: "verified",
          family: "",
          source_hypothesis_id: "ENOD-HYP-ESTABLISHED",
          root_cause_key: "SSEC-HYP-ESTABLISHED",
          suppression_reason: "",
          reportable: true,
          manual_override: true,
          url: "https://example.com/api/profile/1",
          method: "GET",
          parameter: "",
          payload: "",
          confidence: 0.9,
          tool_used: "manual",
          remediation_summary: "Enforce ownership checks",
          owasp_category: "A01:2021 - Broken Access Control",
        })
        .run(),
    )

    const result = await runReport(sessionID, "markdown")
    expect(result.title).toContain("Report (markdown)")
    expect(result.output).not.toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
  })

  test("does not count redundant verification siblings as promotion gaps once a finding resolves the hypothesis", async () => {
    const sessionID = "sess-report-gap-siblings" as SessionID
    seedSession(sessionID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values([
          {
            id: "ENOD-HYP-GAP-SIBLING" as any,
            session_id: sessionID,
            type: "hypothesis",
            fingerprint: "hyp-gap-sibling",
            status: "open",
            confidence: 0.8,
            source_tool: "test",
            payload: {
              statement: "Search endpoint leaks records",
            },
          },
          {
            id: "ENOD-VER-GAP-SIBLING-1" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "ver-gap-sibling-1",
            status: "confirmed",
            confidence: 0.9,
            source_tool: "test",
            payload: {
              family: "sqli",
              passed: true,
              control: "positive",
            },
          },
          {
            id: "ENOD-VER-GAP-SIBLING-2" as any,
            session_id: sessionID,
            type: "verification",
            fingerprint: "ver-gap-sibling-2",
            status: "confirmed",
            confidence: 0.85,
            source_tool: "test",
            payload: {
              family: "sqli",
              passed: true,
              control: "positive",
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
            id: "EEDG-HYP-GAP-SIBLING-1" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-GAP-SIBLING" as any,
            to_node_id: "ENOD-VER-GAP-SIBLING-1" as any,
            relation: "verifies",
            weight: 1,
            metadata: {},
          },
          {
            id: "EEDG-HYP-GAP-SIBLING-2" as any,
            session_id: sessionID,
            from_node_id: "ENOD-HYP-GAP-SIBLING" as any,
            to_node_id: "ENOD-VER-GAP-SIBLING-2" as any,
            relation: "verifies",
            weight: 1,
            metadata: {},
          },
        ])
        .run(),
    )
    Database.use((db) =>
      db
        .insert(FindingTable)
        .values({
          id: "SSEC-GAP-SIBLING" as any,
          session_id: sessionID,
          title: "SQL injection in search endpoint",
          severity: "high",
          description: "Search query leaks arbitrary rows",
          evidence: "",
          confirmed: true,
          state: "verified",
          family: "",
          source_hypothesis_id: "ENOD-HYP-GAP-SIBLING",
          root_cause_key: "SSEC-GAP-SIBLING",
          suppression_reason: "",
          reportable: true,
          manual_override: true,
          url: "https://example.com/rest/search",
          method: "GET",
          parameter: "q",
          payload: "",
          confidence: 0.91,
          tool_used: "manual",
          remediation_summary: "Use parameterized queries",
          owasp_category: "A03:2021 - Injection",
        })
        .run(),
    )

    const result = await runReport(sessionID, "markdown")
    expect(result.title).toContain("Report (markdown)")
    expect((result.metadata as any).projection.promotion_gaps).toBe(0)
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

  test("derives operational phase from canonical readiness", async () => {
    const exploreID = "sess-phase-explore" as SessionID
    seedSession(exploreID)
    expect(readOperationalPhase(exploreID)).toBe("explore")

    const verifyID = "sess-phase-verify" as SessionID
    seedSession(verifyID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-PHASE-VERIFY" as any,
          session_id: verifyID,
          type: "hypothesis",
          fingerprint: "hyp-phase-verify",
          status: "open",
          confidence: 0.6,
          source_tool: "test",
          payload: { statement: "Investigate target" },
        })
        .run(),
    )
    expect(readOperationalPhase(verifyID)).toBe("verify")

    const closeID = "sess-phase-close" as SessionID
    seedSession(closeID)
    insertReportFindings(closeID)
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-HYP-PHASE-CLOSE" as any,
          session_id: closeID,
          type: "hypothesis",
          fingerprint: "hyp-phase-close",
          status: "open",
          confidence: 0.9,
          source_tool: "test",
          payload: { statement: "Close remaining blocker" },
        })
        .run(),
    )
    expect(readOperationalPhase(closeID)).toBe("close")

    const reportID = "sess-phase-report" as SessionID
    seedSession(reportID)
    insertReportFindings(reportID)
    expect(readOperationalPhase(reportID)).toBe("report")
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
