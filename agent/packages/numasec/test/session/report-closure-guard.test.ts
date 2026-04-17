import { describe, expect, test } from "bun:test"
import type { MessageV2 } from "../../src/session/message-v2"
import { Instance } from "../../src/project/instance"
import { FindingTable } from "../../src/security/security.sql"
import { Session } from "../../src/session"
import { MessageTable, PartTable } from "../../src/session/session.sql"
import { blockedReportSummary, reportGuardSummary, reportGuardTurnParts } from "../../src/session/report-closure-guard"
import { Database, eq } from "../../src/storage/db"
import { tmpdir } from "../fixture/fixture"

function blockedPart(tool: "generate_report" | "finalize_report" = "generate_report"): MessageV2.ToolPart {
  return {
    id: "part-blocked" as any,
    sessionID: "sess-blocked" as any,
    messageID: "msg-blocked" as any,
    type: "tool",
    callID: "call-blocked",
    tool,
    state: {
      status: "completed",
      input: {
        format: "markdown",
      },
      output: "REPORT_BLOCKED_INCOMPLETE_STATE",
      output_v2: {},
      title: "Final report blocked: readiness incomplete [REPORT_BLOCKED_INCOMPLETE_STATE]",
      metadata: {
        blocked_code: "REPORT_BLOCKED_INCOMPLETE_STATE",
        closure: {
          hypothesis_open: 0,
          hypothesis_critical_open: 0,
        },
        truthReasons: [
          "10 verification(s) not promoted into findings",
          "4 provisional reportable finding(s) not counted as verified",
        ],
      },
      time: {
        start: 0,
        end: 1,
      },
    },
  }
}

function successfulPart(tool: "generate_report" | "finalize_report" = "generate_report"): MessageV2.ToolPart {
  return {
    id: "part-success" as any,
    sessionID: "sess-success" as any,
    messageID: "msg-success" as any,
    type: "tool",
    callID: "call-success",
    tool,
    state: {
      status: "completed",
      input: {
        format: "markdown",
      },
      output: "# Security Assessment Report",
      output_v2: {},
      title: "Report (markdown): 2 verified, risk 20/100",
      metadata: {
        reportRendered: "working",
      },
      time: {
        start: 0,
        end: 1,
      },
    },
  }
}

function finalPart(tool: "generate_report" | "finalize_report" = "generate_report"): MessageV2.ToolPart {
  return {
    id: "part-final" as any,
    sessionID: "sess-final" as any,
    messageID: "msg-final" as any,
    type: "tool",
    callID: "call-final",
    tool,
    state: {
      status: "completed",
      input: {
        format: "markdown",
      },
      output: "# Security Assessment Report",
      output_v2: {},
      title: "Report (markdown): 2 verified, risk 20/100",
      metadata: {
        reportRendered: "final",
        engagementRevision: 1,
      },
      time: {
        start: 0,
        end: 1,
      },
    },
  }
}

function runningPart(tool: "generate_report" | "finalize_report" = "generate_report"): MessageV2.ToolPart {
  return {
    id: "part-running" as any,
    sessionID: "sess-running" as any,
    messageID: "msg-running" as any,
    type: "tool",
    callID: "call-running",
    tool,
    state: {
      status: "running",
      input: {
        format: "markdown",
      },
      title: "Rendering report",
      time: {
        start: 0,
      },
    },
  }
}

function errorPart(tool: "generate_report" | "finalize_report" = "generate_report"): MessageV2.ToolPart {
  return {
    id: "part-error" as any,
    sessionID: "sess-error" as any,
    messageID: "msg-error" as any,
    type: "tool",
    callID: "call-error",
    tool,
    state: {
      status: "error",
      input: {
        format: "markdown",
      },
      error: "Tool execution aborted",
      time: {
        start: 0,
        end: 1,
      },
    },
  }
}

function assistantMessage(input: {
  id: string
  parentID: string
  parts: MessageV2.Part[]
}): MessageV2.WithParts {
  return {
    info: {
      id: input.id as any,
      sessionID: "sess-turn" as any,
      role: "assistant",
      time: {
        created: 0,
      },
      parentID: input.parentID as any,
      modelID: "gpt-5.4" as any,
      providerID: "openai" as any,
      mode: "pentest",
      agent: "pentest",
      path: {
        cwd: "/tmp",
        root: "/tmp",
      },
      cost: 0,
      tokens: {
        input: 0,
        output: 0,
        reasoning: 0,
        cache: {
          read: 0,
          write: 0,
        },
      },
    },
    parts: input.parts,
  }
}

describe("blockedReportSummary", () => {
  test("summarizes blocked generate_report results canonically", () => {
    const text = blockedReportSummary([blockedPart()])
    expect(text).toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(text).toContain("Open hypotheses: 0")
    expect(text).toContain("10 verification(s) not promoted into findings")
    expect(text).toContain("Do not treat this assessment as final.")
  })

  test("summarizes blocked finalize_report results canonically", () => {
    const text = blockedReportSummary([blockedPart("finalize_report")])
    expect(text).toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(text).toContain("Open hypotheses: 0")
    expect(text).toContain("10 verification(s) not promoted into findings")
  })

  test("returns nothing when no report closure guard is needed", () => {
    const text = blockedReportSummary([])
    expect(text).toBeUndefined()
  })
})

describe("reportGuardSummary", () => {
  test("blocks report-shaped prose when no canonical generate_report result exists", () => {
    const text = reportGuardSummary(
      [],
      "Penetration Test Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "pentest",
    )
    expect(text).toContain("REPORT_DRAFT_BLOCKED_NO_CANONICAL_TOOL")
    expect(text).toContain("No canonical report render result exists for this turn.")
  })

  test("does not block report-shaped prose after successful generate_report", () => {
    const text = reportGuardSummary(
      [successfulPart()],
      "Security Assessment Report\nExecutive Summary\nRecommendations",
      "report",
    )
    expect(text).toBeUndefined()
  })

  test("does not block report-shaped prose after successful finalize_report", () => {
    const text = reportGuardSummary(
      [successfulPart("finalize_report")],
      "Security Assessment Report\nExecutive Summary\nRecommendations",
      "report",
    )
    expect(text).toBeUndefined()
  })

  test("uses successful generate_report from an earlier assistant message in the same turn", () => {
    const parts = reportGuardTurnParts({
      messages: [
        assistantMessage({
          id: "msg-1",
          parentID: "user-1",
          parts: [successfulPart()],
        }),
        assistantMessage({
          id: "msg-2",
          parentID: "user-1",
          parts: [],
        }),
      ],
      parentID: "user-1",
      messageID: "msg-2",
    })
    const text = reportGuardSummary(
      parts,
      "Security Assessment Report\nExecutive Summary\nRecommendations",
      "report",
    )
    expect(text).toBeUndefined()
  })

  test("does not leak generate_report success across different parent turns", () => {
    const parts = reportGuardTurnParts({
      messages: [
        assistantMessage({
          id: "msg-1",
          parentID: "user-1",
          parts: [successfulPart()],
        }),
        assistantMessage({
          id: "msg-2",
          parentID: "user-2",
          parts: [],
        }),
      ],
      parentID: "user-2",
      messageID: "msg-2",
    })
    const text = reportGuardSummary(
      parts,
      "Security Assessment Report\nExecutive Summary\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_DRAFT_BLOCKED_NO_CANONICAL_TOOL")
  })

  test("uses successful finalize_report from an earlier assistant message in the same turn", () => {
    const parts = reportGuardTurnParts({
      messages: [
        assistantMessage({
          id: "msg-1",
          parentID: "user-1",
          parts: [successfulPart("finalize_report")],
        }),
        assistantMessage({
          id: "msg-2",
          parentID: "user-1",
          parts: [],
        }),
      ],
      parentID: "user-1",
      messageID: "msg-2",
    })
    const text = reportGuardSummary(
      parts,
      "Security Assessment Report\nExecutive Summary\nRecommendations",
      "report",
    )
    expect(text).toBeUndefined()
  })

  test("does not block non-security agents without a generate_report result", () => {
    const text = reportGuardSummary([], "Executive Summary\nRecommendations", "build")
    expect(text).toBeUndefined()
  })

  test("does not block blocker explanations that are not full report-shaped output", () => {
    const text = reportGuardSummary(
      [],
      "Why blocked:\n- Open hypotheses remain.\n- Promotion gaps remain.\nRecommendations: close the gaps first.",
      "pentest",
    )
    expect(text).toBeUndefined()
  })

  test("demotes final-claim prose into working status when no canonical report exists", () => {
    const text = reportGuardSummary(
      [],
      "Assessment Summary\nPentest complete. Verified findings: 3. Risk score: 22/100.",
      "pentest",
    )
    expect(text).toContain("Working assessment status")
    expect(text).toContain("pentest status update")
    expect(text).toContain("observed findings")
    expect(text).toContain("working risk view")
    expect(text).not.toContain("canonical report was not generated")
  })

  test("demotes incomplete final-claim prose without claiming tool absence", () => {
    const text = reportGuardSummary(
      [runningPart()],
      "Assessment Summary\nReport complete. Verified findings: 2.",
      "report",
    )
    expect(text).toContain("Working assessment status — report rendering did not complete in this turn.")
    expect(text).toContain("report status update")
    expect(text).not.toContain("No canonical generate_report result exists for this turn.")
  })

  test("demotes final-claim prose when only a working report exists", () => {
    const text = reportGuardSummary(
      [successfulPart()],
      "Assessment Summary\nFinal report complete. Verified findings: 2.",
      "report",
    )
    expect(text).toContain("Working assessment status — only a working report exists for the current session state.")
    expect(text).toContain("report status update")
    expect(text).toContain("observed findings")
  })

  test("demotes blocked final-claim prose instead of replacing it with blocker-only text", () => {
    const text = reportGuardSummary(
      [blockedPart()],
      "Assessment Summary\nFinal report complete. Verified findings: 4.",
      "report",
    )
    expect(text).toContain("Working assessment status")
    expect(text).toContain("report status update")
    expect(text).toContain("observed findings")
    expect(text).not.toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
    expect(text).not.toContain("canonical report was not generated")
  })

  test("still blocks report-shaped prose after a blocked generate_report result", () => {
    const text = reportGuardSummary(
      [blockedPart()],
      "Security Assessment Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
  })

  test("blocks report-shaped prose with truthful message when generate_report is still running", () => {
    const text = reportGuardSummary(
      [runningPart()],
      "Security Assessment Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_DRAFT_BLOCKED_REPORT_NOT_COMPLETED")
    expect(text).toContain("generate_report was requested but did not complete in this turn.")
    expect(text).toContain("still running at text close")
    expect(text).not.toContain("No canonical generate_report result exists for this turn.")
  })

  test("blocks report-shaped prose with truthful message when finalize_report is still running", () => {
    const text = reportGuardSummary(
      [runningPart("finalize_report")],
      "Security Assessment Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_DRAFT_BLOCKED_REPORT_NOT_COMPLETED")
    expect(text).toContain("finalize_report was requested but did not complete in this turn.")
    expect(text).toContain("finalize_report was still running at text close")
    expect(text).not.toContain("No canonical report render result exists for this turn.")
  })

  test("blocks report-shaped prose with truthful message when generate_report errors", () => {
    const text = reportGuardSummary(
      [errorPart()],
      "Security Assessment Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_DRAFT_BLOCKED_REPORT_NOT_COMPLETED")
    expect(text).toContain("generate_report was requested but did not complete in this turn.")
    expect(text).toContain("Tool execution aborted")
    expect(text).not.toContain("No canonical generate_report result exists for this turn.")
  })

  test("still blocks report-shaped prose after a blocked finalize_report result", () => {
    const text = reportGuardSummary(
      [blockedPart("finalize_report")],
      "Security Assessment Report\nExecutive Summary\nDetailed Findings\nRecommendations",
      "report",
    )
    expect(text).toContain("REPORT_BLOCKED_INCOMPLETE_STATE")
  })

  test("demotion header does not claim canonical report absence", () => {
    const text = reportGuardSummary(
      [],
      "Assessment Summary\nReport complete. Verified findings: 2.",
      "report",
    )
    expect(text).toContain("Working assessment status")
    expect(text).not.toContain("canonical report was not generated")
  })

  test("blocks final claims after the session reopens beyond the last final snapshot", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})
        Database.use((db) =>
          db
            .insert(FindingTable)
            .values({
              id: "SSEC-GUARD-REOPEN" as any,
              session_id: session.id,
              title: "Verified finding",
              severity: "high",
              description: "before reopen",
              confirmed: true,
              state: "verified",
              reportable: true,
              manual_override: true,
              url: "https://example.com/api/search",
              method: "GET",
              confidence: 0.9,
              tool_used: "test",
              time_created: 1,
              time_updated: 1,
            })
            .run(),
        )
        Database.use((db) =>
          db
            .insert(MessageTable)
            .values({
              id: "msg-final" as any,
              session_id: session.id,
              data: {
                role: "assistant",
              } as any,
              time_created: 2,
              time_updated: 2,
            })
            .run(),
        )
        Database.use((db) =>
          db
            .insert(PartTable)
            .values({
              id: "part-final" as any,
              message_id: "msg-final" as any,
              session_id: session.id,
              data: {
                type: "tool",
                callID: "call-final",
                tool: "generate_report",
                state: {
                  status: "completed",
                  input: {
                    format: "markdown",
                  },
                  output: "# Security Assessment Report",
                  output_v2: {},
                  title: "Report (markdown): 1 verified, risk 20/100",
                  metadata: {
                    reportRendered: "final",
                    engagementRevision: 1,
                  },
                  time: {
                    start: 1,
                    end: 2,
                  },
                },
              } as any,
              time_created: 2,
              time_updated: 2,
            })
            .run(),
        )
        Database.use((db) =>
          db
            .update(FindingTable)
            .set({
              description: "after reopen",
              time_updated: 3,
            })
            .where(eq(FindingTable.id, "SSEC-GUARD-REOPEN" as any))
            .run(),
        )

        const text = reportGuardSummary(
          [finalPart()],
          "Security Assessment Report\nExecutive Summary\nRecommendations",
          "report",
          session.id,
        )

        expect(text).toContain("REPORT_FINAL_SNAPSHOT_REOPENED")
        expect(text).toContain("session changed after it")
        expect(text).toContain("Current report state: final_ready")
      },
    })
  })
})
