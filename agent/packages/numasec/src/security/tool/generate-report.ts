/**
 * Tool: generate_report
 *
 * Generate a security assessment report in SARIF, HTML, or Markdown format.
 */

import z from "zod"
import path from "path"
import { mkdir } from "fs/promises"
import { Tool } from "../../tool/tool"
import { generateSarif, generateMarkdown, generateHtml, calculateRiskScore } from "../report/generators"
import * as ChainProjection from "../chain-projection"
import { readEngagementTruth } from "../report/readiness"
import { canonicalSecuritySessionID } from "../security-session"
import { FindingTable } from "../security.sql"
import { makeToolResultEnvelope } from "./result-envelope"

type Finding = (typeof FindingTable)["$inferSelect"]

const BLOCKED = "REPORT_BLOCKED_INCOMPLETE_STATE"

function chooseTargetUrl(findings: Finding[]) {
  const counts = new Map<string, number>()
  for (const finding of findings) {
    const value = (finding.url ?? "").trim()
    if (!value) continue
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  let best = ""
  let score = -1
  for (const entry of counts.entries()) {
    if (entry[1] <= score) continue
    best = entry[0]
    score = entry[1]
  }
  return best || "unknown"
}

function reportMode(params: {
  mode: "working" | "final"
  strict?: boolean
}) {
  if (params.strict === true) return "final"
  return params.mode
}

function reportNote(params: {
  note?: string
  incomplete_reason?: string
}) {
  return (params.note ?? params.incomplete_reason ?? "").trim()
}

const DESCRIPTION = `Generate a security assessment report from saved findings.
Formats: sarif (for CI/CD), markdown (for documentation), html (self-contained visual report).

Default behavior renders a working report from the current verified state.
Use mode=final (or strict=true) when you need a closure-gated final report.`

export const GenerateReportTool = Tool.define("generate_report", {
  description: DESCRIPTION,
  parameters: z.object({
    format: z.enum(["sarif", "markdown", "html"]).default("markdown").describe("Report format"),
    target_url: z.string().optional().describe("Target URL (auto-detected from findings if omitted)"),
    mode: z
      .enum(["working", "final"])
      .default("working")
      .describe("working renders the current report state; final enforces closure readiness"),
    strict: z.boolean().optional().describe("Deprecated alias for mode=final"),
    note: z.string().optional().describe("Optional operator note embedded in the rendered report"),
    allow_incomplete: z
      .boolean()
      .optional()
      .describe("Deprecated compatibility flag; working mode is now the default interactive behavior"),
    incomplete_reason: z.string().optional().describe("Deprecated alias for note"),
    output_path: z.string().optional().describe("Optional file path to write the generated report"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const truth = readEngagementTruth(sessionID)
    const readiness = truth.readiness
    ChainProjection.persistAttackPathProjection(sessionID, readiness.projection.snapshot)

    if (!readiness.working_ready) {
      return {
        title: "No findings to report",
        metadata: {
          count: 0,
          requestedMode: reportMode(params),
          state: readiness.state,
          engagementRevision: truth.revision,
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [{ type: "report", generated: false, finding_count: 0 }],
        }),
        output: "No findings saved for this session. Save findings first with save_finding or upsert_finding.",
      }
    }

    const requested = reportMode(params)
    if (requested === "final" && !readiness.final_ready) {
      return {
        title: `Final report blocked: readiness incomplete [${BLOCKED}]`,
        metadata: {
          blocked_code: BLOCKED,
          requestedMode: requested,
          state: readiness.state,
          closure: readiness.closure,
          truthReasons: readiness.truth_reasons,
          projection: readiness.projection.counts,
          engagementRevision: truth.revision,
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "report_closure",
              blocked: true,
              blocked_code: BLOCKED,
              requested_mode: requested,
              working_ready: readiness.working_ready,
              final_ready: readiness.final_ready,
              open_hypotheses: readiness.closure.hypothesis_open,
              open_critical_hypotheses: readiness.closure.hypothesis_critical_open,
            },
          ],
          metrics: {
            closure_open_hypotheses: readiness.closure.hypothesis_open,
            closure_open_critical_hypotheses: readiness.closure.hypothesis_critical_open,
            promotion_gaps: readiness.projection.counts.promotion_gaps,
            provisional_reportable_findings: readiness.projection.provisional.length,
          },
        }),
        output: [
          BLOCKED,
          "Final report generation blocked by readiness policy.",
          "Working report generation is still available.",
          "Do not narrate this session as a final report from memory.",
          `Verified findings: ${readiness.projection.counts.verified}`,
          `Provisional findings: ${readiness.projection.provisional.length}`,
          `Promotion gaps: ${readiness.projection.counts.promotion_gaps}`,
          `Open hypotheses: ${readiness.closure.hypothesis_open}`,
          `Open critical hypotheses: ${readiness.closure.hypothesis_critical_open}`,
          ...readiness.truth_reasons.map((item) => `- ${item}`),
          "Run report_status to inspect readiness, or rerun generate_report in working mode (the interactive default).",
        ].join("\n"),
      }
    }

    const projection = readiness.projection
    const findings = projection.verified
    const chains = projection.chains
    const canonical = projection.canonical
    const targetUrl = params.target_url ?? chooseTargetUrl(projection.all)
    const verifiedRiskScore = calculateRiskScore(findings)
    const upperBoundRiskScore = calculateRiskScore([...findings, ...projection.provisional])
    const note = reportNote(params)
    const state = readiness.final_ready ? "final" : "working_draft"
    const incomplete = state === "working_draft"

    let report: string
    switch (params.format) {
      case "sarif":
        report = generateSarif(findings, targetUrl, chains, {
          incomplete,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
          report_state: state,
          requested_mode: requested,
          note: note || undefined,
          truth_reasons: readiness.truth_reasons,
        })
        break
      case "html":
        report = generateHtml(findings, targetUrl, chains, {
          incomplete,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
          report_state: state,
          requested_mode: requested,
          note: note || undefined,
          truth_reasons: readiness.truth_reasons,
        })
        break
      case "markdown":
      default:
        report = generateMarkdown(findings, targetUrl, chains, {
          incomplete,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          provisional: projection.provisional,
          suppressed: projection.suppressed,
          promotion_gaps: projection.counts.promotion_gaps,
          report_state: state,
          requested_mode: requested,
          note: note || undefined,
          truth_reasons: readiness.truth_reasons,
        })
        break
    }

    const outputPath = (params.output_path ?? "").trim()
    let savedPath = ""
    if (outputPath) {
      const resolved = path.resolve(outputPath)
      const dir = path.dirname(resolved)
      await mkdir(dir, { recursive: true })
      await Bun.write(Bun.file(resolved), report)
      savedPath = resolved
    }

    return {
      title: `${state === "working_draft" ? "[WORKING] " : ""}Report (${params.format}): ${findings.length} verified${projection.provisional.length > 0 ? ` + ${projection.provisional.length} provisional` : ""}, risk ${verifiedRiskScore}/100${upperBoundRiskScore !== verifiedRiskScore ? ` (upper bound ${upperBoundRiskScore}/100)` : ""}`,
      metadata: {
        format: params.format,
        findings: projection.all.length,
        verifiedFindings: findings.length,
        provisionalFindings: projection.provisional.length,
        suppressedFindings: projection.suppressed.length,
        riskScore: verifiedRiskScore,
        upperBoundRiskScore,
        canonical,
        outputPath: savedPath,
        closure: readiness.closure,
        incomplete,
        requestedMode: requested,
        reportState: state,
        reportRendered: incomplete ? "working" : "final",
        engagementRevision: truth.revision,
        finalReady: readiness.final_ready,
        note,
        truthReasons: readiness.truth_reasons,
        promotionGapIds: projection.promotion_gap_ids,
        projection: projection.counts,
        compatibility: {
          allow_incomplete: params.allow_incomplete === true,
          incomplete_reason: (params.incomplete_reason ?? "").trim().length > 0,
          strict: params.strict === true,
        },
      } as any,
      envelope: makeToolResultEnvelope({
        status: incomplete ? "inconclusive" : "ok",
        artifacts: [
          {
            type: "report",
            format: params.format,
            target_url: targetUrl,
            output_path: savedPath || undefined,
            report_state: state,
            report_rendered: incomplete ? "working" : "final",
            requested_mode: requested,
          },
        ],
        observations: [
          ...findings.map((item) => ({
            type: "finding",
            finding_id: item.id,
            severity: item.severity,
            chain_id: item.chain_id,
            state: item.state,
          })),
          ...projection.provisional.map((item) => ({
            type: "finding_provisional",
            finding_id: item.id,
            severity: item.severity,
            state: item.state,
          })),
          {
            type: "report_closure",
            blocked: false,
            incomplete,
            requested_mode: requested,
            report_state: state,
            working_ready: readiness.working_ready,
            final_ready: readiness.final_ready,
            open_hypotheses: readiness.closure.hypothesis_open,
            open_critical_hypotheses: readiness.closure.hypothesis_critical_open,
          },
        ],
        metrics: {
          finding_count: findings.length,
          provisional_count: projection.provisional.length,
          suppressed_count: projection.suppressed.length,
          chain_count: chains.length,
          verified_risk_score: verifiedRiskScore,
          upper_bound_risk_score: upperBoundRiskScore,
          promotion_gaps: projection.counts.promotion_gaps,
        },
      }),
      output: report,
    }
  },
})
