/**
 * Tool: get_findings
 *
 * Retrieve findings for the current session.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq, and } from "../../storage/db"
import { FindingTable } from "../security.sql"
import { getNextActions } from "../enrichment/next-actions"
import { makeToolResultEnvelope } from "./result-envelope"
import { deriveAttackPathProjection } from "../chain-projection"
import { projectFindings } from "../finding-projector"
import { canonicalSecuritySessionID } from "../security-session"

const DESCRIPTION = `Retrieve saved security findings for the current session.
Use this to review what has been found so far, check for gaps, and plan next steps.

Returns findings grouped by severity with CWE/CVSS/OWASP enrichment data.`

export const GetFindingsTool = Tool.define("get_findings", {
  description: DESCRIPTION,
  parameters: z.object({
    severity: z.string().optional().describe("Filter by severity (critical/high/medium/low/info)"),
    limit: z.number().optional().describe("Max findings to return (default all)"),
    view: z.enum(["raw", "provisional", "verified", "suppressed", "canonical", "all"]).optional().describe("Finding truth view"),
    canonical_only: z.boolean().optional().describe("Use canonical deduplicated findings (default true)"),
    include_false_positive: z.boolean().optional().describe("Include findings marked false_positive"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const projected = projectFindings(sessionID)
    const view = params.view ?? (params.canonical_only === true ? "canonical" : params.canonical_only === false ? "raw" : "all")
    let rows = Database.use((db) => {
      const conditions = [eq(FindingTable.session_id, sessionID)]
      if (params.severity) conditions.push(eq(FindingTable.severity, params.severity as any))
      const query = db
        .select()
        .from(FindingTable)
        .where(conditions.length === 1 ? conditions[0] : and(...conditions))
        .orderBy(FindingTable.severity)
      return query.all()
    })
    if (view === "provisional") rows = rows.filter((item) => item.state === "provisional")
    if (view === "verified") rows = rows.filter((item) => item.state === "verified")
    if (view === "suppressed") rows = rows.filter((item) => item.state === "suppressed")
    if (view === "raw") rows = rows.filter((item) => item.state !== "suppressed" && item.state !== "refuted")
    if (view === "canonical") {
      rows = deriveAttackPathProjection({
        sessionID,
        severity: params.severity as any,
        includeFalsePositive: params.include_false_positive,
      }).findings
    }

    if (rows.length === 0) {
      return {
        title: "No findings",
        metadata: { count: 0, view, ...projected.counts } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [{ type: "finding_list", count: 0 }],
        }),
        output: "No findings saved yet for this session.",
      }
    }

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    rows.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))
    if (params.limit) rows = rows.slice(0, params.limit)

    const parts: string[] = [`── ${rows.length} Finding(s) [view=${view}] ──`, ""]
    parts.push(
      `Raw=${projected.counts.raw} Verified=${projected.counts.verified} Provisional=${projected.counts.provisional} Suppressed=${projected.counts.suppressed} PromotionGaps=${projected.counts.promotion_gaps}`,
    )
    parts.push("")
    for (const f of rows) {
      const sev = f.severity.toUpperCase()
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : f.severity === "low" ? "🟢" : "⚪"
      parts.push(`${icon} [${sev}] ${f.title}`)
      parts.push(`   ID: ${f.id} | URL: ${f.url}`)
      if (f.state) parts.push(`   State: ${f.state}${f.reportable ? "" : " | non-reportable"}`)
      if (f.suppression_reason) parts.push(`   Suppressed: ${f.suppression_reason}`)
      if (f.cwe_id) parts.push(`   CWE: ${f.cwe_id} | CVSS: ${f.cvss_score?.toFixed(1) ?? "?"} | OWASP: ${f.owasp_category}`)
      if (f.chain_id) parts.push(`   Chain: ${f.chain_id}`)

      const actions = getNextActions(f.cwe_id, f.title)
      if (actions.length > 0) {
        parts.push(`   Next: ${actions[0]}`)
      }

      parts.push("")
    }

    // Summary by severity
    const counts: Record<string, number> = {}
    for (const f of rows) counts[f.severity] = (counts[f.severity] ?? 0) + 1
    const summary = Object.entries(counts)
      .sort((a, b) => (severityOrder[a[0]] ?? 5) - (severityOrder[b[0]] ?? 5))
      .map(([s, c]) => `${c} ${s}`)
      .join(", ")

    return {
      title: `${rows.length} findings: ${summary}`,
      metadata: { count: rows.length, view, ...counts, ...projected.counts } as any,
      envelope: makeToolResultEnvelope({
        status: projected.counts.promotion_gaps > 0 ? "inconclusive" : "ok",
        observations: rows.map((item) => ({
          type: "finding",
          finding_id: item.id,
          severity: item.severity,
          chain_id: item.chain_id,
          state: item.state,
        })),
        metrics: {
          count: rows.length,
          view_all: view === "all" ? 1 : 0,
          view_canonical: view === "canonical" ? 1 : 0,
          promotion_gaps: projected.counts.promotion_gaps,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
