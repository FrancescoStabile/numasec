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

const DESCRIPTION = `Retrieve saved security findings for the current session.
Use this to review what has been found so far, check for gaps, and plan next steps.

Returns findings grouped by severity with CWE/CVSS/OWASP enrichment data.`

export const GetFindingsTool = Tool.define("get_findings", {
  description: DESCRIPTION,
  parameters: z.object({
    severity: z.string().optional().describe("Filter by severity (critical/high/medium/low/info)"),
    limit: z.number().optional().describe("Max findings to return (default all)"),
    canonical_only: z.boolean().optional().describe("Use canonical deduplicated findings (default true)"),
    include_false_positive: z.boolean().optional().describe("Include findings marked false_positive"),
  }),
  async execute(params, ctx) {
    const canonicalOnly = params.canonical_only ?? true
    let rows = canonicalOnly
      ? deriveAttackPathProjection({
          sessionID: ctx.sessionID,
          severity: params.severity as any,
          includeFalsePositive: params.include_false_positive,
        }).findings
      : Database.use((db) => {
          const conditions = [eq(FindingTable.session_id, ctx.sessionID)]
          if (params.severity) conditions.push(eq(FindingTable.severity, params.severity as any))
          const query = db
            .select()
            .from(FindingTable)
            .where(conditions.length === 1 ? conditions[0] : and(...conditions))
            .orderBy(FindingTable.severity)
          return query.all()
        })

    if (rows.length === 0) {
      return {
        title: "No findings",
        metadata: { count: 0 } as any,
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

    const parts: string[] = [`── ${rows.length} Finding(s) ──`, ""]
    for (const f of rows) {
      const sev = f.severity.toUpperCase()
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : f.severity === "low" ? "🟢" : "⚪"
      parts.push(`${icon} [${sev}] ${f.title}`)
      parts.push(`   ID: ${f.id} | URL: ${f.url}`)
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
      metadata: { count: rows.length, canonicalOnly, ...counts } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: rows.map((item) => ({
          type: "finding",
          finding_id: item.id,
          severity: item.severity,
          chain_id: item.chain_id,
        })),
        metrics: {
          count: rows.length,
          canonical_only: canonicalOnly ? 1 : 0,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
