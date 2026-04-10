/**
 * Tool: get_findings
 *
 * Retrieve findings for the current session.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq, and } from "../../storage/db"
import { FindingTable } from "../security.sql"

const DESCRIPTION = `Retrieve saved security findings for the current session.
Use this to review what has been found so far, check for gaps, and plan next steps.

Returns findings grouped by severity with CWE/CVSS/OWASP enrichment data.`

export const GetFindingsTool = Tool.define("get_findings", {
  description: DESCRIPTION,
  parameters: z.object({
    severity: z.string().optional().describe("Filter by severity (critical/high/medium/low/info)"),
    limit: z.number().optional().describe("Max findings to return (default all)"),
  }),
  async execute(params, ctx) {
    const conditions = [eq(FindingTable.session_id, ctx.sessionID)]
    if (params.severity) {
      conditions.push(eq(FindingTable.severity, params.severity as any))
    }

    const rows = Database.use((db) => {
      let query = db
        .select()
        .from(FindingTable)
        .where(conditions.length === 1 ? conditions[0] : and(...conditions))
        .orderBy(FindingTable.severity)

      return params.limit ? query.limit(params.limit).all() : query.all()
    })

    if (rows.length === 0) {
      return {
        title: "No findings",
        metadata: { count: 0 } as any,
        output: "No findings saved yet for this session.",
      }
    }

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    rows.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))

    const parts: string[] = [`── ${rows.length} Finding(s) ──`, ""]
    for (const f of rows) {
      const sev = f.severity.toUpperCase()
      const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : f.severity === "low" ? "🟢" : "⚪"
      parts.push(`${icon} [${sev}] ${f.title}`)
      parts.push(`   ID: ${f.id} | URL: ${f.url}`)
      if (f.cwe_id) parts.push(`   CWE: ${f.cwe_id} | CVSS: ${f.cvss_score?.toFixed(1) ?? "?"} | OWASP: ${f.owasp_category}`)
      if (f.chain_id) parts.push(`   Chain: ${f.chain_id}`)
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
      metadata: { count: rows.length, ...counts } as any,
      output: parts.join("\n"),
    }
  },
})
