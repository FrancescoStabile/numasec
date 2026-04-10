/**
 * Tool: generate_report
 *
 * Generate a security assessment report in SARIF, HTML, or Markdown format.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq } from "../../storage/db"
import { FindingTable, TargetTable } from "../security.sql"
import { generateSarif, generateMarkdown, generateHtml, calculateRiskScore } from "../report/generators"

const DESCRIPTION = `Generate a security assessment report from saved findings.
Formats: sarif (for CI/CD), markdown (for documentation), html (self-contained visual report).

The report includes:
- Executive summary with risk score
- All findings grouped by severity
- CWE/CVSS/OWASP enrichment data
- Evidence and remediation for each finding
- OWASP Top 10 coverage analysis

Call this at the END of an assessment after all findings have been saved.`

export const GenerateReportTool = Tool.define("generate_report", {
  description: DESCRIPTION,
  parameters: z.object({
    format: z.enum(["sarif", "markdown", "html"]).default("markdown").describe("Report format"),
    target_url: z.string().optional().describe("Target URL (auto-detected from findings if omitted)"),
  }),
  async execute(params, ctx) {
    const findings = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, ctx.sessionID))
        .all(),
    )

    if (findings.length === 0) {
      return {
        title: "No findings to report",
        metadata: { count: 0 } as any,
        output: "No findings saved for this session. Save findings first with save_finding.",
      }
    }

    // Determine target URL
    const targetUrl =
      params.target_url ??
      findings[0]?.url ??
      "unknown"

    let report: string
    switch (params.format) {
      case "sarif":
        report = generateSarif(findings, targetUrl)
        break
      case "html":
        report = generateHtml(findings, targetUrl)
        break
      case "markdown":
      default:
        report = generateMarkdown(findings, targetUrl)
        break
    }

    const riskScore = calculateRiskScore(findings)
    const counts: Record<string, number> = {}
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

    const summary = Object.entries(counts)
      .sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
        return (order[a[0]] ?? 5) - (order[b[0]] ?? 5)
      })
      .map(([s, c]) => `${c} ${s}`)
      .join(", ")

    return {
      title: `Report (${params.format}): ${findings.length} findings, risk ${riskScore}/100`,
      metadata: { format: params.format, findings: findings.length, riskScore } as any,
      output: report,
    }
  },
})
