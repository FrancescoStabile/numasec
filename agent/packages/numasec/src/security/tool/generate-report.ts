/**
 * Tool: generate_report
 *
 * Generate a security assessment report in SARIF, HTML, or Markdown format.
 */

import z from "zod"
import path from "path"
import { mkdir } from "fs/promises"
import { Tool } from "../../tool/tool"
import type { SessionID } from "../../session/schema"
import { and, Database, eq } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { FindingTable } from "../security.sql"
import { generateSarif, generateMarkdown, generateHtml, calculateRiskScore } from "../report/generators"
import { buildChainGroups, type ChainGroup } from "../chain-builder"
import * as ChainProjection from "../chain-projection"
import { makeToolResultEnvelope } from "./result-envelope"

type Finding = (typeof FindingTable)["$inferSelect"]

interface ReportProjection {
  findings: Finding[]
  chains: ChainGroup[]
  canonical: {
    input_count: number
    canonical_count: number
    dropped_superseded_ids: string[]
    dropped_duplicate_ids: string[]
  }
}

interface ClosureStatus {
  hypothesis_open: number
  hypothesis_critical_open: number
  hypothesis_open_ids: string[]
}

function readLegacyProjection(sessionID: SessionID): ReportProjection {
  const findings = Database.use((db) =>
    db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.session_id, sessionID))
      .all(),
  )
  return {
    findings,
    chains: buildChainGroups(findings),
    canonical: {
      input_count: findings.length,
      canonical_count: findings.length,
      dropped_superseded_ids: [],
      dropped_duplicate_ids: [],
    },
  }
}

function readReportProjection(sessionID: SessionID): ReportProjection {
  try {
    const projection = ChainProjection.deriveAttackPathProjection({
      sessionID,
      includeFalsePositive: true,
    })
    if (projection.findings.length > 0) {
      return {
        findings: projection.findings,
        chains: projection.chains,
        canonical: projection.canonical,
      }
    }

    const legacy = readLegacyProjection(sessionID)
    if (legacy.findings.length > 0) return legacy

    return {
      findings: projection.findings,
      chains: projection.chains,
      canonical: projection.canonical,
    }
  } catch {
    return readLegacyProjection(sessionID)
  }
}

function readClosureStatus(sessionID: SessionID): ClosureStatus {
  const rows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(and(eq(EvidenceNodeTable.session_id, sessionID), eq(EvidenceNodeTable.type, "hypothesis")))
      .all(),
  )
  const openStatuses = new Set(["open", "probing", "active", "new"])
  const open: string[] = []
  let critical = 0
  for (const row of rows) {
    if (!openStatuses.has(row.status)) continue
    open.push(row.id)
    if (row.confidence >= 0.75) critical += 1
  }
  return {
    hypothesis_open: open.length,
    hypothesis_critical_open: critical,
    hypothesis_open_ids: open.slice(0, 20),
  }
}

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
    allow_incomplete: z.boolean().optional().describe("Allow report generation when closure checks fail"),
    incomplete_reason: z.string().optional().describe("Required when allow_incomplete=true and critical hypotheses are still open"),
    output_path: z.string().optional().describe("Optional file path to write the generated report"),
  }),
  async execute(params, ctx) {
    const closure = readClosureStatus(ctx.sessionID)
    const incomplete = closure.hypothesis_critical_open > 0
    if (incomplete && params.allow_incomplete !== true) {
      return {
        title: "Report blocked: closure incomplete",
        metadata: {
          closure,
          incomplete,
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "report_closure",
              blocked: true,
              open_hypotheses: closure.hypothesis_open,
              open_critical_hypotheses: closure.hypothesis_critical_open,
            },
          ],
          metrics: {
            closure_open_hypotheses: closure.hypothesis_open,
            closure_open_critical_hypotheses: closure.hypothesis_critical_open,
          },
        }),
        output: [
          "Report generation blocked by closure policy.",
          `Open hypotheses: ${closure.hypothesis_open}`,
          `Open critical hypotheses: ${closure.hypothesis_critical_open}`,
          "Set allow_incomplete=true and provide incomplete_reason to override.",
        ].join("\n"),
      }
    }
    if (incomplete && params.allow_incomplete === true) {
      const reason = (params.incomplete_reason ?? "").trim()
      if (!reason) {
        throw new Error("generate_report requires incomplete_reason when overriding closure policy")
      }
    }

    const projection = readReportProjection(ctx.sessionID)
    const findings = projection.findings
    const chains = projection.chains
    const canonical = projection.canonical

    if (findings.length === 0) {
      return {
        title: "No findings to report",
        metadata: { count: 0 } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [{ type: "report", generated: false, finding_count: 0 }],
        }),
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
        report = generateSarif(findings, targetUrl, chains)
        break
      case "html":
        report = generateHtml(findings, targetUrl, chains)
        break
      case "markdown":
      default:
        report = generateMarkdown(findings, targetUrl, chains)
        break
    }

    const riskScore = calculateRiskScore(findings)
    const override = incomplete && params.allow_incomplete === true
    const reason = override ? (params.incomplete_reason ?? "").trim() : ""
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
      title: `${incomplete ? "[INCOMPLETE] " : ""}Report (${params.format}): ${findings.length} findings, risk ${riskScore}/100`,
      metadata: {
        format: params.format,
        findings: findings.length,
        riskScore,
        canonical,
        outputPath: savedPath,
        closure,
        incomplete,
        override,
        overrideReason: reason,
      } as any,
      envelope: makeToolResultEnvelope({
        status: incomplete ? "inconclusive" : "ok",
        artifacts: [
          {
            type: "report",
            format: params.format,
            target_url: targetUrl,
            output_path: savedPath || undefined,
          },
        ],
        observations: [
          ...findings.map((item) => ({
            type: "finding",
            finding_id: item.id,
            severity: item.severity,
            chain_id: item.chain_id,
          })),
          {
            type: "report_closure",
            blocked: false,
            incomplete,
            override,
            open_hypotheses: closure.hypothesis_open,
            open_critical_hypotheses: closure.hypothesis_critical_open,
          },
          ...(reason
            ? [
                {
                  type: "report_override",
                  reason,
                },
              ]
            : []),
        ],
        metrics: {
          finding_count: findings.length,
          risk_score: riskScore,
          chain_count: chains.length,
          canonical_input_count: canonical.input_count,
          canonical_count: canonical.canonical_count,
          canonical_dropped_superseded: canonical.dropped_superseded_ids.length,
          canonical_dropped_duplicates: canonical.dropped_duplicate_ids.length,
          closure_open_hypotheses: closure.hypothesis_open,
          closure_open_critical_hypotheses: closure.hypothesis_critical_open,
          closure_incomplete: incomplete ? 1 : 0,
        },
      }),
      output: savedPath
        ? `${report}\n\n---\nSaved report to: ${savedPath}`
        : report,
    }
  },
})
