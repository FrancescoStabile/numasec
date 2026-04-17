import z from "zod"
import { Tool } from "../../tool/tool"
import { deriveAttackPathProjection, persistAttackPathProjection } from "../chain-projection"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Derive attack paths from findings and persist chain projection.
This primitive powers evidence-driven chain building and report compatibility.`

export const DeriveAttackPathsTool = Tool.define("derive_attack_paths", {
  description: DESCRIPTION,
  parameters: z.object({
    severity: z.enum(["critical", "high", "medium", "low", "info"]).optional().describe("Optional severity filter"),
    confidence_threshold: z.number().min(0).max(1).optional().describe("Minimum finding confidence to include"),
    include_false_positive: z.boolean().optional().describe("Include findings marked false_positive"),
    explain: z.boolean().optional().describe("Include pair score explainability and canonicalization details"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const result = deriveAttackPathProjection({
      sessionID,
      severity: params.severity,
      confidenceThreshold: params.confidence_threshold,
      includeFalsePositive: params.include_false_positive,
    })
    persistAttackPathProjection(sessionID, result)

    if (result.chains.length === 0) {
      return {
        title: "No attack paths derived",
        metadata: {
          chains: 0,
          findings: result.findings.length,
        } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "attack_chain",
              count: 0,
              finding_count: result.findings.length,
            },
          ],
          metrics: {
            chain_count: 0,
            finding_count: result.findings.length,
          },
        }),
        output:
          result.findings.length === 0
            ? "No findings available for attack path derivation."
            : "No multi-step attack path found from current findings.",
      }
    }

    const lines: string[] = []
    lines.push(`── ${result.chains.length} Attack Path(s) ──`)
    lines.push("")
    for (const chain of result.chains) {
      const icon = chain.severity === "critical" ? "🔴" : chain.severity === "high" ? "🟠" : "🟡"
      lines.push(`${icon} ${chain.id}: ${chain.title}`)
      lines.push(`   Severity: ${chain.severity.toUpperCase()} | Impact: ${chain.impact}`)
      for (const finding of chain.findings) {
        lines.push(`   ├── [${finding.severity.toUpperCase()}] ${finding.title}`)
        lines.push(`   │   ${finding.url}`)
      }
      lines.push("")
    }

    if (result.unchained.length > 0) {
      lines.push(`── ${result.unchained.length} Standalone Finding(s) ──`)
      for (const finding of result.unchained) {
        lines.push(`   [${finding.severity.toUpperCase()}] ${finding.title}`)
      }
      lines.push("")
    }

    if (result.owaspCounts.size > 0) {
      lines.push(`── OWASP Top 10 Coverage: ${result.owaspCounts.size}/10 categories ──`)
      for (const entry of result.owaspCounts.entries()) {
        lines.push(`   ${entry[0]}: ${entry[1]} finding(s)`)
      }
    }

    lines.push("")
    lines.push(`── Canonical Findings ──`)
    lines.push(`   Input: ${result.canonical.input_count}`)
    lines.push(`   Canonical: ${result.canonical.canonical_count}`)
    lines.push(`   Dropped superseded: ${result.canonical.dropped_superseded_ids.length}`)
    lines.push(`   Dropped duplicates: ${result.canonical.dropped_duplicate_ids.length}`)

    if (params.explain === true) {
      lines.push("")
      lines.push(`── Pair Score Explainability ──`)
      const top = result.explain.slice(0, 25)
      if (top.length === 0) {
        lines.push("   No scored pairs")
      }
      for (const item of top) {
        lines.push(`   ${item.left} <-> ${item.right} = ${item.score} (${item.reasons.join(", ")})`)
      }
    }

    return {
      title: `Derived ${result.chains.length} attack path(s)`,
      metadata: {
        chains: result.chains.length,
        findings: result.findings.length,
        unchained: result.unchained.length,
        owaspCoverage: result.owaspCounts.size,
        canonical: result.canonical,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: result.chains.map((item) => ({
          type: "attack_chain",
          chain_id: item.id,
          severity: item.severity,
          finding_ids: item.findings.map((finding) => finding.id),
        })),
        metrics: {
          chain_count: result.chains.length,
          finding_count: result.findings.length,
          unchained_count: result.unchained.length,
          owasp_coverage_count: result.owaspCounts.size,
          canonical_input_count: result.canonical.input_count,
          canonical_count: result.canonical.canonical_count,
          canonical_dropped_superseded: result.canonical.dropped_superseded_ids.length,
          canonical_dropped_duplicates: result.canonical.dropped_duplicate_ids.length,
        },
      }),
      output: lines.join("\n"),
    }
  },
})
