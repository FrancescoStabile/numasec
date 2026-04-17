/**
 * Tool: build_chains
 *
 * Build attack chains from saved findings. Groups related findings
 * that together form a more impactful attack scenario.
 * Also populates CoverageTable with OWASP coverage data.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { deriveAttackPathProjection } from "../chain-projection"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Build attack chains from saved findings.
Groups related findings by URL path and vulnerability relationships into attack narratives.

Example chain: SQLi → Data Leak → Account Takeover
Each chain represents a complete attack path that demonstrates business impact.

Call this after you've saved multiple findings to see the bigger picture.`

export const BuildChainsTool = Tool.define("build_chains", {
  description: DESCRIPTION,
  parameters: z.object({}),
  async execute(_params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const result = deriveAttackPathProjection({
      sessionID,
      includeFalsePositive: true,
    })
    const findings = result.findings
    const chains = result.chains
    const unchained = result.unchained
    const owaspCounts = result.owaspCounts

    if (findings.length < 2) {
      return {
        title: "Not enough findings to build chains",
        metadata: { chains: 0, findings: findings.length } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "attack_chain",
              count: 0,
              finding_count: findings.length,
            },
          ],
          metrics: {
            chain_count: 0,
            finding_count: findings.length,
          },
        }),
        output:
          findings.length === 0
            ? "No findings saved yet."
            : "Only 1 finding saved. Need 2+ related findings to form a chain.",
      }
    }

    const parts: string[] = [`── ${chains.length} Attack Chain(s) ──`, ""]
    for (const chain of chains) {
      const icon = chain.severity === "critical" ? "🔴" : chain.severity === "high" ? "🟠" : "🟡"
      parts.push(`${icon} ${chain.id}: ${chain.title}`)
      parts.push(`   Severity: ${chain.severity.toUpperCase()} | Impact: ${chain.impact}`)
      for (const f of chain.findings) {
        parts.push(`   ├── [${f.severity.toUpperCase()}] ${f.title}`)
        parts.push(`   │   ${f.url}`)
      }
      parts.push("")
    }

    // Unchained findings
    if (unchained.length > 0) {
      parts.push(`── ${unchained.length} Standalone Finding(s) ──`)
      for (const f of unchained) {
        parts.push(`   [${f.severity.toUpperCase()}] ${f.title}`)
      }
    }

    // OWASP coverage summary
    if (owaspCounts.size > 0) {
      parts.push("")
      parts.push(`── OWASP Top 10 Coverage: ${owaspCounts.size}/10 categories ──`)
      for (const [cat, count] of owaspCounts) {
        parts.push(`   ${cat}: ${count} finding(s)`)
      }
    }

    return {
      title: `${chains.length} attack chain(s) from ${findings.length} findings`,
      metadata: { chains: chains.length, findings: findings.length, unchained: unchained.length, owaspCoverage: owaspCounts.size } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: chains.map((item) => ({
          type: "attack_chain",
          chain_id: item.id,
          severity: item.severity,
          finding_ids: item.findings.map((finding) => finding.id),
        })),
        metrics: {
          chain_count: chains.length,
          finding_count: findings.length,
          unchained_count: unchained.length,
          owasp_coverage_count: owaspCounts.size,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
