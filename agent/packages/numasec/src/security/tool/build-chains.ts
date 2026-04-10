/**
 * Tool: build_chains
 *
 * Build attack chains from saved findings. Groups related findings
 * that together form a more impactful attack scenario.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq } from "../../storage/db"
import { FindingTable } from "../security.sql"

const DESCRIPTION = `Build attack chains from saved findings.
Groups related findings by URL path and vulnerability relationships into attack narratives.

Example chain: SQLi → Data Leak → Account Takeover
Each chain represents a complete attack path that demonstrates business impact.

Call this after you've saved multiple findings to see the bigger picture.`

interface ChainGroup {
  id: string
  title: string
  findings: typeof FindingTable.$inferSelect[]
  severity: string
  impact: string
}

function buildChainGroups(findings: (typeof FindingTable.$inferSelect)[]): ChainGroup[] {
  // Group by URL base path
  const pathGroups = new Map<string, typeof findings>()
  for (const f of findings) {
    try {
      const url = new URL(f.url)
      const basePath = url.pathname.split("/").slice(0, 3).join("/") || "/"
      const key = `${url.hostname}${basePath}`
      const group = pathGroups.get(key) ?? []
      group.push(f)
      pathGroups.set(key, group)
    } catch {
      const group = pathGroups.get("unknown") ?? []
      group.push(f)
      pathGroups.set("unknown", group)
    }
  }

  // Only keep groups with 2+ findings
  const chains: ChainGroup[] = []
  let chainIdx = 0

  for (const [path, group] of pathGroups) {
    if (group.length < 2) continue

    chainIdx++
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    group.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))

    const titles = group.map((f) => f.title.replace(/\s+(in|on|at)\s+.*$/i, ""))
    const uniqueTitles = [...new Set(titles)]
    const chainTitle = uniqueTitles.slice(0, 3).join(" → ")

    // Determine highest impact
    const topSeverity = group[0].severity
    const impactMap: Record<string, string> = {
      critical: "Full system compromise possible",
      high: "Significant data exposure or privilege escalation",
      medium: "Moderate security impact",
      low: "Minor security concern",
      info: "Informational finding",
    }

    chains.push({
      id: `CHAIN-${String(chainIdx).padStart(3, "0")}`,
      title: chainTitle,
      findings: group,
      severity: topSeverity,
      impact: impactMap[topSeverity] ?? "Unknown impact",
    })
  }

  // Also merge via related_finding_ids
  for (const f of findings) {
    if (!f.related_finding_ids || f.related_finding_ids.length === 0) continue
    const relatedIds = new Set(f.related_finding_ids)
    const relatedFindings = findings.filter((rf) => relatedIds.has(rf.id))
    if (relatedFindings.length === 0) continue

    // Check if already in a chain
    const alreadyChained = chains.some((c) => c.findings.some((cf) => cf.id === f.id))
    if (alreadyChained) continue

    chainIdx++
    const allInChain = [f, ...relatedFindings]
    chains.push({
      id: `CHAIN-${String(chainIdx).padStart(3, "0")}`,
      title: allInChain.map((cf) => cf.title.split(" ")[0]).join(" → "),
      findings: allInChain,
      severity: allInChain[0].severity,
      impact: "Related vulnerability chain",
    })
  }

  return chains
}

export const BuildChainsTool = Tool.define("build_chains", {
  description: DESCRIPTION,
  parameters: z.object({}),
  async execute(_params, ctx) {
    const findings = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, ctx.sessionID))
        .all(),
    )

    if (findings.length < 2) {
      return {
        title: "Not enough findings to build chains",
        metadata: { chains: 0, findings: findings.length } as any,
        output:
          findings.length === 0
            ? "No findings saved yet."
            : "Only 1 finding saved. Need 2+ related findings to form a chain.",
      }
    }

    const chains = buildChainGroups(findings)

    // Update chain_id on findings
    for (const chain of chains) {
      for (const f of chain.findings) {
        Database.use((db) =>
          db
            .update(FindingTable)
            .set({ chain_id: chain.id })
            .where(eq(FindingTable.id, f.id))
            .run(),
        )
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
    const chainedIds = new Set(chains.flatMap((c) => c.findings.map((f) => f.id)))
    const unchained = findings.filter((f) => !chainedIds.has(f.id))
    if (unchained.length > 0) {
      parts.push(`── ${unchained.length} Standalone Finding(s) ──`)
      for (const f of unchained) {
        parts.push(`   [${f.severity.toUpperCase()}] ${f.title}`)
      }
    }

    return {
      title: `${chains.length} attack chain(s) from ${findings.length} findings`,
      metadata: { chains: chains.length, findings: findings.length, unchained: unchained.length } as any,
      output: parts.join("\n"),
    }
  },
})
