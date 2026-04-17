/**
 * Shared chain-building logic.
 *
 * Used by both build_chains tool (interactive) and generate_report (report generation).
 * Extracted to avoid circular tool→tool dependencies.
 */

import type { FindingTable } from "./security.sql"

type Finding = typeof FindingTable.$inferSelect

export interface ChainGroup {
  id: string
  title: string
  findings: Finding[]
  severity: string
  impact: string
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const IMPACT_MAP: Record<string, string> = {
  critical: "Full system compromise possible",
  high: "Significant data exposure or privilege escalation",
  medium: "Moderate security impact",
  low: "Minor security concern",
  info: "Informational finding",
}

function canonicalTitle(input: string) {
  const value = input
    .replace(/\s+(in|on|at)\s+.*$/i, "")
    .trim()
  if (/^default credentials work for\s+/i.test(value)) return "Default credentials work"
  if (/^common credentials work for\s+/i.test(value)) return "Credentials work"
  if (/^mass assignment accepted protected field\s+/i.test(value)) return "Mass assignment accepted protected field"
  return value
}

function signature(input: Finding) {
  return [
    input.tool_used || "",
    input.cwe_id || "",
    input.method || "",
    canonicalTitle(input.title).toLowerCase(),
  ].join("|")
}

function representatives(input: Finding[]) {
  const out: Finding[] = []
  const seen = new Set<string>()
  const ranked = [...input].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
  for (const item of ranked) {
    const key = signature(item)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(item)
  }
  return out
}

/** Build attack chain groups from a list of findings. */
export function buildChainGroups(findings: Finding[]): ChainGroup[] {
  // Group by URL base path
  const pathGroups = new Map<string, Finding[]>()
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

  const chains: ChainGroup[] = []
  let chainIdx = 0

  for (const [_path, group] of pathGroups) {
    const items = representatives(group)
    if (items.length < 2) continue

    chainIdx++
    const titles = items.map((f) => canonicalTitle(f.title))
    const uniqueTitles = [...new Set(titles)]
    const chainTitle = uniqueTitles.slice(0, 3).join(" → ")

    chains.push({
      id: `CHAIN-${String(chainIdx).padStart(3, "0")}`,
      title: chainTitle,
      findings: items,
      severity: items[0].severity,
      impact: IMPACT_MAP[items[0].severity] ?? "Unknown impact",
    })
  }

  // Merge via related_finding_ids
  for (const f of findings) {
    if (!f.related_finding_ids || f.related_finding_ids.length === 0) continue
    const relatedIds = new Set(f.related_finding_ids)
    const relatedFindings = findings.filter((rf) => relatedIds.has(rf.id))
    if (relatedFindings.length === 0) continue

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
