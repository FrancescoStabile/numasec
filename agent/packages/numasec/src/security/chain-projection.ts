import { createHash } from "crypto"
import { and, eq } from "../storage/db"
import type { SessionID } from "../session/schema"
import { Database } from "../storage/db"
import { buildChainGroups } from "./chain-builder"
import { EvidenceEdgeTable, EvidenceNodeTable } from "./evidence.sql"
import { CoverageTable, FindingTable } from "./security.sql"
import { canonicalSecuritySessionID } from "./security-session"

type FindingRow = (typeof FindingTable)["$inferSelect"]

export interface DeriveAttackPathInput {
  sessionID: SessionID
  severity?: "critical" | "high" | "medium" | "low" | "info"
  confidenceThreshold?: number
  includeFalsePositive?: boolean
  states?: Array<"verified" | "provisional" | "suppressed" | "refuted">
}

export interface DeriveAttackPathResult {
  findings: FindingRow[]
  chains: ReturnType<typeof buildChainGroups>
  unchained: FindingRow[]
  owaspCounts: Map<string, number>
  canonical: {
    input_count: number
    canonical_count: number
    dropped_superseded_ids: string[]
    dropped_duplicate_ids: string[]
  }
  explain: Array<{
    left: string
    right: string
    score: number
    reasons: string[]
  }>
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const TITLE_STOP = new Set([
  "a",
  "an",
  "and",
  "any",
  "also",
  "api",
  "by",
  "for",
  "from",
  "in",
  "is",
  "no",
  "not",
  "of",
  "on",
  "or",
  "same",
  "the",
  "to",
  "via",
  "with",
])

function stableID(ids: string[]): string {
  const seed = ids.slice().sort().join(":")
  const value = createHash("sha256").update(seed).digest("hex").slice(0, 8).toUpperCase()
  return `CHAIN-${value}`
}

function clusterKey(url: string): string {
  try {
    const value = new URL(url)
    const path = value.pathname.split("/").filter(Boolean).slice(0, 2).join("/")
    return `${value.hostname}/${path}`
  } catch {
    return "unknown"
  }
}

export function persistAttackPathProjection(sessionID: SessionID, result: DeriveAttackPathResult) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  Database.transaction((db) => {
    db
      .update(FindingTable)
      .set({
        chain_id: "",
      })
      .where(eq(FindingTable.session_id, currentSessionID))
      .run()

    for (const item of result.chains) {
      for (const finding of item.findings) {
        db
          .update(FindingTable)
          .set({
            chain_id: item.id,
          })
          .where(and(eq(FindingTable.session_id, currentSessionID), eq(FindingTable.id, finding.id)))
          .run()
      }
    }

    db
      .delete(CoverageTable)
      .where(eq(CoverageTable.session_id, currentSessionID))
      .run()

    for (const entry of result.owaspCounts.entries()) {
      db
        .insert(CoverageTable)
        .values({
          session_id: currentSessionID,
          category: entry[0],
          tested: true,
          finding_count: entry[1],
        })
        .run()
    }
  })
}

function hostKey(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return ""
  }
}

function normalizeTitle(title: string): string {
  const value = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
  if (!value) return ""
  const words = value
    .split(/\s+/)
    .filter((item) => item.length > 2 && !TITLE_STOP.has(item))
  if (words.length === 0) return value
  return words.join(" ")
}

function pairID(a: string, b: string): string {
  return a < b ? `${a}|${b}` : `${b}|${a}`
}

function pairParts(value: string): [string, string] {
  const split = value.split("|")
  const left = split[0] ?? ""
  const right = split[1] ?? ""
  return [left, right]
}

function bump(
  pairs: Map<string, number>,
  hosts: Map<string, string>,
  reasons: Map<string, string[]>,
  left: string,
  right: string,
  score: number,
  reason: string,
) {
  if (!left || !right || left === right) return
  const hostLeft = hosts.get(left) ?? ""
  const hostRight = hosts.get(right) ?? ""
  if (hostLeft && hostRight && hostLeft !== hostRight) return
  const key = pairID(left, right)
  const value = pairs.get(key) ?? 0
  pairs.set(key, value + score)
  const note = reasons.get(key) ?? []
  note.push(reason)
  reasons.set(key, note)
}

function bumpGroup(
  pairs: Map<string, number>,
  hosts: Map<string, string>,
  reasons: Map<string, string[]>,
  ids: string[],
  score: number,
  reason: string,
) {
  const list = Array.from(new Set(ids)).sort()
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      bump(pairs, hosts, reasons, list[i]!, list[j]!, score, reason)
    }
  }
}

function collectComponents(items: FindingRow[], pairs: Map<string, number>): string[][] {
  const allowed = new Map<string, string[]>()
  for (const key of pairs.keys()) {
    const score = pairs.get(key) ?? 0
    if (score < 2) continue
    const [left, right] = pairParts(key)
    const leftList = allowed.get(left) ?? []
    leftList.push(right)
    allowed.set(left, leftList)
    const rightList = allowed.get(right) ?? []
    rightList.push(left)
    allowed.set(right, rightList)
  }

  const known = new Set<string>()
  const out: string[][] = []
  for (const item of items) {
    if (known.has(item.id)) continue
    const queue: string[] = [item.id]
    const group: string[] = []
    known.add(item.id)
    while (queue.length > 0) {
      const current = queue.shift()
      if (!current) continue
      group.push(current)
      const next = allowed.get(current) ?? []
      for (const id of next) {
        if (known.has(id)) continue
        known.add(id)
        queue.push(id)
      }
    }
    if (group.length < 2) continue
    out.push(group.sort())
  }
  return out
}

function chainSeverity(items: FindingRow[]): string {
  const sorted = items.slice().sort((left, right) => (SEVERITY_ORDER[left.severity] ?? 5) - (SEVERITY_ORDER[right.severity] ?? 5))
  return sorted[0]?.severity ?? "info"
}

function chainImpact(severity: string): string {
  if (severity === "critical") return "Multi-step compromise path with critical impact"
  if (severity === "high") return "Multi-step compromise path with significant impact"
  if (severity === "medium") return "Verified multi-step path with moderate impact"
  return "Linked findings with limited multi-step impact"
}

function chainTitle(items: FindingRow[]): string {
  const value = items
    .slice()
    .sort((left, right) => (SEVERITY_ORDER[left.severity] ?? 5) - (SEVERITY_ORDER[right.severity] ?? 5))
    .map((item) => item.title.replace(/\s+(in|on|at)\s+.*$/i, ""))
  const unique = Array.from(new Set(value))
  return unique.slice(0, 3).join(" -> ")
}

export function deriveAttackPathProjection(input: DeriveAttackPathInput): DeriveAttackPathResult {
  const sessionID = canonicalSecuritySessionID(input.sessionID)
  const conditions = [eq(FindingTable.session_id, sessionID)]
  if (input.severity) conditions.push(eq(FindingTable.severity, input.severity))
  if (!input.includeFalsePositive) conditions.push(eq(FindingTable.false_positive, false))
  const findingsAll = Database.use((db) =>
    db
      .select()
      .from(FindingTable)
      .where(conditions.length === 1 ? conditions[0] : and(...conditions))
      .all(),
  )
  const states = input.states && input.states.length > 0 ? new Set(input.states) : null
  const findingsEligible = findingsAll.filter(
    (item) =>
      item.reportable &&
      item.state !== "suppressed" &&
      item.state !== "refuted" &&
      (!states || states.has(item.state as "verified" | "provisional" | "suppressed" | "refuted")),
  )

  const threshold = input.confidenceThreshold ?? 0
  const findingsThreshold = findingsEligible.filter((item) => item.confidence >= threshold)
  const findingMapRaw = new Map<string, FindingRow>(findingsThreshold.map((item) => [item.id, item]))

  const nodeRows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(eq(EvidenceNodeTable.session_id, sessionID))
      .all(),
  )
  const edgeRows = Database.use((db) =>
    db
      .select()
      .from(EvidenceEdgeTable)
      .where(eq(EvidenceEdgeTable.session_id, sessionID))
      .all(),
  )

  const findingNodes = nodeRows.filter((item) => item.type === "finding")
  const hypothesisRows = nodeRows.filter((item) => item.type === "hypothesis")
  const hypothesisStatus = new Map<string, string>()
  for (const row of hypothesisRows) {
    hypothesisStatus.set(row.id, row.status)
  }

  const nodeToFinding = new Map<string, string>()
  for (const row of findingNodes) {
    const payload = row.payload
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) continue
    const findingID = typeof payload.finding_id === "string" ? payload.finding_id : ""
    if (!findingID) continue
    if (!findingMapRaw.has(findingID)) continue
    nodeToFinding.set(row.id, findingID)
  }

  const findingToHypothesis = new Map<string, Set<string>>()
  for (const edge of edgeRows) {
    if (edge.relation !== "establishes") continue
    const findingID = nodeToFinding.get(edge.to_node_id)
    if (!findingID) continue
    if (!hypothesisStatus.has(edge.from_node_id)) continue
    const list = findingToHypothesis.get(findingID) ?? new Set<string>()
    list.add(edge.from_node_id)
    findingToHypothesis.set(findingID, list)
  }

  const droppedSuperseded: string[] = []
  const findingsActive: FindingRow[] = []
  for (const item of findingsThreshold) {
    const linked = Array.from(findingToHypothesis.get(item.id) ?? [])
    if (linked.length === 0) {
      findingsActive.push(item)
      continue
    }
    const keep = linked.some((id) => (hypothesisStatus.get(id) ?? "") !== "superseded")
    if (keep) {
      findingsActive.push(item)
      continue
    }
    droppedSuperseded.push(item.id)
  }

  const rank = findingsActive
    .slice()
    .sort((left, right) => {
      const timeDelta = (right.time_updated ?? 0) - (left.time_updated ?? 0)
      if (timeDelta !== 0) return timeDelta
      const confidenceDelta = right.confidence - left.confidence
      if (confidenceDelta !== 0) return confidenceDelta > 0 ? 1 : -1
      const severityDelta = (SEVERITY_ORDER[left.severity] ?? 5) - (SEVERITY_ORDER[right.severity] ?? 5)
      if (severityDelta !== 0) return severityDelta
      return left.id.localeCompare(right.id)
    })
  const canonicalMap = new Map<string, FindingRow>()
  const droppedDuplicate: string[] = []
  for (const item of rank) {
    const linked = Array.from(findingToHypothesis.get(item.id) ?? []).sort().join(",")
    const key = [
      hostKey(item.url),
      clusterKey(item.url),
      item.method.toUpperCase(),
      item.parameter.toLowerCase().trim(),
      normalizeTitle(item.title),
      linked || "legacy",
    ].join("|")
    if (!canonicalMap.has(key)) {
      canonicalMap.set(key, item)
      continue
    }
    droppedDuplicate.push(item.id)
  }

  const findings = Array.from(canonicalMap.values()).sort((left, right) => left.id.localeCompare(right.id))
  const findingMap = new Map<string, FindingRow>(findings.map((item) => [item.id, item]))
  const hosts = new Map<string, string>()
  for (const item of findings) {
    hosts.set(item.id, hostKey(item.url))
  }

  const scores = new Map<string, number>()
  const reasons = new Map<string, string[]>()

  for (const item of findings) {
    const links = item.related_finding_ids ?? []
    for (const related of links) {
      if (!findingMap.has(related)) continue
      bump(scores, hosts, reasons, item.id, related, 3, "related_finding_ids")
    }
  }

  const hypothesisLinks = new Map<string, string[]>()
  const evidenceLinks = new Map<string, string[]>()
  for (const edge of edgeRows) {
    const finding = nodeToFinding.get(edge.to_node_id)
    if (!finding) continue
    if (edge.relation === "establishes") {
      const list = hypothesisLinks.get(edge.from_node_id) ?? []
      list.push(finding)
      hypothesisLinks.set(edge.from_node_id, list)
      continue
    }
    if (edge.relation === "supports" || edge.relation === "controls" || edge.relation === "demonstrates_impact") {
      const list = evidenceLinks.get(edge.from_node_id) ?? []
      list.push(finding)
      evidenceLinks.set(edge.from_node_id, list)
    }
  }
  for (const ids of hypothesisLinks.values()) {
    bumpGroup(scores, hosts, reasons, ids, 3, "shared_hypothesis")
  }
  for (const ids of evidenceLinks.values()) {
    bumpGroup(scores, hosts, reasons, ids, 2, "shared_evidence")
  }

  const pathGroups = new Map<string, string[]>()
  for (const item of findings) {
    const key = clusterKey(item.url)
    const list = pathGroups.get(key) ?? []
    list.push(item.id)
    pathGroups.set(key, list)
  }
  for (const ids of pathGroups.values()) {
    bumpGroup(scores, hosts, reasons, ids, 1, "url_cluster")
  }

  const components = collectComponents(findings, scores)
  const chains = components
    .map((group) => {
      const findings: FindingRow[] = []
      for (const id of group) {
        const row = findingMap.get(id)
        if (!row) continue
        findings.push(row)
      }
      findings.sort((left, right) => (SEVERITY_ORDER[left.severity] ?? 5) - (SEVERITY_ORDER[right.severity] ?? 5))
      if (findings.length < 2) return
      const ids = findings.map((item) => item.id)
      const severity = chainSeverity(findings)
      return {
        id: stableID(ids),
        title: chainTitle(findings),
        findings,
        severity,
        impact: chainImpact(severity),
      }
    })
    .filter(Boolean) as ReturnType<typeof buildChainGroups>
  chains.sort((left, right) => {
    const delta = (SEVERITY_ORDER[left.severity] ?? 5) - (SEVERITY_ORDER[right.severity] ?? 5)
    if (delta !== 0) return delta
    return left.id.localeCompare(right.id)
  })

  const chainsFinal = findingNodes.length > 0 ? chains : buildChainGroups(findings)
  const chainMap = new Map<string, string>()
  for (const item of chainsFinal) {
    for (const finding of item.findings) {
      chainMap.set(finding.id, item.id)
    }
  }
  const findingsWithChain = findings.map((item) => ({
    ...item,
    chain_id: chainMap.get(item.id) ?? "",
  }))
  const linked = new Set(chainsFinal.flatMap((item) => item.findings.map((finding) => finding.id)))
  const unchained = findingsWithChain.filter((item) => !linked.has(item.id))

  const owaspCounts = new Map<string, number>()
  for (const item of findings) {
    if (!item.owasp_category) continue
    const value = owaspCounts.get(item.owasp_category) ?? 0
    owaspCounts.set(item.owasp_category, value + 1)
  }

  const explain = Array.from(scores.entries())
    .map((entry) => {
      const key = entry[0]
      const score = entry[1]
      const pair = pairParts(key)
      return {
        left: pair[0],
        right: pair[1],
        score,
        reasons: reasons.get(key) ?? [],
      }
    })
    .sort((left, right) => right.score - left.score || left.left.localeCompare(right.left))

  return {
    findings: findingsWithChain,
    chains: chainsFinal,
    unchained,
    owaspCounts,
    canonical: {
      input_count: findingsThreshold.length,
      canonical_count: findings.length,
      dropped_superseded_ids: droppedSuperseded.sort(),
      dropped_duplicate_ids: droppedDuplicate.sort(),
    },
    explain,
  }
}
