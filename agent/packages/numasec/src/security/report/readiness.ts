import type { SessionID } from "../../session/schema"
import { and, Database, desc, eq, sql } from "../../storage/db"
import { PartTable } from "../../session/session.sql"
import type { ChainGroup } from "../chain-builder"
import * as ChainProjection from "../chain-projection"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../evidence.sql"
import { projectFindings } from "../finding-projector"
import { SecurityTargetProfileTable } from "../runtime/runtime.sql"
import { canonicalSecuritySessionID } from "../security-session"
import { CoverageTable, FindingTable, TargetTable } from "../security.sql"

type Finding = (typeof FindingTable)["$inferSelect"]

export interface ReportProjection {
  all: Finding[]
  verified: Finding[]
  provisional: Finding[]
  suppressed: Finding[]
  chains: ChainGroup[]
  snapshot: ChainProjection.DeriveAttackPathResult
  canonical: {
    input_count: number
    canonical_count: number
    dropped_superseded_ids: string[]
    dropped_duplicate_ids: string[]
  }
  counts: {
    raw: number
    verified: number
    provisional: number
    suppressed: number
    refuted: number
    reportable: number
    promotion_gaps: number
  }
  promotion_gap_ids: string[]
}

export interface ClosureStatus {
  hypothesis_open: number
  hypothesis_critical_open: number
  hypothesis_open_ids: string[]
}

export interface ReportReadiness {
  state: "empty" | "working_draft" | "final_ready"
  working_ready: boolean
  final_ready: boolean
  final_blocked: boolean
  closure: ClosureStatus
  truth_reasons: string[]
  projection: ReportProjection
}

export type OperationalPhase = "explore" | "verify" | "close" | "report"

export interface FinalReportSnapshot {
  state: "absent" | "current" | "reopened"
  exported_at: number | null
  exported_revision: number | null
}

export interface EngagementTruth {
  readiness: ReportReadiness
  revision: number
  final_report: FinalReportSnapshot
}

function asObject(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input)
}

function rowTime(input: { time_updated: number | null } | undefined) {
  if (!input) return 0
  if (typeof input.time_updated === "number" && Number.isFinite(input.time_updated)) return input.time_updated
  return 0
}

function latest(input: number[]) {
  let value = 0
  for (const item of input) {
    if (item > value) value = item
  }
  return value
}

function revisionValue(input: unknown, fallback: number) {
  if (typeof input === "number" && Number.isFinite(input)) return input
  if (typeof input === "string" && input.trim()) {
    const value = Number(input)
    if (Number.isFinite(value)) return value
  }
  return fallback
}

function toolMetadata(input: unknown) {
  if (!asObject(input)) return {}
  if (!asObject(input.metadata)) return {}
  return input.metadata
}

export function readReportProjection(sessionID: SessionID): ReportProjection {
  const current = canonicalSecuritySessionID(sessionID)
  const projected = projectFindings(current)
  const verified = ChainProjection.deriveAttackPathProjection({
    sessionID: current,
    includeFalsePositive: false,
    states: ["verified"],
  })
  const all = projected.rows
  return {
    all,
    verified: verified.findings,
    provisional: all.filter((item) => item.reportable && item.state === "provisional"),
    suppressed: all.filter((item) => item.state === "suppressed" || item.state === "refuted" || !item.reportable),
    chains: verified.chains,
    snapshot: verified,
    canonical: verified.canonical,
    counts: projected.counts,
    promotion_gap_ids: projected.promotion_gap_ids,
  }
}

export function readClosureStatus(sessionID: SessionID): ClosureStatus {
  const current = canonicalSecuritySessionID(sessionID)
  const rows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(and(eq(EvidenceNodeTable.session_id, current), eq(EvidenceNodeTable.type, "hypothesis")))
      .all(),
  )
  const findings = Database.use((db) =>
    db
      .select({
        source_hypothesis_id: FindingTable.source_hypothesis_id,
      })
      .from(FindingTable)
      .where(eq(FindingTable.session_id, current))
      .all(),
  )
  const resolved = new Set<string>()
  for (const row of findings) {
    const value = (row.source_hypothesis_id ?? "").trim()
    if (!value) continue
    resolved.add(value)
  }
  const statuses = new Set(["open", "probing", "active", "new"])
  const open: string[] = []
  let critical = 0
  for (const row of rows) {
    if (!statuses.has(row.status)) continue
    if (resolved.has(row.id)) continue
    open.push(row.id)
    if (row.confidence >= 0.75) critical += 1
  }
  return {
    hypothesis_open: open.length,
    hypothesis_critical_open: critical,
    hypothesis_open_ids: open.slice(0, 20),
  }
}

export function readReportReadiness(sessionID: SessionID): ReportReadiness {
  const projection = readReportProjection(sessionID)
  const closure = readClosureStatus(sessionID)
  const reasons: string[] = []
  if (closure.hypothesis_critical_open > 0) {
    reasons.push(`${closure.hypothesis_critical_open} critical hypothesis/hypotheses still open`)
  }
  if (projection.counts.promotion_gaps > 0) {
    reasons.push(`${projection.counts.promotion_gaps} verification(s) not promoted into findings`)
  }
  if (projection.provisional.length > 0) {
    reasons.push(`${projection.provisional.length} provisional reportable finding(s) not counted as verified`)
  }
  const working = projection.all.length > 0
  if (!working) {
    return {
      state: "empty",
      working_ready: false,
      final_ready: false,
      final_blocked: false,
      closure,
      truth_reasons: reasons,
      projection,
    }
  }
  const final = reasons.length === 0
  return {
    state: final ? "final_ready" : "working_draft",
    working_ready: true,
    final_ready: final,
    final_blocked: !final,
    closure,
    truth_reasons: reasons,
    projection,
  }
}

export function readSecurityRevision(sessionID: SessionID) {
  const current = canonicalSecuritySessionID(sessionID)
  const target = Database.use((db) =>
    db
      .select({
        time_updated: TargetTable.time_updated,
      })
      .from(TargetTable)
      .where(eq(TargetTable.session_id, current))
      .orderBy(desc(TargetTable.time_updated), desc(TargetTable.id))
      .limit(1)
      .get(),
  )
  const profile = Database.use((db) =>
    db
      .select({
        time_updated: SecurityTargetProfileTable.time_updated,
      })
      .from(SecurityTargetProfileTable)
      .where(eq(SecurityTargetProfileTable.session_id, current))
      .orderBy(desc(SecurityTargetProfileTable.time_updated), desc(SecurityTargetProfileTable.id))
      .limit(1)
      .get(),
  )
  const finding = Database.use((db) =>
    db
      .select({
        time_updated: FindingTable.time_updated,
      })
      .from(FindingTable)
      .where(eq(FindingTable.session_id, current))
      .orderBy(desc(FindingTable.time_updated), desc(FindingTable.id))
      .limit(1)
      .get(),
  )
  const coverage = Database.use((db) =>
    db
      .select({
        time_updated: CoverageTable.time_updated,
      })
      .from(CoverageTable)
      .where(eq(CoverageTable.session_id, current))
      .orderBy(desc(CoverageTable.time_updated), desc(CoverageTable.category))
      .limit(1)
      .get(),
  )
  const node = Database.use((db) =>
    db
      .select({
        time_updated: EvidenceNodeTable.time_updated,
      })
      .from(EvidenceNodeTable)
      .where(eq(EvidenceNodeTable.session_id, current))
      .orderBy(desc(EvidenceNodeTable.time_updated), desc(EvidenceNodeTable.id))
      .limit(1)
      .get(),
  )
  const edge = Database.use((db) =>
    db
      .select({
        time_updated: EvidenceEdgeTable.time_updated,
      })
      .from(EvidenceEdgeTable)
      .where(eq(EvidenceEdgeTable.session_id, current))
      .orderBy(desc(EvidenceEdgeTable.time_updated), desc(EvidenceEdgeTable.id))
      .limit(1)
      .get(),
  )
  return latest([
    rowTime(target),
    rowTime(profile),
    rowTime(finding),
    rowTime(coverage),
    rowTime(node),
    rowTime(edge),
  ])
}

export function readFinalReportSnapshot(sessionID: SessionID, revision: number, finalReady: boolean): FinalReportSnapshot {
  const current = canonicalSecuritySessionID(sessionID)
  const rows = Database.use((db) =>
    db
      .select({
        id: PartTable.id,
        time_updated: PartTable.time_updated,
        data: PartTable.data,
      })
      .from(PartTable)
      .where(
        and(
          eq(PartTable.session_id, current),
          sql`json_extract(${PartTable.data}, '$.type') = 'tool'`,
          sql`json_extract(${PartTable.data}, '$.tool') = 'generate_report'`,
        ),
      )
      .orderBy(desc(PartTable.time_updated), desc(PartTable.id))
      .limit(20)
      .all(),
  )
  for (const row of rows) {
    const data = row.data as any
    if (data.type !== "tool") continue
    if (!asObject(data.state)) continue
    if (data.state.status !== "completed") continue
    const meta = toolMetadata(data.state)
    if (typeof meta.blocked_code === "string" && meta.blocked_code.trim()) continue
    const rendered = String(meta.reportRendered ?? meta.report_rendered ?? "")
    if (rendered !== "final") continue
    const exported = revisionValue(meta.engagementRevision, rowTime(row))
    return {
      state: exported < revision || !finalReady ? "reopened" : "current",
      exported_at: rowTime(row),
      exported_revision: exported,
    }
  }
  return {
    state: "absent",
    exported_at: null,
    exported_revision: null,
  }
}

export function readEngagementTruth(sessionID: SessionID): EngagementTruth {
  const readiness = readReportReadiness(sessionID)
  const revision = readSecurityRevision(sessionID)
  return {
    readiness,
    revision,
    final_report: readFinalReportSnapshot(sessionID, revision, readiness.final_ready),
  }
}

export function readOperationalPhase(sessionID: SessionID): OperationalPhase {
  const readiness = readReportReadiness(sessionID)
  if (readiness.final_ready && readiness.working_ready) return "report"
  if (readiness.working_ready && readiness.final_blocked) return "close"
  if (readiness.closure.hypothesis_open > 0) return "verify"
  return "explore"
}
