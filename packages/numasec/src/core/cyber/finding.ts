import type { Fact } from "./cyber"

export const REPLAY_EXEMPTION_CATEGORIES = [
  "destructive_target",
  "operator_controlled_state",
  "external_dependency",
  "time_bound_access",
  "legacy_unspecified",
] as const

export type ReplayExemptionCategory = (typeof REPLAY_EXEMPTION_CATEGORIES)[number]

export type ReplayExemption = {
  category: ReplayExemptionCategory
  rationale: string
  domain?: string
  approved_by_kind?: string
}

export type FindingShape = {
  kind: "candidate" | "finding"
  status: string
  evidence_refs?: string[]
  replay_present?: boolean
  replay_reason?: string
  replay_exemption?: ReplayExemption
  oracle_status?: string
  oracle_reason?: string
}

export type FindingRecord = FindingShape & {
  key: string
  fact_name: string
  title?: string
  summary?: string
  proof_summary?: string
  severity?: string
  evidence_refs?: string[]
  source_event_id?: string
  operator_promoted?: boolean
}

export type FindingBuckets<T extends FindingShape = FindingRecord> = {
  all: T[]
  candidates: T[]
  findings: T[]
  reportable: T[]
  suspected: T[]
  rejected: T[]
  replay_backed: T[]
  replay_exempt: T[]
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

export function normalizeReplayExemption(input: {
  replay_reason?: string
  replay_exemption?: unknown
}): ReplayExemption | undefined {
  const value = asObject(input.replay_exemption)
  if (value) {
    const category = typeof value.category === "string" ? value.category : undefined
    const rationale = typeof value.rationale === "string" ? value.rationale : undefined
    if (category && rationale) {
      return {
        category: REPLAY_EXEMPTION_CATEGORIES.includes(category as ReplayExemptionCategory)
          ? (category as ReplayExemptionCategory)
          : "legacy_unspecified",
        rationale,
        domain: typeof value.domain === "string" ? value.domain : undefined,
        approved_by_kind: typeof value.approved_by_kind === "string" ? value.approved_by_kind : undefined,
      }
    }
  }
  if (typeof input.replay_reason === "string" && input.replay_reason.trim().length > 0) {
    return {
      category: "legacy_unspecified",
      rationale: input.replay_reason,
    }
  }
  return undefined
}

export function isStructuredReplayExemption(input: ReplayExemption | undefined) {
  return Boolean(input && input.category !== "legacy_unspecified" && input.rationale.trim().length > 0)
}

export function candidateTitle(factName: string, value: Record<string, unknown> | undefined, key: string) {
  return (
    (typeof value?.title === "string" && value.title) ||
    (typeof value?.check_name === "string" && value.check_name) ||
    (typeof value?.check_id === "string" && value.check_id) ||
    (typeof value?.line === "string" && value.line) ||
    factName ||
    key
  )
}

export function candidateSummary(value: Record<string, unknown> | undefined) {
  if (!value) return undefined
  return (
    (typeof value.description === "string" && value.description) ||
    (typeof value.message === "string" && value.message) ||
    (typeof value.line === "string" && value.line) ||
    (typeof value.title === "string" && value.title) ||
    undefined
  )
}

export function summarizeFindingFact(fact: Fact): FindingRecord | undefined {
  const value = asObject(fact.value_json)
  if (fact.entity_kind === "finding_candidate") {
    return {
      key: fact.entity_key,
      kind: "candidate",
      fact_name: fact.fact_name,
      status: fact.status,
      title: candidateTitle(fact.fact_name, value, fact.entity_key),
      summary: candidateSummary(value),
      severity: typeof value?.severity === "string" ? value.severity : undefined,
      evidence_refs: fact.evidence_refs,
      source_event_id: fact.source_event_id,
    }
  }
  if (fact.entity_kind === "finding" && fact.fact_name === "record") {
    return {
      key: fact.entity_key,
      kind: "finding",
      fact_name: fact.fact_name,
      status: fact.status,
      title: typeof value?.title === "string" ? value.title : fact.entity_key,
      summary: typeof value?.summary === "string" ? value.summary : undefined,
      proof_summary: typeof value?.proof_summary === "string" ? value.proof_summary : undefined,
      severity: typeof value?.severity === "string" ? value.severity : undefined,
      evidence_refs: fact.evidence_refs,
      replay_present: Boolean(value?.replay_present),
      replay_reason: typeof value?.replay_reason === "string" ? value.replay_reason : undefined,
      replay_exemption: normalizeReplayExemption({
        replay_reason: typeof value?.replay_reason === "string" ? value.replay_reason : undefined,
        replay_exemption: value?.replay_exemption,
      }),
      oracle_status: typeof value?.oracle_status === "string" ? value.oracle_status : undefined,
      oracle_reason: typeof value?.oracle_reason === "string" ? value.oracle_reason : undefined,
      source_event_id: fact.source_event_id,
      operator_promoted: Boolean(value?.operator_promoted),
    }
  }
  return undefined
}

export function normalizeFindingRecords<T extends FindingShape & { key: string }>(records: T[]): T[] {
  const supersededCandidateKeys = new Set(
    records
      .filter(
        (item) =>
          item.kind === "finding" &&
          (item.status === "verified" || item.status === "rejected" || item.status === "stale"),
      )
      .map((item) => item.key),
  )
  if (supersededCandidateKeys.size === 0) return records
  return records.filter((item) => !(item.kind === "candidate" && supersededCandidateKeys.has(item.key)))
}

export function bucketFindings<T extends FindingShape>(records: T[]): FindingBuckets<T> {
  const normalized = normalizeFindingRecords(records as Array<T & { key: string }>) as T[]
  const candidates = normalized.filter((item) => item.kind === "candidate")
  const findings = normalized.filter((item) => item.kind === "finding")
  const reportable = normalized.filter(isReportableFinding)
  const suspected = normalized.filter(isSuspectedFinding)
  const rejected = normalized.filter(isRejectedFinding)
  const replay_backed = normalized.filter(isReplayBackedFinding)
  const replay_exempt = normalized.filter(isReplayExemptFinding)
  return {
    all: normalized,
    candidates,
    findings,
    reportable,
    suspected,
    rejected,
    replay_backed,
    replay_exempt,
  }
}

export function isReportableFinding(input: FindingShape) {
  if (input.kind !== "finding" || input.status !== "verified") return false
  if (!Array.isArray(input.evidence_refs) || input.evidence_refs.length === 0) return false
  if (input.replay_present) return true
  return isStructuredReplayExemption(normalizeReplayExemption(input))
}

export function isRejectedFinding(input: FindingShape) {
  return input.status === "rejected" || input.status === "stale"
}

export function isSuspectedFinding(input: FindingShape) {
  return !isReportableFinding(input) && !isRejectedFinding(input)
}

export function replayState(input: Pick<FindingShape, "kind" | "replay_present" | "replay_reason">) {
  if (input.kind !== "finding") return undefined
  if (input.replay_present) return "present"
  if (normalizeReplayExemption(input)) return "exempt"
  return "missing"
}

export function isReplayExemptFinding(input: Pick<FindingShape, "kind" | "replay_present" | "replay_reason">) {
  return replayState(input) === "exempt"
}

export function isReplayBackedFinding(input: Pick<FindingShape, "kind" | "replay_present" | "replay_reason">) {
  return replayState(input) === "present"
}
