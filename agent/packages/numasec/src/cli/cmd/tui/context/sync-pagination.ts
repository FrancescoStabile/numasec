import type { Message } from "@numasec/sdk/v2"

export type SecurityFinding = {
  id: string
  severity: string
  title: string
  url: string
  parameter: string
  payload: string
  evidence: string
  cwe_id: string
  owasp_category: string
  confidence: number
  chain_id: string
  tool_used: string
  description: string
  cvss_score: number | null
  time_created: number
  time_updated: number
}

export type SecurityChain = {
  chain_id: string
  severity: string
  finding_count: number
  finding_ids: string[]
  urls: string[]
  time_created: number
  time_updated: number
}

export type SecurityCoverage = {
  category: string
  tested: boolean
  finding_count: number
}

export type SecuritySeveritySummary = {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export type SecurityEngagement = {
  engagement_target_url: string | null
  current_endpoint_url: string | null
  last_tested_url: string | null
  findings: {
    total: number
    verified: number
    provisional: number
    suppressed: number
    severity: SecuritySeveritySummary
  }
  report: {
    state: "empty" | "working_draft" | "final_ready"
    working_ready: boolean
    final_ready: boolean
    final_blocked: boolean
    truth_reasons: string[]
    verification_debt: {
      promotion_gaps: number
      open_hypotheses: number
      open_critical_hypotheses: number
    }
  }
  updated_at: number | null
  revision: number
}

export type SecurityState = {
  status: "idle" | "loading" | "ready" | "error"
  findings: SecurityFinding[]
  chains: SecurityChain[]
  coverage: SecurityCoverage[]
  engagement?: SecurityEngagement
  updated: number
  error?: string
}

export type SecuritySyncMeta = {
  next_cursor: string | null
  has_more: boolean
}

export type SecuritySyncPage<T> = {
  items: T[]
  sync: SecuritySyncMeta
}

export function emptySecurityState(): SecurityState {
  return {
    status: "idle",
    findings: [],
    chains: [],
    coverage: [],
    engagement: undefined,
    updated: 0,
    error: undefined,
  }
}

function byTime(a: { time_updated: number; id: string }, b: { time_updated: number; id: string }) {
  if (a.time_updated === b.time_updated) return a.id.localeCompare(b.id)
  return a.time_updated - b.time_updated
}

function byChain(a: SecurityChain, b: SecurityChain) {
  if (a.time_updated === b.time_updated) return a.chain_id.localeCompare(b.chain_id)
  return a.time_updated - b.time_updated
}

function byMessage(a: Message, b: Message) {
  return a.id.localeCompare(b.id)
}

export function readNextCursor(headers?: Headers | null) {
  if (!headers) return null
  const value = headers.get("x-next-cursor")
  if (!value) return null
  return value
}

export function mergeMessages(current: Message[], next: Message[]) {
  const map = new Map<string, Message>()
  for (const item of current) map.set(item.id, item)
  for (const item of next) map.set(item.id, item)
  return Array.from(map.values()).toSorted(byMessage)
}

export function mergeFindings(current: SecurityFinding[], next: SecurityFinding[]) {
  const map = new Map<string, SecurityFinding>()
  for (const item of current) map.set(item.id, item)
  for (const item of next) map.set(item.id, item)
  return Array.from(map.values()).toSorted(byTime)
}

export function mergeChains(current: SecurityChain[], next: SecurityChain[]) {
  const map = new Map<string, SecurityChain>()
  for (const item of current) map.set(item.chain_id, item)
  for (const item of next) map.set(item.chain_id, item)
  return Array.from(map.values()).toSorted(byChain)
}
