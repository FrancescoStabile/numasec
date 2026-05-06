import { appendFile, mkdir, readFile } from "node:fs/promises"
import path from "node:path"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"
import { and, asc, Database, desc, eq } from "@/storage"
import { Effect } from "effect"
import { CyberFactTable, CyberLedgerTable, CyberRelationTable } from "./cyber.sql"
import {
  bucketFindings,
  isRejectedFinding,
  isReportableFinding,
  isSuspectedFinding,
  normalizeReplayExemption,
  replayState,
  summarizeFindingFact,
} from "./finding"

type LedgerKind =
  | "tool.called"
  | "tool.completed"
  | "tool.error"
  | "operation.note"
  | "evidence.added"
  | "fact.observed"
  | "fact.verified"
  | "relation.observed"
  | "relation.verified"

type FactStatus = "candidate" | "observed" | "verified" | "rejected" | "stale"
type WriterKind = "parser" | "tool" | "oracle" | "operator" | "llm_candidate"

export interface LedgerEvent {
  id: string
  project_id: string
  operation_slug: string
  session_id?: string
  message_id?: string
  kind: LedgerKind | string
  source?: string
  status?: string
  risk?: string
  summary?: string
  evidence_refs?: string[]
  data: Record<string, unknown>
  time_created: number
}

export interface Fact {
  id: string
  project_id: string
  operation_slug: string
  entity_kind: string
  entity_key: string
  fact_name: string
  value_json: unknown
  writer_kind: WriterKind | string
  status: FactStatus | string
  confidence?: number
  source_event_id?: string
  evidence_refs?: string[]
  expires_at?: number
  time_created: number
  time_updated: number
}

export interface Relation {
  id: string
  project_id: string
  operation_slug: string
  src_kind: string
  src_key: string
  relation: string
  dst_kind: string
  dst_key: string
  writer_kind: WriterKind | string
  status: FactStatus | string
  confidence?: number
  source_event_id?: string
  evidence_refs?: string[]
  time_created: number
  time_updated: number
}

export interface ProjectedFinding {
  key: string
  kind: "candidate" | "finding"
  status: string
  title?: string
  summary?: string
  proof_summary?: string
  severity?: string
  evidence_refs?: string[]
  replay_present?: boolean
  replay_reason?: string
  oracle_status?: string
  oracle_reason?: string
  operator_promoted?: boolean
}

export interface ProjectedCapsuleState {
  key: string
  fact_name: "capsule_readiness" | "capsule_recommendation" | "capsule_execution"
  name?: string
  description?: string
  status: string
  operation_kind?: string
  missing_required: string[]
  missing_optional: string[]
  invoked_via?: string
  steps?: number
  skipped?: number
}

export interface ProjectedKnowledgeState {
  key: string
  fact_name: string
  status: string
  query?: string
  returned?: number
  severity?: string
  type?: string
  livecrawl?: string
}

export interface ProjectedToolAdapterState {
  key: string
  status: string
  present: boolean
  path?: string
  version?: string
}

export interface ProjectedVerticalState {
  key: string
  status: string
  missing_required: string[]
  missing_optional: string[]
}

export interface ProjectedObservationState {
  id: string
  subtype: string
  title: string
  severity?: string
  confidence?: number
  status: string
  note?: string
  tags: string[]
  evidence: string[]
  created_at?: number
  updated_at?: number
  removed?: boolean
}

export interface ProjectedPlanNodeState {
  id: string
  title: string
  parent_id?: string
  status: "planned" | "running" | "done" | "blocked" | "skipped"
  note?: string
}

export interface ProjectedWorkflowStatus {
  key: string
  kind: "play" | "runbook"
  steps: number
  skipped: number
  completed_steps: number
  failed_steps: number
  pending_steps: number
  degraded: boolean
}

export interface ProjectedWorkflowStepStatus {
  key: string
  workflow: string
  index: number
  tool?: string
  label?: string
  outcome: string
  outcome_title?: string
  outcome_error?: string
}

export interface ProjectedTimelineEvent {
  id: string
  kind: string
  source?: string
  status?: string
  summary?: string
  time_created: number
}

export interface ProjectedRelationState {
  src_kind: string
  src_key: string
  relation: string
  dst_kind: string
  dst_key: string
  status: string
  confidence?: number
}

export interface ProjectedDeliverableState {
  key: string
  bundle_dir?: string
  report_path?: string
  manifest_path?: string
  counts?: Record<string, unknown>
  format?: string
  time_updated: number
}

export interface ProjectedShareBundleState {
  key: string
  path?: string
  size?: number
  sha256?: string
  signed: boolean
  redacted: boolean
  warning?: string
  time_updated: number
}

export interface ProjectedIdentityState {
  key: string
  fact_name: "descriptor" | "active"
  status: string
  mode?: string
  header_keys: string[]
  has_cookies: boolean
  active?: boolean
}

export interface ProjectedState {
  findings: ProjectedFinding[]
  capsules: ProjectedCapsuleState[]
  knowledge: ProjectedKnowledgeState[]
  identities: ProjectedIdentityState[]
  tool_adapters: ProjectedToolAdapterState[]
  verticals: ProjectedVerticalState[]
  deliverables: ProjectedDeliverableState[]
  share_bundles: ProjectedShareBundleState[]
  observations: ProjectedObservationState[]
  plan_nodes: ProjectedPlanNodeState[]
  plan_nodes_projected: number
  relations: ProjectedRelationState[]
  workflows: ProjectedWorkflowStatus[]
  workflow_steps: ProjectedWorkflowStepStatus[]
  timeline: ProjectedTimelineEvent[]
  summary: Cyber.FactSummary
  operation_state?: Operation.ProjectedOperationState
  scope_policy?: Operation.ProjectedScopePolicy
  autonomy_policy?: Operation.ProjectedAutonomyPolicy
}

export interface ProjectedStateParts {
  operation_state?: Operation.ProjectedOperationState
  scope_policy?: Operation.ProjectedScopePolicy
  autonomy_policy?: Operation.ProjectedAutonomyPolicy
  facts: Fact[]
  ledger: LedgerEvent[]
  relations: Relation[]
}

export interface OperationStateInput {
  slug: string
  label: string
  kind: string
  target?: string
  opsec: string
  in_scope?: string[]
  out_of_scope?: string[]
  session_id?: string
  message_id?: string
  source?: string
  summary?: string
}

export interface ScopePolicyInput {
  operation_slug: string
  default: "allow" | "ask"
  in_scope?: string[]
  out_of_scope?: string[]
  opsec?: string
  session_id?: string
  message_id?: string
  source?: string
  summary?: string
}

export interface WorkflowTraceInput {
  operation_slug: string
  workflow_kind: "play" | "runbook"
  workflow_id: string
  fact_name: string
  args: Record<string, unknown>
  trace: Array<Record<string, unknown>>
  skipped: Array<Record<string, unknown>>
  available: boolean
  degraded: boolean
  session_id?: string
  message_id?: string
  source?: string
  summary?: string
}

export interface WorkflowProgressInput {
  operation_slug: string
  workflow_kind: "play" | "runbook"
  workflow_id: string
  trace: Array<Record<string, unknown>>
  skipped: Array<Record<string, unknown>>
  completed_steps: number
  failed_steps: number
  pending_steps: number
  session_id?: string
  message_id?: string
  source?: string
  summary?: string
}

function id(prefix: string) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
}

function compactJson(value: unknown) {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function projectionDir(workspace: string, slug: string) {
  return path.join(Operation.opDir(workspace, slug), "cyber")
}

async function timeboxed<T>(input: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      input,
      new Promise<T>((resolve) => {
        timer = setTimeout(() => resolve(fallback), timeoutMs)
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function parseProjectedLedgerRecord(
  record: Record<string, unknown>,
  fallback: { operation_slug: string; id_prefix?: string; project_id?: string },
  index: number,
): LedgerEvent | undefined {
  const id = typeof record.id === "string" ? record.id : `${fallback.id_prefix ?? "projected_event"}_${index}`
  const kind = typeof record.kind === "string" ? record.kind : undefined
  const time_created = typeof record.time_created === "number" ? record.time_created : undefined
  if (!kind || time_created == null) return undefined
  return {
    id,
    project_id: typeof record.project_id === "string" ? record.project_id : (fallback.project_id ?? "projected"),
    operation_slug:
      typeof record.operation_slug === "string" ? record.operation_slug : fallback.operation_slug,
    session_id: typeof record.session_id === "string" ? record.session_id : undefined,
    message_id: typeof record.message_id === "string" ? record.message_id : undefined,
    kind,
    source: typeof record.source === "string" ? record.source : undefined,
    status: typeof record.status === "string" ? record.status : undefined,
    risk: typeof record.risk === "string" ? record.risk : undefined,
    summary: typeof record.summary === "string" ? record.summary : undefined,
    evidence_refs: Array.isArray(record.evidence_refs)
      ? record.evidence_refs.filter((item): item is string => typeof item === "string")
      : undefined,
    data:
      record.data && typeof record.data === "object" && !Array.isArray(record.data)
        ? (record.data as Record<string, unknown>)
        : {},
    time_created,
  }
}

function parseProjectedFactRecord(
  fact: Record<string, unknown>,
  fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
  index: number,
): Fact | undefined {
  const entity_kind = typeof fact["entity_kind"] === "string" ? fact["entity_kind"] : undefined
  const entity_key = typeof fact["entity_key"] === "string" ? fact["entity_key"] : undefined
  const fact_name = typeof fact["fact_name"] === "string" ? fact["fact_name"] : undefined
  if (!entity_kind || !entity_key || !fact_name) return undefined
  return {
    id: typeof fact["id"] === "string" ? fact["id"] : `${fallback.id_prefix ?? "projected"}_${index}`,
    project_id: typeof fact["project_id"] === "string" ? fact["project_id"] : (fallback.project_id ?? "projected"),
    operation_slug:
      typeof fact["operation_slug"] === "string" ? fact["operation_slug"] : fallback.operation_slug,
    entity_kind,
    entity_key,
    fact_name,
    value_json: fact["value_json"],
    writer_kind: typeof fact["writer_kind"] === "string" ? fact["writer_kind"] : (fallback.writer_kind ?? "tool"),
    status: typeof fact["status"] === "string" ? fact["status"] : "observed",
    confidence: typeof fact["confidence"] === "number" ? fact["confidence"] : undefined,
    source_event_id: typeof fact["source_event_id"] === "string" ? fact["source_event_id"] : undefined,
    evidence_refs: Array.isArray(fact["evidence_refs"])
      ? fact["evidence_refs"].filter((item): item is string => typeof item === "string")
      : undefined,
    expires_at: typeof fact["expires_at"] === "number" ? fact["expires_at"] : undefined,
    time_created: typeof fact["time_created"] === "number" ? fact["time_created"] : 0,
    time_updated: typeof fact["time_updated"] === "number" ? fact["time_updated"] : 0,
  }
}

export function hydrateProjectedFactRecords(
  records: Record<string, unknown>[],
  fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
): Fact[] {
  return records
    .map((fact, index) => parseProjectedFactRecord(fact, fallback, index))
    .filter((fact): fact is Fact => Boolean(fact))
}

function parseProjectedRelationRecord(
  record: Record<string, unknown>,
  fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
  index: number,
): Relation | undefined {
  const src_kind = typeof record["src_kind"] === "string" ? record["src_kind"] : undefined
  const src_key = typeof record["src_key"] === "string" ? record["src_key"] : undefined
  const relation = typeof record["relation"] === "string" ? record["relation"] : undefined
  const dst_kind = typeof record["dst_kind"] === "string" ? record["dst_kind"] : undefined
  const dst_key = typeof record["dst_key"] === "string" ? record["dst_key"] : undefined
  if (!src_kind || !src_key || !relation || !dst_kind || !dst_key) return undefined
  return {
    id: typeof record["id"] === "string" ? record["id"] : `${fallback.id_prefix ?? "projected_rel"}_${index}`,
    project_id: typeof record["project_id"] === "string" ? record["project_id"] : (fallback.project_id ?? "projected"),
    operation_slug:
      typeof record["operation_slug"] === "string" ? record["operation_slug"] : fallback.operation_slug,
    src_kind,
    src_key,
    relation,
    dst_kind,
    dst_key,
    writer_kind:
      typeof record["writer_kind"] === "string" ? record["writer_kind"] : (fallback.writer_kind ?? "tool"),
    status: typeof record["status"] === "string" ? record["status"] : "observed",
    confidence: typeof record["confidence"] === "number" ? record["confidence"] : undefined,
    source_event_id: typeof record["source_event_id"] === "string" ? record["source_event_id"] : undefined,
    evidence_refs: Array.isArray(record["evidence_refs"])
      ? record["evidence_refs"].filter((item): item is string => typeof item === "string")
      : undefined,
    time_created: typeof record["time_created"] === "number" ? record["time_created"] : 0,
    time_updated: typeof record["time_updated"] === "number" ? record["time_updated"] : 0,
  }
}

function hydrateProjectedRelationRows(
  records: Record<string, unknown>[],
  fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
): Relation[] {
  return records
    .map((record, index) => parseProjectedRelationRecord(record, fallback, index))
    .filter((relation): relation is Relation => Boolean(relation))
}

async function appendProjectionLine(
  workspace: string,
  operation_slug: string,
  filename: string,
  record: Record<string, unknown>,
) {
  const dir = projectionDir(workspace, operation_slug)
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, filename), JSON.stringify(record) + "\n", "utf8")
}

function confidenceLabel(confidence?: number) {
  if (confidence == null) return "-"
  return `${Math.max(0, Math.min(1000, confidence)) / 1000}`
}

function factLine(fact: Fact) {
  const value = compactJson(fact.value_json)
  const preview = value.length > 120 ? value.slice(0, 120) + "..." : value
  return `- [${fact.status}] ${fact.entity_kind}:${fact.entity_key} · ${fact.fact_name} = ${preview} · by=${fact.writer_kind} · conf=${confidenceLabel(fact.confidence)}`
}

function workflowStepLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    index?: number
    tool?: string
    label?: string
    outcome?: string
    outcome_title?: string
    outcome_error?: string
  }
  const descriptor = [value.label, value.tool ? `tool=${value.tool}` : undefined].filter(Boolean).join(" · ")
  const detail = value.outcome_title ?? value.outcome_error
  return `- step ${Number(value.index ?? 0)} · ${value.outcome ?? "pending"}${descriptor ? ` · ${descriptor}` : ""}${detail ? ` · ${detail}` : ""}`
}

function findingLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    title?: string
    summary?: string
    severity?: string
    replay_present?: boolean
    replay_reason?: string
    replay_exemption?: unknown
    oracle_status?: string
    oracle_reason?: string
    description?: string
    message?: string
    line?: string
    check_id?: string
    check_name?: string
  }
  const title =
    value.title ??
    value.check_name ??
    value.check_id ??
    value.line ??
    fact.entity_key
  const summary = value.summary ?? value.description ?? value.message
  const detail =
    [
      `status=${fact.status}`,
      value.severity ? `severity=${value.severity}` : undefined,
      fact.entity_kind === "finding"
        ? `replay=${replayState({
            kind: "finding",
            replay_present: value.replay_present,
            replay_reason: value.replay_reason,
          })}`
        : undefined,
      fact.entity_kind === "finding" && value.replay_reason ? `replay_reason=${value.replay_reason}` : undefined,
      fact.entity_kind === "finding" && value.oracle_status ? `oracle=${value.oracle_status}` : undefined,
      fact.entity_kind === "finding" && value.oracle_reason ? `oracle_reason=${value.oracle_reason}` : undefined,
    ]
      .filter(Boolean)
      .join(" · ")
  return `- ${title} · ${fact.entity_kind}:${fact.entity_key}${detail ? ` · ${detail}` : ""}${summary ? ` · ${summary}` : ""}`
}

function findingLineFromRecord(record: ProjectedFinding) {
  const title = record.title ?? record.key
  const detail = [
    `status=${record.status}`,
    record.severity ? `severity=${record.severity}` : undefined,
    record.kind === "finding"
      ? `replay=${replayState({
          kind: "finding",
          replay_present: record.replay_present,
          replay_reason: record.replay_reason,
        })}`
      : undefined,
    record.kind === "finding" && record.replay_reason ? `replay_reason=${record.replay_reason}` : undefined,
    record.kind === "finding" && record.oracle_status ? `oracle=${record.oracle_status}` : undefined,
    record.kind === "finding" && record.oracle_reason ? `oracle_reason=${record.oracle_reason}` : undefined,
  ]
    .filter(Boolean)
    .join(" · ")
  return `- ${title} · ${record.kind}:${record.key}${detail ? ` · ${detail}` : ""}${record.summary ? ` · ${record.summary}` : ""}`
}

function deliverableLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    report_path?: string
    manifest_path?: string
    counts?: {
      plan?: number
      observations?: number
      evidence?: number
      cyber_findings?: number
      reportable_findings?: number
      suspected_findings?: number
      rejected_findings?: number
      verified_findings?: number
      evidence_backed_findings?: number
      replay_backed_findings?: number
      replay_exempt_findings?: number
    }
  }
  const counts = value.counts
  const summary = counts
    ? [
        `plan=${counts.plan ?? 0}`,
        `observations=${counts.observations ?? 0}`,
        `evidence=${counts.evidence ?? 0}`,
        `cyber_findings=${counts.cyber_findings ?? 0}`,
        `reportable_findings=${counts.reportable_findings ?? 0}`,
        `suspected_findings=${counts.suspected_findings ?? 0}`,
        `rejected_findings=${counts.rejected_findings ?? 0}`,
        `verified_findings=${counts.verified_findings ?? 0}`,
        `evidence_backed_findings=${counts.evidence_backed_findings ?? 0}`,
        `replay_backed_findings=${counts.replay_backed_findings ?? 0}`,
        `replay_exempt_findings=${counts.replay_exempt_findings ?? 0}`,
      ].join(" ")
    : undefined
  return `- ${fact.entity_key} · ${fact.fact_name} · status=${fact.status}${value.report_path ? ` · report=${value.report_path}` : ""}${summary ? ` · ${summary}` : ""}`
}

function shareBundleLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    path?: string
    size?: number
    signed?: boolean
    redacted?: boolean
    sha256?: string
  }
  return `- ${fact.entity_key} · status=${fact.status}${value.path ? ` · path=${value.path}` : ""}${typeof value.size === "number" ? ` · size=${value.size}` : ""}${typeof value.signed === "boolean" ? ` · signed=${value.signed ? "yes" : "no"}` : ""}${typeof value.redacted === "boolean" ? ` · redacted=${value.redacted ? "yes" : "no"}` : ""}`
}

function capsuleLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    name?: string
    status?: string
    operation_kind?: string
    missing_required?: string[]
    missing_optional?: string[]
  }
  const status = value.status ?? fact.status
  const operationKind = value.operation_kind ? ` · operation_kind=${value.operation_kind}` : ""
  const missingRequired =
    Array.isArray(value.missing_required) && value.missing_required.length > 0
      ? ` · missing_required=${value.missing_required.join(",")}`
      : ""
  const missingOptional =
    Array.isArray(value.missing_optional) && value.missing_optional.length > 0
      ? ` · missing_optional=${value.missing_optional.join(",")}`
      : ""
  return `- ${fact.entity_key}${value.name ? ` (${value.name})` : ""} · ${fact.fact_name} · status=${status}${operationKind}${missingRequired}${missingOptional}`
}

function knowledgeLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    query?: string
    severity?: string | null
    returned?: number | null
    results?: Array<{ id?: string; severity?: string }>
    type?: string
    livecrawl?: string
  }
  const resultSummary = Array.isArray(value.results)
    ? value.results
        .slice(0, 3)
        .map((item) => [item.id, item.severity].filter(Boolean).join(":"))
        .filter(Boolean)
        .join(", ")
    : undefined
  return `- ${fact.entity_key} · ${fact.fact_name} · status=${fact.status}${typeof value.returned === "number" ? ` · returned=${value.returned}` : ""}${value.severity ? ` · severity=${value.severity}` : ""}${value.type ? ` · type=${value.type}` : ""}${value.livecrawl ? ` · livecrawl=${value.livecrawl}` : ""}${resultSummary ? ` · ${resultSummary}` : ""}`
}

function planLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    title?: string
    status?: string
    total?: number
    done?: number
    running?: number
    blocked?: number
    planned?: number
  }
  if (fact.entity_kind === "operation" && fact.fact_name === "plan_summary") {
    return `- ${fact.entity_key} · total=${value.total ?? 0} done=${value.done ?? 0} running=${value.running ?? 0} blocked=${value.blocked ?? 0} planned=${value.planned ?? 0}`
  }
  return `- ${fact.entity_key}${value.title ? ` (${value.title})` : ""} · ${fact.fact_name} · status=${value.status ?? fact.status}`
}

function observationLine(fact: Fact) {
  const value = (fact.value_json ?? {}) as {
    title?: string
    subtype?: string
    severity?: string
    confidence?: number
    status?: string
    note?: string
    evidence?: string[]
    removed?: boolean
  }
  const evidenceCount = Array.isArray(value.evidence) ? value.evidence.length : 0
  return `- ${value.title ?? fact.entity_key} · observation:${fact.entity_key}${value.subtype ? ` · subtype=${value.subtype}` : ""}${value.status ? ` · state=${value.status}` : ""}${value.severity ? ` · severity=${value.severity}` : ""}${typeof value.confidence === "number" ? ` · confidence=${value.confidence}` : ""}${evidenceCount > 0 ? ` · evidence=${evidenceCount}` : ""}${value.removed ? " · removed=yes" : ""}${value.note ? ` · ${value.note}` : ""}`
}

function relationLine(relation: Relation) {
  return `- [${relation.status}] ${relation.src_kind}:${relation.src_key} -${relation.relation}-> ${relation.dst_kind}:${relation.dst_key} · by=${relation.writer_kind} · conf=${confidenceLabel(relation.confidence)}`
}

function ledgerLine(event: LedgerEvent) {
  const head = `[${new Date(event.time_created).toISOString()}] ${event.kind}`
  const body = event.summary ?? compactJson(event.data)
  const preview = body.length > 160 ? body.slice(0, 160) + "..." : body
  return `- ${head} · ${preview}`
}

function currentInstance() {
  try {
    return Instance.current
  } catch {
    return undefined
  }
}

async function resolveOperationSlug(input?: string, instance = currentInstance()) {
  if (!instance) return undefined
  if (input) return input
  return Operation.activeSlug(instance.directory).catch(() => undefined)
}

export namespace Cyber {
  export const hydrateProjectedFacts = (
    records: Record<string, unknown>[],
    fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
  ): Fact[] => hydrateProjectedFactRecords(records, fallback)
  export const hydrateProjectedRelationRecords = (
    records: Record<string, unknown>[],
    fallback: { operation_slug: string; id_prefix?: string; project_id?: string; writer_kind?: string },
  ): Relation[] => hydrateProjectedRelationRows(records, fallback)

  export interface FactSummary {
    hosts: number
    services: number
    web_pages: number
    route_facts: number
    http_forms: number
    identities: number
    active_identities: number
    tool_adapters_present: number
    tool_adapters_missing: number
    candidate_findings: number
    findings: number
    knowledge_queries: number
    plan_nodes: number
    observations_projected: number
    running_plan_nodes: number
    done_plan_nodes: number
    ready_capsules: number
    degraded_capsules: number
    unavailable_capsules: number
    executed_capsules: number
    ready_verticals: number
    degraded_verticals: number
    unavailable_verticals: number
    recommended_capsules: number
    deliverables: number
    share_bundles: number
    reportable_findings: number
    suspected_findings: number
    rejected_findings: number
    verified_findings: number
    evidence_backed_findings: number
    replay_backed_findings: number
    replay_exempt_findings: number
    workflow_step_statuses: number
  }

  export const upsertOperationState = Effect.fn("Cyber.upsertOperationState")(function* (input: OperationStateInput) {
    const eventID = yield* appendLedger({
      operation_slug: input.slug,
      kind: "fact.observed",
      source: input.source ?? "operation",
      summary: input.summary ?? `operation state ${input.slug}`,
      session_id: input.session_id,
      message_id: input.message_id,
      data: {
        slug: input.slug,
        label: input.label,
        kind: input.kind,
        target: input.target ?? null,
        opsec: input.opsec,
        in_scope: input.in_scope ?? [],
        out_of_scope: input.out_of_scope ?? [],
      },
    })
    yield* upsertFact({
      operation_slug: input.slug,
      entity_kind: "operation",
      entity_key: input.slug,
      fact_name: "operation_state",
      value_json: {
        label: input.label,
        kind: input.kind,
        target: input.target,
        opsec: input.opsec,
        in_scope: input.in_scope ?? [],
        out_of_scope: input.out_of_scope ?? [],
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    if (input.target) {
      yield* upsertRelation({
        operation_slug: input.slug,
        src_kind: "operation",
        src_key: input.slug,
        relation: "targets",
        dst_kind: "target",
        dst_key: input.target,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
    }
    return eventID
  })

  export const upsertScopePolicy = Effect.fn("Cyber.upsertScopePolicy")(function* (input: ScopePolicyInput) {
    const eventID = yield* appendLedger({
      operation_slug: input.operation_slug,
      kind: "fact.observed",
      source: input.source ?? "scope",
      summary: input.summary ?? `scope policy ${input.operation_slug}`,
      session_id: input.session_id,
      message_id: input.message_id,
      data: {
        default: input.default,
        in_scope: input.in_scope ?? [],
        out_of_scope: input.out_of_scope ?? [],
        opsec: input.opsec ?? null,
      },
    })
    yield* upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "operation",
      entity_key: input.operation_slug,
      fact_name: "scope_policy",
      value_json: {
        default: input.default,
        in_scope: input.in_scope ?? [],
        out_of_scope: input.out_of_scope ?? [],
        opsec: input.opsec,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    return eventID
  })

  export const upsertWorkflowTrace = Effect.fn("Cyber.upsertWorkflowTrace")(function* (input: WorkflowTraceInput) {
    const eventID = yield* appendLedger({
      operation_slug: input.operation_slug,
      kind: "fact.observed",
      source: input.source ?? input.workflow_kind,
      summary: input.summary ?? `${input.workflow_kind} ${input.workflow_id}`,
      session_id: input.session_id,
      message_id: input.message_id,
      data: {
        workflow_kind: input.workflow_kind,
        workflow_id: input.workflow_id,
        steps: input.trace.length,
        skipped: input.skipped.length,
        available: input.available,
        degraded: input.degraded,
      },
    })
    yield* upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: input.workflow_kind,
      entity_key: input.workflow_id,
      fact_name: input.fact_name,
      value_json: {
        args: input.args,
        trace: input.trace,
        skipped: input.skipped,
        available: input.available,
        degraded: input.degraded,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    yield* upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: input.workflow_kind,
      entity_key: input.workflow_id,
      fact_name: "workflow_status",
      value_json: {
        steps: input.trace.length,
        skipped: input.skipped.length,
        available: input.available,
        degraded: input.degraded,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    yield* upsertRelation({
      operation_slug: input.operation_slug,
      src_kind: "operation",
      src_key: input.operation_slug,
      relation: input.workflow_kind === "play" ? "uses_play" : "uses_runbook",
      dst_kind: input.workflow_kind,
      dst_key: input.workflow_id,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    for (const [index, step] of input.trace.entries()) {
      const stepKey = `${input.workflow_kind}:${input.workflow_id}:planned:${index + 1}`
      yield* upsertFact({
        operation_slug: input.operation_slug,
        entity_kind: "workflow_step",
        entity_key: stepKey,
        fact_name: "planned_step",
        value_json: { index: index + 1, ...step },
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
      yield* upsertRelation({
        operation_slug: input.operation_slug,
        src_kind: input.workflow_kind,
        src_key: input.workflow_id,
        relation: "has_step",
        dst_kind: "workflow_step",
        dst_key: stepKey,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
      const outcome =
        step["outcome"] === "completed" || step["outcome"] === "failed" || step["outcome"] === "skipped"
          ? String(step["outcome"])
          : "pending"
      yield* upsertFact({
        operation_slug: input.operation_slug,
        entity_kind: "workflow_step",
        entity_key: stepKey,
        fact_name: "step_status",
        value_json: {
          index: index + 1,
          tool: step["tool"],
          label: step["label"],
          outcome,
          outcome_at: step["outcome_at"],
          outcome_title: step["outcome_title"],
          outcome_error: step["outcome_error"],
        },
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
    }
    for (const [index, step] of input.skipped.entries()) {
      const stepKey = `${input.workflow_kind}:${input.workflow_id}:skipped:${index + 1}`
      yield* upsertFact({
        operation_slug: input.operation_slug,
        entity_kind: "workflow_step",
        entity_key: stepKey,
        fact_name: "skipped_step",
        value_json: { index: index + 1, ...step },
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
      yield* upsertRelation({
        operation_slug: input.operation_slug,
        src_kind: input.workflow_kind,
        src_key: input.workflow_id,
        relation: "skips_step",
        dst_kind: "workflow_step",
        dst_key: stepKey,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
    }
    return eventID
  })

  export const syncWorkflowProgress = Effect.fn("Cyber.syncWorkflowProgress")(function* (input: WorkflowProgressInput) {
    const eventID = yield* appendLedger({
      operation_slug: input.operation_slug,
      kind: "fact.observed",
      source: input.source ?? "workflow",
      summary: input.summary ?? `${input.workflow_kind} ${input.workflow_id} progress`,
      session_id: input.session_id,
      message_id: input.message_id,
      data: {
        workflow_kind: input.workflow_kind,
        workflow_id: input.workflow_id,
        completed_steps: input.completed_steps,
        failed_steps: input.failed_steps,
        pending_steps: input.pending_steps,
      },
    })
    yield* upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: input.workflow_kind,
      entity_key: input.workflow_id,
      fact_name: "workflow_status",
      value_json: {
        steps: input.trace.length,
        skipped: input.skipped.length,
        completed_steps: input.completed_steps,
        failed_steps: input.failed_steps,
        pending_steps: input.pending_steps,
        available: true,
        degraded: input.skipped.length > 0,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    })
    for (const [index, step] of input.trace.entries()) {
      const stepKey = `${input.workflow_kind}:${input.workflow_id}:planned:${index + 1}`
      yield* upsertFact({
        operation_slug: input.operation_slug,
        entity_kind: "workflow_step",
        entity_key: stepKey,
        fact_name: "planned_step",
        value_json: { index: index + 1, ...step },
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
      const outcome =
        step["outcome"] === "completed" || step["outcome"] === "failed" || step["outcome"] === "skipped"
          ? String(step["outcome"])
          : "pending"
      yield* upsertFact({
        operation_slug: input.operation_slug,
        entity_kind: "workflow_step",
        entity_key: stepKey,
        fact_name: "step_status",
        value_json: {
          index: index + 1,
          tool: step["tool"],
          label: step["label"],
          outcome,
          outcome_at: step["outcome_at"],
          outcome_title: step["outcome_title"],
          outcome_error: step["outcome_error"],
        },
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
      })
    }
    return eventID
  })

  export const attachSession = Effect.fn("Cyber.attachSession")(function* (input: {
    project_id: string
    operation_slug: string
    session_id: string
  }) {
    const eventID = id("cled")
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberLedgerTable)
          .values({
            id: eventID,
            project_id: input.project_id,
            operation_slug: input.operation_slug,
            session_id: input.session_id,
            kind: "operation.note",
            source: "session",
            status: "attached",
            summary: `session ${input.session_id} attached`,
            data: {
              session_id: input.session_id,
              operation_slug: input.operation_slug,
            },
            time_created: Date.now(),
          })
          .run(),
      ),
    )
    const now = Date.now()
    const factID = id("cfct")
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberFactTable)
          .values({
            id: factID,
            project_id: input.project_id,
            operation_slug: input.operation_slug,
            entity_kind: "session",
            entity_key: input.session_id,
            fact_name: "attached",
            value_json: true,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
            time_created: now,
            time_updated: now,
          })
          .onConflictDoUpdate({
            target: [
              CyberFactTable.project_id,
              CyberFactTable.operation_slug,
              CyberFactTable.entity_kind,
              CyberFactTable.entity_key,
              CyberFactTable.fact_name,
            ],
            set: {
              value_json: true,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID,
              time_updated: now,
            },
          })
          .run(),
      ),
    )
    const relationID = id("crel")
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberRelationTable)
          .values({
            id: relationID,
            project_id: input.project_id,
            operation_slug: input.operation_slug,
            src_kind: "session",
            src_key: input.session_id,
            relation: "attached_to",
            dst_kind: "operation",
            dst_key: input.operation_slug,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
            time_created: now,
            time_updated: now,
          })
          .onConflictDoUpdate({
            target: [
              CyberRelationTable.project_id,
              CyberRelationTable.operation_slug,
              CyberRelationTable.src_kind,
              CyberRelationTable.src_key,
              CyberRelationTable.relation,
              CyberRelationTable.dst_kind,
              CyberRelationTable.dst_key,
            ],
            set: {
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID,
              time_updated: now,
            },
          })
          .run(),
      ),
    )
    return eventID
  })

  export const appendLedger = Effect.fn("Cyber.appendLedger")(function* (
    input: Omit<LedgerEvent, "id" | "project_id" | "operation_slug" | "time_created"> & { operation_slug?: string },
  ) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input.operation_slug, instance))
    if (!instance) return ""
    if (!operation_slug) return ""
    const project_id = instance.project.id
    const event_id = id("cled")
    const now = Date.now()
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberLedgerTable)
          .values({
            id: event_id,
            project_id,
            operation_slug,
            session_id: input.session_id,
            message_id: input.message_id,
            kind: input.kind,
            source: input.source,
            status: input.status,
            risk: input.risk,
            summary: input.summary,
            evidence_refs: input.evidence_refs,
            data: input.data,
            time_created: now,
          })
          .run(),
      ),
    )
    yield* Effect.promise(() =>
      appendProjectionLine(instance.directory, operation_slug, "ledger.jsonl", {
        id: event_id,
        project_id,
        operation_slug,
        session_id: input.session_id,
        message_id: input.message_id,
        kind: input.kind,
        source: input.source,
        status: input.status,
        risk: input.risk,
        summary: input.summary,
        evidence_refs: input.evidence_refs,
        data: input.data,
        time_created: now,
      }),
    ).pipe(Effect.catch(() => Effect.void))
    return event_id
  })

  export const upsertFact = Effect.fn("Cyber.upsertFact")(function* (
    input: Omit<Fact, "id" | "project_id" | "operation_slug" | "time_created" | "time_updated"> & {
      operation_slug?: string
    },
  ) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input.operation_slug, instance))
    if (!instance) return ""
    if (!operation_slug) return ""
    const project_id = instance.project.id
    const now = Date.now()
    const existing = yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .select()
          .from(CyberFactTable)
          .where(
            and(
              eq(CyberFactTable.project_id, project_id),
              eq(CyberFactTable.operation_slug, operation_slug),
              eq(CyberFactTable.entity_kind, input.entity_kind),
              eq(CyberFactTable.entity_key, input.entity_key),
              eq(CyberFactTable.fact_name, input.fact_name),
            ),
          )
          .get(),
      ),
    )
    if (existing) {
      yield* Effect.sync(() =>
        Database.use((db) =>
          db
            .update(CyberFactTable)
            .set({
              value_json: input.value_json,
              writer_kind: input.writer_kind,
              status: input.status,
              confidence: input.confidence,
              source_event_id: input.source_event_id,
              evidence_refs: input.evidence_refs,
              expires_at: input.expires_at,
              time_updated: now,
            })
            .where(eq(CyberFactTable.id, existing.id))
          .run(),
      ),
    )
      yield* Effect.promise(() =>
        appendProjectionLine(instance.directory, operation_slug, "facts.jsonl", {
          id: existing.id,
          project_id,
          operation_slug,
          entity_kind: input.entity_kind,
          entity_key: input.entity_key,
          fact_name: input.fact_name,
          value_json: input.value_json,
          writer_kind: input.writer_kind,
          status: input.status,
          confidence: input.confidence,
          source_event_id: input.source_event_id,
          evidence_refs: input.evidence_refs,
          expires_at: input.expires_at,
          time_created: existing.time_created,
          time_updated: now,
        }),
      ).pipe(Effect.catch(() => Effect.void))
      return existing.id
    }
    const fact_id = id("cfct")
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberFactTable)
          .values({
            id: fact_id,
            project_id,
            operation_slug,
            entity_kind: input.entity_kind,
            entity_key: input.entity_key,
            fact_name: input.fact_name,
            value_json: input.value_json,
            writer_kind: input.writer_kind,
            status: input.status,
            confidence: input.confidence,
            source_event_id: input.source_event_id,
            evidence_refs: input.evidence_refs,
            expires_at: input.expires_at,
            time_created: now,
            time_updated: now,
          })
          .run(),
      ),
    )
    yield* Effect.promise(() =>
      appendProjectionLine(instance.directory, operation_slug, "facts.jsonl", {
        id: fact_id,
        project_id,
        operation_slug,
        entity_kind: input.entity_kind,
        entity_key: input.entity_key,
        fact_name: input.fact_name,
        value_json: input.value_json,
        writer_kind: input.writer_kind,
        status: input.status,
        confidence: input.confidence,
        source_event_id: input.source_event_id,
        evidence_refs: input.evidence_refs,
        expires_at: input.expires_at,
        time_created: now,
        time_updated: now,
      }),
    ).pipe(Effect.catch(() => Effect.void))
    return fact_id
  })

  export const upsertRelation = Effect.fn("Cyber.upsertRelation")(function* (
    input: Omit<Relation, "id" | "project_id" | "operation_slug" | "time_created" | "time_updated"> & {
      operation_slug?: string
    },
  ) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input.operation_slug, instance))
    if (!instance) return ""
    if (!operation_slug) return ""
    const project_id = instance.project.id
    const now = Date.now()
    const existing = yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .select()
          .from(CyberRelationTable)
          .where(
            and(
              eq(CyberRelationTable.project_id, project_id),
              eq(CyberRelationTable.operation_slug, operation_slug),
              eq(CyberRelationTable.src_kind, input.src_kind),
              eq(CyberRelationTable.src_key, input.src_key),
              eq(CyberRelationTable.relation, input.relation),
              eq(CyberRelationTable.dst_kind, input.dst_kind),
              eq(CyberRelationTable.dst_key, input.dst_key),
            ),
          )
          .get(),
      ),
    )
    if (existing) {
      yield* Effect.sync(() =>
        Database.use((db) =>
          db
            .update(CyberRelationTable)
            .set({
              writer_kind: input.writer_kind,
              status: input.status,
              confidence: input.confidence,
              source_event_id: input.source_event_id,
              evidence_refs: input.evidence_refs,
              time_updated: now,
            })
            .where(eq(CyberRelationTable.id, existing.id))
          .run(),
      ),
    )
      yield* Effect.promise(() =>
        appendProjectionLine(instance.directory, operation_slug, "relations.jsonl", {
          id: existing.id,
          project_id,
          operation_slug,
          src_kind: input.src_kind,
          src_key: input.src_key,
          relation: input.relation,
          dst_kind: input.dst_kind,
          dst_key: input.dst_key,
          writer_kind: input.writer_kind,
          status: input.status,
          confidence: input.confidence,
          source_event_id: input.source_event_id,
          evidence_refs: input.evidence_refs,
          time_created: existing.time_created,
          time_updated: now,
        }),
      ).pipe(Effect.catch(() => Effect.void))
      return existing.id
    }
    const relation_id = id("crel")
    yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .insert(CyberRelationTable)
          .values({
            id: relation_id,
            project_id,
            operation_slug,
            src_kind: input.src_kind,
            src_key: input.src_key,
            relation: input.relation,
            dst_kind: input.dst_kind,
            dst_key: input.dst_key,
            writer_kind: input.writer_kind,
            status: input.status,
            confidence: input.confidence,
            source_event_id: input.source_event_id,
            evidence_refs: input.evidence_refs,
            time_created: now,
            time_updated: now,
          })
          .run(),
      ),
    )
    yield* Effect.promise(() =>
      appendProjectionLine(instance.directory, operation_slug, "relations.jsonl", {
        id: relation_id,
        project_id,
        operation_slug,
        src_kind: input.src_kind,
        src_key: input.src_key,
        relation: input.relation,
        dst_kind: input.dst_kind,
        dst_key: input.dst_key,
        writer_kind: input.writer_kind,
        status: input.status,
        confidence: input.confidence,
        source_event_id: input.source_event_id,
        evidence_refs: input.evidence_refs,
        time_created: now,
        time_updated: now,
      }),
    ).pipe(Effect.catch(() => Effect.void))
    return relation_id
  })

  export const listLedger = Effect.fn("Cyber.listLedger")(function* (input?: {
    operation_slug?: string
    limit?: number
  }) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input?.operation_slug, instance))
    if (!instance) return []
    if (!operation_slug) return []
    const project_id = instance.project.id
    return yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .select()
          .from(CyberLedgerTable)
          .where(and(eq(CyberLedgerTable.project_id, project_id), eq(CyberLedgerTable.operation_slug, operation_slug)))
          .orderBy(desc(CyberLedgerTable.time_created), desc(CyberLedgerTable.id))
          .limit(Math.max(1, Math.min(200, input?.limit ?? 20)))
          .all() as LedgerEvent[],
      ),
    )
  })

  export async function readProjectedLedger(
    workspace: string,
    operation_slug: string,
    options?: { id_prefix?: string; project_id?: string },
  ): Promise<LedgerEvent[]> {
    const file = path.join(projectionDir(workspace, operation_slug), "ledger.jsonl")
    const raw = await readFile(file, "utf8").catch(() => "")
    if (!raw) return []
    const latest = new Map<string, Record<string, unknown>>()
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>
        const key = typeof parsed.id === "string" ? parsed.id : line
        latest.set(key, parsed)
      } catch {}
    }
    return [...latest.values()]
      .map((record, index) =>
        parseProjectedLedgerRecord(
          record,
          {
            operation_slug,
            id_prefix: options?.id_prefix,
            project_id: options?.project_id,
          },
          index,
        ),
      )
      .filter((event): event is LedgerEvent => Boolean(event))
      .sort((a, b) => b.time_created - a.time_created || b.id.localeCompare(a.id))
  }

  export const listFacts = Effect.fn("Cyber.listFacts")(function* (input?: {
    operation_slug?: string
    limit?: number
    status?: string
  }) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input?.operation_slug, instance))
    if (!instance) return []
    if (!operation_slug) return []
    const project_id = instance.project.id
    return yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .select()
          .from(CyberFactTable)
          .where(
            input?.status
              ? and(
                  eq(CyberFactTable.project_id, project_id),
                  eq(CyberFactTable.operation_slug, operation_slug),
                  eq(CyberFactTable.status, input.status),
                )
              : and(eq(CyberFactTable.project_id, project_id), eq(CyberFactTable.operation_slug, operation_slug)),
          )
          .orderBy(asc(CyberFactTable.entity_kind), asc(CyberFactTable.entity_key), asc(CyberFactTable.fact_name))
          .limit(Math.max(1, Math.min(200, input?.limit ?? 40)))
          .all() as Fact[],
      ),
    )
  })

  export async function readProjectedFacts(
    workspace: string,
    operation_slug: string,
    options?: { id_prefix?: string; project_id?: string; writer_kind?: string },
  ): Promise<Fact[]> {
    const file = path.join(projectionDir(workspace, operation_slug), "facts.jsonl")
    const raw = await readFile(file, "utf8").catch(() => "")
    if (!raw) return []
    const latest = new Map<string, Record<string, unknown>>()
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>
        const key = `${parsed["entity_kind"]}:${parsed["entity_key"]}:${parsed["fact_name"]}`
        latest.set(key, parsed)
      } catch {}
    }
    return hydrateProjectedFactRecords([...latest.values()], {
      operation_slug,
      id_prefix: options?.id_prefix,
      project_id: options?.project_id,
      writer_kind: options?.writer_kind,
    })
  }

  export function summarizeFacts(facts: Fact[]): FactSummary {
    const hosts = facts.filter((fact) => fact.entity_kind === "host").length
    const services = facts.filter((fact) => fact.entity_kind === "service").length
    const web_pages = facts.filter((fact) => fact.entity_kind === "web_page" && fact.fact_name === "fetch_result").length
    const route_facts = facts.filter((fact) => fact.entity_kind === "http_route").length
    const http_forms = facts.filter((fact) => fact.entity_kind === "http_form").length
    const identities = facts.filter((fact) => fact.entity_kind === "identity" && fact.fact_name === "descriptor").length
    const active_identities = facts.filter(
      (fact) => fact.entity_kind === "identity" && fact.fact_name === "active" && fact.value_json === true,
    ).length
    const tool_adapters_present = facts.filter(
      (fact) => fact.entity_kind === "tool_adapter" && fact.fact_name === "presence" && fact.status !== "stale",
    ).length
    const tool_adapters_missing = facts.filter(
      (fact) => fact.entity_kind === "tool_adapter" && fact.fact_name === "presence" && fact.status === "stale",
    ).length
    const candidate_findings = facts.filter((fact) => fact.entity_kind === "finding_candidate").length
    const findings = facts.filter((fact) => fact.entity_kind === "finding" && fact.fact_name === "record").length
    const knowledge_queries = facts.filter((fact) => fact.entity_kind === "knowledge_query").length
    const plan_nodes = facts.filter((fact) => fact.entity_kind === "plan_node" && fact.fact_name === "todo_state").length
    const observations_projected = facts.filter(
      (fact) =>
        fact.entity_kind === "observation" &&
        fact.fact_name === "record" &&
        !Boolean((fact.value_json as { removed?: boolean } | null)?.removed),
    ).length
    const running_plan_nodes = facts.filter(
      (fact) =>
        fact.entity_kind === "plan_node" &&
        fact.fact_name === "todo_state" &&
        ((fact.value_json as { status?: string } | null)?.status ?? "") === "running",
    ).length
    const done_plan_nodes = facts.filter(
      (fact) =>
        fact.entity_kind === "plan_node" &&
        fact.fact_name === "todo_state" &&
        ((fact.value_json as { status?: string } | null)?.status ?? "") === "done",
    ).length
    const ready_capsules = facts.filter(
      (fact) =>
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        fact.fact_name === "capsule_readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "ready",
    ).length
    const degraded_capsules = facts.filter(
      (fact) =>
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        fact.fact_name === "capsule_readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "degraded",
    ).length
    const unavailable_capsules = facts.filter(
      (fact) =>
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        fact.fact_name === "capsule_readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "unavailable",
    ).length
    const ready_verticals = facts.filter(
      (fact) =>
        fact.entity_kind === "vertical" &&
        fact.fact_name === "readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "ready",
    ).length
    const degraded_verticals = facts.filter(
      (fact) =>
        fact.entity_kind === "vertical" &&
        fact.fact_name === "readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "degraded",
    ).length
    const unavailable_verticals = facts.filter(
      (fact) =>
        fact.entity_kind === "vertical" &&
        fact.fact_name === "readiness" &&
        ((fact.value_json as { status?: string } | null)?.status ?? fact.status) === "unavailable",
    ).length
    const recommended_capsules = facts.filter(
      (fact) =>
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") && fact.fact_name === "capsule_recommendation",
    ).length
    const executed_capsules = facts.filter(
      (fact) => (fact.entity_kind === "play" || fact.entity_kind === "runbook") && fact.fact_name === "capsule_execution",
    ).length
    const deliverables = facts.filter((fact) => fact.entity_kind === "deliverable").length
    const share_bundles = facts.filter((fact) => fact.entity_kind === "share_bundle").length
    const verified_findings = facts.filter(
      (fact) => fact.entity_kind === "finding" && fact.fact_name === "record" && fact.status === "verified",
    ).length
    const evidence_backed_findings = facts.filter(
      (fact) =>
        fact.entity_kind === "finding" &&
        fact.fact_name === "record" &&
        fact.status === "verified" &&
        Array.isArray(fact.evidence_refs) &&
        fact.evidence_refs.length > 0,
    ).length
      const findingRecords = facts
        .map(summarizeFindingFact)
        .filter((item): item is NonNullable<typeof item> => Boolean(item))
      const findingBuckets = bucketFindings(findingRecords)
      const reportable_findings = findingBuckets.reportable.length
    const rejected_findings = facts.filter(
      (fact) =>
        (fact.entity_kind === "finding_candidate" || (fact.entity_kind === "finding" && fact.fact_name === "record")) &&
        isRejectedFinding({
          kind: fact.entity_kind === "finding" ? "finding" : "candidate",
          status: fact.status,
        }),
    ).length
    const suspected_findings = findingBuckets.suspected.length
    const replay_backed_findings = facts.filter((fact) => {
      if (fact.entity_kind !== "finding" || fact.fact_name !== "record") return false
      const value = fact.value_json as { replay_present?: boolean; replay_reason?: string; replay_exemption?: unknown } | null
      return replayState({
        kind: "finding",
        replay_present: value?.replay_present,
        replay_reason: value?.replay_reason,
      }) === "present"
    }).length
    const replay_exempt_findings = facts.filter((fact) => {
      if (fact.entity_kind !== "finding" || fact.fact_name !== "record") return false
      const value = fact.value_json as { replay_present?: boolean; replay_reason?: string; replay_exemption?: unknown } | null
      return replayState({
        kind: "finding",
        replay_present: value?.replay_present,
        replay_reason: normalizeReplayExemption({
          replay_reason: value?.replay_reason,
          replay_exemption: value?.replay_exemption,
        })?.rationale,
      }) === "exempt"
    }).length
    const workflow_step_statuses = facts.filter(
      (fact) => fact.entity_kind === "workflow_step" && fact.fact_name === "step_status",
    ).length
    return {
      hosts,
      services,
      web_pages,
      route_facts,
      http_forms,
      identities,
      active_identities,
      tool_adapters_present,
      tool_adapters_missing,
      candidate_findings,
      findings,
      knowledge_queries,
      plan_nodes,
      observations_projected,
      running_plan_nodes,
      done_plan_nodes,
      ready_capsules,
      degraded_capsules,
      unavailable_capsules,
      executed_capsules,
      ready_verticals,
      degraded_verticals,
      unavailable_verticals,
      recommended_capsules,
      deliverables,
      share_bundles,
      reportable_findings,
      suspected_findings,
      rejected_findings,
      verified_findings,
      evidence_backed_findings,
      replay_backed_findings,
      replay_exempt_findings,
      workflow_step_statuses,
    }
  }

  export const listRelations = Effect.fn("Cyber.listRelations")(function* (input?: {
    operation_slug?: string
    limit?: number
    status?: string
  }) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input?.operation_slug, instance))
    if (!instance) return []
    if (!operation_slug) return []
    const project_id = instance.project.id
    return yield* Effect.sync(() =>
      Database.use((db) =>
        db
          .select()
          .from(CyberRelationTable)
          .where(
            input?.status
              ? and(
                  eq(CyberRelationTable.project_id, project_id),
                  eq(CyberRelationTable.operation_slug, operation_slug),
                  eq(CyberRelationTable.status, input.status),
                )
              : and(eq(CyberRelationTable.project_id, project_id), eq(CyberRelationTable.operation_slug, operation_slug)),
          )
          .orderBy(
            asc(CyberRelationTable.src_kind),
            asc(CyberRelationTable.src_key),
            asc(CyberRelationTable.relation),
            asc(CyberRelationTable.dst_kind),
            asc(CyberRelationTable.dst_key),
          )
          .limit(Math.max(1, Math.min(200, input?.limit ?? 40)))
          .all() as Relation[],
      ),
    )
  })

  export async function readProjectedRelations(
    workspace: string,
    operation_slug: string,
    options?: { id_prefix?: string; project_id?: string; writer_kind?: string },
  ): Promise<Relation[]> {
    const file = path.join(projectionDir(workspace, operation_slug), "relations.jsonl")
    const raw = await readFile(file, "utf8").catch(() => "")
    if (!raw) return []
    const latest = new Map<string, Record<string, unknown>>()
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>
        const key = `${parsed["src_kind"]}:${parsed["src_key"]}:${parsed["relation"]}:${parsed["dst_kind"]}:${parsed["dst_key"]}`
        latest.set(key, parsed)
      } catch {}
    }
    return hydrateProjectedRelationRows([...latest.values()], {
      operation_slug,
      id_prefix: options?.id_prefix,
      project_id: options?.project_id,
      writer_kind: options?.writer_kind,
    })
  }

  export function projectedDeliverableState(fact: Fact): ProjectedDeliverableState | undefined {
    if (fact.entity_kind !== "deliverable" || fact.fact_name !== "report_bundle") return undefined
    const value = asObject(fact.value_json)
    return {
      key: fact.entity_key,
      bundle_dir: typeof value?.bundle_dir === "string" ? value.bundle_dir : undefined,
      report_path: typeof value?.report_path === "string" ? value.report_path : undefined,
      manifest_path: typeof value?.manifest_path === "string" ? value.manifest_path : undefined,
      counts: asObject(value?.counts) as Record<string, unknown> | undefined,
      format: typeof value?.format === "string" ? value.format : undefined,
      time_updated: fact.time_updated,
    }
  }

  export function projectedShareBundleState(fact: Fact): ProjectedShareBundleState | undefined {
    if (fact.entity_kind !== "share_bundle" || fact.fact_name !== "archive") return undefined
    const value = asObject(fact.value_json)
    return {
      key: fact.entity_key,
      path: typeof value?.path === "string" ? value.path : undefined,
      size: typeof value?.size === "number" ? value.size : undefined,
      sha256: typeof value?.sha256 === "string" ? value.sha256 : undefined,
      signed: Boolean(value?.signed),
      redacted: value?.redacted === false ? false : true,
      warning: typeof value?.warning === "string" ? value.warning : undefined,
      time_updated: fact.time_updated,
    }
  }

  export function latestDeliverableFromFacts(facts: Fact[]): ProjectedDeliverableState | undefined {
    return facts
      .map(projectedDeliverableState)
      .filter((item): item is ProjectedDeliverableState => Boolean(item))
      .filter((item) => item.bundle_dir && item.report_path && item.manifest_path)
      .sort((a, b) => b.time_updated - a.time_updated)[0]
  }

  export function latestShareBundleFromFacts(facts: Fact[]): ProjectedShareBundleState | undefined {
    return facts
      .map(projectedShareBundleState)
      .filter((item): item is ProjectedShareBundleState => Boolean(item))
      .filter((item) => item.path)
      .sort((a, b) => b.time_updated - a.time_updated)[0]
  }

  export function projectStateFromParts(input: ProjectedStateParts): ProjectedState {
    const operationState = input.operation_state
    const scopePolicy = input.scope_policy
    const autonomyPolicy = input.autonomy_policy
    const projectedFacts = input.facts
    const projectedLedger = input.ledger
    const projectedRelations = input.relations
    const findings: ProjectedFinding[] = []
    const capsules: ProjectedCapsuleState[] = []
    const knowledge: ProjectedKnowledgeState[] = []
    const identities: ProjectedIdentityState[] = []
    const toolAdapters: ProjectedToolAdapterState[] = []
    const verticals: ProjectedVerticalState[] = []
    const deliverables: ProjectedDeliverableState[] = []
    const shareBundles: ProjectedShareBundleState[] = []
    const observations: ProjectedObservationState[] = []
    const planNodes: ProjectedPlanNodeState[] = []
    let planNodesProjected = 0
    const workflows: ProjectedWorkflowStatus[] = []
    const workflowSteps: ProjectedWorkflowStepStatus[] = []

    for (const fact of projectedFacts) {
      const value = asObject(fact.value_json)

      if (fact.entity_kind === "finding_candidate") {
        findings.push({
          key: fact.entity_key,
          kind: "candidate",
          status: fact.status,
          title:
            (typeof value?.title === "string" && value.title) ||
            (typeof value?.check_name === "string" && value.check_name) ||
            (typeof value?.check_id === "string" && value.check_id) ||
            (typeof value?.line === "string" && value.line) ||
            fact.entity_key,
          summary:
            (typeof value?.description === "string" && value.description) ||
            (typeof value?.message === "string" && value.message) ||
            (typeof value?.line === "string" && value.line) ||
            undefined,
          severity: typeof value?.severity === "string" ? value.severity : undefined,
        })
        continue
      }

      if (fact.entity_kind === "finding" && fact.fact_name === "record") {
        findings.push({
          key: fact.entity_key,
          kind: "finding",
          status: fact.status,
          title: (typeof value?.title === "string" && value.title) || fact.entity_key,
          summary: typeof value?.summary === "string" ? value.summary : undefined,
          proof_summary: typeof value?.proof_summary === "string" ? value.proof_summary : undefined,
          severity: typeof value?.severity === "string" ? value.severity : undefined,
          evidence_refs: fact.evidence_refs,
          replay_present: Boolean(value?.replay_present),
          replay_reason: typeof value?.replay_reason === "string" ? value.replay_reason : undefined,
          oracle_status: typeof value?.oracle_status === "string" ? value.oracle_status : undefined,
          oracle_reason: typeof value?.oracle_reason === "string" ? value.oracle_reason : undefined,
          operator_promoted: Boolean(value?.operator_promoted),
        })
        continue
      }

      if (
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        (fact.fact_name === "capsule_readiness" || fact.fact_name === "capsule_recommendation" || fact.fact_name === "capsule_execution")
      ) {
        capsules.push({
          key: fact.entity_key,
          fact_name: fact.fact_name,
          name: typeof value?.name === "string" ? value.name : undefined,
          description: typeof value?.description === "string" ? value.description : undefined,
          status: typeof value?.status === "string" ? value.status : fact.status,
          operation_kind: typeof value?.operation_kind === "string" ? value.operation_kind : undefined,
          missing_required: Array.isArray(value?.missing_required)
            ? value.missing_required.filter((item): item is string => typeof item === "string")
            : [],
          missing_optional: Array.isArray(value?.missing_optional)
            ? value.missing_optional.filter((item): item is string => typeof item === "string")
            : [],
          invoked_via: typeof value?.invoked_via === "string" ? value.invoked_via : undefined,
          steps: typeof value?.steps === "number" ? value.steps : undefined,
          skipped: typeof value?.skipped === "number" ? value.skipped : undefined,
        })
        continue
      }

      if (fact.entity_kind === "knowledge_query") {
        knowledge.push({
          key: fact.entity_key,
          fact_name: fact.fact_name,
          status: fact.status,
          query: typeof value?.query === "string" ? value.query : undefined,
          returned: typeof value?.returned === "number" ? value.returned : undefined,
          severity: typeof value?.severity === "string" ? value.severity : undefined,
          type: typeof value?.type === "string" ? value.type : undefined,
          livecrawl: typeof value?.livecrawl === "string" ? value.livecrawl : undefined,
        })
        continue
      }

      if (fact.entity_kind === "identity" && (fact.fact_name === "descriptor" || fact.fact_name === "active")) {
        identities.push({
          key: fact.entity_key,
          fact_name: fact.fact_name,
          status: fact.status,
          mode: typeof value?.mode === "string" ? value.mode : undefined,
          header_keys: Array.isArray(value?.header_keys)
            ? value.header_keys.filter((item): item is string => typeof item === "string")
            : [],
          has_cookies: Boolean(value?.has_cookies),
          active: fact.fact_name === "active" ? fact.value_json === true : undefined,
        })
        continue
      }

      if (fact.entity_kind === "tool_adapter" && fact.fact_name === "presence") {
        toolAdapters.push({
          key: fact.entity_key,
          status: fact.status,
          present: fact.status !== "stale",
          path: typeof value?.path === "string" ? value.path : undefined,
          version: typeof value?.version === "string" ? value.version : undefined,
        })
        continue
      }

      if (fact.entity_kind === "vertical" && fact.fact_name === "readiness") {
        verticals.push({
          key: fact.entity_key,
          status: typeof value?.status === "string" ? value.status : fact.status,
          missing_required: Array.isArray(value?.missing_required)
            ? value.missing_required.filter((item): item is string => typeof item === "string")
            : [],
          missing_optional: Array.isArray(value?.missing_optional)
            ? value.missing_optional.filter((item): item is string => typeof item === "string")
            : [],
        })
        continue
      }

      const deliverable = projectedDeliverableState(fact)
      if (deliverable) {
        deliverables.push(deliverable)
        continue
      }

      const shareBundle = projectedShareBundleState(fact)
      if (shareBundle) {
        shareBundles.push(shareBundle)
        continue
      }

      if (fact.entity_kind === "observation" && fact.fact_name === "record") {
        observations.push({
          id: fact.entity_key,
          subtype: typeof value?.subtype === "string" ? value.subtype : "risk",
          title: typeof value?.title === "string" ? value.title : fact.entity_key,
          severity: typeof value?.severity === "string" ? value.severity : undefined,
          confidence: typeof value?.confidence === "number" ? value.confidence : undefined,
          status: typeof value?.status === "string" ? value.status : fact.status,
          note: typeof value?.note === "string" ? value.note : undefined,
          tags: Array.isArray(value?.tags) ? value.tags.filter((item): item is string => typeof item === "string") : [],
          evidence: Array.isArray(value?.evidence)
            ? value.evidence.filter((item): item is string => typeof item === "string")
            : [],
          created_at: typeof value?.created_at === "number" ? value.created_at : undefined,
          updated_at: typeof value?.updated_at === "number" ? value.updated_at : undefined,
          removed: Boolean(value?.removed),
        })
        continue
      }

      if (fact.entity_kind === "plan_node" && fact.fact_name === "todo_state") {
        planNodes.push({
          id: fact.entity_key,
          title: typeof value?.title === "string" ? value.title : fact.entity_key,
          parent_id: typeof value?.parent_id === "string" ? value.parent_id : undefined,
          status:
            value?.status === "planned" ||
            value?.status === "running" ||
            value?.status === "done" ||
            value?.status === "blocked" ||
            value?.status === "skipped"
              ? value.status
              : "planned",
          note: typeof value?.note === "string" ? value.note : undefined,
        })
        planNodesProjected += 1
        continue
      }

      if (
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        fact.fact_name === "workflow_status"
      ) {
        workflows.push({
          key: fact.entity_key,
          kind: fact.entity_kind,
          steps: Number(value?.steps ?? 0),
          skipped: Number(value?.skipped ?? 0),
          completed_steps: Number(value?.completed_steps ?? 0),
          failed_steps: Number(value?.failed_steps ?? 0),
          pending_steps: Number(value?.pending_steps ?? 0),
          degraded: Boolean(value?.degraded),
        })
        continue
      }

      if (fact.entity_kind === "workflow_step" && fact.fact_name === "step_status") {
        workflowSteps.push({
          key: fact.entity_key,
          workflow: fact.entity_key.split(":").slice(0, 2).join(":"),
          index: Number(value?.index ?? 0),
          tool: typeof value?.tool === "string" ? value.tool : undefined,
          label: typeof value?.label === "string" ? value.label : undefined,
          outcome: typeof value?.outcome === "string" ? value.outcome : "pending",
          outcome_title: typeof value?.outcome_title === "string" ? value.outcome_title : undefined,
          outcome_error: typeof value?.outcome_error === "string" ? value.outcome_error : undefined,
        })
      }
    }

    return {
      findings: findings.sort((a, b) => a.key.localeCompare(b.key)),
      capsules: capsules.sort((a, b) => a.key.localeCompare(b.key) || a.fact_name.localeCompare(b.fact_name)),
      knowledge: knowledge.sort((a, b) => a.key.localeCompare(b.key) || a.fact_name.localeCompare(b.fact_name)),
      identities: identities.sort((a, b) => a.key.localeCompare(b.key) || a.fact_name.localeCompare(b.fact_name)),
      tool_adapters: toolAdapters.sort((a, b) => a.key.localeCompare(b.key)),
      verticals: verticals.sort((a, b) => a.key.localeCompare(b.key)),
      deliverables: deliverables.sort((a, b) => b.time_updated - a.time_updated),
      share_bundles: shareBundles.sort((a, b) => b.time_updated - a.time_updated),
      observations: observations.sort((a, b) => a.id.localeCompare(b.id)),
      plan_nodes: planNodes.sort((a, b) => a.id.localeCompare(b.id)),
      plan_nodes_projected: planNodesProjected,
      relations: projectedRelations
        .map((relation) => ({
          src_kind: relation.src_kind,
          src_key: relation.src_key,
          relation: relation.relation,
          dst_kind: relation.dst_kind,
          dst_key: relation.dst_key,
          status: relation.status,
          confidence: relation.confidence,
        }))
        .sort(
          (a, b) =>
            a.src_kind.localeCompare(b.src_kind) ||
            a.src_key.localeCompare(b.src_key) ||
            a.relation.localeCompare(b.relation) ||
            a.dst_kind.localeCompare(b.dst_kind) ||
            a.dst_key.localeCompare(b.dst_key),
        ),
      workflows: workflows.sort((a, b) => a.key.localeCompare(b.key)),
      workflow_steps: workflowSteps.sort((a, b) => a.workflow.localeCompare(b.workflow) || a.index - b.index),
      timeline: projectedLedger.map((event) => ({
        id: event.id,
        kind: event.kind,
        source: event.source,
        status: event.status,
        summary: event.summary,
        time_created: event.time_created,
      })),
      summary: summarizeFacts(projectedFacts),
      operation_state: operationState,
      scope_policy: scopePolicy,
      autonomy_policy: autonomyPolicy,
    }
  }

  export async function readProjectedState(workspace: string, operation_slug: string): Promise<ProjectedState> {
    const [operationState, scopePolicy, autonomyPolicy, projectedFacts, projectedLedger, projectedRelations] =
      await Promise.all([
        Operation.readProjectedState(workspace, operation_slug).catch(() => undefined),
        Operation.readProjectedScopePolicy(workspace, operation_slug).catch(() => undefined),
        Operation.readProjectedAutonomyPolicy(workspace, operation_slug).catch(() => undefined),
        timeboxed(readProjectedFacts(workspace, operation_slug).catch(() => []), 2_000, []),
        timeboxed(readProjectedLedger(workspace, operation_slug).catch(() => []), 2_000, []),
        timeboxed(readProjectedRelations(workspace, operation_slug).catch(() => []), 2_000, []),
      ])
    return projectStateFromParts({
      operation_state: operationState,
      scope_policy: scopePolicy,
      autonomy_policy: autonomyPolicy,
      facts: projectedFacts,
      ledger: projectedLedger,
      relations: projectedRelations,
    })
  }

  export const contextPack = Effect.fn("Cyber.contextPack")(function* (input?: {
    operation_slug?: string
    max_events?: number
    max_facts?: number
    max_relations?: number
  }) {
    const instance = currentInstance()
    const operation_slug = yield* Effect.promise(() => resolveOperationSlug(input?.operation_slug, instance))
    if (!instance) return undefined
    if (!operation_slug) return undefined
    const [facts, relations, ledger] = yield* Effect.all([
      listFacts({
        operation_slug,
        limit: Math.max(1, Math.min(80, input?.max_facts ?? 20)),
      }),
      listRelations({
        operation_slug,
        limit: Math.max(1, Math.min(80, input?.max_relations ?? 20)),
      }),
      listLedger({
        operation_slug,
        limit: Math.max(1, Math.min(80, input?.max_events ?? 12)),
      }),
    ])
    const workflowSteps = facts
      .filter((fact) => fact.entity_kind === "workflow_step" && fact.fact_name === "step_status")
      .sort((a, b) => {
        const ai = Number((a.value_json as { index?: number } | null)?.index ?? 0)
        const bi = Number((b.value_json as { index?: number } | null)?.index ?? 0)
        return ai - bi
      })
    const findingRecords = facts.map(summarizeFindingFact).filter((item): item is NonNullable<typeof item> => Boolean(item))
    const findingBuckets = bucketFindings(findingRecords)
    const deliverables = facts.filter((fact) => fact.entity_kind === "deliverable")
    const shareBundles = facts.filter((fact) => fact.entity_kind === "share_bundle")
    const identities = facts.filter(
      (fact) => fact.entity_kind === "identity" && (fact.fact_name === "descriptor" || fact.fact_name === "active"),
    )
    const capsules = facts.filter(
      (fact) =>
        (fact.entity_kind === "play" || fact.entity_kind === "runbook") &&
        (fact.fact_name === "capsule_readiness" || fact.fact_name === "capsule_recommendation" || fact.fact_name === "capsule_execution"),
    )
    const knowledge = facts.filter((fact) => fact.entity_kind === "knowledge_query")
    const toolAdapters = facts.filter((fact) => fact.entity_kind === "tool_adapter" && fact.fact_name === "presence")
    const verticals = facts.filter((fact) => fact.entity_kind === "vertical" && fact.fact_name === "readiness")
    const observations = facts.filter((fact) => fact.entity_kind === "observation" && fact.fact_name === "record")
    const plan = facts.filter(
      (fact) =>
        (fact.entity_kind === "operation" && fact.fact_name === "plan_summary") ||
        (fact.entity_kind === "plan_node" && fact.fact_name === "todo_state"),
    )
    const lines = ["# Active Cyber Context", `operation_slug: ${operation_slug}`, `project_id: ${instance.project.id}`, "", "## Facts"]
    if (facts.length === 0) lines.push("_none yet_")
    else facts.forEach((fact) => lines.push(factLine(fact)))
    lines.push("")
    lines.push("## Findings")
    if (findingBuckets.all.length === 0) lines.push("_none yet_")
    else {
      lines.push("### Reportable")
      if (findingBuckets.reportable.length === 0) lines.push("_none yet_")
      else findingBuckets.reportable.slice(0, 12).forEach((fact) => lines.push(findingLineFromRecord(fact)))
      lines.push("")
      lines.push("### Suspected")
      if (findingBuckets.suspected.length === 0) lines.push("_none yet_")
      else findingBuckets.suspected.slice(0, 12).forEach((fact) => lines.push(findingLineFromRecord(fact)))
      lines.push("")
      lines.push("### Rejected Or Stale")
      if (findingBuckets.rejected.length === 0) lines.push("_none yet_")
      else findingBuckets.rejected.slice(0, 12).forEach((fact) => lines.push(findingLineFromRecord(fact)))
    }
    lines.push("")
    lines.push("## Knowledge")
    if (knowledge.length === 0) lines.push("_none yet_")
    else knowledge.slice(0, 12).forEach((fact) => lines.push(knowledgeLine(fact)))
    lines.push("")
    lines.push("## Identities")
    if (identities.length === 0) lines.push("_none yet_")
    else identities.slice(0, 16).forEach((fact) => lines.push(factLine(fact)))
    lines.push("")
    lines.push("## Tool Adapters")
    if (toolAdapters.length === 0) lines.push("_none yet_")
    else toolAdapters.slice(0, 20).forEach((fact) => lines.push(factLine(fact)))
    lines.push("")
    lines.push("## Plan")
    if (plan.length === 0) lines.push("_none yet_")
    else plan.slice(0, 16).forEach((fact) => lines.push(planLine(fact)))
    lines.push("")
    lines.push("## Observations")
    if (observations.length === 0) lines.push("_none yet_")
    else observations.slice(0, 16).forEach((fact) => lines.push(observationLine(fact)))
    lines.push("")
    lines.push("## Capsules")
    if (capsules.length === 0) lines.push("_none yet_")
    else capsules.slice(0, 16).forEach((fact) => lines.push(capsuleLine(fact)))
    lines.push("")
    lines.push("## Verticals")
    if (verticals.length === 0) lines.push("_none yet_")
    else verticals.slice(0, 16).forEach((fact) => lines.push(factLine(fact)))
    lines.push("")
    lines.push("## Deliverables")
    if (deliverables.length === 0) lines.push("_none yet_")
    else deliverables.slice(0, 10).forEach((fact) => lines.push(deliverableLine(fact)))
    lines.push("")
    lines.push("## Share Bundles")
    if (shareBundles.length === 0) lines.push("_none yet_")
    else shareBundles.slice(0, 10).forEach((fact) => lines.push(shareBundleLine(fact)))
    lines.push("")
    lines.push("## Workflow Steps")
    if (workflowSteps.length === 0) lines.push("_none yet_")
    else workflowSteps.slice(0, 20).forEach((fact) => lines.push(workflowStepLine(fact)))
    lines.push("")
    lines.push("## Relations")
    if (relations.length === 0) lines.push("_none yet_")
    else relations.forEach((relation) => lines.push(relationLine(relation)))
    lines.push("")
    lines.push("## Recent Ledger")
    if (ledger.length === 0) lines.push("_none yet_")
    else ledger.slice().reverse().forEach((event) => lines.push(ledgerLine(event)))
    return lines.join("\n")
  })
}
