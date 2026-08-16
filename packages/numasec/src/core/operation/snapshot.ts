import { stat } from "node:fs/promises"
import path from "node:path"
import { Effect } from "effect"
import { Cyber, type Fact, type LedgerEvent, type ProjectedFinding, type ProjectedState, type Relation } from "@/core/cyber"
import { bucketFindings, replayState } from "@/core/cyber/finding"
import { Doctor, type DoctorReport } from "@/core/doctor"
import { Evidence, type EvidenceEntry } from "@/core/evidence"
import { PlayRegistry, isNormalizedStep } from "@/core/play"
import { activeIdentity, type ResolvedIdentity } from "@/core/vault"
import * as Operation from "./operation"

const CAPABILITY_READINESS_TTL_MS = 24 * 60 * 60 * 1000

export type SourceMarker = { id: string; at: number; iso: string }
export type TimeMarker = { at: number; iso: string }

export type CapabilityDomain =
  | "AppSec"
  | "Pentest"
  | "SAST"
  | "SCA"
  | "OSINT"
  | "CTF"
  | "Binary"
  | "Cloud/IaC"
  | "Forensics"

export type DomainCapability = {
  domain: CapabilityDomain
  status: "ready" | "degraded" | "unavailable"
  ready: string[]
  degraded: string[]
  unavailable: string[]
  missing_required: string[]
  missing_optional: string[]
}

export type SnapshotRoute = {
  key: string
  fact_names: string[]
  status: string
  method?: string
  http_status?: number
  route?: string
  content_type?: string
  evidence_refs: string[]
  source_event_ids: string[]
  time_updated: number
}

export type SnapshotService = {
  key: string
  fact_names: string[]
  status: string
  value?: unknown
  evidence_refs: string[]
  time_updated: number
}

export type SnapshotComponent = {
  key: string
  name?: string
  version?: string
  status: string
  evidence_refs: string[]
  time_updated: number
}

export type SnapshotEvidence = {
  sha256: string
  ext: string
  size: number
  mime?: string
  label?: string
  source?: string
  at: number
  linked_finding_keys: string[]
  linked_observation_ids: string[]
  linked_routes: string[]
  replay_labels: string[]
}

export type OperationSnapshot = {
  generated_at: string
  stale: boolean
  context_file_stale: boolean
  stale_context: boolean
  stale_capability_readiness: boolean
  source_latest?: SourceMarker
  source_semantic_latest?: SourceMarker
  source_audit_latest?: SourceMarker
  source_ledger_latest?: SourceMarker
  source_fact_latest?: SourceMarker
  source_evidence_latest?: SourceMarker
  capability_source_latest?: SourceMarker
  source_context_mtime?: TimeMarker
  audit_after_context?: boolean
  projection_lag_ms?: number
  warnings: string[]
  counts: {
    facts: number
    relations: number
    ledger: number
    routes: number
    route_facts: number
    services: number
    components: number
    observations: number
    open_observations: number
    findings: number
    candidate_findings: number
    reportable_findings: number
    suspected_findings: number
    rejected_findings: number
    evidence: number
    deliverables: number
    share_bundles: number
  }
  operation?: Operation.Info
  scope?: Operation.ProjectedScopePolicy
  autonomy?: Operation.ProjectedAutonomyPolicy
  active_identity?: {
    key: string
    mode: ResolvedIdentity["mode"]
    header_keys: string[]
    has_cookies: boolean
  }
  active_workflow?: {
    kind: "play" | "runbook"
    id: string
    completed_steps: number
    failed_steps: number
    pending_steps: number
    skipped: number
    next_step?: SnapshotWorkflowStep
    no_next_step_reason?: string
  }
  projected?: ProjectedState
  facts: Fact[]
  relations: Relation[]
  ledger: LedgerEvent[]
  findings: {
    reportable: ProjectedFinding[]
    suspected: ProjectedFinding[]
    rejected: ProjectedFinding[]
    all: ProjectedFinding[]
  }
  observations: ProjectedState["observations"]
  evidence: {
    count: number
    total_bytes: number
    latest?: SnapshotEvidence
    entries: SnapshotEvidence[]
  }
  routes: SnapshotRoute[]
  services: SnapshotService[]
  components: SnapshotComponent[]
  capabilities: {
    domains: DomainCapability[]
    tools_present: number
    tools_total: number
    missing_binaries: string[]
    browser_present?: boolean
  }
  deliverables: {
    latest?: ProjectedState["deliverables"][number]
    count: number
  }
  sharing: {
    latest?: ProjectedState["share_bundles"][number]
    count: number
  }
  recommended_next_actions: string[]
}

export type SnapshotWorkflowStep = {
  index: number
  kind: string
  tool?: string
  label?: string
  args?: unknown
  outcome?: string
  read_only_hint?: boolean
}

export type BuildOptions = {
  slug?: string
  includeDoctor?: boolean
  doctorTimeoutMs?: number
  maxFindings?: number
  maxObservations?: number
  maxEvidence?: number
  maxRoutes?: number
  maxComponents?: number
}

type PlayReadiness = {
  id: string
  name: string
  status: "ready" | "degraded" | "unavailable"
  missing_required: string[]
  missing_optional: string[]
}

type CapabilityItem = {
  id: string
  status: "ready" | "degraded" | "unavailable"
  missing_required: string[]
  missing_optional: string[]
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  informational: 0,
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  return Object.fromEntries(Object.entries(value))
}

function unique(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((item): item is string => Boolean(item)))]
}

function normalizeEvidenceRef(ref: string) {
  return ref.startsWith("sha256:") ? ref.slice("sha256:".length) : ref
}

function normalizeFindingKey(key: string) {
  if (key.startsWith("finding:")) return key.slice("finding:".length)
  if (key.startsWith("candidate:")) return key.slice("candidate:".length)
  return key
}

function routeNeedles(routeKey: string, route?: SnapshotRoute) {
  const candidates = [routeKey, route?.key, route?.route]
  for (const value of [routeKey, route?.key]) {
    if (!value) continue
    try {
      const url = new URL(value)
      candidates.push(url.pathname)
      candidates.push(`${url.pathname}${url.search}`)
    } catch {}
  }
  return unique(
    candidates
      .filter((item): item is string => Boolean(item))
      .map((item) => item.trim())
      .filter((item) => item.length > 1),
  )
}

function findingSearchText(finding: ProjectedFinding) {
  return [finding.key, finding.title, finding.summary, finding.proof_summary].filter(Boolean).join("\n").toLowerCase()
}

function mentionsRoute(finding: ProjectedFinding, needles: string[]) {
  const text = findingSearchText(finding)
  return needles.some((needle) => {
    const normalized = needle.toLowerCase()
    if (normalized === "/" || normalized.length < 3) return false
    return text.includes(normalized)
  })
}

function intersects(a: string[] | undefined, b: Set<string>) {
  return (a ?? []).some((item) => b.has(normalizeEvidenceRef(item)))
}

function severityRank(finding: ProjectedFinding) {
  return SEVERITY_RANK[(finding.severity ?? "").toLowerCase()] ?? -1
}

function sortFindings(input: ProjectedFinding[]) {
  return [...input].sort((a, b) => {
    const severity = severityRank(b) - severityRank(a)
    if (severity !== 0) return severity
    const evidence = (b.evidence_refs?.length ?? 0) - (a.evidence_refs?.length ?? 0)
    if (evidence !== 0) return evidence
    const replayA = replayState({ kind: a.kind, replay_present: a.replay_present, replay_reason: a.replay_reason })
    const replayB = replayState({ kind: b.kind, replay_present: b.replay_present, replay_reason: b.replay_reason })
    const replayScore = (replayB === "present" ? 2 : replayB === "exempt" ? 1 : 0) - (replayA === "present" ? 2 : replayA === "exempt" ? 1 : 0)
    if (replayScore !== 0) return replayScore
    return a.key.localeCompare(b.key)
  })
}

function latestLedger(ledger: LedgerEvent[]) {
  const latest = [...ledger].sort((a, b) => b.time_created - a.time_created)[0]
  if (!latest) return undefined
  return { id: latest.id, at: latest.time_created, iso: new Date(latest.time_created).toISOString() }
}

function isAuditOnlyLedger(event: LedgerEvent) {
  return event.kind === "tool.called" || event.kind === "tool.completed" || event.kind === "tool.error"
}

function latestAuditLedger(ledger: LedgerEvent[]) {
  return latestLedger(ledger.filter(isAuditOnlyLedger))
}

function latestSemanticLedger(ledger: LedgerEvent[]) {
  return latestLedger(ledger.filter((event) => !isAuditOnlyLedger(event)))
}

function latestFact(facts: Fact[]) {
  const latest = [...facts].sort((a, b) => (b.time_updated || b.time_created) - (a.time_updated || a.time_created))[0]
  const at = latest ? latest.time_updated || latest.time_created : undefined
  if (!latest || !at) return undefined
  return { id: latest.id, at, iso: new Date(at).toISOString() }
}

function latestRelation(relations: Relation[]) {
  const latest = [...relations].sort((a, b) => (b.time_updated || b.time_created) - (a.time_updated || a.time_created))[0]
  const at = latest ? latest.time_updated || latest.time_created : undefined
  if (!latest || !at) return undefined
  return { id: latest.id, at, iso: new Date(at).toISOString() }
}

function latestEvidence(entries: EvidenceEntry[]) {
  const latest = [...entries].sort((a, b) => b.at - a.at)[0]
  if (!latest) return undefined
  return { id: latest.sha256, at: latest.at, iso: new Date(latest.at).toISOString() }
}

function latestCapabilitySource(facts: Fact[]) {
  return latestFact(
    facts.filter((fact) => {
      if (fact.entity_kind === "environment" && fact.fact_name === "doctor_summary") return true
      if (fact.entity_kind === "tool_adapter" && fact.fact_name === "presence") return true
      if (fact.entity_kind === "vertical" && fact.fact_name === "readiness") return true
      if ((fact.entity_kind === "play" || fact.entity_kind === "runbook") && fact.fact_name.startsWith("capsule_")) return true
      return false
    }),
  )
}

function latestSource(...sources: Array<SourceMarker | undefined>) {
  return sources.filter((source): source is SourceMarker => Boolean(source)).sort((a, b) => b.at - a.at)[0]
}

async function contextFileMtime(workspace: string, slug: string) {
  const file = path.join(workspace, ".numasec", "operation", slug, "context", "active-context.md")
  return stat(file)
    .then((item) => ({ at: item.mtimeMs, iso: item.mtime.toISOString() }))
    .catch(() => undefined)
}

async function probeDoctorBounded(workspace: string, timeoutMs: number): Promise<DoctorReport | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      Effect.runPromise(Doctor.probe(workspace)),
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), timeoutMs)
      }),
    ])
  } catch {
    return undefined
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function summarizeRoutes(facts: Fact[]): SnapshotRoute[] {
  const grouped = new Map<string, SnapshotRoute>()
  for (const fact of facts) {
    if (fact.entity_kind !== "http_route") continue
    const value = asObject(fact.value_json)
    const existing =
      grouped.get(fact.entity_key) ??
      {
        key: fact.entity_key,
        fact_names: [],
        status: fact.status,
        evidence_refs: [],
        source_event_ids: [],
        time_updated: 0,
      }
    existing.fact_names = unique([...existing.fact_names, fact.fact_name])
    existing.status = fact.status === "stale" ? existing.status : fact.status
    existing.method = typeof value?.method === "string" ? value.method : existing.method
    existing.http_status = typeof value?.status === "number" ? value.status : existing.http_status
    existing.route = typeof value?.route === "string" ? value.route : existing.route
    existing.content_type = typeof value?.content_type === "string" ? value.content_type : existing.content_type
    existing.evidence_refs = unique([...existing.evidence_refs, ...(fact.evidence_refs ?? [])])
    existing.source_event_ids = unique([...existing.source_event_ids, fact.source_event_id])
    existing.time_updated = Math.max(existing.time_updated, fact.time_updated || fact.time_created)
    grouped.set(fact.entity_key, existing)
  }
  return [...grouped.values()].sort((a, b) => b.time_updated - a.time_updated || a.key.localeCompare(b.key))
}

function summarizeServices(facts: Fact[]): SnapshotService[] {
  const grouped = new Map<string, SnapshotService>()
  for (const fact of facts) {
    if (fact.entity_kind !== "service") continue
    const existing =
      grouped.get(fact.entity_key) ??
      {
        key: fact.entity_key,
        fact_names: [],
        status: fact.status,
        evidence_refs: [],
        time_updated: 0,
      }
    existing.fact_names = unique([...existing.fact_names, fact.fact_name])
    existing.status = fact.status === "stale" ? existing.status : fact.status
    existing.value = fact.value_json
    existing.evidence_refs = unique([...existing.evidence_refs, ...(fact.evidence_refs ?? [])])
    existing.time_updated = Math.max(existing.time_updated, fact.time_updated || fact.time_created)
    grouped.set(fact.entity_key, existing)
  }
  return [...grouped.values()].sort((a, b) => b.time_updated - a.time_updated || a.key.localeCompare(b.key))
}

function summarizeComponents(facts: Fact[]): SnapshotComponent[] {
  return facts
    .filter((fact) => fact.entity_kind === "component")
    .map((fact) => {
      const value = asObject(fact.value_json)
      return {
        key: fact.entity_key,
        name: typeof value?.name === "string" ? value.name : fact.entity_key,
        version: typeof value?.version === "string" ? value.version : undefined,
        status: fact.status,
        evidence_refs: fact.evidence_refs ?? [],
        time_updated: fact.time_updated || fact.time_created,
      }
    })
    .sort((a, b) => b.time_updated - a.time_updated || a.key.localeCompare(b.key))
}

function evidenceIndex(input: {
  entries: EvidenceEntry[]
  facts: Fact[]
  relations: Relation[]
  routes: SnapshotRoute[]
}): SnapshotEvidence[] {
  const routeKeys = new Set(input.routes.map((route) => route.key))
  return input.entries
    .map((entry) => {
      const sha = normalizeEvidenceRef(entry.sha256)
      const linkedFindingKeys = input.facts
        .filter((fact) => (fact.evidence_refs ?? []).map(normalizeEvidenceRef).includes(sha))
        .filter((fact) => fact.entity_kind === "finding" || fact.entity_kind === "finding_candidate")
        .map((fact) => fact.entity_key)
      const linkedObservationIds = input.facts
        .filter((fact) => fact.entity_kind === "observation" && fact.fact_name === "record")
        .filter((fact) => {
          const value = asObject(fact.value_json)
          const valueEvidence = Array.isArray(value?.evidence) ? value.evidence.map((item) => normalizeEvidenceRef(String(item))) : []
          return valueEvidence.includes(sha) || (fact.evidence_refs ?? []).map(normalizeEvidenceRef).includes(sha)
        })
        .map((fact) => fact.entity_key)
      const relationFindingKeys = input.relations
        .filter((relation) => normalizeEvidenceRef(relation.dst_key) === sha || normalizeEvidenceRef(relation.src_key) === sha)
        .filter((relation) => relation.src_kind === "finding" || relation.dst_kind === "finding")
        .map((relation) => (relation.src_kind === "finding" ? relation.src_key : relation.dst_key))
      const relationObservationIds = input.relations
        .filter((relation) => normalizeEvidenceRef(relation.dst_key) === sha || normalizeEvidenceRef(relation.src_key) === sha)
        .filter((relation) => relation.src_kind === "observation" || relation.dst_kind === "observation")
        .map((relation) => (relation.src_kind === "observation" ? relation.src_key : relation.dst_key))
      const linkedRoutes = input.facts
        .filter((fact) => fact.entity_kind === "http_route")
        .filter((fact) => (fact.evidence_refs ?? []).map(normalizeEvidenceRef).includes(sha))
        .map((fact) => fact.entity_key)
      const relationRoutes = input.relations
        .filter((relation) => (relation.evidence_refs ?? []).map(normalizeEvidenceRef).includes(sha))
        .flatMap((relation) => [relation.src_key, relation.dst_key].filter((key) => routeKeys.has(key)))
      const replayLabels = input.facts
        .filter((fact) => fact.entity_kind === "finding" && fact.fact_name === "replay_bundle")
        .filter((fact) => (fact.evidence_refs ?? []).map(normalizeEvidenceRef).includes(sha))
        .map((fact) => fact.entity_key)
      return {
        ...entry,
        linked_finding_keys: unique([...linkedFindingKeys, ...relationFindingKeys]),
        linked_observation_ids: unique([...linkedObservationIds, ...relationObservationIds]),
        linked_routes: unique([...linkedRoutes, ...relationRoutes]),
        replay_labels: unique(replayLabels),
      }
    })
    .sort((a, b) => b.at - a.at)
}

function collectPlayReadiness(report: DoctorReport | undefined): PlayReadiness[] {
  if (!report) return []
  const binaries = new Set(report.binaries.filter((item) => item.present).map((item) => item.name))
  const runtimes: Record<string, boolean | undefined> = { browser: report.browser.present }
  return PlayRegistry.list().map((play) => {
    const missing_required: string[] = []
    const missing_optional: string[] = []
    const seen = new Set<string>()
    for (const step of play.steps) {
      if (!isNormalizedStep(step)) continue
      for (const req of step.requires ?? []) {
        const key = `${req.kind}:${req.id}:${req.missingAs}`
        if (seen.has(key)) continue
        seen.add(key)
        const present = req.kind === "binary" ? binaries.has(req.id) : Boolean(runtimes[req.id])
        if (present) continue
        if (req.missingAs === "required") missing_required.push(req.label)
        else missing_optional.push(req.label)
      }
    }
    return {
      id: play.id,
      name: play.name,
      status: missing_required.length > 0 ? "unavailable" : missing_optional.length > 0 ? "degraded" : "ready",
      missing_required,
      missing_optional,
    }
  })
}

function domainStatus(items: Array<{ status: "ready" | "degraded" | "unavailable" }>) {
  if (items.some((item) => item.status === "unavailable")) return "unavailable"
  if (items.some((item) => item.status === "degraded")) return "degraded"
  return "ready"
}

function domain(input: {
  domain: DomainCapability["domain"]
  items: Array<{ id: string; status: "ready" | "degraded" | "unavailable"; missing_required: string[]; missing_optional: string[] }>
}): DomainCapability {
  return {
    domain: input.domain,
    status: domainStatus(input.items),
    ready: input.items.filter((item) => item.status === "ready").map((item) => item.id),
    degraded: input.items.filter((item) => item.status === "degraded").map((item) => item.id),
    unavailable: input.items.filter((item) => item.status === "unavailable").map((item) => item.id),
    missing_required: unique(input.items.flatMap((item) => item.missing_required)),
    missing_optional: unique(input.items.flatMap((item) => item.missing_optional)),
  }
}

function staticCapability(
  id: string,
  status: "ready" | "degraded" | "unavailable",
  missing_required: string[] = [],
  missing_optional: string[] = [],
) {
  return { id, status, missing_required, missing_optional }
}

function normalizeCapabilityStatus(status: string | undefined): "ready" | "degraded" | "unavailable" {
  if (status === "ready" || status === "degraded" || status === "unavailable") return status
  return "unavailable"
}

function itemFromPlay(
  id: string,
  input: { projected?: ProjectedState; binaries: Set<string>; browser_present?: boolean },
): CapabilityItem {
  const projected = input.projected?.capsules.find(
    (item) => item.fact_name === "capsule_readiness" && item.key === id,
  )
  if (projected) {
    return {
      id,
      status: normalizeCapabilityStatus(projected.status),
      missing_required: projected.missing_required,
      missing_optional: projected.missing_optional,
    }
  }

  const play = PlayRegistry.get(id)
  if (!play) return staticCapability(id, "unavailable", [id])

  const missing_required: string[] = []
  const missing_optional: string[] = []
  const seen = new Set<string>()
  for (const step of play.steps) {
    if (!isNormalizedStep(step)) continue
    for (const req of step.requires ?? []) {
      const key = `${req.kind}:${req.id}:${req.missingAs}`
      if (seen.has(key)) continue
      seen.add(key)
      const present =
        req.kind === "binary" ? input.binaries.has(req.id) : req.id === "browser" && input.browser_present === true
      if (present) continue
      if (req.missingAs === "required") missing_required.push(req.label)
      else missing_optional.push(req.label)
    }
  }
  return staticCapability(
    id,
    missing_required.length > 0 ? "unavailable" : missing_optional.length > 0 ? "degraded" : "ready",
    missing_required,
    missing_optional,
  )
}

function itemFromVertical(
  id: string,
  input: { projected?: ProjectedState; binaries: Set<string> },
  fallback: CapabilityItem,
): CapabilityItem {
  const projected = input.projected?.verticals.find((item) => item.key === id)
  if (!projected) return fallback
  return {
    id,
    status: normalizeCapabilityStatus(projected.status),
    missing_required: projected.missing_required,
    missing_optional: projected.missing_optional,
  }
}

function browserPresentFromFacts(facts: Fact[]) {
  const latest = facts
    .filter((fact) => fact.entity_kind === "environment" && fact.fact_name === "doctor_summary")
    .sort((a, b) => (b.time_updated || b.time_created) - (a.time_updated || a.time_created))[0]
  const value = asObject(latest?.value_json)
  const browser = asObject(value?.browser)
  return typeof browser?.present === "boolean" ? browser.present : undefined
}

function capabilitiesFromProjection(projected: ProjectedState | undefined, facts: Fact[]) {
  const adapterFacts = facts.filter((fact) => fact.entity_kind === "tool_adapter" && fact.fact_name === "presence")
  const projectedAdapters = projected?.tool_adapters ?? []
  const adapterNames = new Set([
    ...adapterFacts.map((fact) => fact.entity_key),
    ...projectedAdapters.map((adapter) => adapter.key),
  ])
  const presentBinaries = new Set(
    projectedAdapters
      .filter((adapter) => adapter.present)
      .map((adapter) => adapter.key)
      .concat(
        adapterFacts
          .filter((fact) => fact.status !== "stale")
          .map((fact) => fact.entity_key),
      ),
  )
  const missingBinaries = unique(
    [...adapterNames]
      .filter((name) => !presentBinaries.has(name))
      .sort((a, b) => a.localeCompare(b)),
  )
  const browserPresent = browserPresentFromFacts(facts)
  const play = (id: string) => itemFromPlay(id, { projected, binaries: presentBinaries, browser_present: browserPresent })
  const hasBinary = (name: string) => presentBinaries.has(name)
  const optionalTools = (names: string[]) => names.filter((name) => !hasBinary(name))
  const repoReady = hasBinary("git") && hasBinary("rg")
  const scaMissingOptional = optionalTools(["trivy", "grype", "osv-scanner"])
  const vertical = (id: string, fallback: CapabilityItem) =>
    itemFromVertical(id, { projected, binaries: presentBinaries }, fallback)

  const domains: DomainCapability[] = [
    domain({
      domain: "AppSec",
      items: [play("appsec-triage"), play("appsec-web-triage"), play("api-surface"), play("auth-surface")],
    }),
    domain({
      domain: "Pentest",
      items: [
        play("web-surface"),
        play("network-surface"),
        play("api-surface"),
        play("auth-surface"),
        vertical("active-web-testing", staticCapability("active-web-testing", "unavailable", optionalTools(["nuclei", "ffuf"]), optionalTools(["gobuster", "httpx"]))),
        vertical("network-recon", staticCapability("network-recon", hasBinary("nmap") ? (optionalTools(["subfinder", "amass"]).length ? "degraded" : "ready") : "unavailable", hasBinary("nmap") ? [] : ["nmap"], optionalTools(["subfinder", "amass"]))),
      ],
    }),
    domain({
      domain: "SAST",
      items: [staticCapability("repo-search", repoReady ? "ready" : "unavailable", repoReady ? [] : ["git/rg"])],
    }),
    domain({
      domain: "SCA",
      items: [
        staticCapability(
          "dependency-intel",
          repoReady ? (scaMissingOptional.length > 0 ? "degraded" : "ready") : "unavailable",
          repoReady ? [] : ["git/rg"],
          scaMissingOptional,
        ),
      ],
    }),
    domain({
      domain: "OSINT",
      items: [
        play("osint-target"),
        staticCapability("passive-recon-adapters", optionalTools(["subfinder", "amass"]).length === 0 ? "ready" : "degraded", [], optionalTools(["subfinder", "amass"])),
      ],
    }),
    domain({ domain: "CTF", items: [play("ctf-warmup")] }),
    domain({ domain: "Binary", items: [play("binary-triage")] }),
    domain({ domain: "Cloud/IaC", items: [play("cloud-posture"), play("iac-triage"), play("container-surface")] }),
    domain({
      domain: "Forensics",
      items: [staticCapability("forensics-adapters", "degraded", [], optionalTools(["binwalk", "exiftool", "strings"]))],
    }),
  ]

  return {
    domains,
    tools_present: presentBinaries.size,
    tools_total: adapterNames.size,
    missing_binaries: missingBinaries,
    browser_present: browserPresent,
  }
}

function capabilitiesFromDoctor(report: DoctorReport | undefined) {
  if (!report) {
    return {
      domains: [],
      tools_present: 0,
      tools_total: 0,
      missing_binaries: [],
      browser_present: undefined,
    }
  }

  const plays = collectPlayReadiness(report)
  const play = (id: string) => plays.find((item) => item.id === id) ?? staticCapability(id, "unavailable", [id])
  const vertical = (id: string) =>
    report.capability.verticals.find((item) => item.id === id) ?? staticCapability(id, "unavailable", [id])
  const hasBinary = (name: string) => report.binaries.some((item) => item.name === name && item.present)
  const optionalTools = (names: string[]) => names.filter((name) => !hasBinary(name))
  const repoReady = hasBinary("git") && hasBinary("rg")
  const scaMissingOptional = optionalTools(["trivy", "grype", "osv-scanner"])

  const domains: DomainCapability[] = [
    domain({
      domain: "AppSec",
      items: [play("appsec-triage"), play("appsec-web-triage"), play("api-surface"), play("auth-surface")],
    }),
    domain({
      domain: "Pentest",
      items: [play("web-surface"), play("network-surface"), play("api-surface"), play("auth-surface"), vertical("active-web-testing"), vertical("network-recon")],
    }),
    domain({
      domain: "SAST",
      items: [staticCapability("repo-search", repoReady ? "ready" : "unavailable", repoReady ? [] : ["git/rg"])],
    }),
    domain({
      domain: "SCA",
      items: [
        staticCapability(
          "dependency-intel",
          repoReady ? (scaMissingOptional.length > 0 ? "degraded" : "ready") : "unavailable",
          repoReady ? [] : ["git/rg"],
          scaMissingOptional,
        ),
      ],
    }),
    domain({
      domain: "OSINT",
      items: [play("osint-target"), staticCapability("passive-recon-adapters", optionalTools(["subfinder", "amass"]).length === 0 ? "ready" : "degraded", [], optionalTools(["subfinder", "amass"]))],
    }),
    domain({ domain: "CTF", items: [play("ctf-warmup")] }),
    domain({ domain: "Binary", items: [play("binary-triage")] }),
    domain({ domain: "Cloud/IaC", items: [play("cloud-posture"), play("iac-triage"), play("container-surface")] }),
    domain({
      domain: "Forensics",
      items: [staticCapability("forensics-adapters", "degraded", [], optionalTools(["binwalk", "exiftool", "strings"]))],
    }),
  ]

  return {
    domains,
    tools_present: report.binaries.filter((item) => item.present).length,
    tools_total: report.binaries.length,
    missing_binaries: report.binaries.filter((item) => !item.present).map((item) => item.name),
    browser_present: report.browser.present,
  }
}

function stepRecord(step: unknown, index: number): SnapshotWorkflowStep | undefined {
  const value = asObject(step)
  if (!value) return undefined
  const kind = typeof value.kind === "string" ? value.kind : "step"
  const tool = typeof value.tool === "string" ? value.tool : undefined
  const label = typeof value.label === "string" ? value.label : undefined
  const outcome = typeof value.outcome === "string" ? value.outcome : undefined
  return {
    index: index + 1,
    kind,
    tool,
    label,
    args: value.args,
    outcome,
    read_only_hint: tool === "knowledge" || tool === "workspace" || tool === "evidence",
  }
}

function nextWorkflowStep(workflow?: Record<string, unknown>) {
  if (!workflow) return { no_next_step_reason: "active workflow state file not found" }
  if (workflow.available === false) return { no_next_step_reason: "active workflow is unavailable or skipped" }
  const trace = Array.isArray(workflow.trace) ? workflow.trace : []
  if (trace.length === 0) return { no_next_step_reason: "active workflow has no planned steps" }
  const index = trace.findIndex((step) => {
    const value = asObject(step)
    return value?.kind === "tool" && value.outcome === undefined
  })
  if (index < 0) return { no_next_step_reason: "active workflow has no unresolved tool steps" }
  return { next_step: stepRecord(trace[index], index) }
}

function workflowStatus(
  projected: ProjectedState | undefined,
  activeWorkflow?: { kind: "play" | "runbook"; id: string },
  workflow?: Record<string, unknown>,
) {
  if (!activeWorkflow) return undefined
  const projectedWorkflow = projected?.workflows.find((item) => item.kind === activeWorkflow.kind && item.key === activeWorkflow.id)
  const next = nextWorkflowStep(workflow)
  return {
    kind: activeWorkflow.kind,
    id: activeWorkflow.id,
    completed_steps: projectedWorkflow?.completed_steps ?? 0,
    failed_steps: projectedWorkflow?.failed_steps ?? 0,
    pending_steps: projectedWorkflow?.pending_steps ?? 0,
    skipped: projectedWorkflow?.skipped ?? 0,
    next_step: next.next_step,
    no_next_step_reason: next.no_next_step_reason,
  }
}

function isOpenObservation(item: ProjectedState["observations"][number]) {
  return !item.removed && !["closed", "resolved"].includes(item.status)
}

function recommendedActions(snapshot: Omit<OperationSnapshot, "recommended_next_actions">): string[] {
  const actions: string[] = []
  if (snapshot.context_file_stale) actions.push("Regenerate active-context.md from the operation snapshot before relying on file context.")
  if (snapshot.operation && !snapshot.active_identity) actions.push("Select or create an active identity before authenticated testing.")
  const activeWeb = snapshot.capabilities.domains.find((item) => item.domain === "Pentest")
  if ((snapshot.operation?.kind === "pentest" || snapshot.operation?.kind === "bughunt") && activeWeb?.status === "unavailable") {
    actions.push(`Install or configure active web/network tools: ${activeWeb.missing_required.join(", ") || "missing adapters"}.`)
  }
  if ((snapshot.operation?.kind === "appsec") && snapshot.capabilities.domains.find((item) => item.domain === "AppSec")?.status === "unavailable") {
    actions.push("Resolve AppSec readiness gaps before claiming coverage.")
  }
  if (snapshot.deliverables.count > 0 && snapshot.sharing.count === 0) actions.push("Share or export the latest report bundle if it needs to leave this workspace.")
  const verifiedMissingReplay = snapshot.findings.all.filter(
    (finding) =>
      finding.kind === "finding" &&
      finding.status === "verified" &&
      Array.isArray(finding.evidence_refs) &&
      finding.evidence_refs.length > 0 &&
      replayState({ kind: "finding", replay_present: finding.replay_present, replay_reason: finding.replay_reason }) === "missing",
  )
  if (verifiedMissingReplay.length > 0) actions.push(`Add replay material or a structured replay exemption for ${verifiedMissingReplay.length} verified finding(s).`)
  const highObservations = snapshot.observations.filter((item) => isOpenObservation(item) && ["critical", "high"].includes((item.severity ?? "").toLowerCase()))
  if (highObservations.length > 0) actions.push(`Promote, reject, or collect evidence for ${highObservations.length} open critical/high observation(s).`)
  if (actions.length === 0) actions.push("Continue from the highest-severity suspected finding or the next incomplete workflow step.")
  return actions
}

function snapshotCounts(input: {
  facts: Fact[]
  relations: Relation[]
  ledger: LedgerEvent[]
  routes: SnapshotRoute[]
  services: SnapshotService[]
  components: SnapshotComponent[]
  observations: ProjectedState["observations"]
  findings: {
    reportable: ProjectedFinding[]
    suspected: ProjectedFinding[]
    rejected: ProjectedFinding[]
    all: ProjectedFinding[]
  }
  evidence: SnapshotEvidence[]
  deliverables: number
  share_bundles: number
}) {
  return {
    facts: input.facts.length,
    relations: input.relations.length,
    ledger: input.ledger.length,
    routes: input.routes.length,
    route_facts: input.facts.filter((fact) => fact.entity_kind === "http_route").length,
    services: input.services.length,
    components: input.components.length,
    observations: input.observations.length,
    open_observations: input.observations.filter(isOpenObservation).length,
    findings: input.findings.all.filter((finding) => finding.kind === "finding").length,
    candidate_findings: input.findings.all.filter((finding) => finding.kind === "candidate").length,
    reportable_findings: input.findings.reportable.length,
    suspected_findings: input.findings.suspected.length,
    rejected_findings: input.findings.rejected.length,
    evidence: input.evidence.length,
    deliverables: input.deliverables,
    share_bundles: input.share_bundles,
  }
}

export async function build(workspace: string, options: BuildOptions = {}): Promise<OperationSnapshot> {
  const active = options.slug ? await Operation.read(workspace, options.slug).catch(() => undefined) : await Operation.active(workspace).catch(() => undefined)
  const generatedAt = new Date()
  const includeDoctor = options.includeDoctor === true
  const doctorTimeoutMs = options.doctorTimeoutMs ?? 5_000

  if (!active) {
    const report = includeDoctor ? await probeDoctorBounded(workspace, doctorTimeoutMs) : undefined
    const capabilities = report ? capabilitiesFromDoctor(report) : capabilitiesFromProjection(undefined, [])
    const snapshot = {
      generated_at: generatedAt.toISOString(),
      stale: false,
      context_file_stale: false,
      stale_context: false,
      stale_capability_readiness: false,
      projection_lag_ms: 0,
      warnings: ["No active operation."],
      counts: {
        facts: 0,
        relations: 0,
        ledger: 0,
        routes: 0,
        route_facts: 0,
        services: 0,
        components: 0,
        observations: 0,
        open_observations: 0,
        findings: 0,
        candidate_findings: 0,
        reportable_findings: 0,
        suspected_findings: 0,
        rejected_findings: 0,
        evidence: 0,
        deliverables: 0,
        share_bundles: 0,
      },
      facts: [],
      relations: [],
      ledger: [],
      findings: { reportable: [], suspected: [], rejected: [], all: [] },
      observations: [],
      evidence: { count: 0, total_bytes: 0, entries: [] },
      routes: [],
      services: [],
      components: [],
      capabilities,
      deliverables: { count: 0 },
      sharing: { count: 0 },
    }
    return { ...snapshot, recommended_next_actions: recommendedActions(snapshot) }
  }

  const [operationState, scope, autonomy, facts, ledger, relations, evidenceEntries, doctorReport, identity, activeWorkflow] =
    await Promise.all([
      Operation.readProjectedState(workspace, active.slug).catch(() => undefined),
      Operation.readProjectedScopePolicy(workspace, active.slug).catch(() => undefined),
      Operation.readProjectedAutonomyPolicy(workspace, active.slug).catch(() => undefined),
      Cyber.readProjectedFacts(workspace, active.slug).catch(() => []),
      Cyber.readProjectedLedger(workspace, active.slug).catch(() => []),
      Cyber.readProjectedRelations(workspace, active.slug).catch(() => []),
      Evidence.list(workspace, active.slug).catch(() => []),
      includeDoctor ? probeDoctorBounded(workspace, doctorTimeoutMs) : Promise.resolve(undefined),
      activeIdentity().catch(() => undefined),
      Operation.activeWorkflow(workspace, active.slug).catch(() => undefined),
    ])
  const projected = Cyber.projectStateFromParts({
    operation_state: operationState,
    scope_policy: scope,
    autonomy_policy: autonomy,
    facts,
    ledger,
    relations,
  })
  const buckets = bucketFindings(projected.findings)
  const latestLedgerSource = latestLedger(ledger)
  const latestAuditSource = latestAuditLedger(ledger)
  const latestSemanticLedgerSource = latestSemanticLedger(ledger)
  const latestFactSource = latestFact(facts)
  const latestRelationSource = latestRelation(relations)
  const latestEvidenceSource = latestEvidence(evidenceEntries)
  const capabilitySource = doctorReport ? { id: "doctor_probe", at: generatedAt.getTime(), iso: generatedAt.toISOString() } : latestCapabilitySource(facts)
  const latestSemanticSourceMarker = latestSource(latestSemanticLedgerSource, latestFactSource, latestRelationSource, latestEvidenceSource)
  const latestSourceMarker = latestSemanticSourceMarker
  const latestSourceAt = latestSemanticSourceMarker?.at ?? 0
  const contextMtime = await contextFileMtime(workspace, active.slug)
  const contextFileStale = contextMtime == null || (latestSourceAt > 0 && contextMtime.at < latestSourceAt)
  const auditAfterContext = Boolean(contextMtime && latestAuditSource && latestAuditSource.at > contextMtime.at)
  const staleCapabilityReadiness =
    !capabilitySource || (!doctorReport && generatedAt.getTime() - capabilitySource.at > CAPABILITY_READINESS_TTL_MS)
  const routes = summarizeRoutes(facts)
  const services = summarizeServices(facts)
  const components = summarizeComponents(facts)
  const evidence = evidenceIndex({ entries: evidenceEntries, facts, relations, routes })
  const capabilities = doctorReport ? capabilitiesFromDoctor(doctorReport) : capabilitiesFromProjection(projected, facts)
  const observations = projected.observations.filter((item) => !item.removed)
  const findings = {
    reportable: sortFindings(buckets.reportable),
    suspected: sortFindings(buckets.suspected),
    rejected: sortFindings(buckets.rejected),
    all: sortFindings(buckets.all),
  }
  const warnings = [
    ...(contextFileStale ? ["active-context.md is older than the latest operation source projection."] : []),
    ...(staleCapabilityReadiness ? ["Capability readiness is stale or has not been refreshed recently."] : []),
    ...(includeDoctor && !doctorReport ? [`capability probe did not complete within ${doctorTimeoutMs}ms; readiness may be incomplete.`] : []),
    ...(projected.summary.findings > 0 && projected.summary.evidence_backed_findings === 0 ? ["Findings exist but none are evidence-backed."] : []),
  ]
  const activeIdentitySummary = identity
    ? {
        key: identity.key,
        mode: identity.mode,
        header_keys: Object.keys(identity.headers ?? {}),
        has_cookies: Boolean(identity.cookies),
      }
    : undefined
  const activeWorkflowState = activeWorkflow
    ? await Operation.readWorkflow(workspace, active.slug, activeWorkflow).catch(() => undefined)
    : undefined
  const snapshot = {
    generated_at: generatedAt.toISOString(),
    stale: contextFileStale || staleCapabilityReadiness,
    context_file_stale: contextFileStale,
    stale_context: contextFileStale,
    stale_capability_readiness: staleCapabilityReadiness,
    source_latest: latestSourceMarker,
    source_semantic_latest: latestSemanticSourceMarker,
    source_audit_latest: latestAuditSource,
    source_ledger_latest: latestLedgerSource,
    source_fact_latest: latestFactSource,
    source_evidence_latest: latestEvidenceSource,
    capability_source_latest: capabilitySource,
    source_context_mtime: contextMtime,
    audit_after_context: auditAfterContext,
    projection_lag_ms: latestSourceAt > 0 ? Math.max(0, generatedAt.getTime() - latestSourceAt) : undefined,
    warnings,
    operation: active,
    scope,
    autonomy,
    active_identity: activeIdentitySummary,
    active_workflow: workflowStatus(projected, activeWorkflow, activeWorkflowState),
    projected,
    counts: snapshotCounts({
      facts,
      relations,
      ledger,
      routes,
      services,
      components,
      observations,
      findings,
      evidence,
      deliverables: projected.deliverables.length,
      share_bundles: projected.share_bundles.length,
    }),
    facts,
    relations,
    ledger,
    findings,
    observations,
    evidence: {
      count: evidence.length,
      total_bytes: evidence.reduce((sum, entry) => sum + entry.size, 0),
      latest: evidence[0],
      entries: evidence,
    },
    routes,
    services,
    components,
    capabilities,
    deliverables: {
      latest: projected.deliverables[0],
      count: projected.deliverables.length,
    },
    sharing: {
      latest: projected.share_bundles[0],
      count: projected.share_bundles.length,
    },
  }

  return {
    ...snapshot,
    findings: {
      reportable: snapshot.findings.reportable.slice(0, options.maxFindings ?? 12),
      suspected: snapshot.findings.suspected.slice(0, options.maxFindings ?? 12),
      rejected: snapshot.findings.rejected.slice(0, options.maxFindings ?? 12),
      all: snapshot.findings.all,
    },
    observations: snapshot.observations.slice(0, options.maxObservations ?? 16),
    evidence: {
      ...snapshot.evidence,
      entries: snapshot.evidence.entries.slice(0, options.maxEvidence ?? 20),
    },
    routes: snapshot.routes.slice(0, options.maxRoutes ?? 40),
    components: snapshot.components.slice(0, options.maxComponents ?? 40),
    recommended_next_actions: recommendedActions(snapshot),
  }
}

function lineFinding(finding: ProjectedFinding) {
  const replay = replayState({ kind: finding.kind, replay_present: finding.replay_present, replay_reason: finding.replay_reason })
  return `- ${finding.title ?? finding.key} | ${finding.kind}:${finding.key} | status=${finding.status}${finding.severity ? ` | severity=${finding.severity}` : ""}${replay ? ` | replay=${replay}` : ""}${finding.evidence_refs?.length ? ` | evidence=${finding.evidence_refs.length}` : ""}${finding.summary ? ` | ${finding.summary}` : ""}`
}

function lineObservation(item: ProjectedState["observations"][number]) {
  return `- ${item.title} | observation:${item.id} | status=${item.status}${item.severity ? ` | severity=${item.severity}` : ""}${item.evidence.length ? ` | evidence=${item.evidence.length}` : ""}${item.note ? ` | ${item.note}` : ""}`
}

function lineRoute(route: SnapshotRoute) {
  return `- ${route.key}${route.method ? ` | method=${route.method}` : ""}${route.http_status != null ? ` | status=${route.http_status}` : ""}${route.fact_names.length ? ` | facts=${route.fact_names.join(",")}` : ""}${route.evidence_refs.length ? ` | evidence=${route.evidence_refs.length}` : ""}`
}

function lineCapability(domain: DomainCapability) {
  const missing = [...domain.missing_required, ...domain.missing_optional]
  return `- ${domain.domain}: ${domain.status}${domain.ready.length ? ` | ready=${domain.ready.join(",")}` : ""}${domain.degraded.length ? ` | degraded=${domain.degraded.join(",")}` : ""}${domain.unavailable.length ? ` | unavailable=${domain.unavailable.join(",")}` : ""}${missing.length ? ` | missing=${missing.join(",")}` : ""}`
}

export type RenderContextOptions = {
  mode?: "orientation" | "write_context"
}

function withoutContextStale(items: string[]) {
  return items.filter((item) => !item.startsWith("active-context.md is older") && !item.startsWith("Regenerate active-context.md"))
}

export function renderContext(snapshot: OperationSnapshot, options: RenderContextOptions = {}): string {
  const writeContext = options.mode === "write_context"
  // The prompt render (every mode except write_context) is embedded in the
  // system prompt of each LLM request. Wall-clock fields (generated_at,
  // projection_lag_ms) change on every request and context-file-mtime fields
  // change on every derived-context refresh; any of them invalidates provider
  // prefix caching for the whole conversation. Render those only into the
  // on-disk context file.
  const stale = snapshot.stale_capability_readiness
  const warnings = withoutContextStale(snapshot.warnings)
  const recommendedNextActions = withoutContextStale(snapshot.recommended_next_actions)
  if (!snapshot.operation) {
    return [
      "# Active Operation Context",
      ...(writeContext ? [`generated_at: ${snapshot.generated_at}`] : []),
      `stale: ${stale ? "true" : "false"}`,
      "",
      "No active operation.",
    ].join("\n")
  }
  return [
    "# Active Operation Context",
    ...(writeContext ? [`generated_at: ${snapshot.generated_at}`] : []),
    `source_latest: ${snapshot.source_latest?.iso ?? "-"}`,
    `source_semantic_latest: ${snapshot.source_semantic_latest?.iso ?? "-"}`,
    `source_audit_latest: ${snapshot.source_audit_latest?.iso ?? "-"}`,
    `source_ledger_latest: ${snapshot.source_ledger_latest?.iso ?? "-"}`,
    `source_fact_latest: ${snapshot.source_fact_latest?.iso ?? "-"}`,
    `source_evidence_latest: ${snapshot.source_evidence_latest?.iso ?? "-"}`,
    ...(writeContext ? [`source_context_mtime: ${snapshot.generated_at}`] : []),
    `capability_source_latest: ${snapshot.capability_source_latest?.iso ?? "-"}`,
    ...(writeContext
      ? [
          `audit_after_context: ${snapshot.audit_after_context ? "true" : "false"}`,
          `projection_lag_ms: ${snapshot.projection_lag_ms ?? "-"}`,
        ]
      : []),
    `stale: ${stale ? "true" : "false"}`,
    `stale_capability_readiness: ${snapshot.stale_capability_readiness ? "true" : "false"}`,
    ...(writeContext ? [`stale_context: false`, `context_file_stale: false`] : []),
    "",
    "Active operation",
    "",
    "## Operation",
    `slug: ${snapshot.operation.slug}`,
    `label: ${snapshot.operation.label}`,
    `kind: ${snapshot.operation.kind}`,
    `target: ${snapshot.operation.target ?? "-"}`,
    `opsec: ${snapshot.operation.opsec}`,
    `autonomy: ${snapshot.autonomy?.mode ?? "-"}`,
    `identity: ${snapshot.active_identity?.key ?? "none"}`,
    "",
    "## Scope",
    `- default: ${snapshot.scope?.default ?? "allow"}`,
    ...(snapshot.scope?.in_scope?.length ? snapshot.scope.in_scope.map((item) => `- in: ${item}`) : ["- in:"]),
    ...(snapshot.scope?.out_of_scope?.length ? snapshot.scope.out_of_scope.map((item) => `- out: ${item}`) : ["- out:"]),
    "",
    "## Summary",
    `- facts: ${snapshot.counts.facts}`,
    `- relations: ${snapshot.counts.relations}`,
    `- ledger: ${snapshot.counts.ledger}`,
    `- routes: ${snapshot.counts.routes}`,
    `- route_facts: ${snapshot.counts.route_facts}`,
    `- services: ${snapshot.counts.services}`,
    `- observations: ${snapshot.counts.observations}`,
    `- open_observations: ${snapshot.counts.open_observations}`,
    `- findings: ${snapshot.counts.findings}`,
    `- candidate_findings: ${snapshot.counts.candidate_findings}`,
    `- reportable_findings: ${snapshot.counts.reportable_findings}`,
    `- suspected_findings: ${snapshot.counts.suspected_findings}`,
    `- rejected_findings: ${snapshot.counts.rejected_findings}`,
    `- evidence: ${snapshot.counts.evidence}`,
    `- deliverables: ${snapshot.counts.deliverables}`,
    `- share_bundles: ${snapshot.counts.share_bundles}`,
    "",
    "## Findings",
    "### Reportable",
    ...(snapshot.findings.reportable.length ? snapshot.findings.reportable.map(lineFinding) : ["_none yet_"]),
    "",
    "### Suspected",
    ...(snapshot.findings.suspected.length ? snapshot.findings.suspected.map(lineFinding) : ["_none yet_"]),
    "",
    "### Rejected Or Stale",
    ...(snapshot.findings.rejected.length ? snapshot.findings.rejected.map(lineFinding) : ["_none yet_"]),
    "",
    "## Observations",
    `showing: ${snapshot.observations.length}/${snapshot.counts.observations}`,
    ...(snapshot.observations.length ? snapshot.observations.map(lineObservation) : ["_none yet_"]),
    "",
    "## Routes",
    ...(snapshot.routes.length ? snapshot.routes.slice(0, 20).map(lineRoute) : ["_none yet_"]),
    "",
    "## Evidence",
    snapshot.evidence.count === 0
      ? "_none yet_"
      : `- total: ${snapshot.evidence.count} artifacts | bytes=${snapshot.evidence.total_bytes}${snapshot.evidence.latest ? ` | latest=${snapshot.evidence.latest.sha256}` : ""}`,
    "",
    "## Deliverables",
    snapshot.deliverables.latest
      ? `- latest: ${snapshot.deliverables.latest.report_path ?? snapshot.deliverables.latest.bundle_dir ?? snapshot.deliverables.latest.key}`
      : "_none yet_",
    "",
    "## Share Bundles",
    snapshot.sharing.latest ? `- latest: ${snapshot.sharing.latest.path ?? snapshot.sharing.latest.key}` : "_none yet_",
    "",
    "## Workflow",
    snapshot.active_workflow
      ? `- active: ${snapshot.active_workflow.kind}:${snapshot.active_workflow.id} | done=${snapshot.active_workflow.completed_steps} failed=${snapshot.active_workflow.failed_steps} pending=${snapshot.active_workflow.pending_steps} skipped=${snapshot.active_workflow.skipped}`
      : "_none active_",
    snapshot.active_workflow?.next_step
      ? `- next_step: ${snapshot.active_workflow.next_step.index} | tool=${snapshot.active_workflow.next_step.tool ?? "-"} | label=${snapshot.active_workflow.next_step.label ?? "-"}`
      : snapshot.active_workflow?.no_next_step_reason
        ? `- no_next_step: ${snapshot.active_workflow.no_next_step_reason}`
        : undefined,
    "",
    "## Capabilities",
    ...(snapshot.capabilities.domains.length ? snapshot.capabilities.domains.map(lineCapability) : ["_not probed_"]),
    "",
    "## Warnings",
    ...(warnings.length ? warnings.map((item) => `- ${item}`) : ["_none_"]),
    "",
    "## Recommended Next Actions",
    ...recommendedNextActions.map((item) => `- ${item}`),
    "",
  ].join("\n")
}

export function renderSnapshot(snapshot: OperationSnapshot): string {
  if (!snapshot.operation) return renderContext(snapshot)
  return [
    `Operation: ${snapshot.operation.label} (${snapshot.operation.slug})`,
    `Kind: ${snapshot.operation.kind} | Target: ${snapshot.operation.target ?? "-"} | Opsec: ${snapshot.operation.opsec}`,
    `Generated: ${snapshot.generated_at} | source_latest=${snapshot.source_latest?.iso ?? "-"} | source_semantic_latest=${snapshot.source_semantic_latest?.iso ?? "-"} | source_audit_latest=${snapshot.source_audit_latest?.iso ?? "-"} | source_fact_latest=${snapshot.source_fact_latest?.iso ?? "-"} | source_ledger_latest=${snapshot.source_ledger_latest?.iso ?? "-"} | source_evidence_latest=${snapshot.source_evidence_latest?.iso ?? "-"}`,
    `Freshness: stale=${snapshot.stale ? "true" : "false"} | stale_context=${snapshot.stale_context ? "true" : "false"} | stale_capability_readiness=${snapshot.stale_capability_readiness ? "true" : "false"} | projection_lag_ms=${snapshot.projection_lag_ms ?? "-"}`,
    `Identity: ${snapshot.active_identity?.key ?? "none"} | Autonomy: ${snapshot.autonomy?.mode ?? "-"}`,
    `Counts: routes=${snapshot.counts.routes} route_facts=${snapshot.counts.route_facts} services=${snapshot.counts.services} observations=${snapshot.counts.observations} open_observations=${snapshot.counts.open_observations} findings=${snapshot.counts.findings} candidates=${snapshot.counts.candidate_findings} reportable=${snapshot.counts.reportable_findings} suspected=${snapshot.counts.suspected_findings} rejected=${snapshot.counts.rejected_findings} evidence=${snapshot.counts.evidence} deliverables=${snapshot.counts.deliverables} shares=${snapshot.counts.share_bundles}`,
    "",
    "Top reportable findings:",
    ...(snapshot.findings.reportable.length ? snapshot.findings.reportable.slice(0, 8).map(lineFinding) : ["_none yet_"]),
    "",
    "Top suspected findings:",
    ...(snapshot.findings.suspected.length ? snapshot.findings.suspected.slice(0, 8).map(lineFinding) : ["_none yet_"]),
    "",
    "Rejected or stale findings:",
    ...(snapshot.findings.rejected.length ? snapshot.findings.rejected.slice(0, 8).map(lineFinding) : ["_none yet_"]),
    "",
    `Open observations (showing ${Math.min(snapshot.observations.filter(isOpenObservation).length, 8)}/${snapshot.counts.open_observations}):`,
    ...(snapshot.observations.filter(isOpenObservation).length ? snapshot.observations.filter(isOpenObservation).slice(0, 8).map(lineObservation) : ["_none yet_"]),
    "",
    "Recent routes:",
    ...(snapshot.routes.length ? snapshot.routes.slice(0, 8).map(lineRoute) : ["_none yet_"]),
    "",
    "Readiness:",
    ...(snapshot.capabilities.domains.length ? snapshot.capabilities.domains.map(lineCapability) : ["_not probed_"]),
    "",
    "Warnings:",
    ...(snapshot.warnings.length ? snapshot.warnings.map((item) => `- ${item}`) : ["_none_"]),
    "",
    "Recommended next actions:",
    ...snapshot.recommended_next_actions.map((item) => `- ${item}`),
  ].join("\n")
}

export function renderCapabilities(snapshot: OperationSnapshot): string {
  return [
    `Capability readiness: ${snapshot.capabilities.tools_present}/${snapshot.capabilities.tools_total} catalog binaries present`,
    `Capability source: ${snapshot.capability_source_latest?.iso ?? "-"} | stale_capability_readiness=${snapshot.stale_capability_readiness ? "true" : "false"}`,
    `Browser: ${snapshot.capabilities.browser_present === undefined ? "-" : snapshot.capabilities.browser_present ? "present" : "missing"}`,
    ...(snapshot.stale_capability_readiness ? ["Warning: capability readiness is stale or has not been refreshed recently."] : []),
    "",
    ...snapshot.capabilities.domains.map(lineCapability),
  ].join("\n")
}

function enrichObservation(snapshot: OperationSnapshot, item: ProjectedState["observations"][number]) {
  const evidenceRefs = new Set(item.evidence.map(normalizeEvidenceRef))
  const linkedFindings = snapshot.findings.all.filter((finding) => {
    if (intersects(finding.evidence_refs, evidenceRefs)) return true
    const text = [item.title, item.note, item.id].filter(Boolean).join("\n").toLowerCase()
    return finding.key.length > 2 && text.includes(finding.key.toLowerCase())
  })
  const verified = linkedFindings.filter((finding) => finding.status === "verified").map((finding) => finding.key)
  const rejected = linkedFindings.filter((finding) => finding.status === "rejected").map((finding) => finding.key)
  return {
    ...item,
    triage: {
      open_untriaged: isOpenObservation(item) && linkedFindings.length === 0,
      linked_verified_finding: verified,
      linked_rejected_finding: rejected,
      needs_evidence: item.evidence.length === 0,
    },
  }
}

export function query(snapshot: OperationSnapshot, input: { query: string; key?: string; limit?: number }) {
  const limit = Math.max(1, Math.min(100, input.limit ?? 20))
  if (input.query === "routes") return { rows: snapshot.routes.slice(0, limit), count: snapshot.counts.routes }
  if (input.query === "components") return { rows: snapshot.components.slice(0, limit), count: snapshot.counts.components }
  if (input.query === "workflow") {
    const rows = snapshot.active_workflow
      ? [
          {
            active_workflow: snapshot.active_workflow,
            steps: snapshot.projected?.workflow_steps.filter(
              (step) => step.workflow === `${snapshot.active_workflow?.kind}:${snapshot.active_workflow?.id}`,
            ) ?? [],
          },
        ]
      : []
    return { rows: rows.slice(0, limit), count: rows.length }
  }
  if (input.query === "next_workflow_step") {
    const row = snapshot.active_workflow
      ? {
          active_workflow: {
            kind: snapshot.active_workflow.kind,
            id: snapshot.active_workflow.id,
          },
          next_step: snapshot.active_workflow.next_step,
          no_next_step_reason: snapshot.active_workflow.no_next_step_reason,
        }
      : { active_workflow: undefined, next_step: undefined, no_next_step_reason: "no active workflow" }
    return { rows: [row], count: snapshot.active_workflow?.next_step ? 1 : 0 }
  }
  if (input.query === "open_observations") {
    const matches = snapshot.observations.filter(isOpenObservation)
    return { rows: matches.map((item) => enrichObservation(snapshot, item)).slice(0, limit), count: snapshot.counts.open_observations }
  }
  if (input.query === "route") {
    const matches = snapshot.routes.filter((route) => route.key === input.key || route.key.includes(input.key ?? ""))
    return { rows: matches.slice(0, limit), count: matches.length }
  }
  if (input.query === "findings_by_route") {
    const routeKey = input.key ?? ""
    const matchingRoute = snapshot.routes.find((route) => route.key === routeKey || route.key.includes(routeKey) || route.route === routeKey)
    const needles = routeNeedles(routeKey, matchingRoute)
    const routeEvidenceRefs = new Set((matchingRoute?.evidence_refs ?? []).map(normalizeEvidenceRef))
    const relatedKeys = new Set(
      snapshot.relations
        .filter((relation) => relation.src_key === routeKey || relation.dst_key === routeKey)
        .filter((relation) => relation.src_kind.includes("finding") || relation.dst_kind.includes("finding") || relation.relation.includes("finding"))
        .map((relation) => (relation.src_kind.includes("finding") ? relation.src_key : relation.dst_key)),
    )
    const matches = snapshot.findings.all
      .map((finding) => {
        if (relatedKeys.has(finding.key)) return { finding, link_state: "explicit", matched_by: ["relation"] }
        if (routeEvidenceRefs.size > 0 && intersects(finding.evidence_refs, routeEvidenceRefs)) {
          return { finding, link_state: "derived", matched_by: ["shared_evidence"] }
        }
        if (mentionsRoute(finding, needles)) return { finding, link_state: "derived", matched_by: ["route_text"] }
        return undefined
      })
      .filter((item): item is { finding: ProjectedFinding; link_state: string; matched_by: string[] } => Boolean(item))
    return { rows: matches.slice(0, limit), count: matches.length }
  }
  if (input.query === "evidence_by_finding") {
    const findingKey = normalizeFindingKey(input.key ?? "")
    const finding = snapshot.findings.all.find((item) => item.key === findingKey || `${item.kind}:${item.key}` === input.key)
    const refs = new Set((finding?.evidence_refs ?? []).map(normalizeEvidenceRef))
    const relationRefs = new Set(
      snapshot.relations
        .filter((relation) => relation.src_key === findingKey || relation.dst_key === findingKey)
        .flatMap((relation) => [relation.src_key, relation.dst_key, ...(relation.evidence_refs ?? [])])
        .map(normalizeEvidenceRef),
    )
    const matches = snapshot.evidence.entries
      .map((entry) => {
        const sha = normalizeEvidenceRef(entry.sha256)
        if (refs.has(sha)) return { ...entry, link_state: "explicit", matched_by: ["finding_evidence_ref"] }
        if (relationRefs.has(sha)) return { ...entry, link_state: "explicit", matched_by: ["relation"] }
        if (entry.linked_finding_keys.map(normalizeFindingKey).includes(findingKey)) {
          return { ...entry, link_state: "derived", matched_by: ["evidence_index"] }
        }
        return undefined
      })
      .filter((item): item is SnapshotEvidence & { link_state: string; matched_by: string[] } => Boolean(item))
    return { rows: matches.slice(0, limit), count: matches.length }
  }
  return { rows: [], count: 0 }
}
