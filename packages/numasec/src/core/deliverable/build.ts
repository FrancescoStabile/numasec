import { createHash } from "crypto"
import { mkdir, writeFile } from "fs/promises"
import path from "path"
import { Operation } from "@/core/operation"
import type { OperationInfo } from "@/core/operation"
import { Plan } from "@/core/plan"
import { Observation } from "@/core/observation"
import { Evidence } from "@/core/evidence"
import { Cyber } from "@/core/cyber"
import type { ProjectedFinding, ProjectedState } from "@/core/cyber/cyber"
import {
  bucketFindings,
  replayState,
} from "@/core/cyber/finding"
import type { Observation as Obs } from "@/core/observation/info"
import type { Node as PlanNode } from "@/core/plan/info"

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const
type Sev = (typeof SEV_ORDER)[number]
function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex")
}

function groupBySeverity(items: Obs[]): Record<Sev | "none", Obs[]> {
  const out: Record<string, Obs[]> = { critical: [], high: [], medium: [], low: [], info: [], none: [] }
  for (const o of items) out[o.severity ?? "none"].push(o)
  return out as Record<Sev | "none", Obs[]>
}

function renderReport(
  op: OperationInfo,
  plan: PlanNode[],
  observations: Obs[],
  evidence: Evidence.Entry[],
  cyber: ProjectedState,
): string {
  const effectivePlan: PlanNode[] =
    cyber.plan_nodes.length > 0
      ? cyber.plan_nodes.map((item) => ({
          id: item.id,
          title: item.title,
          parent_id: item.parent_id,
          status: item.status,
          note: item.note,
          created_at: 0,
          updated_at: 0,
        }))
      : plan
  const effectiveObservations: Obs[] =
    cyber.observations.length > 0
      ? cyber.observations
          .filter((item) => !item.removed)
          .map((item) => ({
            id: item.id,
            subtype: item.subtype as Obs["subtype"],
            title: item.title,
            severity: item.severity as Obs["severity"],
            confidence: item.confidence,
            status: item.status as Obs["status"],
            note: item.note,
            tags: item.tags,
            evidence: item.evidence,
            created_at: item.created_at ?? 0,
            updated_at: item.updated_at ?? 0,
          }))
      : observations
  const lines: string[] = []
  lines.push(`# ${op.label}`)
  lines.push("")
  lines.push(`- **Operation slug**: \`${op.slug}\``)
  lines.push(`- **Kind**: \`${op.kind}\``)
  lines.push(`- **Opsec**: \`${op.opsec}\``)
  lines.push(`- **Active**: \`${op.active}\``)
  lines.push(`- **Created**: \`${new Date(op.created_at).toISOString()}\``)
  lines.push(`- **Updated**: \`${new Date(op.updated_at).toISOString()}\``)
  if (op.target) lines.push(`- **Target**: \`${op.target}\``)
  lines.push("")

  lines.push("## Operation State")
  lines.push(`- kind: \`${cyber.operation_state?.kind ?? op.kind}\``)
  lines.push(`- opsec: \`${cyber.operation_state?.opsec ?? op.opsec}\``)
  lines.push(`- target: \`${cyber.operation_state?.target ?? op.target ?? "-" }\``)
  if (cyber.autonomy_policy?.mode) lines.push(`- autonomy: \`${cyber.autonomy_policy.mode}\``)
  const inScope = cyber.scope_policy?.in_scope ?? cyber.operation_state?.in_scope ?? []
  const outOfScope = cyber.scope_policy?.out_of_scope ?? cyber.operation_state?.out_of_scope ?? []
  const scopeDefault = cyber.scope_policy?.default
  if (scopeDefault || inScope.length > 0 || outOfScope.length > 0) {
    lines.push(`- scope_default: \`${scopeDefault ?? "ask"}\``)
    if (inScope.length > 0) lines.push(`- in_scope: ${inScope.map((item) => `\`${item}\``).join(", ")}`)
    if (outOfScope.length > 0) lines.push(`- out_of_scope: ${outOfScope.map((item) => `\`${item}\``).join(", ")}`)
  }
  lines.push("")

  lines.push("## Plan")
  if (effectivePlan.length === 0) lines.push("_empty_")
  else {
    const progress = Plan.progress(effectivePlan)
    lines.push(`_${progress.done}/${progress.total} done · ${progress.running} running · ${progress.blocked} blocked_`)
    lines.push("")
    const byParent = new Map<string | undefined, PlanNode[]>()
    for (const n of effectivePlan) {
      const p = n.parent_id
      if (!byParent.has(p)) byParent.set(p, [])
      byParent.get(p)!.push(n)
    }
    const render = (parent: string | undefined, depth: number) => {
      for (const n of byParent.get(parent) ?? []) {
        lines.push(`${"  ".repeat(depth)}- [${n.status}] ${n.title}`)
        render(n.id, depth + 1)
      }
    }
    render(undefined, 0)
  }
  lines.push("")

  lines.push("## Observations")
  const counts = Observation.severityCounts(effectiveObservations)
  lines.push(
    `_${effectiveObservations.length} total · ${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info · ${counts.none} unrated_`,
  )
  lines.push("")
  const grouped = groupBySeverity(effectiveObservations)
  for (const sev of [...SEV_ORDER, "none"] as const) {
    const list = grouped[sev]
    if (list.length === 0) continue
    lines.push(`### ${sev === "none" ? "Unrated" : sev.charAt(0).toUpperCase() + sev.slice(1)}`)
    for (const o of list) {
      lines.push(`- **${o.title}** \`[${o.subtype}]\` · status=\`${o.status}\`${o.confidence != null ? ` · confidence=${o.confidence}` : ""}`)
      if (o.note) lines.push(`  - ${o.note.replace(/\n/g, " ")}`)
      if (o.tags.length > 0) lines.push(`  - tags: ${o.tags.map((t) => `\`${t}\``).join(", ")}`)
      if (o.evidence.length > 0) {
        lines.push(`  - evidence:`)
        for (const ev of o.evidence) lines.push(`    - \`${ev}\``)
      }
    }
    lines.push("")
  }

  lines.push("## Cyber Findings")
  const cyberFindings = cyber.findings
  if (cyberFindings.length === 0) lines.push("_empty_")
  else {
    const buckets = bucketFindings(cyberFindings)
    lines.push(
      `_${cyberFindings.length} total · ${buckets.candidates.length} candidates · ${buckets.findings.length} promoted · ${buckets.reportable.length} reportable · ${buckets.suspected.length} suspected · ${buckets.rejected.length} rejected/stale · ${buckets.replay_backed.length} replay-backed_`,
    )
    lines.push("")
    const renderFindingBucket = (title: string, items: ProjectedFinding[]) => {
      lines.push(`### ${title}`)
      if (items.length === 0) {
        lines.push("_empty_")
        lines.push("")
        return
      }
      for (const item of items) {
        const replay = replayState(item)
        lines.push(
          `- **${item.title}** \`${item.kind}\` · status=\`${item.status}\`${item.severity ? ` · severity=${item.severity}` : ""}${replay ? ` · replay=${replay}` : ""}`,
        )
        lines.push(`  - key: \`${item.key}\``)
        if (item.proof_summary) lines.push(`  - proof: ${item.proof_summary.replace(/\n/g, " ")}`)
        if (item.summary && item.summary !== item.proof_summary) lines.push(`  - claim: ${item.summary.replace(/\n/g, " ")}`)
        else if (item.summary) lines.push(`  - claim: ${item.summary.replace(/\n/g, " ")}`)
        if (item.operator_promoted) lines.push(`  - origin: operator_promoted`)
        if (item.replay_reason) lines.push(`  - replay_reason: ${item.replay_reason}`)
      }
      lines.push("")
    }
    renderFindingBucket("Reportable Findings", buckets.reportable)
    renderFindingBucket("Suspected Findings", buckets.suspected)
    renderFindingBucket("Rejected Or Stale Findings", buckets.rejected)
  }

  lines.push("## Knowledge")
  if (cyber.knowledge.length === 0) lines.push("_empty_")
  else {
    for (const item of cyber.knowledge) {
      lines.push(
        `- **${item.key}** \`${item.fact_name}\` · status=\`${item.status}\`${typeof item.returned === "number" ? ` · returned=${item.returned}` : ""}${item.severity ? ` · severity=${item.severity}` : ""}${item.type ? ` · type=${item.type}` : ""}${item.livecrawl ? ` · livecrawl=${item.livecrawl}` : ""}`,
      )
    }
    lines.push("")
  }

  lines.push("## Identities")
  if (cyber.identities.length === 0) lines.push("_empty_")
  else {
    const descriptors = cyber.identities.filter((item) => item.fact_name === "descriptor")
    const active = cyber.identities.filter((item) => item.fact_name === "active" && item.active)
    if (descriptors.length > 0) {
      lines.push("### Descriptors")
      for (const identity of descriptors) {
        lines.push(
          `- **${identity.key}** · status=\`${identity.status}\`${identity.mode ? ` · mode=${identity.mode}` : ""}${identity.header_keys.length > 0 ? ` · headers=${identity.header_keys.join(",")}` : ""}${identity.has_cookies ? " · cookies=present" : ""}`,
        )
      }
      lines.push("")
    }
    if (active.length > 0) {
      lines.push("### Active")
      for (const identity of active) {
        lines.push(`- **${identity.key}** · status=\`${identity.status}\``)
      }
      lines.push("")
    }
  }

  lines.push("## Tool Adapters")
  if (cyber.tool_adapters.length === 0) lines.push("_empty_")
  else {
    const present = cyber.tool_adapters.filter((item) => item.present)
    const missing = cyber.tool_adapters.filter((item) => !item.present)
    if (present.length > 0) {
      lines.push("### Present")
      for (const adapter of present) {
        lines.push(
          `- **${adapter.key}** · status=\`${adapter.status}\`${adapter.version ? ` · version=${adapter.version}` : ""}${adapter.path ? ` · path=\`${adapter.path}\`` : ""}`,
        )
      }
      lines.push("")
    }
    if (missing.length > 0) {
      lines.push("### Missing")
      for (const adapter of missing) {
        lines.push(`- **${adapter.key}** · status=\`${adapter.status}\``)
      }
      lines.push("")
    }
  }

  lines.push("## Verticals")
  if (cyber.verticals.length === 0) lines.push("_empty_")
  else {
    for (const vertical of cyber.verticals) {
      lines.push(`- **${vertical.key}** · status=\`${vertical.status}\``)
      if (vertical.missing_required.length > 0) {
        lines.push(`  - missing_required: ${vertical.missing_required.join(", ")}`)
      }
      if (vertical.missing_optional.length > 0) {
        lines.push(`  - missing_optional: ${vertical.missing_optional.join(", ")}`)
      }
    }
    lines.push("")
  }

  lines.push("## Capsules")
  if (cyber.capsules.length === 0) lines.push("_empty_")
  else {
    const readiness = cyber.capsules.filter((item) => item.fact_name === "capsule_readiness")
    const recommendations = cyber.capsules.filter((item) => item.fact_name === "capsule_recommendation")
    const executions = cyber.capsules.filter((item) => item.fact_name === "capsule_execution")
    if (readiness.length > 0) {
      lines.push("### Readiness")
      for (const capsule of readiness) {
        lines.push(`- **${capsule.key}**${capsule.name ? ` (${capsule.name})` : ""} · status=\`${capsule.status}\``)
        if (capsule.missing_required.length > 0) lines.push(`  - missing_required: ${capsule.missing_required.join(", ")}`)
        if (capsule.missing_optional.length > 0) lines.push(`  - missing_optional: ${capsule.missing_optional.join(", ")}`)
      }
      lines.push("")
    }
    if (recommendations.length > 0) {
      lines.push("### Recommendations")
      for (const capsule of recommendations) {
        lines.push(
          `- **${capsule.key}**${capsule.name ? ` (${capsule.name})` : ""}${capsule.operation_kind ? ` · operation_kind=\`${capsule.operation_kind}\`` : ""} · status=\`${capsule.status}\``,
        )
      }
      lines.push("")
    }
    if (executions.length > 0) {
      lines.push("### Executions")
      for (const capsule of executions) {
        lines.push(
          `- **${capsule.key}**${capsule.name ? ` (${capsule.name})` : ""} · status=\`${capsule.status}\`${capsule.invoked_via ? ` · via=\`${capsule.invoked_via}\`` : ""}${typeof capsule.steps === "number" ? ` · steps=${capsule.steps}` : ""}${typeof capsule.skipped === "number" ? ` · skipped=${capsule.skipped}` : ""}`,
        )
      }
      lines.push("")
    }
  }

  lines.push("## Deliverables")
  if (cyber.deliverables.length === 0) lines.push("_empty_")
  else {
    for (const deliverable of cyber.deliverables) {
      lines.push(
        `- **${deliverable.key}**${deliverable.report_path ? ` · report=\`${deliverable.report_path}\`` : ""}${deliverable.manifest_path ? ` · manifest=\`${deliverable.manifest_path}\`` : ""}${deliverable.format ? ` · format=\`${deliverable.format}\`` : ""}`,
      )
      const counts = deliverable.counts
      if (counts) {
        lines.push(
          `  - counts: reportable=${Number(counts.reportable_findings ?? 0)} suspected=${Number(counts.suspected_findings ?? 0)} verified=${Number(counts.verified_findings ?? 0)} evidence_backed=${Number(counts.evidence_backed_findings ?? 0)} replay_backed=${Number(counts.replay_backed_findings ?? 0)}`,
        )
      }
    }
    lines.push("")
  }

  lines.push("## Cyber Workflows")
  if (cyber.workflows.length === 0) lines.push("_empty_")
  else {
    for (const workflow of cyber.workflows) {
      lines.push(
        `- **${workflow.kind}:${workflow.key}** · steps=${workflow.steps} · completed=${workflow.completed_steps} · failed=${workflow.failed_steps} · pending=${workflow.pending_steps} · skipped=${workflow.skipped}${workflow.degraded ? " · degraded=yes" : ""}`,
      )
      const steps = cyber.workflow_steps.filter((item) => item.workflow === `${workflow.kind}:${workflow.key}`).slice(0, 8)
      for (const step of steps) {
        const label = [step.label, step.tool ? `tool=${step.tool}` : undefined].filter(Boolean).join(" · ")
        const detail = step.outcome_title ?? step.outcome_error
        lines.push(`  - step ${step.index} · ${step.outcome}${label ? ` · ${label}` : ""}${detail ? ` · ${detail}` : ""}`)
      }
    }
    lines.push("")
  }

  lines.push("## Cyber Timeline")
  if (cyber.timeline.length === 0) lines.push("_empty_")
  else {
    for (const event of cyber.timeline.slice(0, 12)) {
      lines.push(
        `- ${new Date(event.time_created).toISOString()} · ${event.kind}${event.source ? ` · source=${event.source}` : ""}${event.status ? ` · status=${event.status}` : ""}${event.summary ? ` · ${event.summary}` : ""}`,
      )
    }
    lines.push("")
  }

  lines.push("## Cyber Relations")
  if (cyber.relations.length === 0) lines.push("_empty_")
  else {
    for (const relation of cyber.relations.slice(0, 20)) {
      lines.push(
        `- ${relation.src_kind}:${relation.src_key} -${relation.relation}-> ${relation.dst_kind}:${relation.dst_key}${relation.status ? ` · status=${relation.status}` : ""}${relation.confidence != null ? ` · confidence=${relation.confidence}` : ""}`,
      )
    }
    lines.push("")
  }

  lines.push("## Evidence Locker")
  if (evidence.length === 0) lines.push("_empty_")
  else {
    lines.push("| SHA-256 | Size | MIME | Label | Source |")
    lines.push("|---|---|---|---|---|")
    for (const e of evidence) {
      lines.push(
        `| \`${e.sha256}\` | ${e.size} | ${e.mime ?? "-"} | ${e.label ?? ""} | ${e.source ?? ""} |`,
      )
    }
  }
  lines.push("")
  lines.push("---")
  lines.push(`_Generated by numasec on ${new Date().toISOString()}_`)
  return lines.join("\n")
}

export interface Manifest {
  operation: string
  kind: string
  generated_at: number
  files: Array<{ path: string; sha256: string; size: number }>
  counts: {
    plan: number
    observations: number
    observations_projected: number
    evidence: number
    cyber_findings: number
    plan_nodes_projected: number
    knowledge_queries: number
    identities: number
    active_identities: number
    tool_adapters_present: number
    tool_adapters_missing: number
    capsules: number
    recommended_capsules: number
    ready_capsules: number
    degraded_capsules: number
    unavailable_capsules: number
    executed_capsules: number
    ready_verticals: number
    degraded_verticals: number
    unavailable_verticals: number
    reportable_findings: number
    suspected_findings: number
    rejected_findings: number
    verified_findings: number
    evidence_backed_findings: number
    replay_backed_findings: number
    replay_exempt_findings: number
    relations_projected: number
    workflows: number
    completed_steps: number
    ledger_events: number
    context_artifacts: number
    scope_policy_facts: number
    operation_state_facts: number
    autonomy_policy_facts: number
  }
}

export interface BuildResult {
  bundleDir: string
  manifest: Manifest
  reportPath: string
  manifestPath: string
}

export const BUILD_PHASES = [
  "load_operation",
  "load_plan",
  "load_observations",
  "load_evidence",
  "load_projected_cyber_state",
  "prepare_bundle",
  "render_markdown",
  "render_json",
  "write_bundle_files",
  "write_manifest",
  "finalize_bundle",
] as const

export type BuildPhase = (typeof BUILD_PHASES)[number]

export async function build(
  workspace: string,
  slug: string,
  options: { format?: "md" | "json"; onPhase?: (phase: BuildPhase) => void } = {},
): Promise<BuildResult> {
  const phase = async <T>(name: BuildPhase, fn: () => Promise<T>): Promise<T> => {
    options.onPhase?.(name)
    return await fn()
  }

  const op = await phase("load_operation", () => Operation.get(workspace, slug))
  if (!op) throw new Error(`operation not found: ${slug}`)
  const [plan, planProjected, observations, observationsProjected, evidence, cyber] = await Promise.all([
    phase("load_plan", () => Plan.list(workspace, slug)),
    phase("load_plan", () => Plan.listProjected(workspace, slug).catch(() => [])),
    phase("load_observations", () => Observation.list(workspace, slug)),
    phase("load_observations", () => Observation.listProjected(workspace, slug).catch(() => [])),
    phase("load_evidence", () => Evidence.list(workspace, slug)),
    phase("load_projected_cyber_state", async () => {
      const [operationState, scopePolicy, autonomyPolicy, projectedFacts, projectedLedger, projectedRelations] =
        await Promise.all([
          Operation.readProjectedState(workspace, slug).catch(() => undefined),
          Operation.readProjectedScopePolicy(workspace, slug).catch(() => undefined),
          Operation.readProjectedAutonomyPolicy(workspace, slug).catch(() => undefined),
          Cyber.readProjectedFacts(workspace, slug).catch(() => []),
          Cyber.readProjectedLedger(workspace, slug).catch(() => []),
          Promise.resolve([] as Awaited<ReturnType<typeof Cyber.readProjectedRelations>>),
        ])
      return Cyber.projectStateFromParts({
        operation_state: operationState,
        scope_policy: scopePolicy,
        autonomy_policy: autonomyPolicy,
        facts: projectedFacts,
        ledger: projectedLedger,
        relations: projectedRelations,
      })
    }),
  ])

  const stamp = new Date().toISOString().replace(/[:.]/g, "-")
  const bundleDir = path.join(
    workspace,
    ".numasec",
    "operation",
    slug,
    "deliverable",
    `bundle-${stamp}`,
  )
  await phase("prepare_bundle", () => mkdir(bundleDir, { recursive: true }))

  const files: Array<{ path: string; bytes: Buffer }> = []
  const contextArtifact = await Operation.readContextPack(workspace, slug).catch(() => undefined)
  const manifestCounts: Manifest["counts"] = {
    plan: plan.length,
    observations: observations.length,
    observations_projected: cyber.summary.observations_projected,
    evidence: evidence.length,
    cyber_findings: cyber.findings.length,
    plan_nodes_projected: cyber.plan_nodes_projected,
    knowledge_queries: cyber.summary.knowledge_queries,
    identities: cyber.summary.identities,
    active_identities: cyber.summary.active_identities,
    tool_adapters_present: cyber.summary.tool_adapters_present,
    tool_adapters_missing: cyber.summary.tool_adapters_missing,
    capsules: cyber.summary.ready_capsules + cyber.summary.degraded_capsules + cyber.summary.unavailable_capsules,
    recommended_capsules: cyber.summary.recommended_capsules,
      ready_capsules: cyber.summary.ready_capsules,
      degraded_capsules: cyber.summary.degraded_capsules,
      unavailable_capsules: cyber.summary.unavailable_capsules,
      executed_capsules: cyber.summary.executed_capsules,
      ready_verticals: cyber.summary.ready_verticals,
    degraded_verticals: cyber.summary.degraded_verticals,
    unavailable_verticals: cyber.summary.unavailable_verticals,
    reportable_findings: cyber.summary.reportable_findings,
    suspected_findings: cyber.summary.suspected_findings,
    rejected_findings: cyber.summary.rejected_findings,
    verified_findings: cyber.summary.verified_findings,
    evidence_backed_findings: cyber.summary.evidence_backed_findings,
    replay_backed_findings: cyber.summary.replay_backed_findings,
    replay_exempt_findings: cyber.summary.replay_exempt_findings,
    relations_projected: cyber.relations.length,
    workflows: cyber.workflows.length,
    completed_steps: cyber.workflow_steps.filter((item) => item.outcome === "completed").length,
    ledger_events: cyber.timeline.length,
    context_artifacts: contextArtifact ? 1 : 0,
    scope_policy_facts: cyber.scope_policy ? 1 : 0,
    operation_state_facts: cyber.operation_state ? 1 : 0,
    autonomy_policy_facts: cyber.autonomy_policy ? 1 : 0,
  }
  const deliverableKey = path.basename(bundleDir)
  const deliverables = [
    {
      key: deliverableKey,
      bundle_dir: bundleDir,
      report_path: path.join(bundleDir, "report.md"),
      manifest_path: path.join(bundleDir, "manifest.json"),
      counts: manifestCounts,
      format: options.format,
      time_updated: Date.now(),
    },
    ...cyber.deliverables.filter((item) => item.key !== deliverableKey),
  ]
  const cyberWithCurrentDeliverable: ProjectedState = {
    ...cyber,
    deliverables,
  }

  if (options.format !== "json") {
    options.onPhase?.("render_markdown")
    const md = renderReport(op, plan, observations, evidence, cyberWithCurrentDeliverable)
    files.push({ path: "report.md", bytes: Buffer.from(md, "utf8") })
  }

  options.onPhase?.("render_json")
  const jsonPayload = JSON.stringify(
    {
      operation: op,
      operation_state: cyber.operation_state,
      scope_policy: cyber.scope_policy,
      autonomy_policy: cyber.autonomy_policy,
      plan,
      plan_projected: planProjected.length > 0 ? planProjected : cyber.plan_nodes,
      observations,
      observations_projected: observationsProjected.length > 0 ? observationsProjected : cyber.observations,
      evidence,
      cyber_findings: cyber.findings,
      knowledge: cyber.knowledge,
      identities: cyber.identities,
      tool_adapters: cyber.tool_adapters,
      verticals: cyber.verticals,
      capsules: cyber.capsules,
      deliverables: cyberWithCurrentDeliverable.deliverables,
      share_bundles: cyber.share_bundles,
      relations: cyber.relations,
      workflows: cyber.workflows,
      workflow_steps: cyber.workflow_steps,
      timeline: cyber.timeline,
      summary: cyber.summary,
    },
    null,
    2,
  )
  files.push({ path: "report.json", bytes: Buffer.from(jsonPayload, "utf8") })

  const manifest: Manifest = {
    operation: op.slug,
    kind: op.kind,
    generated_at: Date.now(),
    files: files.map((f) => ({ path: f.path, sha256: sha256(f.bytes), size: f.bytes.length })),
    counts: manifestCounts,
  }

  await phase("write_bundle_files", async () => {
    for (const f of files) {
      await writeFile(path.join(bundleDir, f.path), f.bytes)
    }
  })
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2), "utf8")
  const manifestPath = path.join(bundleDir, "manifest.json")
  await phase("write_manifest", () => writeFile(manifestPath, manifestBytes))

  const digest = sha256(manifestBytes)
  await phase("finalize_bundle", () =>
    writeFile(path.join(bundleDir, "manifest.sha256"), `${digest}  manifest.json\n`, "utf8"),
  )

  return {
    bundleDir,
    manifest,
    reportPath: path.join(bundleDir, "report.md"),
    manifestPath,
  }
}
