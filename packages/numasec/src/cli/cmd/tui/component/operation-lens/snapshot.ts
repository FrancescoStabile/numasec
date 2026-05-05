import path from "path"
import { evaluate, type Decision, type Request } from "@/core/boundary"
import { Cyber } from "@/core/cyber"
import type {
  ProjectedDeliverableState,
  ProjectedFinding,
  ProjectedRelationState,
  ProjectedState,
  ProjectedTimelineEvent,
  ProjectedWorkflowStatus,
  ProjectedWorkflowStepStatus,
} from "@/core/cyber/cyber"
import {
  bucketFindings,
  isRejectedFinding,
  isReportableFinding,
  isSuspectedFinding,
  replayState,
} from "@/core/cyber/finding"
import { Evidence, type EvidenceEntry } from "@/core/evidence"
import { Operation, type OperationInfo } from "@/core/operation"

export type OperationConsoleSnapshot = {
  directory: string
  active?: OperationInfo
  projected?: ProjectedState
  evidenceCount: number
  evidenceEntries: EvidenceEntry[]
  activeWorkflow?: { kind: "play" | "runbook"; id: string }
  workflow?: ProjectedWorkflowStatus
  deliverable?: ProjectedDeliverableState
  timeline: ProjectedTimelineEvent[]
}

export type FindingLensStatus = "reportable" | "verified" | "suspected" | "rejected" | "candidate"

export type FindingLensRow = {
  key: string
  finding: ProjectedFinding
  title: string
  summary?: string
  severity: string
  severityCode: string
  status: FindingLensStatus
  evidenceCount: number
  replay: "present" | "exempt" | "missing" | "n/a"
  action: string
}

export type EvidenceKind = "replay" | "http" | "browser" | "file" | "tool" | "artifact"

export type EvidenceLensRow = {
  key: string
  entry: EvidenceEntry
  kind: EvidenceKind
  compactRef: string
  findingKeys: string[]
  findingTitles: string[]
  relationKinds: Array<"evidence_artifact" | "replay_artifact" | "unlinked">
  primaryRelationKind: "evidence_artifact" | "replay_artifact" | "unlinked"
  sourceLabel: string
}

export type ReplayLensStatus = "backed" | "exempt" | "missing" | "n/a"

export type ReplayLensRow = {
  key: string
  finding: ProjectedFinding
  title: string
  severityCode: string
  status: ReplayLensStatus
  artifactSha?: string
  artifactLabel?: string
  compactArtifact?: string
  gap: string
  oracle?: string
  reportable: boolean
}

export type WorkflowLensState = "active" | "failed" | "pending" | "completed" | "skipped" | "other"

export type WorkflowLensRow = {
  key: string
  step: ProjectedWorkflowStepStatus
  state: WorkflowLensState
  toolLabel: string
  stepLabel: string
  outcomeLabel: string
  active: boolean
}

export type ReportGateTone = "success" | "warning" | "error" | "muted"

export type ReportGateRow = {
  key: string
  label: string
  value: string
  tone: ReportGateTone
  detail: string
  findingKeys: string[]
}

function requestForTarget(target: string): Request {
  try {
    if (target.includes("://")) {
      return { kind: "url", value: target }
    }
    const parsed = new URL(`http://${target}`)
    return { kind: "host", value: parsed.host || parsed.hostname || target }
  } catch {
    return { kind: "raw", value: target }
  }
}

function severityRank(value?: string) {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return 0
    case "high":
      return 1
    case "medium":
      return 2
    case "low":
      return 3
    case "info":
      return 4
    default:
      return 5
  }
}

function statusRank(value: FindingLensStatus) {
  switch (value) {
    case "reportable":
      return 0
    case "verified":
      return 1
    case "suspected":
      return 2
    case "rejected":
      return 3
    case "candidate":
      return 4
  }
}

function severityCode(value?: string) {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "C"
    case "high":
      return "H"
    case "medium":
      return "M"
    case "low":
      return "L"
    case "info":
      return "I"
    default:
      return "?"
  }
}

function findingStatus(finding: ProjectedFinding): FindingLensStatus {
  if (finding.kind === "candidate") return "candidate"
  if (isReportableFinding(finding)) return "reportable"
  if (finding.status === "verified") return "verified"
  if (isRejectedFinding(finding)) return "rejected"
  if (isSuspectedFinding(finding)) return "suspected"
  return "suspected"
}

function replayLabel(finding: ProjectedFinding): FindingLensRow["replay"] {
  if (finding.kind === "candidate") return "n/a"
  return replayState(finding) ?? "missing"
}

function findingAction(status: FindingLensStatus, replay: FindingLensRow["replay"]) {
  if (status === "reportable") return "open"
  if (status === "verified") {
    if (replay === "missing") return "replay"
    return "review"
  }
  if (status === "rejected") return "closed"
  if (status === "candidate") return "promote"
  return "verify"
}

function findingMap(snapshot?: OperationConsoleSnapshot) {
  return new Map((snapshot?.projected?.findings ?? []).map((finding) => [finding.key, finding]))
}

function relationsForEvidence(
  snapshot?: OperationConsoleSnapshot,
): Map<string, Array<{ findingKey: string; relationKind: "evidence_artifact" | "replay_artifact" }>> {
  const result = new Map<string, Array<{ findingKey: string; relationKind: "evidence_artifact" | "replay_artifact" }>>()
  for (const relation of snapshot?.projected?.relations ?? []) {
    if (relation.src_kind !== "finding") continue
    if (relation.relation !== "backed_by") continue
    if (relation.dst_kind !== "evidence_artifact" && relation.dst_kind !== "replay_artifact") continue
    const existing = result.get(relation.dst_key) ?? []
    existing.push({
      findingKey: relation.src_key,
      relationKind: relation.dst_kind,
    })
    result.set(relation.dst_key, existing)
  }
  return result
}

function reportableFindings(snapshot?: OperationConsoleSnapshot) {
  return findingsRows(snapshot).filter((row) => row.status === "reportable")
}

function verifiedRows(snapshot?: OperationConsoleSnapshot) {
  return findingsRows(snapshot).filter((row) => row.status === "verified" || row.status === "reportable")
}

export function compactSha(sha?: string, size = 10) {
  if (!sha) return "-"
  if (sha.length <= size) return sha
  return sha.slice(0, size)
}

export function evidenceKind(
  entry: EvidenceEntry,
  relationKind?: "evidence_artifact" | "replay_artifact" | "unlinked",
): EvidenceKind {
  if (entry.ext === "replay" || relationKind === "replay_artifact") return "replay"
  const source = `${entry.source ?? ""} ${entry.label ?? ""}`.toLowerCase()
  const mime = (entry.mime ?? "").toLowerCase()
  if (source.startsWith("http") || mime.includes("html") || mime.includes("json")) return "http"
  if (source.includes("browser") || mime.startsWith("image/") || mime.includes("screenshot")) return "browser"
  if (source.includes("/") || source.includes("\\") || source.startsWith("file:")) return "file"
  if (entry.label || entry.source) return "tool"
  return "artifact"
}

export function findingByKey(snapshot: OperationConsoleSnapshot | undefined, key?: string) {
  if (!snapshot || !key) return undefined
  return findingMap(snapshot).get(key)
}

export function findingRefs(snapshot: OperationConsoleSnapshot | undefined, findingKey?: string) {
  const finding = findingByKey(snapshot, findingKey)
  const refs = new Set<string>(finding?.evidence_refs ?? [])
  const replayRefs = new Set<string>()
  for (const relation of snapshot?.projected?.relations ?? []) {
    if (relation.src_kind !== "finding" || relation.src_key !== findingKey) continue
    if (relation.relation !== "backed_by") continue
    if (relation.dst_kind === "evidence_artifact" || relation.dst_kind === "replay_artifact") {
      refs.add(relation.dst_key)
      if (relation.dst_kind === "replay_artifact") replayRefs.add(relation.dst_key)
    }
  }
  return {
    evidenceRefs: [...refs],
    replayRefs: [...replayRefs],
  }
}

export function evidenceBySha(snapshot?: OperationConsoleSnapshot) {
  return new Map((snapshot?.evidenceEntries ?? []).map((entry) => [entry.sha256, entry]))
}

export function findingsBadgeCount(snapshot?: OperationConsoleSnapshot) {
  const summary = snapshot?.projected?.summary
  if (!summary) return 0
  if (summary.reportable_findings > 0) return summary.reportable_findings
  if (summary.verified_findings > 0) return summary.verified_findings
  return summary.findings + summary.candidate_findings
}

export function findingsRows(snapshot?: OperationConsoleSnapshot): FindingLensRow[] {
  const findings = snapshot?.projected?.findings ?? []
  const rows = bucketFindings(findings).all.map((finding) => {
    const status = findingStatus(finding)
    const replay = replayLabel(finding)
    return {
      key: finding.key,
      finding,
      title: finding.title ?? finding.key,
      summary: finding.proof_summary ?? finding.summary,
      severity: finding.severity ?? "unrated",
      severityCode: severityCode(finding.severity),
      status,
      evidenceCount: finding.evidence_refs?.length ?? 0,
      replay,
      action: findingAction(status, replay),
    }
  })

  return rows.toSorted((a, b) => {
    const severityDelta = severityRank(a.severity) - severityRank(b.severity)
    if (severityDelta !== 0) return severityDelta
    const statusDelta = statusRank(a.status) - statusRank(b.status)
    if (statusDelta !== 0) return statusDelta
    return a.title.localeCompare(b.title)
  })
}

export function evidenceRows(
  snapshot?: OperationConsoleSnapshot,
  filter?: { findingKey?: string },
): EvidenceLensRow[] {
  const bySha = evidenceBySha(snapshot)
  const relations = relationsForEvidence(snapshot)
  const findings = findingMap(snapshot)
  const refsByFinding = new Map<string, Set<string>>()

  for (const finding of snapshot?.projected?.findings ?? []) {
    const refs = refsByFinding.get(finding.key) ?? new Set<string>()
    for (const ref of finding.evidence_refs ?? []) refs.add(ref)
    refsByFinding.set(finding.key, refs)
  }
  for (const [sha, entries] of relations) {
    for (const entry of entries) {
      const refs = refsByFinding.get(entry.findingKey) ?? new Set<string>()
      refs.add(sha)
      refsByFinding.set(entry.findingKey, refs)
    }
  }

  const selectedRefs = filter?.findingKey ? refsByFinding.get(filter.findingKey) : undefined
  const rows = [...bySha.values()]
    .filter((entry) => !selectedRefs || selectedRefs.has(entry.sha256))
    .map((entry) => {
      const linked = relations.get(entry.sha256) ?? []
      const directFindingKeys = [...refsByFinding.entries()]
        .filter(([, refs]) => refs.has(entry.sha256))
        .map(([findingKey]) => findingKey)
      const findingKeys = [...new Set([...linked.map((item) => item.findingKey), ...directFindingKeys])]
      const relationKinds: Array<"evidence_artifact" | "replay_artifact" | "unlinked"> = findingKeys.length === 0
        ? ["unlinked"]
        : findingKeys.map(
            (findingKey) => linked.find((item) => item.findingKey === findingKey)?.relationKind ?? "evidence_artifact",
          )
      const primaryRelationKind: "evidence_artifact" | "replay_artifact" | "unlinked" = relationKinds.includes("replay_artifact")
        ? "replay_artifact"
        : relationKinds.includes("evidence_artifact")
          ? "evidence_artifact"
          : "unlinked"
      const findingTitles = findingKeys.map((key) => findings.get(key)?.title ?? key)
      return {
        key: entry.sha256,
        entry,
        kind: evidenceKind(entry, primaryRelationKind),
        compactRef: compactSha(entry.sha256),
        findingKeys,
        findingTitles,
        relationKinds,
        primaryRelationKind,
        sourceLabel: entry.label ?? entry.source ?? entry.sha256,
      }
    })

  return rows.toSorted((a, b) => {
    if (a.findingTitles[0] !== b.findingTitles[0]) return (a.findingTitles[0] ?? "unlinked").localeCompare(b.findingTitles[0] ?? "unlinked")
    if (a.entry.at !== b.entry.at) return b.entry.at - a.entry.at
    return a.entry.sha256.localeCompare(b.entry.sha256)
  })
}

export function replayRows(
  snapshot?: OperationConsoleSnapshot,
  filter?: { findingKey?: string },
): ReplayLensRow[] {
  const evidence = evidenceBySha(snapshot)
  const rows = findingsRows(snapshot)
    .filter((item) => !filter?.findingKey || item.key === filter.findingKey)
    .map((item) => {
      const refs = findingRefs(snapshot, item.key)
      const replayRef = refs.replayRefs.find((ref) => evidence.has(ref)) ?? refs.replayRefs[0]
      const replayEntry = replayRef ? evidence.get(replayRef) : undefined
      const status: ReplayLensStatus =
        item.finding.kind === "candidate"
          ? "n/a"
          : item.replay === "present"
            ? "backed"
            : item.replay === "exempt"
              ? "exempt"
              : "missing"
      const oracle =
        item.finding.oracle_status
          ? `${item.finding.oracle_status}${item.finding.oracle_reason ? ` · ${item.finding.oracle_reason}` : ""}`
          : undefined
      let gap = "candidate not promoted"
      if (status === "backed") gap = "replay bundle present"
      if (status === "exempt") gap = item.finding.replay_reason ? `structured exemption accepted · ${item.finding.replay_reason}` : "structured exemption accepted"
      if (status === "missing" && item.status === "verified") gap = "verified finding missing replay bundle"
      if (status === "missing" && item.status === "reportable") gap = "reportable finding missing replay bundle"
      if (status === "missing" && item.status === "suspected") gap = "suspected finding not reportable"
      if (status === "missing" && item.status === "rejected") gap = "rejected finding closed"
      return {
        key: item.key,
        finding: item.finding,
        title: item.title,
        severityCode: item.severityCode,
        status,
        artifactSha: replayEntry?.sha256 ?? replayRef,
        artifactLabel: replayEntry?.label ?? replayEntry?.source,
        compactArtifact: compactSha(replayEntry?.sha256 ?? replayRef),
        gap,
        oracle,
        reportable: item.status === "reportable",
      }
    })

  return rows.toSorted((a, b) => {
    const severityDelta = severityRank(a.finding.severity) - severityRank(b.finding.severity)
    if (severityDelta !== 0) return severityDelta
    return a.title.localeCompare(b.title)
  })
}

export function workflowRows(
  snapshot?: OperationConsoleSnapshot,
  _filter?: { findingKey?: string },
): WorkflowLensRow[] {
  const steps = workflowStepRows(snapshot)
  const activeStep =
    steps.find((item) => item.outcome === "failed") ??
    steps.find((item) => item.outcome === "pending") ??
    [...steps].reverse().find((item) => item.outcome === "completed")

  return steps.map((step) => {
    const state: WorkflowLensState =
      step.key === activeStep?.key
        ? "active"
        : step.outcome === "failed"
          ? "failed"
          : step.outcome === "pending"
            ? "pending"
            : step.outcome === "completed"
              ? "completed"
              : step.outcome === "skipped"
                ? "skipped"
                : "other"
    return {
      key: step.key,
      step,
      state,
      toolLabel: step.tool ?? "-",
      stepLabel: step.label ?? step.tool ?? `step ${step.index}`,
      outcomeLabel: step.outcome_title ?? step.outcome,
      active: step.key === activeStep?.key,
    }
  })
}

export function reportGateRows(snapshot?: OperationConsoleSnapshot): ReportGateRow[] {
  if (!snapshot) return []
  const summary = snapshot.projected?.summary
  const deliverable = snapshot.deliverable
  const verified = verifiedRows(snapshot)
  const reportable = reportableFindings(snapshot)
  const missingEvidence = verified.filter((row) => (row.finding.evidence_refs?.length ?? 0) === 0)
  const missingReplay = verified.filter((row) => row.replay === "missing")
  const reportableCount = reportable.length || summary?.reportable_findings || 0
  const verifiedCount = verified.length || summary?.verified_findings || 0
  const replayCovered = replayCoveredCount(snapshot)
  const workflow = workflowProgress(snapshot)
  const manifestPresent = Boolean(deliverable?.manifest_path)
  const bundlePresent = Boolean(deliverable?.bundle_dir)
  const ready = reportStatus(snapshot) === "ready"
  const evidenceBacked = verifiedCount - missingEvidence.length

  return [
    {
      key: "deliverable",
      label: "deliverable",
      value: ready ? "built" : "not built",
      tone: ready ? "success" : "error",
      detail: ready ? deliverableLabel(snapshot) : "build report bundle to freeze the current operation state",
      findingKeys: [],
    },
    {
      key: "bundle",
      label: "bundle/manifest",
      value: `${bundlePresent ? "bundle" : "no bundle"} · ${manifestPresent ? "manifest" : "no manifest"}`,
      tone: bundlePresent && manifestPresent ? "success" : "warning",
      detail: deliverable?.bundle_dir ?? "no deliverable paths projected",
      findingKeys: [],
    },
    {
      key: "reportable",
      label: "reportable",
      value: `${reportableCount}/${verifiedCount || reportableCount}`,
      tone: verifiedCount === 0 || reportableCount === verifiedCount ? "success" : "warning",
      detail: verifiedCount === reportableCount
        ? "all verified findings are currently ship-ready"
        : `${verifiedCount - reportableCount} verified findings are not yet ship-ready`,
      findingKeys: verified.filter((row) => row.status !== "reportable").map((row) => row.key),
    },
    {
      key: "evidence",
      label: "evidence",
      value: `${evidenceBacked}/${verifiedCount || evidenceBacked}`,
      tone: missingEvidence.length === 0 ? "success" : "error",
      detail: missingEvidence.length === 0
        ? "all verified findings have evidence refs"
        : `missing evidence refs: ${missingEvidence.map((row) => row.title).join(", ")}`,
      findingKeys: missingEvidence.map((row) => row.key),
    },
    {
      key: "replay",
      label: "replay",
      value: `${replayCovered}/${verifiedCount || replayCovered}`,
      tone: missingReplay.length === 0 ? "success" : "error",
      detail: missingReplay.length === 0
        ? "all verified findings are replay-backed or exempt"
        : `missing replay: ${missingReplay.map((row) => row.title).join(", ")}`,
      findingKeys: missingReplay.map((row) => row.key),
    },
    {
      key: "replay-exempt",
      label: "replay exempt",
      value: String(summary?.replay_exempt_findings ?? 0),
      tone: "muted",
      detail: "structured exemptions counted toward reportability",
      findingKeys: replayRows(snapshot).filter((row) => row.status === "exempt").map((row) => row.key),
    },
    {
      key: "workflow",
      label: "workflow failures",
      value: `${workflow.failed}`,
      tone: workflow.failed > 0 ? "warning" : "success",
      detail: workflow.failed > 0 ? `${workflow.failed} workflow steps failed` : "no workflow failures projected",
      findingKeys: [],
    },
    {
      key: "rejected",
      label: "rejected/stale",
      value: String(summary?.rejected_findings ?? 0),
      tone: "muted",
      detail: `${summary?.rejected_findings ?? 0} findings are intentionally excluded from the ship-ready set`,
      findingKeys: findingsRows(snapshot).filter((row) => row.status === "rejected").map((row) => row.key),
    },
  ]
}

export function reportGateFocusIndex(snapshot: OperationConsoleSnapshot | undefined, findingKey?: string) {
  if (!snapshot || !findingKey) return 0
  const rows = reportGateRows(snapshot)
  const index = rows.findIndex((row) => row.findingKeys.includes(findingKey))
  return index >= 0 ? index : 0
}

export function restoreSelectedIndex<T extends { key: string }>(
  rows: T[],
  focusedKey: string | undefined,
  fallbackIndex: number,
) {
  if (rows.length === 0) return 0
  if (focusedKey) {
    const index = rows.findIndex((row) => row.key === focusedKey)
    if (index >= 0) return index
  }
  return Math.max(0, Math.min(fallbackIndex, rows.length - 1))
}

export function scopeDecision(snapshot: OperationConsoleSnapshot): Decision | undefined {
  const boundary = snapshot.projected?.scope_policy
  const target = snapshot.projected?.operation_state?.target ?? snapshot.active?.target
  if (!boundary) return undefined
  if (!target) return { mode: boundary.default, reason: "no target" }
  return evaluate(boundary, requestForTarget(target))
}

export function scopeCounts(snapshot: OperationConsoleSnapshot) {
  const boundary = snapshot.projected?.scope_policy
  return {
    inScope: boundary?.in_scope.length ?? 0,
    outOfScope: boundary?.out_of_scope.length ?? 0,
  }
}

export function replayCoveredCount(snapshot: OperationConsoleSnapshot): number {
  const summary = snapshot.projected?.summary
  if (!summary) return 0
  return summary.replay_backed_findings + summary.replay_exempt_findings
}

export function reportStatus(snapshot: OperationConsoleSnapshot): "ready" | "draft" | "cold" {
  if (snapshot.deliverable?.report_path) return "ready"
  const summary = snapshot.projected?.summary
  if (!summary) return "cold"
  if (summary.verified_findings > 0 || summary.reportable_findings > 0) return "draft"
  return "cold"
}

export function workflowProgress(snapshot: OperationConsoleSnapshot) {
  const workflow = snapshot.workflow
  if (!workflow) return { completed: 0, total: 0, failed: 0, pending: 0, degraded: false }
  return {
    completed: workflow.completed_steps,
    total: workflow.steps,
    failed: workflow.failed_steps,
    pending: workflow.pending_steps,
    degraded: workflow.degraded,
  }
}

export function workflowLabel(snapshot: OperationConsoleSnapshot): string {
  const activeWorkflow = snapshot.activeWorkflow
  if (!activeWorkflow) return "none"
  return activeWorkflow.id
}

export function workflowStepRows(snapshot?: OperationConsoleSnapshot) {
  if (!snapshot?.projected?.workflow_steps) return []
  const workflowKey = snapshot.activeWorkflow ? `${snapshot.activeWorkflow.kind}:${snapshot.activeWorkflow.id}` : undefined
  const rows = workflowKey
    ? snapshot.projected.workflow_steps.filter((item) => item.workflow === workflowKey)
    : snapshot.projected.workflow_steps
  return rows.toSorted((a, b) => a.index - b.index)
}

export function deliverableLabel(snapshot: OperationConsoleSnapshot): string {
  const reportPath = snapshot.deliverable?.report_path
  if (!reportPath) return "not built"
  return path.basename(reportPath)
}

export function numericCount(counts: Record<string, unknown> | undefined, key: string) {
  const value = counts?.[key]
  return typeof value === "number" ? value : 0
}

export async function loadOperationConsoleSnapshot(directory?: string): Promise<OperationConsoleSnapshot | undefined> {
  if (!directory) return undefined
  const active = await Operation.active(directory).catch(() => undefined)
  if (!active) {
    return {
      directory,
      active: undefined,
      projected: undefined,
      evidenceCount: 0,
      evidenceEntries: [],
      activeWorkflow: undefined,
      workflow: undefined,
      deliverable: undefined,
      timeline: [],
    }
  }

  const [projected, evidenceEntries, activeWorkflow] = await Promise.all([
    Cyber.readProjectedState(directory, active.slug).catch(() => undefined),
    Evidence.list(directory, active.slug).catch(() => []),
    Operation.activeWorkflow(directory, active.slug).catch(() => undefined),
  ])

  const workflow =
    activeWorkflow && projected
      ? projected.workflows.find((item) => item.kind === activeWorkflow.kind && item.key === activeWorkflow.id)
      : projected?.workflows[0]

  return {
    directory,
    active,
    projected,
    evidenceCount: evidenceEntries.length,
    evidenceEntries,
    activeWorkflow,
    workflow,
    deliverable: projected?.deliverables[0],
    timeline: (projected?.timeline ?? []).slice(0, 8),
  }
}
