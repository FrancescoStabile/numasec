import path from "path"
import { evaluate, type Decision, type Request } from "@/core/boundary"
import { Cyber } from "@/core/cyber"
import type {
  ProjectedDeliverableState,
  ProjectedFinding,
  ProjectedState,
  ProjectedTimelineEvent,
  ProjectedWorkflowStatus,
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
  return rows.toSorted((a, b) => a.index - b.index).slice(0, 12)
}

export function deliverableLabel(snapshot: OperationConsoleSnapshot): string {
  const reportPath = snapshot.deliverable?.report_path
  if (!reportPath) return "not built"
  return path.basename(reportPath)
}

export function numericCount(
  counts: Record<string, unknown> | undefined,
  key: string,
) {
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
