import path from "path"
import { evaluate, type Decision, type Request } from "@/core/boundary"
import { Cyber } from "@/core/cyber"
import type { ProjectedDeliverableState, ProjectedState, ProjectedTimelineEvent, ProjectedWorkflowStatus } from "@/core/cyber/cyber"
import { Evidence } from "@/core/evidence"
import { Operation, type OperationInfo } from "@/core/operation"

export type OperationConsoleSnapshot = {
  directory: string
  active?: OperationInfo
  projected?: ProjectedState
  evidenceCount: number
  activeWorkflow?: { kind: "play" | "runbook"; id: string }
  workflow?: ProjectedWorkflowStatus
  deliverable?: ProjectedDeliverableState
  timeline: ProjectedTimelineEvent[]
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
  return `${activeWorkflow.id}`
}

export function deliverableLabel(snapshot: OperationConsoleSnapshot): string {
  const reportPath = snapshot.deliverable?.report_path
  if (!reportPath) return "not built"
  return path.basename(reportPath)
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
      activeWorkflow: undefined,
      workflow: undefined,
      deliverable: undefined,
      timeline: [],
    }
  }

  const [projected, evidence, activeWorkflow] = await Promise.all([
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
    evidenceCount: evidence.length,
    activeWorkflow,
    workflow,
    deliverable: projected?.deliverables[0],
    timeline: (projected?.timeline ?? []).slice(0, 8),
  }
}
