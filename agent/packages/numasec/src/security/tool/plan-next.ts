import z from "zod"
import { Effect } from "effect"
import { and, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceGraphStore } from "../evidence-store"
import { EvidenceNodeTable, EvidenceRunTable } from "../evidence.sql"
import { applyPlannerEvent, createPlannerKernel, type PlannerEvent, type PlannerKernel, type PlannerSignal } from "../planner/kernel"
import { normalizePlannerEvent, plannerStateOrDefault } from "../planner/event-normalizer"
import { selectPlannerPrimitives } from "../planner/policy"
import {
  SecurityActorSessionTable,
  SecurityTargetProfileTable,
} from "../runtime/runtime.sql"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Advance the deterministic planner kernel and return the next primitive action.
Use this to move between scope, hypothesis, evidence, decision, and closure states.`

const STATE = z.enum([
  "idle",
  "scope_defined",
  "hypothesis_open",
  "evidence_collecting",
  "decision_pending",
  "closed_positive",
  "closed_negative",
])

const POLICY_SIGNAL = z.enum([
  "waf_detected",
  "auth_obtained",
  "escalation_found",
  "spa_detected",
  "api_app_detected",
  "workflow_actions_mined",
  "destructive_actions_mined",
])
const PLANNER_RUN_ID = "planner"

const PlanNextParameters = z.object({
  state: STATE.optional(),
  target: z.string().optional(),
  scope: z.enum(["quick", "standard", "deep"]).optional(),
  hypothesis_id: z.string().optional(),
  finding_id: z.string().optional(),
  evidence_nodes: z.array(z.string()).optional(),
  notes: z.array(z.string()).optional(),
  event_type: z.string().optional(),
  event: z.string().optional(),
  event_payload: z.record(z.string(), z.any()).optional(),
  event_payload_json: z.string().optional(),
  policy_signals: z.array(POLICY_SIGNAL).optional(),
  remaining_seconds: z.number().int().min(1).optional(),
  primitive_budget: z.number().int().min(1).max(4).optional(),
})

function plannerRunID(sessionID: string) {
  return `${PLANNER_RUN_ID}:${sessionID}`
}

function strings(input: unknown): string[] {
  if (!Array.isArray(input)) return []
  return input.filter((item): item is string => typeof item === "string")
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function signals(input: unknown): PlannerSignal[] {
  return strings(input).filter((item): item is PlannerSignal =>
    item === "waf_detected" ||
    item === "auth_obtained" ||
    item === "escalation_found" ||
    item === "spa_detected" ||
    item === "api_app_detected" ||
    item === "workflow_actions_mined" ||
    item === "destructive_actions_mined",
  )
}

function noteObject(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
}

function readStoredKernel(sessionID: string) {
  const row = Database.use((db) =>
    db
      .select()
      .from(EvidenceRunTable)
      .where(
        and(
          eq(EvidenceRunTable.session_id, sessionID as any),
          eq(EvidenceRunTable.id, plannerRunID(sessionID) as any),
        ),
      )
      .get(),
  )
  if (!row) {
    return {
      kernel: createPlannerKernel(),
      attempts: 0,
    }
  }
  const notes = noteObject(row.notes)
  return {
    kernel: {
      state: plannerStateOrDefault(row.planner_state),
      target: typeof notes.target === "string" ? notes.target : "",
      scope: notes.scope === "quick" || notes.scope === "deep" ? notes.scope : "standard",
      hypothesis_id: row.hypothesis_id ?? "",
      finding_id: typeof notes.finding_id === "string" ? notes.finding_id : "",
      evidence_nodes: strings(notes.evidence_nodes),
      notes: strings(notes.notes),
      signals: signals(notes.signals),
      history: [],
    } satisfies PlannerKernel,
    attempts: row.attempts ?? 0,
  }
}

function readKernel(params: z.infer<typeof PlanNextParameters>, stored: PlannerKernel) {
  const value = params.state ? createPlannerKernel() : stored
  return {
    ...value,
    state: params.state ? plannerStateOrDefault(params.state) : value.state,
    target: params.target ?? value.target,
    scope: params.scope ?? value.scope,
    hypothesis_id: params.hypothesis_id ?? value.hypothesis_id,
    finding_id: params.finding_id ?? value.finding_id,
    evidence_nodes: params.evidence_nodes ?? value.evidence_nodes,
    notes: params.notes ?? value.notes,
    signals: value.signals,
  } satisfies PlannerKernel
}

function mergeSignals(kernel: PlannerKernel, list: PlannerSignal[]) {
  if (list.length === 0) return kernel
  const next = new Set(kernel.signals)
  for (const item of list) next.add(item)
  return {
    ...kernel,
    signals: Array.from(next),
  } satisfies PlannerKernel
}

function mergeNotes(kernel: PlannerKernel, list: string[]) {
  if (list.length === 0) return kernel
  const next = new Set(kernel.notes)
  for (const item of list) next.add(item)
  return {
    ...kernel,
    notes: Array.from(next),
  } satisfies PlannerKernel
}

function trimFence(input: string) {
  const value = input.trim()
  const match = /^```[a-z0-9_-]*\s*([\s\S]*?)\s*```$/i.exec(value)
  if (typeof match?.[1] === "string") return match[1].trim()
  return value
}

function readEventPayload(params: z.infer<typeof PlanNextParameters>): Record<string, unknown> | undefined {
  if (params.event_payload) return params.event_payload
  const text = params.event_payload_json
  if (!text) return
  const value = JSON.parse(trimFence(text))
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  throw new Error("plan_next event_payload_json must decode to an object")
}

function readEvent(params: z.infer<typeof PlanNextParameters>): {
  event?: PlannerEvent
  rawType: string
  canonicalType: string
  warnings: string[]
} {
  const normalized = normalizePlannerEvent({
    event_type: params.event_type,
    event: params.event,
    event_payload: readEventPayload(params),
    target: params.target,
    scope: params.scope,
    hypothesis_id: params.hypothesis_id,
    finding_id: params.finding_id,
    evidence_nodes: params.evidence_nodes,
  })
  return {
    event: normalized.event,
    rawType: normalized.raw_type,
    canonicalType: normalized.canonical_type,
    warnings: normalized.warnings,
  }
}

function destructive(action: string, target: string) {
  if (["delete", "archive", "close", "remove"].includes(action)) return true
  return ["deleted", "archived", "closed"].includes(target)
}

function readRuntimeContext(sessionID: string) {
  const signals = new Set<PlannerSignal>()
  const notes = new Set<string>()
  let actorSessions = 0
  let targetProfiles = 0
  let networkActions = 0
  const actors = Database.use((db) =>
    db
      .select()
      .from(SecurityActorSessionTable)
      .where(eq(SecurityActorSessionTable.session_id, sessionID as any))
      .all(),
  )
  for (const item of actors) {
    const summary = noteObject(item.material_summary)
    const headerKeys = strings(summary.header_keys)
    const cookieNames = strings(summary.cookie_names)
    const actorID = text(summary.actor_id)
    const actorEmail = text(summary.actor_email)
    const actorRole = text(summary.actor_role)
    if (!actorID && !actorEmail && !actorRole && headerKeys.length === 0 && cookieNames.length === 0) continue
    actorSessions += 1
    signals.add("auth_obtained")
  }
  if (actorSessions > 0) {
    notes.add(`Runtime actor sessions available: ${actorSessions}`)
  }

  const profiles = Database.use((db) =>
    db
      .select()
      .from(SecurityTargetProfileTable)
      .where(eq(SecurityTargetProfileTable.session_id, sessionID as any))
      .all(),
  )
  for (const item of profiles) {
    targetProfiles += 1
    if (item.last_signal === "waf_suspected" || item.status === "blocked") {
      signals.add("waf_detected")
      notes.add(`Target profile ${item.origin} is ${item.status} after ${item.last_signal || "runtime signals"}`)
      continue
    }
    if (item.status === "throttled") {
      notes.add(`Target profile ${item.origin} is throttled after ${item.last_signal || "runtime signals"}`)
    }
  }

  const observations = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(
        and(
          eq(EvidenceNodeTable.session_id, sessionID as any),
          eq(EvidenceNodeTable.type, "observation"),
        ),
      )
      .all(),
  )
  for (const item of observations) {
    const payload = noteObject(item.payload)
    if (text(payload.family) !== "resource_inventory") continue
    const source = text(payload.source_kind)
    const action = text(payload.action_kind).toLowerCase()
    const target = text(payload.action_target_state).toLowerCase()
    if (action) signals.add("workflow_actions_mined")
    if (destructive(action, target)) signals.add("destructive_actions_mined")
    if (source === "browser_network" && action) networkActions += 1
  }
  if (networkActions > 0) {
    notes.add(`Browser network mining produced ${networkActions} action candidate(s)`)
  }

  return {
    signals: Array.from(signals),
    notes: Array.from(notes),
    actorSessions,
    targetProfiles,
    networkActions,
  }
}

export const PlanNextTool = Tool.define("plan_next", {
  description: DESCRIPTION,
  parameters: PlanNextParameters,
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const stored = readStoredKernel(sessionID)
    const runtime = readRuntimeContext(sessionID)
    const current = mergeNotes(
      mergeSignals(readKernel(params, stored.kernel), runtime.signals),
      runtime.notes,
    )
    const event = readEvent(params)
    const next = mergeSignals(
      event.event ? applyPlannerEvent(current, event.event) : current,
      (params.policy_signals ?? []) as PlannerSignal[],
    )
    const policy = selectPlannerPrimitives(next, {
      budget: {
        remaining_seconds: params.remaining_seconds,
        primitive_budget: params.primitive_budget,
      },
    })
    const step = policy.primary
    const queue = policy.steps.map((item) => item.primitive)
    const run = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertRun({
          id: plannerRunID(sessionID),
          sessionID,
          plannerState: next.state,
          hypothesisID: next.hypothesis_id,
          status: next.state,
          attempts: stored.attempts + 1,
          notes: {
            target: next.target,
            scope: next.scope,
            finding_id: next.finding_id,
            evidence_nodes: next.evidence_nodes,
            notes: next.notes,
            signals: next.signals,
            last_event_raw: event.rawType,
            last_event_canonical: event.canonicalType,
            last_event_warnings: event.warnings,
            last_policy_primitives: queue,
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    return {
      title: `Planner: ${next.state} -> ${step.primitive}`,
      metadata: {
        state: next.state,
        primitive: step.primitive,
        policyPrimitives: queue,
        budgetSeconds: policy.budget.remaining_seconds,
        budgetPrimitives: policy.budget.primitive_budget,
        evidenceSupports: policy.evidence.supports,
        evidenceRefutes: policy.evidence.refutes,
        verificationPassed: policy.evidence.verification_passed,
        hypothesis: next.hypothesis_id,
        evidenceNodes: next.evidence_nodes.length,
        carriedSignals: next.signals,
        runtimeActorSessions: runtime.actorSessions,
        runtimeTargetProfiles: runtime.targetProfiles,
        runtimeNetworkActions: runtime.networkActions,
        plannerAttempts: run.attempts,
        eventRaw: event.rawType,
        eventCanonical: event.canonicalType,
        eventWarnings: event.warnings,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
            {
              type: "planner_state",
              state: next.state,
              primitive: step.primitive,
              hypothesis_id: next.hypothesis_id,
              signals: next.signals,
            },
            {
              type: "planner_policy",
              primitives: queue,
              supports: policy.evidence.supports,
              refutes: policy.evidence.refutes,
              observes: policy.evidence.observes,
              budget_seconds: policy.budget.remaining_seconds,
              primitive_budget: policy.budget.primitive_budget,
            },
            {
              type: "planner_runtime",
              actor_sessions: runtime.actorSessions,
              target_profiles: runtime.targetProfiles,
              network_actions: runtime.networkActions,
              runtime_signals: runtime.signals,
            },
        ],
        verifications:
          event.event && event.canonicalType
            ? [
                {
                  type: "planner_event",
                  raw_event: event.rawType,
                  canonical_event: event.canonicalType,
                  warning_count: event.warnings.length,
                },
              ]
            : [],
        metrics: {
          evidence_supports: policy.evidence.supports,
          evidence_refutes: policy.evidence.refutes,
          evidence_observes: policy.evidence.observes,
          policy_primitives: queue.length,
          policy_budget_seconds: policy.budget.remaining_seconds,
          policy_budget_primitives: policy.budget.primitive_budget,
          planner_event_warnings: event.warnings.length,
        },
      }),
      output: [
        `State: ${next.state}`,
        `Next primitive: ${step.primitive}`,
        `Policy sequence: ${queue.join(" -> ")}`,
        `Why: ${step.description}`,
        `Hypothesis: ${next.hypothesis_id || "none"}`,
        `Signals: ${next.signals.join(", ") || "none"}`,
        `Runtime: actor_sessions=${runtime.actorSessions}, target_profiles=${runtime.targetProfiles}, network_actions=${runtime.networkActions}`,
        `Evidence nodes: ${next.evidence_nodes.length}`,
        event.rawType ? `Event: ${event.rawType} -> ${event.canonicalType || "none"}` : "Event: none",
        event.warnings.length > 0 ? `Event warnings: ${event.warnings.join("; ")}` : "Event warnings: none",
        `Evidence signals: supports=${policy.evidence.supports}, refutes=${policy.evidence.refutes}, observes=${policy.evidence.observes}`,
        `Budget: ${policy.budget.remaining_seconds}s remaining, ${policy.budget.primitive_budget} primitive(s)`,
      ].join("\n"),
    }
  },
})
