import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import type { Play, PlayRequirement } from "@/core/play/play"
import { PlayRegistry, PlayRunner, PlayArgError, PlayNotFoundError, isNormalizedStep } from "@/core/play"
import { Doctor } from "@/core/doctor"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"
import { Operation } from "@/core/operation"

const parameters = z.object({
  action: z.enum(["list", "status", "run"]).default("list"),
  id: z.string().optional(),
  args: z.record(z.string(), z.unknown()).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

function availabilityOf(result: ReturnType<typeof PlayRunner.run>) {
  const requiredSkipped = result.skipped.some((item) => {
    if (!isNormalizedStep(item.step)) return false
    return (item.step.requires ?? []).some((req) => req.missingAs === "required")
  })
  if (!requiredSkipped) return { available: true, degraded: result.skipped.length > 0 }
  if (result.trace.length > 0) return { available: true, degraded: true }
  return { available: false, degraded: false }
}

type CapsuleStatus = "ready" | "degraded" | "unavailable"

function collectRequirements(play: Play): PlayRequirement[] {
  const seen = new Set<string>()
  const out: PlayRequirement[] = []
  for (const step of play.steps) {
    if (!isNormalizedStep(step)) continue
    for (const req of step.requires ?? []) {
      const key = `${req.kind}:${req.id}:${req.missingAs}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push(req)
    }
  }
  return out
}

function summarizePlay(play: Play, environment: { binaries: Set<string>; runtimes: Record<string, boolean | undefined> }) {
  const requirements = collectRequirements(play)
  const missing_required = requirements
    .filter((req) => req.missingAs === "required")
    .filter((req) => (req.kind === "binary" ? !environment.binaries.has(req.id) : !environment.runtimes[req.id]))
    .map((req) => req.label)
  const missing_optional = requirements
    .filter((req) => req.missingAs === "optional")
    .filter((req) => (req.kind === "binary" ? !environment.binaries.has(req.id) : !environment.runtimes[req.id]))
    .map((req) => req.label)
  const required_args = play.args.filter((arg) => arg.required).map((arg) => arg.name)
  const status: CapsuleStatus =
    missing_required.length > 0 ? "unavailable" : missing_optional.length > 0 ? "degraded" : "ready"
  return {
    id: play.id,
    name: play.name,
    description: play.description,
    status,
    required_args,
    requirements,
    missing_required,
    missing_optional,
  }
}

function recommendedPlayIDs(kind?: string): string[] {
  if (kind === "pentest" || kind === "bughunt") return ["web-surface", "api-surface", "auth-surface", "network-surface"]
  if (kind === "appsec") return ["appsec-triage", "iac-triage", "container-surface", "cloud-posture", "binary-triage"]
  if (kind === "osint") return ["osint-target"]
  if (kind === "ctf" || kind === "hacking" || kind === "research") return ["ctf-warmup", "binary-triage"]
  return []
}

function capsuleFactStatus(status: CapsuleStatus) {
  return status === "unavailable" ? "stale" : "observed"
}

function capsuleStatus(input: { available: boolean; degraded?: boolean }): CapsuleStatus {
  if (!input.available) return "unavailable"
  if (input.degraded) return "degraded"
  return "ready"
}

function* persistCapsuleReadiness(input: {
  operation_slug: string
  ctx: Tool.Context
  source: string
  summary: string
  capsules: ReturnType<typeof summarizePlay>[]
}) {
  const eventID = yield* Cyber.appendLedger({
    operation_slug: input.operation_slug,
    kind: "fact.observed",
    source: input.source,
    session_id: input.ctx.sessionID,
    message_id: input.ctx.messageID,
    summary: input.summary,
    data: { count: input.capsules.length, capsules: input.capsules.map((capsule) => capsule.id) },
  }).pipe(Effect.catch(() => Effect.succeed("")))
  for (const capsule of input.capsules) {
    yield* Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "runbook",
      entity_key: capsule.id,
      fact_name: "capsule_readiness",
      value_json: capsule,
      writer_kind: "tool",
      status: capsuleFactStatus(capsule.status),
      confidence: 1000,
      source_event_id: eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  }
}

function* persistCapsuleRecommendations(input: {
  operation_slug: string
  operation_kind: string
  ctx: Tool.Context
  source: string
  capsules: ReturnType<typeof summarizePlay>[]
}) {
  const eventID = yield* Cyber.appendLedger({
    operation_slug: input.operation_slug,
    kind: "fact.observed",
    source: input.source,
    session_id: input.ctx.sessionID,
    message_id: input.ctx.messageID,
    summary: `runbook recommendations for ${input.operation_kind}`,
    data: {
      operation_kind: input.operation_kind,
      recommendations: input.capsules.map((capsule) => capsule.id),
    },
  }).pipe(Effect.catch(() => Effect.succeed("")))
  for (const capsule of input.capsules) {
    yield* Cyber.upsertFact({
      operation_slug: input.operation_slug,
      entity_kind: "runbook",
      entity_key: capsule.id,
      fact_name: "capsule_recommendation",
      value_json: {
        operation_kind: input.operation_kind,
        ...capsule,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      operation_slug: input.operation_slug,
      src_kind: "operation",
      src_key: input.operation_slug,
      relation: "recommends_runbook",
      dst_kind: "runbook",
      dst_key: capsule.id,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  }
}

export const RunbookTool = Tool.define<typeof parameters, Metadata, never>(
  "runbook",
  Effect.gen(function* () {
    return {
      description:
        "Run or inspect structured security runbooks. This is the semantic workflow surface for built-in plays and future domain capsules.",
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const report = yield* Doctor.probe(Instance.directory)
          const environment = {
            binaries: new Set(report.binaries.filter((item) => item.present).map((item) => item.name)),
            runtimes: { browser: report.browser.present } as Record<string, boolean | undefined>,
          }
          const workspace = Instance.directory
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))

          if (params.action === "list") {
            const plays = PlayRegistry.list().map((play) => summarizePlay(play, environment))
            if (active) {
              yield* persistCapsuleReadiness({
                operation_slug: active.slug,
                ctx,
                source: "runbook",
                summary: "runbook inventory refreshed",
                capsules: plays,
              })
            }
            return {
              title: "runbook · list",
              output:
                plays.length === 0
                  ? "No runbooks."
                  : plays
                      .map((play) => {
                        const missing = [...play.missing_required, ...play.missing_optional]
                        const args = play.required_args.length > 0 ? ` · args=${play.required_args.join(",")}` : ""
                        return `- ${play.id} · ${play.status}${args}${missing.length > 0 ? ` · missing ${missing.join(", ")}` : ""}`
                      })
                      .join("\n"),
              metadata: {
                action: "list",
                count: plays.length,
                ready: plays.filter((play) => play.status === "ready").length,
                degraded: plays.filter((play) => play.status === "degraded").length,
                unavailable: plays.filter((play) => play.status === "unavailable").length,
              },
            }
          }

          if (params.action === "status") {
            if (!params.id) {
              if (active) {
                const recommendations = recommendedPlayIDs(active.kind)
                  .map((id) => PlayRegistry.get(id))
                  .filter((item): item is Play => Boolean(item))
                  .map((play) => summarizePlay(play, environment))
                if (recommendations.length > 0) {
                  yield* persistCapsuleRecommendations({
                    operation_slug: active.slug,
                    operation_kind: active.kind,
                    ctx,
                    source: "runbook",
                    capsules: recommendations,
                  })
                  return {
                    title: `runbook: ${active.kind} recommendations`,
                    output: [
                      `Active operation kind: ${active.kind}`,
                      "Recommended runbooks:",
                      ...recommendations.map((item) => {
                        const missing = [...item.missing_required, ...item.missing_optional]
                        return `- ${item.id} · ${item.status}${missing.length > 0 ? ` · missing ${missing.join(", ")}` : ""}`
                      }),
                    ].join("\n"),
                    metadata: {
                      action: "status",
                      recommended: recommendations.map((item) => item.id),
                    },
                  }
                }
              }
              return {
                title: "runbook status",
                output: "Provide id when action = status.",
                metadata: { action: "status" },
              }
            }
            const play = PlayRegistry.get(params.id)
            if (!play) {
              return {
                title: `runbook: ${params.id} — error`,
                output: `Unknown runbook "${params.id}".`,
                metadata: { action: "status", id: params.id, available: false },
              }
            }
            const summary = summarizePlay(play, environment)
            if (active) {
              yield* persistCapsuleReadiness({
                operation_slug: active.slug,
                ctx,
                source: "runbook",
                summary: `runbook status ${summary.id}`,
                capsules: [summary],
              })
            }
            return {
              title: `runbook: ${summary.name}`,
              output: [
                `Runbook: ${summary.name} (${summary.id})`,
                `Status: ${summary.status}`,
                `Required args: ${summary.required_args.length > 0 ? summary.required_args.join(", ") : "-"}`,
                `Missing required: ${summary.missing_required.length > 0 ? summary.missing_required.join(", ") : "-"}`,
                `Missing optional: ${summary.missing_optional.length > 0 ? summary.missing_optional.join(", ") : "-"}`,
                "",
                summary.description,
              ].join("\n"),
              metadata: {
                action: "status",
                id: summary.id,
                status: summary.status,
                required_args: summary.required_args,
                missing_required: summary.missing_required,
                missing_optional: summary.missing_optional,
                available: summary.status !== "unavailable",
                degraded: summary.status === "degraded",
              },
            }
          }

          if (!params.id) {
            return {
              title: "runbook run",
              output: "Provide id when action = run.",
              metadata: { action: "run" },
            }
          }

          yield* ctx.ask({
            permission: "runbook",
            patterns: [params.id],
            always: [params.id],
            metadata: { id: params.id },
          })

          const outcome = (() => {
            try {
              return { ok: true as const, result: PlayRunner.run({ id: params.id!, args: params.args ?? {}, environment }) }
            } catch (error) {
              if (error instanceof PlayArgError || error instanceof PlayNotFoundError) {
                return { ok: false as const, message: error.message }
              }
              return { ok: false as const, message: `runbook failed: ${String(error)}` }
            }
          })()

          if (!outcome.ok) {
            return {
              title: `runbook: ${params.id} — error`,
              output: outcome.message,
              metadata: { action: "run", id: params.id, available: false },
            }
          }

          const availability = availabilityOf(outcome.result)
          if (active) {
            yield* Effect.promise(() =>
              Operation.writeWorkflow(workspace, active.slug, {
                kind: "runbook",
                id: outcome.result.play.id,
                payload: {
                  args: params.args ?? {},
                  available: availability.available,
                  degraded: availability.degraded ?? false,
                  trace: outcome.result.trace,
                  skipped: outcome.result.skipped.map((item) => ({ reason: item.reason })),
                },
              }),
            ).pipe(Effect.catch(() => Effect.succeed(undefined)))
            yield* Effect.promise(() =>
              Operation.setActiveWorkflow(workspace, active.slug, {
                kind: "runbook",
                id: outcome.result.play.id,
              }),
            ).pipe(Effect.catch(() => Effect.succeed(undefined)))
            yield* Cyber.upsertWorkflowTrace({
              operation_slug: active.slug,
              workflow_kind: "runbook",
              workflow_id: outcome.result.play.id,
              fact_name: "execution_plan",
              args: params.args ?? {},
              trace: outcome.result.trace.map((item) => ({ ...item })),
              skipped: outcome.result.skipped.map((item) => ({ reason: item.reason })),
              available: availability.available,
              degraded: availability.degraded ?? false,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              source: "runbook",
              summary: `runbook ${outcome.result.play.id}`,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: active.slug,
              entity_kind: "runbook",
              entity_key: outcome.result.play.id,
              fact_name: "capsule_readiness",
              value_json: {
                id: outcome.result.play.id,
                name: outcome.result.play.name,
                description: outcome.result.play.description,
                status: capsuleStatus(availability),
                available: availability.available,
                degraded: availability.degraded ?? false,
                required_args: outcome.result.play.args.filter((arg) => arg.required).map((arg) => arg.name),
              },
              writer_kind: "tool",
              status: capsuleFactStatus(capsuleStatus(availability)),
              confidence: 1000,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: active.slug,
              entity_kind: "runbook",
              entity_key: outcome.result.play.id,
              fact_name: "capsule_execution",
              value_json: {
                id: outcome.result.play.id,
                name: outcome.result.play.name,
                description: outcome.result.play.description,
                status: capsuleStatus(availability),
                invoked_via: "runbook",
                args: params.args ?? {},
                steps: outcome.result.trace.length,
                skipped: outcome.result.skipped.length,
                available: availability.available,
                degraded: availability.degraded ?? false,
              },
              writer_kind: "tool",
              status: capsuleFactStatus(capsuleStatus(availability)),
              confidence: 1000,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return {
            title: `runbook: ${outcome.result.play.name}`,
            output: PlayRunner.format(outcome.result),
            metadata: {
              action: "run",
              id: outcome.result.play.id,
              steps: outcome.result.trace.length,
              skipped: outcome.result.skipped.length,
              available: availability.available,
              degraded: availability.degraded,
            },
          }
        }),
    }
  }),
)
