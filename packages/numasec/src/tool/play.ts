import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./play.txt"
import { PlayRegistry, PlayRunner, PlayNotFoundError, PlayArgError, isNormalizedStep } from "../core/play"
import { Doctor } from "../core/doctor"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"
import { Operation } from "@/core/operation"

// Mutable so tests can inject a controlled probe without patching module namespaces.
export const _deps = { probe: Doctor.probe }

const parameters = z.object({
  id: z
    .string()
    .describe(
      "play id (e.g. web-surface, network-surface, appsec-triage, osint-target, ctf-warmup, api-surface, auth-surface, cloud-posture, container-surface, iac-triage, binary-triage)",
    ),
  args: z.record(z.string(), z.unknown()).optional().describe("play-specific arguments"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  play?: string
  steps: number
  skipped: number
  available: boolean
  degraded?: boolean
  reason?: string
}

function availabilityOf(result: ReturnType<typeof PlayRunner.run>) {
  const requiredSkipped = result.skipped.some((item) => {
    if (!isNormalizedStep(item.step)) return false
    return (item.step.requires ?? []).some((req) => req.missingAs === "required")
  })

  if (!requiredSkipped) return { available: true, degraded: result.skipped.length > 0 }
  // Future-proofed: if required capability was skipped but other steps ran, report available + degraded.
  if (result.trace.length > 0) return { available: true, degraded: true }
  return { available: false, degraded: false }
}

function capsuleStatus(input: { available: boolean; degraded?: boolean }) {
  if (!input.available) return "unavailable"
  if (input.degraded) return "degraded"
  return "ready"
}

export const PlayTool = Tool.define<typeof parameters, Metadata, never>(
  "play",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "play",
            patterns: [params.id],
            always: [params.id],
            metadata: { id: params.id },
          })

          const known = PlayRegistry.get(params.id)
          if (!known) {
            const ids = PlayRegistry.ids().join(", ")
            return {
              title: `play: unknown id "${params.id}"`,
              output: `Unknown play "${params.id}". Available: ${ids || "<none>"}.`,
              metadata: { steps: 0, skipped: 0, available: false, reason: "unknown-id" },
            }
          }

          const report = yield* _deps.probe(Instance.directory)
          const environment = {
            binaries: new Set(report.binaries.filter((b) => b.present).map((b) => b.name)),
            runtimes: { browser: report.browser.present },
          }

          const outcome = ((): { ok: true; result: ReturnType<typeof PlayRunner.run> } | { ok: false; message: string } => {
            try {
              return { ok: true, result: PlayRunner.run({ id: params.id, args: params.args ?? {}, environment }) }
            } catch (error) {
              if (error instanceof PlayArgError || error instanceof PlayNotFoundError) {
                return { ok: false, message: error.message }
              }
              return { ok: false, message: `play runner failed: ${String(error)}` }
            }
          })()

          if (!outcome.ok) {
            return {
              title: `play: ${params.id} — error`,
              output: outcome.message,
              metadata: {
                play: params.id,
                steps: 0,
                skipped: 0,
                available: false,
                reason: outcome.message,
              },
            }
          }

          const result = outcome.result
          const availability = availabilityOf(result)
          const workspace = Instance.directory
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))
          if (active) {
            yield* Effect.promise(() =>
              Operation.writeWorkflow(workspace, active.slug, {
                kind: "play",
                id: result.play.id,
                payload: {
                  args: params.args ?? {},
                  available: availability.available,
                  degraded: availability.degraded ?? false,
                  trace: result.trace,
                  skipped: result.skipped.map((item) => ({ reason: item.reason })),
                },
              }),
            ).pipe(Effect.catch(() => Effect.succeed(undefined)))
            yield* Effect.promise(() =>
              Operation.setActiveWorkflow(workspace, active.slug, {
                kind: "play",
                id: result.play.id,
              }),
            ).pipe(Effect.catch(() => Effect.succeed(undefined)))
            yield* Cyber.upsertWorkflowTrace({
              operation_slug: active.slug,
              workflow_kind: "play",
              workflow_id: result.play.id,
              fact_name: "execution_trace",
              args: params.args ?? {},
              trace: result.trace.map((item) => ({ ...item })),
              skipped: result.skipped.map((item) => ({ reason: item.reason })),
              available: availability.available,
              degraded: availability.degraded ?? false,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              source: "play",
              summary: `play ${result.play.id}`,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: active.slug,
              entity_kind: "play",
              entity_key: result.play.id,
              fact_name: "capsule_readiness",
              value_json: {
                id: result.play.id,
                name: result.play.name,
                description: result.play.description,
                status: capsuleStatus(availability),
                available: availability.available,
                degraded: availability.degraded ?? false,
                required_args: result.play.args.filter((arg) => arg.required).map((arg) => arg.name),
              },
              writer_kind: "tool",
              status: availability.available ? "observed" : "stale",
              confidence: 1000,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: active.slug,
              entity_kind: "play",
              entity_key: result.play.id,
              fact_name: "capsule_execution",
              value_json: {
                id: result.play.id,
                name: result.play.name,
                description: result.play.description,
                status: capsuleStatus(availability),
                invoked_via: "play",
                args: params.args ?? {},
                steps: result.trace.length,
                skipped: result.skipped.length,
                available: availability.available,
                degraded: availability.degraded ?? false,
              },
              writer_kind: "tool",
              status: availability.available ? "observed" : "stale",
              confidence: 1000,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return {
            title: `play: ${result.play.name}`,
            output: PlayRunner.format(result),
            metadata: {
              play: result.play.id,
              steps: result.trace.length,
              skipped: result.skipped.length,
              available: availability.available,
              degraded: availability.degraded,
            },
          }
        }),
    }
  }),
)
