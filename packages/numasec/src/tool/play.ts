import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./play.txt"
import { PlayRegistry, PlayRunner, PlayNotFoundError, PlayArgError, isNormalizedStep } from "../core/play"
import { Doctor } from "../core/doctor"

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

          const report = yield* _deps.probe(process.cwd())
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
