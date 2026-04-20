import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./play.txt"
import { PlayRegistry, PlayRunner, PlayNotFoundError, PlayArgError } from "../core/play"

const parameters = z.object({
  id: z.string().describe("play id (e.g. web-surface, network-surface, appsec-triage, osint-target, ctf-warmup)"),
  args: z.record(z.string(), z.unknown()).optional().describe("play-specific arguments"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  play?: string
  steps: number
  skipped: number
  available: boolean
  reason?: string
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

          const outcome = ((): { ok: true; result: ReturnType<typeof PlayRunner.run> } | { ok: false; message: string } => {
            try {
              return { ok: true, result: PlayRunner.run({ id: params.id, args: params.args ?? {} }) }
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
          return {
            title: `play: ${result.play.name}`,
            output: PlayRunner.format(result),
            metadata: {
              play: result.play.id,
              steps: result.trace.length,
              skipped: result.skipped.length,
              available: true,
            },
          }
        }),
    }
  }),
)
