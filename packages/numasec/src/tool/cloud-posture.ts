import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./cloud-posture.txt"
import { runProcess } from "./process"

const parameters = z.object({
  provider: z.literal("aws").describe("cloud provider for this slice"),
  mode: z.enum(["quick", "full"]).default("quick").describe("scan depth"),
  profile: z.string().optional().describe("optional AWS profile name"),
  region: z.string().optional().describe("optional AWS region"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  available: boolean
  adapter: "prowler"
  provider: "aws"
  command?: string[]
  exit_code?: number
}

export const _deps = {
  which: (name: string) => Bun.which(name),
  run: (argv: string[]) => Effect.promise(() => runProcess(argv)),
}

function buildCommand(params: Params) {
  return [
    "prowler",
    "aws",
    ...(params.mode === "quick" ? ["--quick"] : []),
    ...(params.profile ? ["--profile", params.profile] : []),
    ...(params.region ? ["--region", params.region] : []),
  ]
}

export const CloudPostureTool = Tool.define<typeof parameters, Metadata, never>(
  "cloud_posture",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          if (!_deps.which("prowler")) {
            return {
              title: "cloud posture · adapter unavailable",
              output: 'Required adapter "prowler" is not installed. Install it to run cloud-posture.',
              metadata: {
                available: false,
                adapter: "prowler",
                provider: "aws",
              } satisfies Metadata,
            }
          }

          const command = buildCommand(params)
          yield* ctx.ask({
            permission: "cloud_posture",
            patterns: [`${params.provider}:${params.mode}:${params.profile ?? "default"}:${params.region ?? "all"}`],
            always: [],
            metadata: {
              available: true,
              adapter: "prowler",
              provider: params.provider,
              command,
            },
          })

          const result = yield* _deps.run(command)
          if (result.exitCode !== 0) {
            throw new Error(
              `prowler exited with code ${result.exitCode}${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
            )
          }

          return {
            title: "cloud posture · prowler",
            output: result.stdout || "prowler completed with no stdout output",
            metadata: {
              available: true,
              adapter: "prowler",
              provider: "aws",
              command,
              exit_code: result.exitCode,
            } satisfies Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
