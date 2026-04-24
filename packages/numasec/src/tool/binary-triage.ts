import { resolve } from "node:path"
import z from "zod"
import { Effect } from "effect"
import { InstanceState } from "@/effect"
import * as Tool from "./tool"
import DESCRIPTION from "./binary-triage.txt"
import { runProcess } from "./process"

const parameters = z.object({
  path: z
    .string()
    .min(1)
    .describe("local binary file path to inspect (e.g., ./chal.bin, ./dist/app)"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  available: boolean
  adapter: "checksec"
  target_kind: "path"
  path: string
  command?: string[]
  exit_code?: number
}

export const _deps = {
  which: (name: string) => Bun.which(name),
  run: (argv: string[]) => Effect.promise(() => runProcess(argv)),
}

function buildCommand(params: Params, directory: string) {
  const absolutePath = resolve(directory, params.path)
  return ["checksec", "file", absolutePath, "--output", "json"]
}

export const BinaryTriageTool = Tool.define<typeof parameters, Metadata, never>(
  "binary_triage",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          if (!_deps.which("checksec")) {
            return {
              title: "binary triage · adapter unavailable",
              output: 'Required adapter "checksec" is not installed. Install it to run binary-triage.',
              metadata: {
                available: false,
                adapter: "checksec",
                target_kind: "path",
                path: params.path,
              } satisfies Metadata,
            }
          }

          const ins = yield* InstanceState.context
          const command = buildCommand(params, ins.directory)
          yield* ctx.ask({
            permission: "binary_triage",
            patterns: [params.path],
            always: [],
            metadata: {
              available: true,
              adapter: "checksec",
              target_kind: "path",
              path: params.path,
              command,
            },
          })

          const result = yield* _deps.run(command)
          if (result.exitCode !== 0) {
            throw new Error(
              `checksec exited with code ${result.exitCode}${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
            )
          }

          return {
            title: "binary triage · checksec",
            output: result.stdout || "checksec completed with no stdout output",
            metadata: {
              available: true,
              adapter: "checksec",
              target_kind: "path",
              path: params.path,
              command,
              exit_code: result.exitCode,
            } satisfies Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
