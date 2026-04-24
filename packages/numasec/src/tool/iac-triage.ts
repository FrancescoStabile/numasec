import { statSync } from "node:fs"
import { resolve } from "node:path"
import z from "zod"
import { Effect } from "effect"
import { InstanceState } from "@/effect"
import * as Tool from "./tool"
import DESCRIPTION from "./iac-triage.txt"
import { runProcess } from "./process"

const parameters = z.object({
  path: z
    .string()
    .min(1)
    .describe("local IaC file or directory path to inspect (e.g., ./infra, ./main.tf)"),
  mode: z
    .enum(["quick", "full"])
    .default("quick")
    .describe("scan depth: quick uses inferred frameworks; full forces framework=all for broader local coverage"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  available: boolean
  adapter: "checkov"
  target_kind: "path"
  path: string
  mode: "quick" | "full"
  command?: string[]
  exit_code?: number
}

export const _deps = {
  which: (name: string) => Bun.which(name),
  run: (argv: string[]) => Effect.promise(() => runProcess(argv)),
  isDirectory: (path: string) => {
    try {
      return statSync(path).isDirectory()
    } catch {
      return false
    }
  },
}

function buildCommand(params: Params, directory: string) {
  const absolutePath = resolve(directory, params.path)
  const target = _deps.isDirectory(absolutePath) ? ["-d", absolutePath] : ["-f", absolutePath]

  if (params.mode === "quick") {
    return ["checkov", ...target, "-o", "json", "--quiet"]
  }

  return ["checkov", ...target, "-o", "json", "--quiet", "--framework", "all"]
}

export const IacTriageTool = Tool.define<typeof parameters, Metadata, never>(
  "iac_triage",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          if (!_deps.which("checkov")) {
            return {
              title: "iac triage · adapter unavailable",
              output: 'Required adapter "checkov" is not installed. Install it to run iac-triage.',
              metadata: {
                available: false,
                adapter: "checkov",
                target_kind: "path",
                path: params.path,
                mode: params.mode,
              } satisfies Metadata,
            }
          }

          const ins = yield* InstanceState.context
          const command = buildCommand(params, ins.directory)
          yield* ctx.ask({
            permission: "iac_triage",
            patterns: [`${params.mode}:${params.path}`],
            always: [],
            metadata: {
              available: true,
              adapter: "checkov",
              target_kind: "path",
              path: params.path,
              mode: params.mode,
              command,
            },
          })
          const result = yield* _deps.run(command)
          if (result.exitCode !== 0 && result.exitCode !== 1) {
            throw new Error(
              `checkov exited with code ${result.exitCode}${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
            )
          }

          return {
            title: "iac triage · checkov",
            output: result.stdout || "checkov completed with no stdout output",
            metadata: {
              available: true,
              adapter: "checkov",
              target_kind: "path",
              path: params.path,
              mode: params.mode,
              command,
              exit_code: result.exitCode,
            } satisfies Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
