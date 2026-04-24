import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./container-surface.txt"
import { runProcess } from "./process"

const parameters = z.object({
  image: z
    .string()
    .min(1)
    .describe(
      "fully-qualified container image reference (e.g., nginx:latest, ghcr.io/org/app:sha-abc123)",
    ),
  mode: z
    .enum(["quick", "full"])
    .default("quick")
    .describe(
      "scan depth: quick focuses on HIGH and CRITICAL vulnerabilities only; full scans all severities and includes secrets",
    ),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  available: boolean
  adapter: "trivy"
  target_kind: "image"
  image: string
  mode: "quick" | "full"
  command?: string[]
  exit_code?: number
}

export const _deps = {
  which: (name: string) => Bun.which(name),
  run: (argv: string[]) => Effect.promise(() => runProcess(argv)),
}

function buildCommand(params: Params) {
  if (params.mode === "quick") {
    return [
      "trivy",
      "image",
      "--format",
      "json",
      "--scanners",
      "vuln",
      "--severity",
      "HIGH,CRITICAL",
      params.image,
    ]
  }

  return [
    "trivy",
    "image",
    "--format",
    "json",
    "--scanners",
    "vuln,secret",
    params.image,
  ]
}

export const ContainerSurfaceTool = Tool.define<typeof parameters, Metadata, never>(
  "container_surface",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          if (!_deps.which("trivy")) {
            return {
              title: "container surface · adapter unavailable",
              output: 'Required adapter "trivy" is not installed. Install it to run container-surface.',
              metadata: {
                available: false,
                adapter: "trivy",
                target_kind: "image",
                image: params.image,
                mode: params.mode,
              } satisfies Metadata,
            }
          }

          const command = buildCommand(params)
          yield* ctx.ask({
            permission: "container_surface",
            patterns: [`${params.mode}:${params.image}`],
            always: [],
            metadata: {
              available: true,
              adapter: "trivy",
              target_kind: "image",
              image: params.image,
              mode: params.mode,
              command,
            },
          })

          const result = yield* _deps.run(command)
          if (result.exitCode !== 0) {
            throw new Error(
              `trivy exited with code ${result.exitCode}${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
            )
          }

          return {
            title: "container surface · trivy",
            output: result.stdout || "trivy completed with no stdout output",
            metadata: {
              available: true,
              adapter: "trivy",
              target_kind: "image",
              image: params.image,
              mode: params.mode,
              command,
              exit_code: result.exitCode,
            } satisfies Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
