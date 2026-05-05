import { resolve } from "node:path"
import z from "zod"
import { Effect } from "effect"
import { InstanceState } from "@/effect"
import * as Tool from "./tool"
import DESCRIPTION from "./binary-triage.txt"
import { runProcess } from "./process"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

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

function summarize(output: string) {
  try {
    const parsed = JSON.parse(output) as Array<{
      name?: string
      file?: string
      checks?: Record<string, string>
    }> | {
      name?: string
      file?: string
      checks?: Record<string, string>
    }
    const first = Array.isArray(parsed) ? parsed[0] : parsed
    if (!first || typeof first !== "object") return undefined
    const checks = first.checks ?? {}
    const findings = Object.entries(checks)
      .filter(([, value]) => /no\b|disabled|missing|partial/i.test(value))
      .slice(0, 20)
      .map(([key, value]) => ({ key, value }))
    return {
      name: first.name,
      file: first.file,
      checks,
      finding_count: findings.length,
      findings,
    }
  } catch {
    return undefined
  }
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

          const toolResult = {
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
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, toolResult.output, {
                    mime: "application/json",
                    ext: "json",
                    label: `binary triage ${params.path}`,
                    source: "binary_triage",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const summary = summarize(toolResult.output)
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "binary_triage",
            summary: `binary triage ${params.path}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              path: params.path,
              checks: summary ? Object.keys(summary.checks).length : null,
              finding_count: summary?.finding_count ?? null,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "binary_artifact",
            entity_key: params.path,
            fact_name: "checksec_summary",
            value_json: summary ?? { parse_error: true },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          for (const item of summary?.findings ?? []) {
            const entityKey = `${params.path}:${item.key}`
            yield* Cyber.upsertFact({
              entity_kind: "finding_candidate",
              entity_key: entityKey,
              fact_name: "binary_hardening_gap",
              value_json: item,
              writer_kind: "parser",
              status: "candidate",
              confidence: 700,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              src_kind: "binary_artifact",
              src_key: params.path,
              relation: "has_candidate",
              dst_kind: "finding_candidate",
              dst_key: entityKey,
              writer_kind: "parser",
              status: "candidate",
              confidence: 700,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return toolResult
        }).pipe(Effect.orDie),
    }
  }),
)
