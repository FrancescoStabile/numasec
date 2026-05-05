import { statSync } from "node:fs"
import { resolve } from "node:path"
import z from "zod"
import { Effect } from "effect"
import { InstanceState } from "@/effect"
import * as Tool from "./tool"
import DESCRIPTION from "./iac-triage.txt"
import { runProcess } from "./process"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"

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

function summarize(output: string) {
  try {
    const parsed = JSON.parse(output) as {
      summary?: { passed?: number; failed?: number; skipped?: number }
      results?: {
        failed_checks?: Array<{ check_id?: string; check_name?: string; resource?: string; severity?: string }>
      }
    }
    return {
      passed: parsed.summary?.passed ?? 0,
      failed: parsed.summary?.failed ?? parsed.results?.failed_checks?.length ?? 0,
      skipped: parsed.summary?.skipped ?? 0,
      failed_checks: parsed.results?.failed_checks ?? [],
    }
  } catch {
    return undefined
  }
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

          const toolResult = {
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

          const workspace = ins.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, toolResult.output, {
                    mime: "application/json",
                    ext: "json",
                    label: `iac triage ${params.path}`,
                    source: "iac_triage",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const summary = summarize(toolResult.output)
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "iac_triage",
            summary: `iac triage ${params.path}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              path: params.path,
              mode: params.mode,
              adapter: "checkov",
              failed: summary?.failed ?? null,
              passed: summary?.passed ?? null,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "iac_target",
            entity_key: params.path,
            fact_name: "checkov_summary",
            value_json: summary ?? { parse_error: true },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          for (const item of summary?.failed_checks.slice(0, 100) ?? []) {
            if (!item.check_id) continue
            yield* Cyber.upsertFact({
              entity_kind: "finding_candidate",
              entity_key: `${params.path}:${item.check_id}`,
              fact_name: "iac_misconfig",
              value_json: item,
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
