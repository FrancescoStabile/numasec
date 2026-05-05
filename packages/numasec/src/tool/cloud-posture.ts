import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./cloud-posture.txt"
import { runProcess } from "./process"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

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
  profile?: string
  region?: string
  command?: string[]
  exit_code?: number
}

function summarize(output: string) {
  const lines = output
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
  const findings = lines
    .filter((line) => /critical|high|medium|low|fail|failed|pass|passed/i.test(line))
    .slice(0, 100)
  return {
    line_count: lines.length,
    finding_count: findings.length,
    findings,
    parse_mode: "line_summary",
  }
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
                profile: params.profile,
                region: params.region,
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

          const toolResult = {
            title: "cloud posture · prowler",
            output: result.stdout || "prowler completed with no stdout output",
            metadata: {
              available: true,
              adapter: "prowler",
              provider: "aws",
              profile: params.profile,
              region: params.region,
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
                    mime: "text/plain",
                    ext: "txt",
                    label: `cloud posture aws ${params.profile ?? "default"} ${params.region ?? "all"}`,
                    source: "cloud_posture",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const accountKey = `${params.provider}:${params.profile ?? "default"}:${params.region ?? "all"}`
          const summary = summarize(toolResult.output)
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "cloud_posture",
            summary: `cloud posture ${accountKey}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              provider: params.provider,
              profile: params.profile ?? null,
              region: params.region ?? null,
              mode: params.mode,
              adapter: "prowler",
              line_count: summary.line_count,
              finding_count: summary.finding_count,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "cloud_account",
            entity_key: accountKey,
            fact_name: "prowler_summary",
            value_json: summary,
            writer_kind: "tool",
            status: "observed",
            confidence: 850,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          for (const line of summary.findings) {
            const entityKey = `${accountKey}:${line.slice(0, 120)}`
            yield* Cyber.upsertFact({
              entity_kind: "finding_candidate",
              entity_key: entityKey,
              fact_name: "cloud_posture_signal",
              value_json: {
                provider: params.provider,
                profile: params.profile,
                region: params.region,
                mode: params.mode,
                line,
              },
              writer_kind: "parser",
              status: "candidate",
              confidence: 500,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              src_kind: "cloud_account",
              src_key: accountKey,
              relation: "has_candidate",
              dst_kind: "finding_candidate",
              dst_key: entityKey,
              writer_kind: "parser",
              status: "candidate",
              confidence: 500,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return toolResult
        }).pipe(Effect.orDie),
    }
  }),
)
