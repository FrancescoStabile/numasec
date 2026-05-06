import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./container-surface.txt"
import { runProcess } from "./process"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { autoEnrichKnowledge } from "@/core/knowledge"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

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

function summarize(output: string) {
  try {
    const parsed = JSON.parse(output) as {
      Results?: Array<{
        Type?: string
        Target?: string
        Vulnerabilities?: Array<{ Severity?: string; VulnerabilityID?: string; PkgName?: string }>
        Secrets?: Array<{ RuleID?: string; Title?: string; Severity?: string }>
      }>
    }
    const findings: Array<Record<string, unknown>> = []
    let vulnerabilities = 0
    let secrets = 0
    let critical = 0
    let high = 0
    for (const result of parsed.Results ?? []) {
      for (const vuln of result.Vulnerabilities ?? []) {
        vulnerabilities += 1
        if (vuln.Severity === "CRITICAL") critical += 1
        if (vuln.Severity === "HIGH") high += 1
        if (findings.length < 100) {
          findings.push({
            kind: "vulnerability",
            type: result.Type,
            target: result.Target,
            id: vuln.VulnerabilityID,
            package: vuln.PkgName,
            severity: vuln.Severity,
          })
        }
      }
      for (const secret of result.Secrets ?? []) {
        secrets += 1
        if (findings.length < 100) {
          findings.push({
            kind: "secret",
            type: result.Type,
            target: result.Target,
            id: secret.RuleID,
            title: secret.Title,
            severity: secret.Severity,
          })
        }
      }
    }
    return {
      result_count: parsed.Results?.length ?? 0,
      vulnerabilities,
      secrets,
      critical,
      high,
      findings,
    }
  } catch {
    return undefined
  }
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

          const toolResult = {
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
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, toolResult.output, {
                    mime: "application/json",
                    ext: "json",
                    label: `container surface ${params.image}`,
                    source: "container_surface",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const summary = summarize(toolResult.output)
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "container_surface",
            summary: `container surface ${params.image}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              image: params.image,
              mode: params.mode,
              adapter: "trivy",
              vulnerabilities: summary?.vulnerabilities ?? null,
              secrets: summary?.secrets ?? null,
              critical: summary?.critical ?? null,
              high: summary?.high ?? null,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "container_image",
            entity_key: params.image,
            fact_name: "trivy_summary",
            value_json: summary ?? { parse_error: true },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          for (const item of summary?.findings ?? []) {
            const findingID =
              typeof item.id === "string" ? item.id : typeof item.title === "string" ? item.title : undefined
            if (!findingID) continue
            const entityKey = `${params.image}:${findingID}`
            yield* Cyber.upsertFact({
              entity_kind: "finding_candidate",
              entity_key: entityKey,
              fact_name: item.kind === "secret" ? "container_secret" : "container_vulnerability",
              value_json: item,
              writer_kind: "parser",
              status: "candidate",
              confidence: 750,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              src_kind: "container_image",
              src_key: params.image,
              relation: "has_candidate",
              dst_kind: "finding_candidate",
              dst_key: entityKey,
              writer_kind: "parser",
              status: "candidate",
              confidence: 750,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          yield* autoEnrichKnowledge({
            workspace,
            operation_slug: slug,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            source: "container_surface",
            items: (summary?.findings ?? [])
              .filter((item) => item.kind === "vulnerability" && typeof item.id === "string")
              .slice(0, 6)
              .map((item) => ({
                intent: "vuln_intel" as const,
                action: "prioritize" as const,
                query: String(item.id),
                observed_refs: [`container_image:${params.image}`],
                limit: 5,
              })),
          }).pipe(Effect.catch(() => Effect.succeed(undefined)))
          return toolResult
        }).pipe(Effect.orDie),
    }
  }),
)
