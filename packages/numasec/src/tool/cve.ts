import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./cve.txt"
import { KnowledgeBroker, persistKnowledgeResult, workspaceKnowledgeCache } from "@/core/knowledge"
import type { KnowledgeResult } from "@/core/knowledge"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z.object({
  query: z.string().min(1).describe("CVE id, vendor/product name, package spec, or keyword. Uses live no-key vulnerability intelligence sources when available."),
  severity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Compatibility option. Results may include this as advisory context but filtering is source-dependent."),
  limit: z.coerce.number().int().min(1).max(50).optional().describe("Max results/cards to return (default 10, max 50)."),
})

type Params = z.infer<typeof parameters>

type Metadata = {
  available: boolean
  returned?: number
  mode: "live"
  delegated_to: "knowledge"
  degraded?: boolean
}

function output(result: KnowledgeResult) {
  return JSON.stringify(
    {
      operator_summary: result.operator_summary ?? result.summary,
      request: result.request,
      cards_compact: result.cards_compact ?? [],
      degraded: result.degraded,
      errors: result.errors,
      full_result_persisted_as_evidence: true,
    },
    null,
    2,
  )
}

export const CVETool = Tool.define<typeof parameters, Metadata, never>(
  "cve",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "cve",
            patterns: [params.query],
            always: ["*"],
            metadata: { query: params.query, severity: params.severity ?? null },
          })

          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const request = KnowledgeBroker.normalize({
            source: "cve",
            query: params.query,
            limit: params.limit,
            mode: "live",
          })
          const result = yield* Effect.promise(() => KnowledgeBroker.query(request, workspaceKnowledgeCache(workspace)))
          yield* persistKnowledgeResult({
            workspace,
            operation_slug: slug,
            result,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            source: "cve",
            fact_name: "cve_result",
            legacy_query_key: `cve:${params.query}`,
          })

          return {
            title: `cve: ${result.cards.length} intelligence card${result.cards.length === 1 ? "" : "s"} for "${params.query}"`,
            output: output(result),
            metadata: {
              available: !result.degraded,
              returned: result.cards.length,
              mode: "live" as const,
              delegated_to: "knowledge" as const,
              degraded: result.degraded,
            },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
