import z from "zod"
import { Effect } from "effect"
import { HttpClient } from "effect/unstable/http"
import * as Tool from "./tool"
import DESCRIPTION from "./knowledge.txt"
import { CVETool } from "./cve"
import { WebSearchTool } from "./websearch"
import { Agent } from "@/agent/agent"
import * as Truncate from "./truncate"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z
  .object({
    source: z.enum(["cve", "web"]).describe("knowledge source to query"),
    query: z.string().min(1).describe("CVE id, vendor/product, keyword, or web search query"),
    severity: z.enum(["low", "medium", "high", "critical"]).optional().describe("optional severity floor"),
    limit: z.coerce.number().int().min(1).max(50).optional().describe("max CVE results to return"),
    numResults: z.number().optional().describe("number of web search results to return"),
    livecrawl: z.enum(["fallback", "preferred"]).optional().describe("live crawl preference"),
    type: z.enum(["auto", "fast", "deep"]).optional().describe("search depth"),
    contextMaxCharacters: z.number().optional().describe("max web context size"),
  })
  .superRefine((value, issue) => {
    if (value.source === "web" && value.severity) {
      issue.addIssue({
        code: "custom",
        path: ["severity"],
        message: "severity is only valid when source=cve",
      })
    }

    if (value.source === "web" && value.limit != null) {
      issue.addIssue({
        code: "custom",
        path: ["limit"],
        message: "limit is only valid when source=cve",
      })
    }

    if (value.source === "cve" && value.numResults != null) {
      issue.addIssue({
        code: "custom",
        path: ["numResults"],
        message: "numResults is only valid when source=web",
      })
    }

    if (value.source === "cve" && value.livecrawl) {
      issue.addIssue({
        code: "custom",
        path: ["livecrawl"],
        message: "livecrawl is only valid when source=web",
      })
    }

    if (value.source === "cve" && value.type) {
      issue.addIssue({
        code: "custom",
        path: ["type"],
        message: "type is only valid when source=web",
      })
    }

    if (value.source === "cve" && value.contextMaxCharacters != null) {
      issue.addIssue({
        code: "custom",
        path: ["contextMaxCharacters"],
        message: "contextMaxCharacters is only valid when source=web",
      })
    }
  })

type Params = z.infer<typeof parameters>
type Metadata = {
  surface: "knowledge"
  delegated_to: "cve" | "websearch"
  source: Params["source"]
  available?: boolean
  [key: string]: unknown
}

export const KnowledgeTool = Tool.define<
  typeof parameters,
  Metadata,
  Agent.Service | Truncate.Service | HttpClient.HttpClient
>(
  "knowledge",
  Effect.gen(function* () {
    const cve = yield* CVETool
    const websearch = yield* WebSearchTool

    const cveTool = yield* Tool.init(cve)
    const webTool = yield* Tool.init(websearch)

    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          if (params.source === "cve") {
            const result = yield* cveTool.execute(
              {
                query: params.query,
                severity: params.severity,
                limit: params.limit,
              },
              ctx as any,
            )
            const parsed = (() => {
              try {
                return JSON.parse(result.output) as {
                  available?: boolean
                  returned?: number
                  total_indexed?: number
                  query?: string
                  severity_floor?: string | null
                  results?: Array<{ id?: string; severity?: string; summary?: string }>
                }
              } catch {
                return undefined
              }
            })()
            const eventID = yield* Cyber.appendLedger({
              operation_slug: slug,
              kind: "fact.observed",
              source: "knowledge",
              summary: `cve knowledge query ${params.query}`,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              data: {
                query: params.query,
                severity: params.severity ?? null,
                limit: params.limit ?? null,
                returned: parsed?.returned ?? result.metadata?.returned ?? null,
              },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "knowledge_query",
              entity_key: `cve:${params.query}`,
              fact_name: "cve_result",
              value_json: {
                query: params.query,
                severity: params.severity ?? null,
                limit: params.limit ?? null,
                available: result.metadata?.available ?? parsed?.available ?? true,
                returned: parsed?.returned ?? result.metadata?.returned ?? null,
                total_indexed: parsed?.total_indexed ?? result.metadata?.total_indexed ?? null,
                results:
                  parsed?.results?.map((item) => ({
                    id: item.id,
                    severity: item.severity,
                    summary: item.summary,
                  })) ?? [],
              },
              writer_kind: "tool",
              status: result.metadata?.available === false ? "stale" : "observed",
              confidence: 900,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            return {
              ...result,
              metadata: {
                ...result.metadata,
                surface: "knowledge",
                delegated_to: "cve",
                source: "cve",
              } satisfies Metadata,
            }
          }

          const result = yield* webTool.execute(
            {
              query: params.query,
              numResults: params.numResults,
              livecrawl: params.livecrawl,
              type: params.type,
              contextMaxCharacters: params.contextMaxCharacters,
            },
            ctx as any,
          )
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, result.output, {
                    mime: "text/plain",
                    ext: "txt",
                    label: `knowledge web ${params.query}`,
                    source: "knowledge",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            operation_slug: slug,
            kind: "fact.observed",
            source: "knowledge",
            summary: `web knowledge query ${params.query}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              query: params.query,
              num_results: params.numResults ?? null,
              livecrawl: params.livecrawl ?? "fallback",
              type: params.type ?? "auto",
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "knowledge_query",
            entity_key: `web:${params.query}`,
            fact_name: "web_result",
            value_json: {
              query: params.query,
              output: result.output,
              num_results: params.numResults ?? null,
              livecrawl: params.livecrawl ?? "fallback",
              type: params.type ?? "auto",
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 700,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          return {
            ...result,
            metadata: {
              ...result.metadata,
              surface: "knowledge",
              delegated_to: "websearch",
              source: "web",
            } satisfies Metadata,
          }
        }),
    }
  }),
)
