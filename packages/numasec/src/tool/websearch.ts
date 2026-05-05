import z from "zod"
import { Effect } from "effect"
import { HttpClient } from "effect/unstable/http"
import * as Tool from "./tool"
import * as McpExa from "./mcp-exa"
import DESCRIPTION from "./websearch.txt"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const Parameters = z.object({
  query: z.string().describe("Websearch query"),
  numResults: z.number().optional().describe("Number of search results to return (default: 8)"),
  livecrawl: z
    .enum(["fallback", "preferred"])
    .optional()
    .describe(
      "Live crawl mode - 'fallback': use live crawling as backup if cached content unavailable, 'preferred': prioritize live crawling (default: 'fallback')",
    ),
  type: z
    .enum(["auto", "fast", "deep"])
    .optional()
    .describe("Search type - 'auto': balanced search (default), 'fast': quick results, 'deep': comprehensive search"),
  contextMaxCharacters: z
    .number()
    .optional()
    .describe("Maximum characters for context string optimized for LLMs (default: 10000)"),
})

export const WebSearchTool = Tool.define(
  "websearch",
  Effect.gen(function* () {
    const http = yield* HttpClient.HttpClient

    return {
      get description() {
        return DESCRIPTION.replace("{{year}}", new Date().getFullYear().toString())
      },
      parameters: Parameters,
      execute: (params: z.infer<typeof Parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "websearch",
            patterns: [params.query],
            always: ["*"],
            metadata: {
              query: params.query,
              numResults: params.numResults,
              livecrawl: params.livecrawl,
              type: params.type,
              contextMaxCharacters: params.contextMaxCharacters,
            },
          })

          const result = yield* McpExa.call(
            http,
            "web_search_exa",
            McpExa.SearchArgs,
            {
              query: params.query,
              type: params.type || "auto",
              numResults: params.numResults || 8,
              livecrawl: params.livecrawl || "fallback",
              contextMaxCharacters: params.contextMaxCharacters,
            },
            "25 seconds",
          )

          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const output = result ?? "No search results found. Please try a different query."
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, output, {
                    mime: "text/plain",
                    ext: "txt",
                    label: `websearch ${params.query}`,
                    source: "websearch",
                  }),
                ).pipe(Effect.catch(() => Effect.succeed(undefined)))
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            operation_slug: slug,
            kind: "fact.observed",
            source: "websearch",
            summary: `websearch ${params.query}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              query: params.query,
              num_results: params.numResults ?? 8,
              livecrawl: params.livecrawl || "fallback",
              type: params.type || "auto",
              context_max_characters: params.contextMaxCharacters ?? null,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "knowledge_query",
            entity_key: `web:${params.query}`,
            fact_name: "web_result",
            value_json: {
              query: params.query,
              output,
              num_results: params.numResults ?? 8,
              livecrawl: params.livecrawl || "fallback",
              type: params.type || "auto",
              context_max_characters: params.contextMaxCharacters ?? null,
            },
            writer_kind: "tool",
            status: result ? "observed" : "stale",
            confidence: result ? 700 : 300,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))

          return {
            output,
            title: `Web search: ${params.query}`,
            metadata: {},
          }
        }).pipe(Effect.orDie),
    }
  }),
)
