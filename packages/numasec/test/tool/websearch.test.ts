import { describe, expect, test } from "bun:test"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { Agent } from "../../src/agent/agent"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { Evidence } from "../../src/core/evidence"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { WebSearchTool } from "../../src/tool/websearch"
import { tmpdir } from "../fixture/fixture"

const ctx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("message"),
  callID: "",
  agent: "security",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
} as any

function mockHttpClient(body: string) {
  const client = HttpClient.make((request) =>
    Effect.flatMap(HttpClientRequest.toWeb(request), () =>
      Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/event-stream" },
          }),
        ),
      ),
    ).pipe(Effect.orDie),
  )
  return Layer.succeed(HttpClient.HttpClient, client)
}

function exec(
  args: {
    query: string
    numResults?: number
    livecrawl?: "fallback" | "preferred"
    type?: "auto" | "fast" | "deep"
    contextMaxCharacters?: number
  },
  httpLayer: Layer.Layer<HttpClient.HttpClient>,
) {
  return WebSearchTool.pipe(
    Effect.flatMap((info) => info.init()),
    Effect.flatMap((tool) => tool.execute(args as any, ctx)),
    Effect.provide(Layer.mergeAll(httpLayer, Truncate.defaultLayer, Agent.defaultLayer)),
    Effect.runPromise,
  )
}

describe("tool/websearch", () => {
  test("persists direct websearch results into evidence and the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "WebSearch", kind: "osint" })
        const body = 'data: {"result":{"content":[{"type":"text","text":"Result 1\\nResult 2"}]}}\n\n'
        const result = await exec(
          {
            query: "latest ai news 2026",
            numResults: 5,
            livecrawl: "preferred",
            type: "deep",
            contextMaxCharacters: 5000,
          },
          mockHttpClient(body),
        )
        const [facts, evidence] = await Promise.all([
          AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 })),
          Evidence.list(fixture.path, op.slug),
        ])

        expect(result.output).toContain("Result 1")
        expect(evidence.some((item) => item.label === "websearch latest ai news 2026")).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "knowledge_query" &&
              item.entity_key === "web:latest ai news 2026" &&
              item.fact_name === "web_result",
          ),
        ).toBe(true)
      },
    })
  })
})
