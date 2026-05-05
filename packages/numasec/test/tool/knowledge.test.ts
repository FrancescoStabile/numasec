import { describe, expect, test } from "bun:test"
import z from "zod"
import { Effect, Layer, ManagedRuntime } from "effect"
import { FetchHttpClient } from "effect/unstable/http"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { KnowledgeTool } from "../../src/tool/knowledge"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    FetchHttpClient.layer,
  ),
)

const baseCtx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make(""),
  callID: "",
  agent: "security",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  extra: {},
  ask: () => Effect.succeed(undefined as any),
} as any

async function exec(params: Record<string, unknown>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* KnowledgeTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/knowledge", () => {
  test("exports an object JSON schema for provider tool registration", async () => {
    const schema = (await runtime.runPromise(
      Effect.gen(function* () {
        const info = yield* KnowledgeTool
        const tool = yield* info.init()
        return z.toJSONSchema(tool.parameters)
      }) as any,
    )) as { type?: string }

    expect(schema.type).toBe("object")
  })

  test("delegates cve lookups and preserves structured knowledge facts", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Knowledge", kind: "appsec" })
        const result: any = await exec({ source: "cve", query: "openssl", limit: 3 })
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 100 }))

        expect(result.metadata.surface).toBe("knowledge")
        expect(result.metadata.delegated_to).toBe("cve")
        expect(result.metadata.source).toBe("cve")
        expect(result.metadata.available).toBe(true)
        expect(result.output).toContain("\"results\"")
        expect(facts.some((item) => item.entity_kind === "cve" && item.fact_name === "details")).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "knowledge_query" &&
              item.entity_key === "cve:openssl" &&
              item.fact_name === "cve_result",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "knowledge_query" &&
              item.src_key === "cve:openssl" &&
              item.relation === "matched" &&
              item.dst_kind === "cve",
          ),
        ).toBe(true)
      },
    })
  })
})
