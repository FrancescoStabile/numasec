import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { IdentityTool } from "../../src/tool/identity"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
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
      const info = yield* IdentityTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/identity", () => {
  test("add stores an identity descriptor without leaking the raw secret into the graph", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Identity", kind: "appsec" })
        const result: any = await exec({
          action: "add",
          key: "alice",
          value: JSON.stringify({
            headers: { "X-Role": "admin" },
            bearer: "super-secret-token",
          }),
        })

        expect(result.metadata.mode).toBe("headers")
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const descriptor = facts.find(
          (item) =>
            item.entity_kind === "identity" &&
            item.entity_key === "alice" &&
            item.fact_name === "descriptor",
        )
        expect(JSON.stringify(descriptor?.value_json)).toContain("\"X-Role\"")
        expect(JSON.stringify(descriptor?.value_json)).not.toContain("super-secret-token")
      },
    })
  })

  test("use marks the active identity in the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Identity Use", kind: "pentest" })
        await exec({ action: "add", key: "bob", value: "Cookie: session=abc123" })
        const result: any = await exec({ action: "use", key: "bob" })
        expect(result.metadata.mode).toBe("cookies")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "identity" &&
              item.entity_key === "bob" &&
              item.fact_name === "active" &&
              item.value_json === true,
          ),
        ).toBe(true)
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 100 }))
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === op.slug &&
              item.relation === "uses_identity" &&
              item.dst_kind === "identity" &&
              item.dst_key === "bob",
          ),
        ).toBe(true)
      },
    })
  })
})
