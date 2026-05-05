import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { DoctorTool } from "../../src/tool/doctor"
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

async function exec() {
  await using fixture = await tmpdir()
  return await Instance.provide({
    directory: fixture.path,
    fn: () =>
      runtime.runPromise(
        Effect.gen(function* () {
          const info = yield* DoctorTool
          const tool = yield* info.init()
          return yield* tool.execute({}, baseCtx)
        }) as any,
      ),
  })
}

describe("tool/doctor", () => {
  test("returns readiness counts in metadata", async () => {
    const result: any = await exec()

    expect(result.output).toContain("## play readiness")
    expect(result.output).toContain("## vertical readiness")
    expect(typeof result.metadata.plays_ready).toBe("number")
    expect(typeof result.metadata.plays_total).toBe("number")
    expect(typeof result.metadata.verticals_ready).toBe("number")
    expect(typeof result.metadata.verticals_total).toBe("number")
    expect(typeof result.metadata.browser_present).toBe("boolean")
  })

  test("writes installed-tool and readiness state into the cyber kernel when an operation is active", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Doctor", kind: "pentest" })
        await runtime.runPromise(
          Effect.gen(function* () {
            const info = yield* DoctorTool
            const tool = yield* info.init()
            return yield* tool.execute({}, baseCtx)
          }) as any,
        )
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))

        expect(
          facts.some(
            (item) =>
              item.entity_kind === "environment" &&
              item.entity_key === "local" &&
              item.fact_name === "doctor_summary",
          ),
        ).toBe(true)
        expect(facts.some((item) => item.entity_kind === "tool_adapter" && item.fact_name === "presence")).toBe(true)
        expect(
          facts.some(
            (item) => item.fact_name === "readiness" && (item.entity_kind === "play" || item.entity_kind === "vertical"),
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "environment" &&
              item.src_key === "local" &&
              (item.relation === "has_tool" || item.relation === "missing_tool"),
          ),
        ).toBe(true)
      },
    })
  })
})
