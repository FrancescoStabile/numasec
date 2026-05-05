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
import { Session } from "../../src/session"
import type { Session as SessionNS } from "../../src/session"
import { MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { AutonomyTool } from "../../src/tool/autonomy"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    Session.defaultLayer,
  ),
)

async function createSessionID(): Promise<string> {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const session = yield* Session.Service
      const created = yield* session.create()
      return String(created.id)
    }) as any,
  )
}

async function exec(sessionID: string, params: Record<string, unknown>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* AutonomyTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, {
        sessionID,
        messageID: MessageID.make(""),
        callID: "",
        agent: "security",
        abort: AbortSignal.any([]),
        messages: [],
        metadata: () => Effect.void,
        extra: {},
        ask: () => Effect.succeed(undefined as any),
      } as any)
    }) as any,
  )
}

async function getSessionInfo(sessionID: string): Promise<SessionNS.Info> {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const session = yield* Session.Service
      return (yield* session.get(sessionID as any)) as SessionNS.Info
    }) as any,
  )
}

describe("tool/autonomy", () => {
  test("status reports custom mode by default", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID()
        const result: any = await exec(sessionID, { action: "status" })
        expect(result.metadata.action).toBe("status")
        expect(result.metadata.mode).toBe("custom")
        expect(result.output).toContain("Autonomy mode: custom")
      },
    })
  })

  test("set persists auto mode on the session and writes autonomy policy into the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID()
        const op = await Operation.create({ workspace: fixture.path, label: "Autonomy", kind: "pentest" })
        const result: any = await exec(sessionID, { action: "set", mode: "auto" })
        expect(result.metadata.action).toBe("set")
        expect(result.metadata.mode).toBe("auto")

        const sessionInfo = await getSessionInfo(sessionID)
        expect(sessionInfo.permission?.[0]?.action).toBe("allow")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === op.slug &&
              item.fact_name === "autonomy_policy",
          ),
        ).toBe(true)
      },
    })
  })
})
