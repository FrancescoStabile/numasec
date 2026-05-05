import { describe, expect, test } from "bun:test"
import path from "path"
import { mkdir, rm } from "fs/promises"
import { Effect, Layer, ManagedRuntime } from "effect"
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
import { OpsecTool } from "../../src/tool/opsec"
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
      const info = yield* OpsecTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/opsec", () => {
  test("set persists operation_state with updated opsec immediately", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Opsec",
          kind: "pentest",
          target: "https://target.test",
        })
        const result: any = await exec({ action: "set", level: "strict" })
        expect(result.output).toContain("Opsec: strict")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const state = facts.find(
          (item) =>
            item.entity_kind === "operation" &&
            item.entity_key === op.slug &&
            item.fact_name === "operation_state",
        )
        expect(state).toBeDefined()
        expect(JSON.stringify(state?.value_json)).toContain("\"opsec\":\"strict\"")
      },
    })
  })

  test("set uses the requested level even when the legacy notebook is missing", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Kernel Only Opsec",
          kind: "pentest",
          target: "https://target.test",
        })
        const dir = path.join(fixture.path, ".numasec", "operation", op.slug)
        const cyberDir = path.join(dir, "cyber")
        await mkdir(cyberDir, { recursive: true })
        await Bun.write(
          path.join(cyberDir, "facts.jsonl"),
          [
            JSON.stringify({
              entity_kind: "operation",
              entity_key: op.slug,
              fact_name: "operation_state",
              value_json: {
                label: "Kernel Only Opsec",
                kind: "pentest",
                target: "https://target.test",
                opsec: "strict",
              },
            }),
            "",
          ].join("\n"),
        )
        await rm(path.join(dir, "numasec.md"), { force: true })

        const result: any = await exec({ action: "set", level: "normal" })
        expect(result.output).toContain("Opsec: normal")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const state = facts.find(
          (item) =>
            item.entity_kind === "operation" &&
            item.entity_key === op.slug &&
            item.fact_name === "operation_state",
        )
        expect(JSON.stringify(state?.value_json)).toContain("\"opsec\":\"normal\"")
      },
    })
  })
})
