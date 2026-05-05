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
import { ScopeTool } from "../../src/tool/scope"
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
      const info = yield* ScopeTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/scope", () => {
  test("status shows scope patterns and writes scope policy into the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Scope",
          kind: "pentest",
          target: "https://target.test",
          opsec: "strict",
        })
        const result: any = await exec({ action: "status" })
        expect(result.output).toContain("Scope mode: strict")
        expect(result.output).toContain("- in: target.test")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === op.slug &&
              item.fact_name === "scope_policy",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === op.slug &&
              item.fact_name === "operation_state",
          ),
        ).toBe(true)
      },
    })
  })

  test("set updates opsec level and persists updated scope policy", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Scope",
          kind: "pentest",
          target: "https://target.test",
        })
        const result: any = await exec({ action: "set", level: "strict" })
        expect(result.output).toContain("Scope mode: strict")

        const updated = await Operation.read(fixture.path, op.slug)
        expect(updated?.opsec).toBe("strict")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const policy = facts.find(
          (item) =>
            item.entity_kind === "operation" &&
            item.entity_key === op.slug &&
            item.fact_name === "scope_policy",
        )
        expect(policy).toBeDefined()
        expect(JSON.stringify(policy?.value_json)).toContain("\"opsec\":\"strict\"")
        expect(JSON.stringify(policy?.value_json)).toContain("\"default\":\"ask\"")
      },
    })
  })

  test("set uses the requested scope mode even when the legacy notebook is missing", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({
          workspace: fixture.path,
          label: "Kernel Only Scope",
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
                label: "Kernel Only Scope",
                kind: "pentest",
                target: "https://target.test",
                opsec: "strict",
              },
            }),
            JSON.stringify({
              entity_kind: "operation",
              entity_key: op.slug,
              fact_name: "scope_policy",
              value_json: {
                default: "ask",
                in_scope: ["target.test"],
                out_of_scope: [],
              },
            }),
            "",
          ].join("\n"),
        )
        await rm(path.join(dir, "numasec.md"), { force: true })

        const result: any = await exec({ action: "set", level: "normal" })
        expect(result.output).toContain("Scope mode: normal")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const policy = facts.find(
          (item) =>
            item.entity_kind === "operation" &&
            item.entity_key === op.slug &&
            item.fact_name === "scope_policy",
        )
        expect(JSON.stringify(policy?.value_json)).toContain("\"opsec\":\"normal\"")
      },
    })
  })
})
