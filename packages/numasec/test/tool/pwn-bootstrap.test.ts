import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import { PwnBootstrapTool } from "../../src/tool/pwn-bootstrap"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { tmpdir } from "../fixture/fixture"
import { Session } from "../../src/session"

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

async function createSessionID(permission?: Array<{ permission: string; pattern: string; action: "allow" | "ask" | "deny" }>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const session = yield* Session.Service
      const created = yield* session.create({ permission })
      return created.id
    }) as any,
  )
}

async function exec(sessionID: string, params: { target: string }) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* PwnBootstrapTool
      const tool = yield* info.init()
      return yield* tool.execute(params, {
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

describe("tool/pwn-bootstrap", () => {
  test("URL target → pentest / web-surface", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID([{ permission: "*", pattern: "*", action: "allow" }])
        const r: any = await exec(String(sessionID), { target: "https://acme.example.com" })
        expect(r.metadata.ok).toBe(true)
        expect(r.metadata.shape).toBe("url")
        expect(r.metadata.kind).toBe("pentest")
        expect(r.metadata.agent).toBe("pentest")
        expect(r.metadata.play_id).toBe("web-surface")
        expect(typeof r.metadata.slug).toBe("string")

        const active = await Operation.activeSlug(fixture.path)
        expect(active).toBe(r.metadata.slug)

        const info = await Operation.read(fixture.path, r.metadata.slug)
        expect(info?.kind).toBe("pentest")
        expect(info?.target).toBe("https://acme.example.com")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: r.metadata.slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === r.metadata.slug &&
              item.fact_name === "operation_state",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === r.metadata.slug &&
              item.fact_name === "autonomy_policy" &&
              (item.value_json as { mode?: string } | null)?.mode === "auto",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) => item.entity_kind === "tool_adapter" && item.fact_name === "presence",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) => item.entity_kind === "vertical" && item.fact_name === "readiness",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "identity" &&
              item.entity_key === "anonymous" &&
              item.fact_name === "descriptor",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "identity" &&
              item.entity_key === "anonymous" &&
              item.fact_name === "active" &&
              item.value_json === true,
          ),
        ).toBe(true)
      },
    })
  })

  test("IP/CIDR target → hacking / network-surface", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID()
        const r: any = await exec(String(sessionID), { target: "10.0.0.0/24" })
        expect(r.metadata.ok).toBe(true)
        expect(r.metadata.shape).toBe("ip")
        expect(r.metadata.kind).toBe("hacking")
        expect(r.metadata.agent).toBe("hacking")
        expect(r.metadata.play_id).toBe("network-surface")

        const r2: any = await exec(String(sessionID), { target: "192.168.1.42" })
        expect(r2.metadata.shape).toBe("ip")
        expect(r2.metadata.kind).toBe("hacking")
        expect(r2.metadata.play_id).toBe("network-surface")
      },
    })
  })

  test("bare domain → osint / osint-target", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID()
        const r: any = await exec(String(sessionID), { target: "acme.com" })
        expect(r.metadata.ok).toBe(true)
        expect(r.metadata.shape).toBe("domain")
        expect(r.metadata.kind).toBe("osint")
        expect(r.metadata.agent).toBe("osint")
        expect(r.metadata.play_id).toBe("osint-target")
      },
    })
  })

  test("junk target → error, no operation created", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const sessionID = await createSessionID()
        const r: any = await exec(String(sessionID), { target: "??? not a target" })
        expect(r.metadata.ok).toBe(false)
        expect(r.metadata.reason).toContain("target shape unclear")
        expect(r.output).toContain("Could not classify")
        expect(r.metadata.slug).toBeUndefined()

        const ops = await Operation.list(fixture.path)
        expect(ops.length).toBe(0)
      },
    })
  })
})
