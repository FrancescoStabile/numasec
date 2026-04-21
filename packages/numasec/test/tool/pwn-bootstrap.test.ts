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

async function exec(params: { target: string }) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* PwnBootstrapTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

describe("tool/pwn-bootstrap", () => {
  test("URL target → pentest / web-surface", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const r: any = await exec({ target: "https://acme.example.com" })
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
      },
    })
  })

  test("IP/CIDR target → hacking / network-surface", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const r: any = await exec({ target: "10.0.0.0/24" })
        expect(r.metadata.ok).toBe(true)
        expect(r.metadata.shape).toBe("ip")
        expect(r.metadata.kind).toBe("hacking")
        expect(r.metadata.agent).toBe("hacking")
        expect(r.metadata.play_id).toBe("network-surface")

        const r2: any = await exec({ target: "192.168.1.42" })
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
        const r: any = await exec({ target: "acme.com" })
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
        const r: any = await exec({ target: "??? not a target" })
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
