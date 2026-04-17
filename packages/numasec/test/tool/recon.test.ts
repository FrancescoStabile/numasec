import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import fs from "fs/promises"
import path from "path"
import { ReconTool } from "../../src/tool/recon"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
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

async function exec(params: any) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* ReconTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

describe("tool/recon", () => {
  test("missing binary returns clear error", async () => {
    await using fixture = await tmpdir()
    // Point PATH at an empty dir so no recon binaries resolve
    const emptyBin = path.join(fixture.path, "empty-bin")
    await fs.mkdir(emptyBin, { recursive: true })
    const prev = process.env.PATH
    process.env.PATH = emptyBin
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({ tool: "nuclei", args: ["-version"] })
          expect(r.output).toContain("Binary not found")
          expect(r.metadata.exit_code).toBeNull()
          expect(r.metadata.family).toBe("web")
        },
      })
    } finally {
      process.env.PATH = prev
    }
  })

  test("runs a fake binary and captures stdout+exit", async () => {
    await using fixture = await tmpdir()
    const bin = path.join(fixture.path, "bin")
    await fs.mkdir(bin, { recursive: true })
    // Stub a fake `whois` that prints a known line and exits 0
    const stub = path.join(bin, "whois")
    await fs.writeFile(stub, "#!/bin/sh\necho 'Domain Name: EXAMPLE.COM'\nexit 0\n", { mode: 0o755 })
    const prev = process.env.PATH
    process.env.PATH = `${bin}:${prev}`
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({ tool: "whois", args: ["example.com"] })
          expect(r.output).toContain("Domain Name: EXAMPLE.COM")
          expect(r.metadata.exit_code).toBe(0)
          expect(r.metadata.family).toBe("osint")
        },
      })
    } finally {
      process.env.PATH = prev
    }
  })
})
