import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import { SecretsTool } from "../../src/tool/secrets"
import { AuthAsTool } from "../../src/tool/auth-as"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import path from "path"

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

async function runSecrets(params: any) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* SecretsTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}
async function runAuth(params: any) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* AuthAsTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

async function withSandbox(fn: () => Promise<void>) {
  await using fixture = await tmpdir()
  // Redirect XDG config so stores don't touch real ~/.config
  const prev = process.env.XDG_CONFIG_HOME
  process.env.XDG_CONFIG_HOME = path.join(fixture.path, "xdg")
  try {
    await Instance.provide({ directory: fixture.path, fn })
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME
    else process.env.XDG_CONFIG_HOME = prev
  }
}

describe("tool/secrets", () => {
  test("set/get/list/remove roundtrip", async () => {
    await withSandbox(async () => {
      const setR: any = await runSecrets({ op: "set", name: "API_KEY", value: "sk-abc" })
      expect(setR.output).toContain("stored")
      const getR: any = await runSecrets({ op: "get", name: "API_KEY" })
      expect(getR.output).toBe("sk-abc")
      const listR: any = await runSecrets({ op: "list" })
      expect(listR.output).toContain("API_KEY")
      const rmR: any = await runSecrets({ op: "remove", name: "API_KEY" })
      expect(rmR.output).toContain("removed")
      const listR2: any = await runSecrets({ op: "list" })
      expect(listR2.output).not.toContain("API_KEY")
    })
  })
})

describe("tool/auth_as", () => {
  test("set/get/list/remove profile", async () => {
    await withSandbox(async () => {
      const setR: any = await runAuth({
        op: "set",
        name: "admin",
        type: "bearer",
        target_url: "https://example.com",
        credentials: { token: "tkn" },
      })
      expect(setR.output).toContain("stored")
      const getR: any = await runAuth({ op: "get", name: "admin" })
      const parsed = JSON.parse(getR.output)
      expect(parsed.type).toBe("bearer")
      expect(parsed.credentials.token).toBe("tkn")
      const listR: any = await runAuth({ op: "list" })
      expect(listR.output).toContain("admin")
      const rmR: any = await runAuth({ op: "remove", name: "admin" })
      expect(rmR.output).toContain("removed")
    })
  })
})
