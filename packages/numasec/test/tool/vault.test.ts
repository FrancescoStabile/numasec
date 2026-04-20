import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import { VaultTool } from "../../src/tool/vault"
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

async function runVault(params: any) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* VaultTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

async function withSandbox(fn: (xdg: string) => Promise<void>) {
  await using fixture = await tmpdir()
  const prev = process.env.XDG_CONFIG_HOME
  const xdg = path.join(fixture.path, "xdg")
  process.env.XDG_CONFIG_HOME = xdg
  try {
    await Instance.provide({ directory: fixture.path, fn: () => fn(xdg) })
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME
    else process.env.XDG_CONFIG_HOME = prev
  }
}

describe("tool/vault", () => {
  test("set/get/list/delete roundtrip, get redacts by default", async () => {
    await withSandbox(async (xdg) => {
      const setR: any = await runVault({ action: "set", key: "API_KEY", value: "sk-abc" })
      expect(setR.output).toContain("[REDACTED:API_KEY]")
      expect(setR.output).not.toContain("sk-abc")

      const getR: any = await runVault({ action: "get", key: "API_KEY" })
      const meta = JSON.parse(getR.output)
      expect(meta).toEqual({ present: true, key: "API_KEY", length: 6 })
      expect(getR.output).not.toContain("sk-abc")

      const revealR: any = await runVault({ action: "get", key: "API_KEY", reveal: true })
      expect(revealR.output).toBe("sk-abc")

      const listR: any = await runVault({ action: "list" })
      expect(listR.output).toContain("API_KEY")

      const delR: any = await runVault({ action: "delete", key: "API_KEY" })
      expect(delR.output).toContain("deleted")

      const listR2: any = await runVault({ action: "list" })
      expect(listR2.output).not.toContain("API_KEY")

      const vaultFile = path.join(xdg, "numasec", "vault.json")
      const stat = await fs.stat(vaultFile)
      expect(stat.mode & 0o777).toBe(0o600)
    })
  })

  test("use_as sets active identity and delete clears it", async () => {
    await withSandbox(async (xdg) => {
      await runVault({ action: "set", key: "admin_token", value: "tkn-123" })
      const useR: any = await runVault({ action: "use_as", key: "admin_token" })
      expect(useR.output).toContain("admin_token")

      const raw = JSON.parse(await fs.readFile(path.join(xdg, "numasec", "vault.json"), "utf-8"))
      expect(raw.active_identity).toBe("admin_token")
      expect(raw.active_identity_set_at).toBeString()

      await runVault({ action: "delete", key: "admin_token" })
      const raw2 = JSON.parse(await fs.readFile(path.join(xdg, "numasec", "vault.json"), "utf-8"))
      expect(raw2.active_identity).toBeNull()
    })
  })

  test("use_as on unknown key fails", async () => {
    await withSandbox(async () => {
      await expect(runVault({ action: "use_as", key: "missing" })).rejects.toThrow(/unknown key/)
    })
  })
})
