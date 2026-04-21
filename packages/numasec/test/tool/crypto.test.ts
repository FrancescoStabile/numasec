import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import { CryptoTool } from "../../src/tool/crypto"
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
  const program = Effect.gen(function* () {
    const info = yield* CryptoTool
    const tool = yield* info.init()
    return yield* tool.execute(params, baseCtx)
  })
  return await runtime.runPromise(program as any)
}

describe("tool/crypto", () => {
  test("sha256 + hmac + jwt + base64", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const r1: any = await exec({ op: "hash", algo: "sha256", data: "hello" })
        expect(r1.output).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        const r2: any = await exec({
          op: "hmac",
          algo: "sha1",
          key: "key",
          data: "The quick brown fox jumps over the lazy dog",
        })
        expect(r2.output).toBe("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
        const r3: any = await exec({
          op: "jwt_decode",
          token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc",
        })
        const parsed = JSON.parse(r3.output)
        expect(parsed.header.alg).toBe("HS256")
        expect(parsed.payload.sub).toBe("123")
        const enc: any = await exec({ op: "encode", codec: "base64", data: "ping" })
        expect(enc.output).toBe("cGluZw==")
        const dec: any = await exec({ op: "decode", codec: "base64", data: enc.output })
        expect(dec.output).toBe("ping")
      },
    })
  })
})
