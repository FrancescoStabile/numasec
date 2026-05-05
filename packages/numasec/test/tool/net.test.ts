import { describe, expect, mock, test } from "bun:test"
import { EventEmitter } from "node:events"
import { Effect, ManagedRuntime, Layer } from "effect"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

void mock.module("node:net", () => ({
  createConnection: ({
    timeout: _timeout,
  }: {
    host: string
    port: number
    timeout?: number
  }) => {
    class MockSocket extends EventEmitter {
      destroy() {}
      write(data: Buffer | string) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data)
        queueMicrotask(() => {
          this.emit("data", buf)
          this.emit("end")
        })
        return true
      }
    }

    const socket = new MockSocket()
    queueMicrotask(() => socket.emit("connect"))
    return socket
  },
}))

const { NetTool } = await import("../../src/tool/net")

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
      const info = yield* NetTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

describe("tool/net", () => {
  test("tcp_send echoes payload", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const r: any = await exec({
          op: "tcp_send",
          host: "127.0.0.1",
          port: 31337,
          payload: "ping",
          timeout_ms: 2000,
        })
        expect(r.output).toBe("ping")
        expect(r.metadata.bytes_read).toBe(4)
      },
    })
  })
})
