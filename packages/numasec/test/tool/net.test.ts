import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import * as net from "node:net"
import { NetTool } from "../../src/tool/net"
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
      const info = yield* NetTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

describe("tool/net", () => {
  test("tcp_send echoes payload", async () => {
    await using fixture = await tmpdir()
    const server = net.createServer((sock) => {
      sock.on("data", (d) => {
        sock.write(d)
        sock.end()
      })
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    const port = (server.address() as net.AddressInfo).port
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const r: any = await exec({
            op: "tcp_send",
            host: "127.0.0.1",
            port,
            payload: "ping",
            timeout_ms: 2000,
          })
          expect(r.output).toBe("ping")
          expect(r.metadata.bytes_read).toBe(4)
        },
      })
    } finally {
      server.close()
    }
  })
})
