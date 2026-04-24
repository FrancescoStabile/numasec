import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { DoctorTool } from "../../src/tool/doctor"
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

async function exec() {
  await using fixture = await tmpdir()
  return await Instance.provide({
    directory: fixture.path,
    fn: () =>
      runtime.runPromise(
        Effect.gen(function* () {
          const info = yield* DoctorTool
          const tool = yield* info.init()
          return yield* tool.execute({}, baseCtx)
        }) as any,
      ),
  })
}

describe("tool/doctor", () => {
  test("returns readiness counts in metadata", async () => {
    const result: any = await exec()

    expect(result.output).toContain("## play readiness")
    expect(result.output).toContain("## vertical readiness")
    expect(typeof result.metadata.plays_ready).toBe("number")
    expect(typeof result.metadata.plays_total).toBe("number")
    expect(typeof result.metadata.verticals_ready).toBe("number")
    expect(typeof result.metadata.verticals_total).toBe("number")
    expect(typeof result.metadata.browser_present).toBe("boolean")
  })
})
