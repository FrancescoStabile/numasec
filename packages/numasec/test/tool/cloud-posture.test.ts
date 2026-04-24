import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { CloudPostureTool, _deps } from "../../src/tool/cloud-posture"
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

async function exec(params: Record<string, unknown>) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* CloudPostureTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/cloud-posture", () => {
  test("reports clean adapter absence when prowler is missing", async () => {
    await using fixture = await tmpdir()
    const saved = _deps.which
    _deps.which = () => null
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ provider: "aws", mode: "quick" })
          expect(result.title).toContain("cloud posture")
          expect(result.metadata.available).toBe(false)
          expect(result.metadata.adapter).toBe("prowler")
          expect(result.metadata.provider).toBe("aws")
          expect(result.output).toContain('Required adapter "prowler" is not installed')
        },
      })
    } finally {
      _deps.which = saved
    }
  })

  test("runs prowler in quick aws mode when adapter is present", async () => {
    await using fixture = await tmpdir()
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/prowler"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: "prowler-summary",
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ provider: "aws", mode: "quick", profile: "dev", region: "eu-west-1" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("prowler")
          expect(result.metadata.provider).toBe("aws")
          expect(result.output).toContain("prowler-summary")
          expect(result.metadata.command).toEqual([
            "prowler",
            "aws",
            "--quick",
            "--profile",
            "dev",
            "--region",
            "eu-west-1",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })
})
