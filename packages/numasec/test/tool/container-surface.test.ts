import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { ContainerSurfaceTool, _deps } from "../../src/tool/container-surface"
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
      const info = yield* ContainerSurfaceTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/container-surface", () => {
  test("reports clean adapter absence when trivy is missing", async () => {
    await using fixture = await tmpdir()
    const saved = _deps.which
    _deps.which = () => null
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ image: "nginx:latest", mode: "quick" })
          expect(result.title).toContain("container surface")
          expect(result.metadata.available).toBe(false)
          expect(result.metadata.adapter).toBe("trivy")
          expect(result.metadata.target_kind).toBe("image")
          expect(result.metadata.image).toBe("nginx:latest")
          expect(result.output).toContain('Required adapter "trivy" is not installed')
        },
      })
    } finally {
      _deps.which = saved
    }
  })

  test("runs trivy image in quick mode when adapter is present", async () => {
    await using fixture = await tmpdir()
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/trivy"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"Results":[]}',
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ image: "nginx:latest", mode: "quick" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("trivy")
          expect(result.metadata.target_kind).toBe("image")
          expect(result.metadata.image).toBe("nginx:latest")
          expect(result.metadata.mode).toBe("quick")
          expect(result.output).toContain('"Results":[]')
          expect(result.metadata.command).toEqual([
            "trivy",
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "nginx:latest",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("runs trivy image in full mode when adapter is present", async () => {
    await using fixture = await tmpdir()
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/trivy"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"Results":[{"Vulnerabilities":[],"Secrets":[]}]}',
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ image: "nginx:latest", mode: "full" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("trivy")
          expect(result.metadata.target_kind).toBe("image")
          expect(result.metadata.image).toBe("nginx:latest")
          expect(result.metadata.mode).toBe("full")
          expect(result.output).toContain("Vulnerabilities")
          expect(result.metadata.command).toEqual([
            "trivy",
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln,secret",
            "nginx:latest",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("throws when trivy exits non-zero", async () => {
    await using fixture = await tmpdir()
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/trivy"
    _deps.run = () =>
      Effect.succeed({
        argv: ["trivy"],
        stdout: "",
        stderr: "boom",
        exitCode: 2,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await expect(exec({ image: "nginx:latest", mode: "full" })).rejects.toThrow(
            "trivy exited with code 2: boom",
          )
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("parameter descriptions match expected clarity", async () => {
    const info = await runtime.runPromise(ContainerSurfaceTool)
    const tool = await runtime.runPromise(info.init())
    const schema = tool.parameters.shape

    expect(schema.image.description).toContain("fully-qualified")
    expect(schema.image.description).toContain("nginx:latest")
    expect(schema.image.description).toContain("ghcr.io")

    expect(schema.mode.description).toContain("quick")
    expect(schema.mode.description).toContain("full")
    expect(schema.mode.description).toMatch(/HIGH.*CRITICAL|CRITICAL.*HIGH/)
  })
})
