import { describe, expect, test } from "bun:test"
import path from "path"
import { mkdir, writeFile } from "node:fs/promises"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { IacTriageTool, _deps } from "../../src/tool/iac-triage"
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
      const info = yield* IacTriageTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/iac-triage", () => {
  test("reports clean adapter absence when checkov is missing", async () => {
    await using fixture = await tmpdir()
    const saved = _deps.which
    _deps.which = () => null
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./iac", mode: "quick" })
          expect(result.title).toContain("iac triage")
          expect(result.metadata.available).toBe(false)
          expect(result.metadata.adapter).toBe("checkov")
          expect(result.metadata.target_kind).toBe("path")
          expect(result.metadata.path).toBe("./iac")
          expect(result.output).toContain('Required adapter "checkov" is not installed')
        },
      })
    } finally {
      _deps.which = saved
    }
  })

  test("runs checkov directory scan in quick mode when adapter is present", async () => {
    await using fixture = await tmpdir()
    await mkdir(`${fixture.path}/iac`, { recursive: true })
    await writeFile(`${fixture.path}/iac/main.tf`, 'resource "null_resource" "x" {}')
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"summary":{"failed":0}}',
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./iac", mode: "quick" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("checkov")
          expect(result.metadata.target_kind).toBe("path")
          expect(result.metadata.path).toBe("./iac")
          expect(result.metadata.mode).toBe("quick")
          expect(result.output).toContain('"failed":0')
          expect(result.metadata.command).toEqual([
            "checkov",
            "-d",
            path.join(fixture.path, "iac"),
            "-o",
            "json",
            "--quiet",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("runs checkov file scan in full mode when adapter is present", async () => {
    await using fixture = await tmpdir()
    await writeFile(`${fixture.path}/main.tf`, 'resource "null_resource" "x" {}')
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"summary":{"failed":1}}',
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./main.tf", mode: "full" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("checkov")
          expect(result.metadata.target_kind).toBe("path")
          expect(result.metadata.path).toBe("./main.tf")
          expect(result.metadata.mode).toBe("full")
          expect(result.output).toContain('"failed":1')
          expect(result.metadata.command).toEqual([
            "checkov",
            "-f",
            path.join(fixture.path, "main.tf"),
            "-o",
            "json",
            "--quiet",
            "--framework",
            "all",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("throws when checkov exits non-zero", async () => {
    await using fixture = await tmpdir()
    await mkdir(`${fixture.path}/iac`, { recursive: true })
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = () =>
      Effect.succeed({
        argv: ["checkov"],
        stdout: "",
        stderr: "boom",
        exitCode: 2,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await expect(exec({ path: "./iac", mode: "full" })).rejects.toThrow(
            "checkov exited with code 2: boom",
          )
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("treats exit code 1 as successful scan with findings", async () => {
    await using fixture = await tmpdir()
    await mkdir(`${fixture.path}/iac`, { recursive: true })
    await writeFile(`${fixture.path}/iac/main.tf`, 'resource "null_resource" "x" {}')
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"summary":{"failed":5}}',
        stderr: "",
        exitCode: 1,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./iac", mode: "quick" })
          expect(result.title).toContain("iac triage")
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.exit_code).toBe(1)
          expect(result.output).toContain('"failed":5')
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("asks permission before running adapter", async () => {
    await using fixture = await tmpdir()
    const whichSaved = _deps.which
    const runSaved = _deps.run
    const askOrder: string[] = []
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = () => {
      askOrder.push("run")
      return Effect.succeed({
        argv: ["checkov"],
        stdout: "{}",
        stderr: "",
        exitCode: 0,
      } as any)
    }
    const ctxWithTracking = {
      ...baseCtx,
      ask: () => {
        askOrder.push("ask")
        return Effect.succeed(undefined)
      },
    }
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await runtime.runPromise(
            Effect.gen(function* () {
              const info = yield* IacTriageTool
              const tool = yield* info.init()
              return yield* tool.execute({ path: "./nonexistent" } as any, ctxWithTracking)
            }) as any,
          )
          expect(askOrder[0]).toBe("ask")
          expect(askOrder.indexOf("ask")).toBeLessThan(askOrder.indexOf("run"))
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("resolves relative paths before passing to checkov command", async () => {
    await using fixture = await tmpdir()
    await mkdir(`${fixture.path}/iac`, { recursive: true })
    await writeFile(`${fixture.path}/iac/main.tf`, 'resource "null_resource" "x" {}')
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    let capturedCommand: string[] = []
    _deps.run = (argv) => {
      capturedCommand = argv
      return Effect.succeed({
        argv,
        stdout: '{"summary":{"failed":0}}',
        stderr: "",
        exitCode: 0,
      } as any)
    }
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./iac", mode: "quick" })
          expect(result.metadata.available).toBe(true)
          // Command must contain resolved absolute path, not raw relative path
          expect(capturedCommand).toContain(path.join(fixture.path, "iac"))
          expect(capturedCommand).not.toContain("./iac")
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("includes resolved command in approval metadata", async () => {
    await using fixture = await tmpdir()
    await mkdir(`${fixture.path}/iac`, { recursive: true })
    await writeFile(`${fixture.path}/iac/main.tf`, 'resource "null_resource" "x" {}')
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checkov"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '{"summary":{"failed":0}}',
        stderr: "",
        exitCode: 0,
      } as any)
    let capturedAskMetadata: any = null
    const ctxWithTracking = {
      ...baseCtx,
      ask: (req: any) => {
        capturedAskMetadata = req.metadata
        return Effect.succeed(undefined)
      },
    }
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await runtime.runPromise(
            Effect.gen(function* () {
              const info = yield* IacTriageTool
              const tool = yield* info.init()
              return yield* tool.execute({ path: "./iac", mode: "quick" } as any, ctxWithTracking)
            }) as any,
          )
          expect(capturedAskMetadata).not.toBeNull()
          expect(capturedAskMetadata.command).toEqual([
            "checkov",
            "-d",
            path.join(fixture.path, "iac"),
            "-o",
            "json",
            "--quiet",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })
})
