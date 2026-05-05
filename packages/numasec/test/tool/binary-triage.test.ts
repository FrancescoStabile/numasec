import { describe, expect, test } from "bun:test"
import path from "path"
import { writeFile } from "node:fs/promises"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { BinaryTriageTool, _deps } from "../../src/tool/binary-triage"
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

async function exec(params: Record<string, unknown>, ctx: typeof baseCtx = baseCtx) {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* BinaryTriageTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, ctx)
    }) as any,
  )
}

describe("tool/binary-triage", () => {
  test("reports clean adapter absence when checksec is missing", async () => {
    await using fixture = await tmpdir()
    const saved = _deps.which
    _deps.which = () => null
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./chal.bin" })
          expect(result.title).toContain("binary triage")
          expect(result.metadata.available).toBe(false)
          expect(result.metadata.adapter).toBe("checksec")
          expect(result.metadata.target_kind).toBe("path")
          expect(result.metadata.path).toBe("./chal.bin")
          expect(result.output).toContain('Required adapter "checksec" is not installed')
        },
      })
    } finally {
      _deps.which = saved
    }
  })

  test("runs checksec with a resolved file path when adapter is present", async () => {
    await using fixture = await tmpdir()
    await writeFile(`${fixture.path}/chal.bin`, "binary")
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checksec"
    _deps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: '[{"name":"binary","checks":{"pie":"PIE Enabled"}}]',
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const result: any = await exec({ path: "./chal.bin" })
          expect(result.metadata.available).toBe(true)
          expect(result.metadata.adapter).toBe("checksec")
          expect(result.metadata.target_kind).toBe("path")
          expect(result.metadata.path).toBe("./chal.bin")
          expect(result.output).toContain('"pie":"PIE Enabled"')
          expect(result.metadata.command).toEqual([
            "checksec",
            "file",
            path.join(fixture.path, "chal.bin"),
            "--output",
            "json",
          ])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("includes the resolved command in approval metadata", async () => {
    await using fixture = await tmpdir()
    await writeFile(`${fixture.path}/chal.bin`, "binary")
    const whichSaved = _deps.which
    const runSaved = _deps.run
    const seen: any[] = []
    _deps.which = () => "/usr/bin/checksec"
    _deps.run = () =>
      Effect.succeed({
        argv: ["checksec"],
        stdout: "[]",
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await exec(
            { path: "./chal.bin" },
            {
              ...baseCtx,
              ask: (input: any) => {
                seen.push(input.metadata?.command)
                return Effect.succeed(undefined)
              },
            } as any,
          )
          expect(seen).toEqual([["checksec", "file", path.join(fixture.path, "chal.bin"), "--output", "json"]])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("asks permission before running adapter", async () => {
    await using fixture = await tmpdir()
    await writeFile(`${fixture.path}/chal.bin`, "binary")
    const whichSaved = _deps.which
    const runSaved = _deps.run
    const order: string[] = []
    _deps.which = () => "/usr/bin/checksec"
    _deps.run = () => {
      order.push("run")
      return Effect.succeed({
        argv: ["checksec"],
        stdout: "[]",
        stderr: "",
        exitCode: 0,
      } as any)
    }
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await exec(
            { path: "./chal.bin" },
            {
              ...baseCtx,
              ask: () => {
                order.push("ask")
                return Effect.succeed(undefined)
              },
            } as any,
          )
          expect(order).toEqual(["ask", "run"])
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("throws when checksec exits non-zero", async () => {
    await using fixture = await tmpdir()
    await writeFile(`${fixture.path}/chal.bin`, "binary")
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checksec"
    _deps.run = () =>
      Effect.succeed({
        argv: ["checksec"],
        stdout: "",
        stderr: "boom",
        exitCode: 2,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          await expect(exec({ path: "./chal.bin" })).rejects.toThrow(
            "checksec exited with code 2: boom",
          )
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })

  test("writes binary facts into the cyber kernel when an operation is active", async () => {
    await using fixture = await tmpdir({ git: true })
    await writeFile(`${fixture.path}/chal.bin`, "binary")
    const whichSaved = _deps.which
    const runSaved = _deps.run
    _deps.which = () => "/usr/bin/checksec"
    _deps.run = () =>
      Effect.succeed({
        argv: ["checksec"],
        stdout: JSON.stringify([
          {
            name: "chal.bin",
            file: path.join(fixture.path, "chal.bin"),
            checks: {
              pie: "PIE Enabled",
              nx: "NX enabled",
              canary: "No canary found",
            },
          },
        ]),
        stderr: "",
        exitCode: 0,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const op = await Operation.create({ workspace: fixture.path, label: "Binary", kind: "hacking" })
          await exec({ path: "./chal.bin" })
          const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
          const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 100 }))

          expect(
            facts.some(
              (item) =>
                item.entity_kind === "binary_artifact" &&
                item.entity_key === "./chal.bin" &&
                item.fact_name === "checksec_summary",
            ),
          ).toBe(true)
          expect(
            facts.some(
              (item) =>
                item.entity_kind === "finding_candidate" &&
                item.entity_key === "./chal.bin:canary" &&
                item.fact_name === "binary_hardening_gap",
            ),
          ).toBe(true)
          expect(
            relations.some(
              (item) =>
                item.src_kind === "binary_artifact" &&
                item.src_key === "./chal.bin" &&
                item.relation === "has_candidate" &&
                item.dst_key === "./chal.bin:canary",
            ),
          ).toBe(true)
        },
      })
    } finally {
      _deps.which = whichSaved
      _deps.run = runSaved
    }
  })
})
