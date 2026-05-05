import { describe, expect, test } from "bun:test"
import z from "zod"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { AnalyzeTool } from "../../src/tool/analyze"
import { _deps as iacDeps } from "../../src/tool/iac-triage"
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
      const info = yield* AnalyzeTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/analyze", () => {
  test("exports an object JSON schema for provider tool registration", async () => {
    const schema = await runtime.runPromise(
      Effect.gen(function* () {
        const info = yield* AnalyzeTool
        const tool = yield* info.init()
        return z.toJSONSchema(tool.parameters)
      }) as any,
    )

    expect(schema.type).toBe("object")
  })

  test("delegates iac analysis to iac_triage and preserves graph side effects", async () => {
    await using fixture = await tmpdir({ git: true })
    const whichSaved = iacDeps.which
    const runSaved = iacDeps.run
    const isDirectorySaved = iacDeps.isDirectory
    iacDeps.which = () => "/usr/bin/checkov"
    iacDeps.isDirectory = () => true
    iacDeps.run = (argv) =>
      Effect.succeed({
        argv,
        stdout: JSON.stringify({
          summary: { passed: 3, failed: 1, skipped: 0 },
          results: {
            failed_checks: [
              { check_id: "CKV_AWS_1", check_name: "bad bucket", resource: "aws_s3_bucket.bad", severity: "HIGH" },
            ],
          },
        }),
        stderr: "",
        exitCode: 1,
      } as any)
    try {
      await Instance.provide({
        directory: fixture.path,
        fn: async () => {
          const op = await Operation.create({ workspace: fixture.path, label: "Analyze", kind: "appsec" })
          const result: any = await exec({ target: "iac", path: "./infra", mode: "quick" })
          const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))

          expect(result.metadata.surface).toBe("analyze")
          expect(result.metadata.delegated_to).toBe("iac_triage")
          expect(result.metadata.target).toBe("iac")
          expect(result.metadata.available).toBe(true)
          expect(
            facts.some(
              (item) =>
                item.entity_kind === "iac_target" &&
                item.entity_key === "./infra" &&
                item.fact_name === "checkov_summary",
            ),
          ).toBe(true)
        },
      })
    } finally {
      iacDeps.which = whichSaved
      iacDeps.run = runSaved
      iacDeps.isDirectory = isDirectorySaved
    }
  })
})
