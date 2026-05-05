import { describe, expect, test } from "bun:test"
import { Effect, ManagedRuntime, Layer } from "effect"
import { mkdir, writeFile } from "node:fs/promises"
import path from "node:path"
import { RemediateTool } from "../../src/tool/remediate"
import { Cyber } from "../../src/core/cyber"
import { Format } from "../../src/format"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Truncate } from "../../src/tool"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { SessionID, MessageID } from "../../src/session/schema"
import { Instance } from "../../src/project/instance"
import { Observation } from "../../src/core/observation"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
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
      const info = yield* RemediateTool
      const tool = yield* info.init()
      return yield* tool.execute(params, baseCtx)
    }) as any,
  )
}

async function seedWorkspace(dir: string) {
  await Operation.create({ workspace: dir, label: "Fix It", kind: "appsec" })
  const slug = (await Operation.activeSlug(dir))!
  const srcDir = path.join(dir, "src")
  await mkdir(srcDir, { recursive: true })
  const lines = Array.from({ length: 60 }, (_, i) => `const line${i + 1} = ${i + 1};`)
  lines[41] = `const password = "hunter2";` // line 42 (1-indexed)
  await writeFile(path.join(srcDir, "app.js"), lines.join("\n"), "utf8")
  const obs = await Observation.add(dir, slug, {
    subtype: "vuln",
    title: "Hardcoded credential",
    severity: "high",
    note: "see src/app.js:42 — secret literal",
  })
  await Observation.linkEvidence(dir, slug, obs.id, "src/app.js:42")
  return { slug, observation_id: obs.id }
}

describe("tool/remediate", () => {
  test("returns a scaffold patch with rationale for file-backed observation", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const { observation_id } = await seedWorkspace(fixture.path)
        const r: any = await exec({ observation_id })
        const data = JSON.parse(r.output)
        expect(data.observation_id).toBe(observation_id)
        expect(data.file).toBe("src/app.js")
        expect(data.line).toBe(42)
        expect(typeof data.patch).toBe("string")
        expect(data.patch.length).toBeGreaterThan(0)
        expect(data.patch).toContain("--- a/src/app.js")
        expect(data.patch).toContain("+++ b/src/app.js")
        expect(data.patch).toContain("numasec: TODO remediate")
        expect(typeof data.rationale).toBe("string")
        expect(data.rationale.length).toBeGreaterThan(0)
        expect(data.tested).toBe(false)
        expect(["low", "medium", "high"]).toContain(data.risk)
        expect(r.metadata.found_file).toBe(true)
        expect(r.metadata.refused_fixture).toBe(false)

        const slug = await Operation.activeSlug(fixture.path)
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: slug, limit: 100 }))
        const ledger = await AppRuntime.runPromise(Cyber.listLedger({ operation_slug: slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "observation" &&
              item.entity_key === observation_id &&
              item.fact_name === "remediation_patch_scaffold",
          ),
        ).toBe(true)
        expect(ledger.some((item) => item.source === "remediate" && item.summary?.includes(observation_id))).toBe(true)
      },
    })
  })

  test("returns a clean error when the observation id is unknown", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        await seedWorkspace(fixture.path)
        const r: any = await exec({ observation_id: "obs_does_not_exist" })
        const data = JSON.parse(r.output)
        expect(data.error).toBe("observation_not_found")
        expect(typeof data.message).toBe("string")
        expect(r.metadata.found_file).toBe(false)
      },
    })
  })

  test("advice mode returns structured steps, no patch", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const { observation_id } = await seedWorkspace(fixture.path)
        const r: any = await exec({ observation_id, mode: "advice" })
        const data = JSON.parse(r.output)
        expect(data.patch).toBeUndefined()
        expect(Array.isArray(data.steps)).toBe(true)
        expect(data.steps.length).toBeGreaterThan(0)
        expect(Array.isArray(data.references)).toBe(true)
        expect(r.metadata.mode).toBe("advice")
        expect(r.metadata.found_file).toBe(false)
      },
    })
  })

  test("reads observations from projected cyber facts when the legacy store is absent", async () => {
    await using fixture = await tmpdir()
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Projected Remediate", kind: "appsec" })
        const srcDir = path.join(fixture.path, "src")
        await mkdir(srcDir, { recursive: true })
        await writeFile(path.join(srcDir, "app.js"), 'const password = "hunter2";\n', "utf8")
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "observation",
            entity_key: "obs_projected",
            fact_name: "record",
            value_json: {
              id: "obs_projected",
              subtype: "vuln",
              title: "Projected hardcoded credential",
              severity: "high",
              status: "confirmed",
              note: "see src/app.js:1",
              tags: ["secret"],
              evidence: ["src/app.js:1"],
              created_at: Date.now(),
              updated_at: Date.now(),
            },
            writer_kind: "tool",
            status: "verified",
            confidence: 1000,
          }),
        )

        const r: any = await exec({ observation_id: "obs_projected" })
        const data = JSON.parse(r.output)
        expect(data.observation_id).toBe("obs_projected")
        expect(data.file).toBe("src/app.js")
        expect(data.line).toBe(1)
        expect(r.metadata.found_file).toBe(true)
      },
    })
  })
})
