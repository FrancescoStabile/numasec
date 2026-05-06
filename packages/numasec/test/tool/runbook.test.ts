import { describe, expect, test } from "bun:test"
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
import { RunbookTool } from "../../src/tool/runbook"
import path from "path"
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
      const info = yield* RunbookTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/runbook", () => {
  test("list exposes runbook readiness counts", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const result: any = await exec({ action: "list" })
        expect(result.metadata.action).toBe("list")
        expect(typeof result.metadata.ready).toBe("number")
        expect(typeof result.metadata.degraded).toBe("number")
        expect(typeof result.metadata.unavailable).toBe("number")
        expect(result.output).toContain("web-surface")
      },
    })
  })

  test("status writes capsule readiness into the cyber kernel when an operation is active", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Runbook Status", kind: "pentest" })
        const result: any = await exec({ action: "status", id: "web-surface" })
        expect(result.metadata.action).toBe("status")
        expect(result.metadata.id).toBe("web-surface")
        expect(typeof result.metadata.status).toBe("string")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const ledger = await AppRuntime.runPromise(Cyber.listLedger({ operation_slug: op.slug, limit: 200 }))

        expect(
          facts.some(
            (item) =>
              item.entity_kind === "runbook" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "capsule_readiness",
          ),
        ).toBe(true)
        expect(ledger.some((item) => item.source === "runbook" && item.summary?.includes("runbook status web-surface"))).toBe(true)
      },
    })
  })

  test("status without id suggests recommended runbooks for the active operation kind", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Runbook Recommendations", kind: "appsec" })
        const result: any = await exec({ action: "status" })
        expect(result.metadata.action).toBe("status")
        expect(Array.isArray(result.metadata.recommended)).toBe(true)
        expect(result.metadata.recommended).toContain("appsec-web-triage")
        expect(result.metadata.recommended).toContain("appsec-triage")
        expect(result.output).toContain("Active operation kind: appsec")
        expect(result.output).toContain("Recommended runbooks:")
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "runbook" &&
              item.entity_key === "appsec-triage" &&
              item.fact_name === "capsule_recommendation",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === op.slug &&
              item.relation === "recommends_runbook" &&
              item.dst_kind === "runbook" &&
              item.dst_key === "appsec-triage",
          ),
        ).toBe(true)
      },
    })
  })

  test("run writes execution plan into the cyber kernel when an operation is active", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Runbook", kind: "pentest" })
        const result: any = await exec({
          action: "run",
          id: "web-surface",
          args: { target: "https://example.com", domain: "example.com" },
        })
        expect(result.metadata.action).toBe("run")
        expect(result.metadata.id).toBe("web-surface")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        const ledger = await AppRuntime.runPromise(Cyber.listLedger({ operation_slug: op.slug, limit: 100 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        const workflowProjection = path.join(
          fixture.path,
          ".numasec",
          "operation",
          op.slug,
          "workflow",
          "runbook-web-surface.json",
        )
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "runbook" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "capsule_readiness",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "runbook" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "capsule_execution",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "runbook" &&
              item.entity_key === "web-surface" &&
              item.fact_name === "execution_plan",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "workflow_step" &&
              item.entity_key.startsWith("runbook:web-surface:planned:") &&
              item.fact_name === "planned_step",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "runbook" &&
              item.src_key === "web-surface" &&
              item.relation === "has_step" &&
              item.dst_kind === "workflow_step",
          ),
        ).toBe(true)
        expect(await Bun.file(workflowProjection).exists()).toBe(true)
        expect(ledger.some((item) => item.source === "runbook" && item.summary?.includes("web-surface"))).toBe(true)
      },
    })
  })
})
