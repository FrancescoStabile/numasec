import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { ObservationTool } from "../../src/tool/observation"
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
      const info = yield* ObservationTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/observation", () => {
  test("add and list manage observations for the active operation", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Observation", kind: "appsec" })
        const added: any = await exec({
          action: "add",
          subtype: "vuln",
          title: "Leaked debug endpoint",
          severity: "medium",
          confidence: 0.7,
          note: "Found during crawl.",
          tags: ["web", "debug"],
        })

        expect(added.metadata.status).toBe("open")
        const listed: any = await exec({ action: "list" })
        expect(listed.metadata.count).toBe(1)
        expect(listed.output).toContain("Leaked debug endpoint")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "observation" &&
              item.fact_name === "record" &&
              item.entity_key === added.metadata.id,
          ),
        ).toBe(true)
      },
    })
  })

  test("update and link_evidence keep observation state readable", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        await Operation.create({ workspace: fixture.path, label: "Observation Update", kind: "pentest" })
        const added: any = await exec({
          action: "add",
          subtype: "risk",
          title: "Suspicious admin panel",
        })
        const id = String(added.metadata.id)

        const updated: any = await exec({
          action: "update",
          id,
          status: "confirmed",
          severity: "high",
          note: "Confirmed with manual replay.",
        })
        expect(updated.metadata.status).toBe("confirmed")
        expect(updated.output).toContain("severity: high")

        const linked: any = await exec({
          action: "link_evidence",
          id,
          evidence: "sha256:obs-proof",
        })
        expect(linked.output).toContain("sha256:obs-proof")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ limit: 100 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ limit: 100 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "observation" &&
              item.entity_key === id &&
              item.fact_name === "record" &&
              item.status === "verified",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "observation" &&
              item.src_key === id &&
              item.relation === "supported_by" &&
              item.dst_kind === "evidence_artifact",
          ),
        ).toBe(true)
      },
    })
  })
})
