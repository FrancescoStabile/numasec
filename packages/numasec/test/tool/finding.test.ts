import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Cyber } from "../../src/core/cyber"
import { Evidence } from "../../src/core/evidence"
import { Operation } from "../../src/core/operation"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { FindingTool } from "../../src/tool/finding"
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
      const info = yield* FindingTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/finding", () => {
  test("list separates reportable, suspected, and rejected findings", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Finding List", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-1111",
            fact_name: "container_vulnerability",
            value_json: { title: "Candidate vuln", severity: "medium" },
            writer_kind: "parser",
            status: "candidate",
            confidence: 600,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:CVE-2026-2222",
            fact_name: "record",
            value_json: { title: "Confirmed vuln", replay_present: true, oracle_status: "passed" },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["ev1"],
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-3333",
            fact_name: "container_vulnerability",
            value_json: { title: "Rejected vuln" },
            writer_kind: "parser",
            status: "rejected",
            confidence: 200,
          }),
        )

        const result: any = await exec({ action: "list" })
        expect(result.metadata.reportable_findings).toBe(1)
        expect(result.metadata.suspected_findings).toBe(1)
        expect(result.metadata.rejected_findings).toBe(1)
        expect(result.output).toContain("## Reportable Findings")
        expect(result.output).toContain("## Suspected Findings")
        expect(result.output).toContain("## Rejected Or Stale Findings")
        expect(result.output).toContain("Confirmed vuln")
        expect(result.output).toContain("Candidate vuln")
        expect(result.output).toContain("Rejected vuln")
      },
    })
  })

  test("promote turns a candidate into an evidence-backed verified finding with replay", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Finding", kind: "appsec" })
        const entry = await Evidence.put(fixture.path, op.slug, "seed evidence", {
          mime: "text/plain",
          label: "seed",
          source: "test",
        })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-0001",
            fact_name: "container_vulnerability",
            value_json: {
              title: "Outdated dependency",
              severity: "high",
              description: "A dependency is vulnerable.",
            },
            writer_kind: "parser",
            status: "candidate",
            confidence: 700,
            evidence_refs: [entry.sha256],
          }),
        )

        const result: any = await exec({
          action: "promote",
          key: "repo:CVE-2026-0001",
          summary: "Confirmed vulnerable package in shipped image",
          replay: "1. Pull image\n2. Run trivy image repo/app:latest\n3. Observe CVE-2026-0001",
        })

        expect(result.metadata.status).toBe("verified")
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "finding" &&
              item.entity_key === "repo:CVE-2026-0001" &&
              item.fact_name === "record" &&
              item.status === "verified",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "finding" &&
              item.entity_key === "repo:CVE-2026-0001" &&
              item.fact_name === "replay_bundle",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "finding" &&
              item.src_key === "repo:CVE-2026-0001" &&
              item.relation === "promotes" &&
              item.dst_kind === "finding_candidate",
          ),
        ).toBe(true)
      },
    })
  })

  test("list suppresses duplicate candidate entries once a verified finding with the same key exists", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Finding Dedup", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-dedup",
            fact_name: "container_vulnerability",
            value_json: { title: "Candidate dup", severity: "medium" },
            writer_kind: "parser",
            status: "candidate",
            confidence: 600,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:CVE-2026-dedup",
            fact_name: "record",
            value_json: { title: "Verified dup", replay_present: true, oracle_status: "passed" },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["ev1"],
          }),
        )

        const result: any = await exec({ action: "list" })
        expect(result.metadata.reportable_findings).toBe(1)
        expect(result.metadata.suspected_findings).toBe(0)
        expect(result.output).toContain("Verified dup")
        expect(result.output).not.toContain("Candidate dup")
      },
    })
  })

  test("status exposes structured replay exemption explicitly", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Finding Exempt", kind: "appsec" })
        const entry = await Evidence.put(fixture.path, op.slug, "seed evidence", {
          mime: "text/plain",
          label: "seed",
          source: "test",
        })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:manual-review",
            fact_name: "record",
            value_json: {
              title: "Manual review only",
              summary: "requires human-controlled target state",
              replay_present: false,
              replay_reason: "environment is ephemeral and operator-owned",
              replay_exemption: {
                category: "operator_controlled_state",
                rationale: "environment is ephemeral and operator-owned",
                domain: "appsec",
                approved_by_kind: "operator",
              },
              oracle_status: "passed",
            },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: [entry.sha256],
          }),
        )

        const result: any = await exec({
          action: "status",
          key: "repo:manual-review",
        })

        expect(result.metadata.replay_exempt).toBe(true)
        expect(result.metadata.replay_reason).toBe("environment is ephemeral and operator-owned")
        expect(result.output).toContain("replay: exempt")
        expect(result.output).toContain("replay_reason: environment is ephemeral and operator-owned")
      },
    })
  })

  test("promote rejects conflicting replay and replay_reason input", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Finding Replay Conflict", kind: "appsec" })
        const entry = await Evidence.put(fixture.path, op.slug, "seed evidence", {
          mime: "text/plain",
          label: "seed",
          source: "test",
        })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-conflict",
            fact_name: "container_vulnerability",
            value_json: {
              title: "Replay conflict",
              severity: "medium",
            },
            writer_kind: "parser",
            status: "candidate",
            confidence: 700,
            evidence_refs: [entry.sha256],
          }),
        )

        const result: any = await exec({
          action: "promote",
          key: "repo:CVE-2026-conflict",
          replay: "1. do thing",
          replay_reason: "not applicable",
        })

        expect(result.metadata.promoted).toBe(false)
        expect(result.metadata.invalid_replay_input).toBe(true)
        expect(result.output).toContain("either replay steps or replay exemption")
      },
    })
  })

  test("reject marks a candidate as rejected", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Reject", kind: "pentest" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "web:/admin:debug",
            fact_name: "passive_appsec_signal",
            value_json: { title: "Debug marker", description: "Likely false positive" },
            writer_kind: "parser",
            status: "candidate",
            confidence: 400,
          }),
        )

        const result: any = await exec({
          action: "reject",
          key: "web:/admin:debug",
          note: "marker is static text only",
        })

        expect(result.metadata.rejected).toBe(true)
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "finding_candidate" &&
              item.entity_key === "web:/admin:debug" &&
              item.status === "rejected",
          ),
        ).toBe(true)
      },
    })
  })
})
