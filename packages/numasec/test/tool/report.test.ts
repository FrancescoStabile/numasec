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
import { ReportTool } from "../../src/tool/report"
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
      const info = yield* ReportTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

describe("tool/report", () => {
  test("build creates a deliverable bundle and records it in the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Report", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "tool_adapter",
            entity_key: "nmap",
            fact_name: "presence",
            value_json: {
              present: true,
              path: "/usr/bin/nmap",
              version: "7.95",
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "vertical",
            entity_key: "active-web-testing",
            fact_name: "readiness",
            value_json: {
              status: "ready",
              missing_required: [],
              missing_optional: ["Semgrep"],
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "runbook",
            entity_key: "appsec-triage",
            fact_name: "capsule_execution",
            value_json: {
              name: "AppSec Triage",
              status: "ready",
              invoked_via: "runbook",
              steps: 3,
              skipped: 1,
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:CVE-2026-9999",
            fact_name: "record",
            value_json: {
              title: "Confirmed vulnerable package",
              summary: "reproducible",
              replay_present: true,
              oracle_status: "passed",
            },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["sha256:seed-report-evidence"],
          }),
        )

        const result: any = await exec({ action: "build" })
        expect(result.metadata.counts.cyber_findings).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.reportable_findings).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.verified_findings).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.evidence_backed_findings).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.identities).toBeGreaterThanOrEqual(0)
        expect(result.metadata.counts.active_identities).toBeGreaterThanOrEqual(0)
        expect(result.metadata.counts.tool_adapters_present).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.executed_capsules).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.ready_verticals).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.context_artifacts).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.scope_policy_facts).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.operation_state_facts).toBeGreaterThanOrEqual(1)
        expect(result.metadata.counts.autonomy_policy_facts).toBeGreaterThanOrEqual(0)
        expect(result.output).toContain("reportable_findings=")
        expect(result.output).toContain("verified_findings=")
        expect(result.output).toContain("evidence_backed_findings=")
        expect(result.output).toContain("identities=")
        expect(result.output).toContain("active_identities=")
        expect(result.output).toContain("tool_adapters_present=")
        expect(result.output).toContain("executed_capsules=")
        expect(result.output).toContain("ready_verticals=")
        expect(result.output).toContain("context_artifacts=")
        expect(result.output).toContain("scope_policy_facts=")
        expect(result.output).toContain("operation_state_facts=")
        expect(result.output).toContain("autonomy_policy_facts=")

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "deliverable" &&
              item.fact_name === "report_bundle" &&
              item.status === "verified",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === op.slug &&
              item.relation === "exports" &&
              item.dst_kind === "deliverable",
          ),
        ).toBe(true)
      },
    })
  })

  test("status reports the latest generated bundle", async () => {
    await using fixture = await tmpdir({ git: true })
    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        await Operation.create({ workspace: fixture.path, label: "Report Status", kind: "pentest" })
        await exec({ action: "build" })
        const status: any = await exec({ action: "status" })
        expect(status.metadata.available).toBe(true)
        expect(status.metadata.source).toBe("kernel")
        expect(String(status.metadata.bundle_dir)).toContain("bundle-")
        expect(status.output).toContain("Manifest:")
        expect(status.output).toContain("reportable_findings=")
        expect(status.output).toContain("ledger_events=")
        expect(status.output).toContain("evidence_backed_findings=")
        expect(status.output).toContain("identities=")
        expect(status.output).toContain("active_identities=")
        expect(status.output).toContain("tool_adapters_present=")
        expect(status.output).toContain("executed_capsules=")
        expect(status.output).toContain("ready_verticals=")
        expect(status.output).toContain("context_artifacts=")
        expect(status.output).toContain("scope_policy_facts=")
        expect(status.output).toContain("operation_state_facts=")
        expect(status.output).toContain("autonomy_policy_facts=")
      },
    })
  })
})
