import { describe, expect, test } from "bun:test"
import path from "path"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Bus } from "../../src/bus"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { saveVault } from "../../src/core/vault"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { MessageID, SessionID } from "../../src/session/schema"
import { Truncate } from "../../src/tool"
import { ReportTool } from "../../src/tool/report"
import { WorkspaceTool } from "../../src/tool/workspace"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    Session.defaultLayer,
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
      const info = yield* WorkspaceTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, baseCtx)
    }) as any,
  )
}

async function buildReport() {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* ReportTool
      const tool = yield* info.init()
      return yield* tool.execute({ action: "build", format: "md" } as any, baseCtx)
    }) as any,
  )
}

describe("tool/workspace", () => {
  test("start writes operation state into the cyber kernel immediately", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const result: any = await exec({
          action: "start",
          label: "Immediate State",
          kind: "appsec",
          target: "https://target.test",
        })
        const slug = String(result.metadata.slug)
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: slug, limit: 100 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: slug, limit: 100 }))

        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === slug &&
              item.fact_name === "operation_state",
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === slug &&
              item.relation === "targets" &&
              item.dst_key === "https://target.test",
          ),
        ).toBe(true)
      },
    })
  })

  test("rename updates the active operation label through the workspace tool", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const started: any = await exec({
          action: "start",
          label: "Original Name",
          kind: "pentest",
          target: "https://target.test",
        })
        const slug = String(started.metadata.slug)

        const result: any = await exec({
          action: "rename",
          label: "Renamed Operation",
        })
        const reread = await Operation.read(fixture.path, slug)
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: slug, limit: 100 }))

        expect(result.metadata.action).toBe("rename")
        expect(result.metadata.slug).toBe(slug)
        expect(reread?.label).toBe("Renamed Operation")
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === slug &&
              item.fact_name === "operation_state" &&
              (item.value_json as { label?: string }).label === "Renamed Operation",
          ),
        ).toBe(true)
      },
    })
  })

  test("graph_digest exposes relation counts and relation lines", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Digest", kind: "pentest" })
        const eventID = await AppRuntime.runPromise(
          Cyber.appendLedger({
            operation_slug: op.slug,
            kind: "fact.observed",
            source: "test",
            summary: "seed workspace digest",
            data: {},
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertRelation({
            operation_slug: op.slug,
            src_kind: "host",
            src_key: "api.example.test",
            relation: "serves",
            dst_kind: "http_route",
            dst_key: "GET /status",
            writer_kind: "parser",
            status: "observed",
            confidence: 900,
            source_event_id: eventID,
          }),
        )

        const result: any = await exec({ action: "graph_digest" })
        expect(result.metadata.action).toBe("graph_digest")
        expect(result.metadata.relations).toBeGreaterThan(0)
        expect(result.metadata.route_facts).toBe(0)
        expect(result.metadata.candidate_findings).toBe(0)
        expect(result.metadata.autonomy_mode).toBe("custom")
        expect(result.output).toContain("## Relations")
        expect(result.output).toContain("host:api.example.test -serves-> http_route:GET /status")
      },
    })
  })

  test("status reports kernel and workflow counts for the active operation", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const started: any = await exec({
          action: "start",
          label: "Status Counts",
          kind: "pentest",
          target: "https://target.test",
        })
        const slug = String(started.metadata.slug)
        const workflowDir = path.join(fixture.path, ".numasec", "operation", slug, "workflow")
        await Bun.write(
          path.join(workflowDir, "runbook-web-surface.json"),
          JSON.stringify({ kind: "runbook", id: "web-surface" }, null, 2),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "host",
            entity_key: "target.test",
            fact_name: "last_seen_url",
            value_json: "https://target.test",
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "service",
            entity_key: "target.test:443",
            fact_name: "transport",
            value_json: "https",
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "web_page",
            entity_key: "https://target.test/page",
            fact_name: "fetch_result",
            value_json: {
              url: "https://target.test/page",
              host: "target.test",
              preview: "hello",
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 900,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "finding",
            entity_key: "target.test:authz",
            fact_name: "record",
            value_json: {
              title: "Confirmed authz issue",
              summary: "reproducible by replay",
              replay_present: true,
              oracle_status: "passed",
            },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["sha256:evidence-authz"],
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "runbook",
            entity_key: "web-surface",
            fact_name: "capsule_readiness",
            value_json: {
              name: "Web Surface",
              status: "ready",
              missing_required: [],
              missing_optional: [],
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "runbook",
            entity_key: "api-surface",
            fact_name: "capsule_recommendation",
            value_json: {
              name: "API Surface",
              operation_kind: "pentest",
              status: "degraded",
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "knowledge_query",
            entity_key: "cve:openssl",
            fact_name: "cve_result",
            value_json: {
              query: "openssl",
              returned: 2,
              severity: "high",
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 900,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "tool_adapter",
            entity_key: "nmap",
            fact_name: "presence",
            value_json: { name: "nmap", present: true },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "tool_adapter",
            entity_key: "zap",
            fact_name: "presence",
            value_json: { name: "zap", present: false },
            writer_kind: "tool",
            status: "stale",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "vertical",
            entity_key: "pentest",
            fact_name: "readiness",
            value_json: { id: "pentest", status: "ready" },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "observation",
            entity_key: "obs_status",
            fact_name: "record",
            value_json: {
              id: "obs_status",
              subtype: "risk",
              title: "Projected observation",
              status: "open",
              evidence: [],
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )
        await saveVault({
          secrets: {
            alice: {
              value: "Bearer testing-token",
              updated_at: new Date().toISOString(),
            },
          },
          active_identity: "alice",
          active_identity_set_at: new Date().toISOString(),
        })
        await buildReport()
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: slug,
            entity_kind: "share_bundle",
            entity_key: "share-status.tar.gz",
            fact_name: "archive",
            value_json: {
              path: "/tmp/share-status.tar.gz",
              size: 2048,
              signed: false,
              redacted: true,
            },
            writer_kind: "tool",
            status: "verified",
            confidence: 1000,
          }),
        )
        const result: any = await exec({ action: "status" })
        expect(result.metadata.action).toBe("status")
        expect(result.metadata.slug).toBe(slug)
        expect(result.metadata.facts).toBeGreaterThan(0)
        expect(result.metadata.workflows).toBeGreaterThan(0)
        expect(result.metadata.autonomy_mode).toBe("custom")
        expect(result.metadata.active_identity).toBe("alice")
        expect(result.metadata.hosts).toBe(1)
        expect(result.metadata.services).toBe(1)
        expect(result.metadata.web_pages).toBe(1)
        expect(result.metadata.identities).toBe(1)
        expect(result.metadata.active_identities).toBe(1)
        expect(result.metadata.tool_adapters_present).toBe(1)
        expect(result.metadata.tool_adapters_missing).toBe(1)
        expect(result.metadata.knowledge_queries).toBe(1)
        expect(result.metadata.ready_verticals).toBe(1)
        expect(result.metadata.observations_projected).toBe(1)
        expect(result.metadata.ready_capsules).toBe(1)
        expect(result.metadata.recommended_capsules).toBe(1)
        expect(result.metadata.deliverables).toBeGreaterThanOrEqual(1)
        expect(result.metadata.share_bundles).toBe(1)
        expect(String(result.metadata.latest_deliverable_path)).toContain("report.md")
        expect(result.metadata.latest_share_bundle_path).toBe("/tmp/share-status.tar.gz")
        expect(result.metadata.reportable_findings).toBe(1)
        expect(result.metadata.suspected_findings).toBe(0)
        expect(result.metadata.rejected_findings).toBe(0)
        expect(result.metadata.verified_findings).toBe(1)
        expect(result.metadata.evidence_backed_findings).toBe(1)
        expect(result.metadata.replay_backed_findings).toBe(1)
        expect(result.output).toContain("Facts:")
        expect(result.output).toContain(
          "Surface entities: hosts=1 services=1 web_pages=1 routes=0 identities=1 active_identities=1",
        )
        expect(result.output).toContain("Projected observations: 1")
        expect(result.output).toContain("Tool adapters: present=1 missing=1")
        expect(result.output).toContain("Knowledge queries: 1")
        expect(result.output).toContain("Capsules: ready=1")
        expect(result.output).toContain("Verticals: ready=1 degraded=0 unavailable=0")
        expect(result.output).toContain("Workflows:")
        expect(result.output).toContain("Autonomy: custom")
        expect(result.output).toContain("Identity: alice")
        expect(result.output).toContain("Deliverables:")
        expect(result.output).toContain("Share bundles: 1")
        expect(result.output).toContain("Latest deliverable:")
        expect(result.output).toContain("Latest share bundle: /tmp/share-status.tar.gz")
        expect(result.output).toContain("Candidate findings:")
        expect(result.output).toContain("Reportable: 1")
        expect(result.output).toContain("Suspected: 0")
        expect(result.output).toContain("Rejected: 0")
        expect(result.output).toContain("Replay-backed: 1")
        expect(result.output).toContain("Evidence-backed: 1")
        const derived = await Operation.readContextPack(fixture.path, slug)
        expect(derived).toContain("# Active Operation Context")
        expect(derived).toContain(`slug: ${slug}`)
        expect(derived).toContain("## Findings")
        expect(derived).toContain("### Reportable")
      },
    })
  })

  test("tool wrapper updates the active workflow step outcome when workspace runs", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Workflow Step", kind: "pentest" })
        await Operation.writeWorkflow(fixture.path, op.slug, {
          kind: "play",
          id: "custom-play",
          payload: {
            trace: [{ kind: "tool", tool: "workspace", args: { action: "status" } }],
            skipped: [],
          },
        })
        await Operation.setActiveWorkflow(fixture.path, op.slug, { kind: "play", id: "custom-play" })

        await exec({ action: "status" })

        const workflow = await Operation.readWorkflow(fixture.path, op.slug, {
          kind: "play",
          id: "custom-play",
        })
        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        expect(Array.isArray(workflow?.trace)).toBe(true)
        expect((workflow?.trace as Array<any>)[0]?.outcome).toBe("completed")
        expect(workflow?.completed_steps).toBe(1)
        const status = facts.find(
          (item) =>
            item.entity_kind === "play" &&
            item.entity_key === "custom-play" &&
            item.fact_name === "workflow_status",
        )
        expect(status).toBeDefined()
        expect(JSON.stringify(status?.value_json)).toContain("\"completed_steps\":1")
        expect(JSON.stringify(status?.value_json)).toContain("\"pending_steps\":0")
        const stepStatus = facts.find(
          (item) =>
            item.entity_kind === "workflow_step" &&
            item.entity_key === "play:custom-play:planned:1" &&
            item.fact_name === "step_status",
        )
        expect(stepStatus).toBeDefined()
        expect(JSON.stringify(stepStatus?.value_json)).toContain("\"outcome\":\"completed\"")
        const statusView: any = await exec({ action: "status" })
        expect(statusView.metadata.active_workflow).toBe("custom-play")
        expect(statusView.metadata.completed_steps).toBe(1)
        expect(statusView.metadata.pending_steps).toBe(0)
        expect(statusView.metadata.workflow_step_statuses).toBe(1)
        expect(statusView.metadata.autonomy_mode).toBe("custom")
        expect(statusView.output).toContain("Progress: done=1")
        expect(statusView.output).toContain("Workflow steps:")
        expect(statusView.output).toContain("step 1 · completed")
      },
    })
  })
})
