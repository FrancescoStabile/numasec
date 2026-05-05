import { describe, expect, test } from "bun:test"
import path from "path"
import { Instance } from "../../../src/project/instance"
import { Operation } from "../../../src/core/operation"
import { Cyber } from "../../../src/core/cyber"
import { AppRuntime } from "../../../src/effect/app-runtime"
import { tmpdir } from "../../fixture/fixture"

describe("core/cyber", () => {
  test("listRelations and contextPack expose derived graph relations", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Cyber", kind: "pentest" })
        const eventID = await AppRuntime.runPromise(
          Cyber.appendLedger({
            operation_slug: op.slug,
            kind: "fact.observed",
            source: "test",
            summary: "seed relation",
            data: { seeded: true },
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "host",
            entity_key: "api.example.test",
            fact_name: "resolved",
            value_json: { ip: "127.0.0.1" },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertRelation({
            operation_slug: op.slug,
            src_kind: "host",
            src_key: "api.example.test",
            relation: "serves",
            dst_kind: "http_route",
            dst_key: "GET /health",
            writer_kind: "parser",
            status: "observed",
            confidence: 900,
            source_event_id: eventID,
          }),
        )

        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 20 }))
        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_relations: 20 }))

        expect(relations).toHaveLength(1)
        expect(relations[0]?.src_kind).toBe("host")
        expect(relations[0]?.relation).toBe("serves")
        expect(pack).toContain("## Relations")
        expect(pack).toContain("host:api.example.test -serves-> http_route:GET /health")
      },
    })
  })

  test("syncWorkflowProgress materializes per-step status facts", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Workflow Graph", kind: "pentest" })
        await AppRuntime.runPromise(
          Cyber.upsertWorkflowTrace({
            operation_slug: op.slug,
            workflow_kind: "play",
            workflow_id: "web-surface",
            fact_name: "execution_trace",
            args: { target: "https://target.test" },
            trace: [
              { kind: "tool", label: "Status", tool: "workspace", args: { action: "status" } },
              { kind: "tool", label: "Timeline", tool: "workspace", args: { action: "timeline" } },
            ],
            skipped: [],
            available: true,
            degraded: false,
            source: "test",
          }),
        )
        await AppRuntime.runPromise(
          Cyber.syncWorkflowProgress({
            operation_slug: op.slug,
            workflow_kind: "play",
            workflow_id: "web-surface",
            trace: [
              {
                kind: "tool",
                label: "Status",
                tool: "workspace",
                args: { action: "status" },
                outcome: "completed",
                outcome_title: "workspace status",
              },
              {
                kind: "tool",
                label: "Timeline",
                tool: "workspace",
                args: { action: "timeline" },
              },
            ],
            skipped: [],
            completed_steps: 1,
            failed_steps: 0,
            pending_steps: 1,
            source: "test",
          }),
        )

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        const completed = facts.find(
          (item) =>
            item.entity_kind === "workflow_step" &&
            item.entity_key === "play:web-surface:planned:1" &&
            item.fact_name === "step_status",
        )
        const pending = facts.find(
          (item) =>
            item.entity_kind === "workflow_step" &&
            item.entity_key === "play:web-surface:planned:2" &&
            item.fact_name === "step_status",
        )

        expect(JSON.stringify(completed?.value_json)).toContain("\"outcome\":\"completed\"")
        expect(JSON.stringify(completed?.value_json)).toContain("\"outcome_title\":\"workspace status\"")
        expect(JSON.stringify(pending?.value_json)).toContain("\"outcome\":\"pending\"")
        expect(pack).toContain("## Workflow Steps")
        expect(pack).toContain("step 1 · completed")
        expect(pack).toContain("step 2 · pending")
      },
    })
  })

  test("writes JSONL projections for ledger, facts, and relations under the operation", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Projection", kind: "pentest" })
        const eventID = await AppRuntime.runPromise(
          Cyber.appendLedger({
            operation_slug: op.slug,
            kind: "fact.observed",
            source: "test",
            summary: "projection seed",
            data: { seeded: true },
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "operation",
            entity_key: op.slug,
            fact_name: "operation_state",
            value_json: { label: "Projection" },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertRelation({
            operation_slug: op.slug,
            src_kind: "operation",
            src_key: op.slug,
            relation: "targets",
            dst_kind: "target",
            dst_key: "https://target.test",
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
          }),
        )

        const cyberDir = path.join(tmp.path, ".numasec", "operation", op.slug, "cyber")
        const ledger = await Bun.file(path.join(cyberDir, "ledger.jsonl")).text()
        const facts = await Bun.file(path.join(cyberDir, "facts.jsonl")).text()
        const relations = await Bun.file(path.join(cyberDir, "relations.jsonl")).text()

        expect(ledger).toContain("\"summary\":\"projection seed\"")
        expect(facts).toContain("\"fact_name\":\"operation_state\"")
        expect(relations).toContain("\"relation\":\"targets\"")
      },
    })
  })

  test("readProjectedFacts and readProjectedLedger hydrate projected cyber JSONL consistently", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Projected Reads", kind: "pentest" })
        const cyberDir = path.join(tmp.path, ".numasec", "operation", op.slug, "cyber")
        await Bun.write(
          path.join(cyberDir, "facts.jsonl"),
          [
            JSON.stringify({
              entity_kind: "finding_candidate",
              entity_key: "repo:CVE-2026-9999",
              fact_name: "container_vulnerability",
              status: "candidate",
              value_json: { title: "Candidate vuln" },
            }),
            "",
          ].join("\n"),
        )
        await Bun.write(
          path.join(cyberDir, "ledger.jsonl"),
          [
            JSON.stringify({
              id: "evt_1",
              operation_slug: op.slug,
              kind: "fact.observed",
              source: "test",
              summary: "seed projected ledger",
              data: { seeded: true },
              time_created: 123,
            }),
            "",
          ].join("\n"),
        )

        const [facts, ledger] = await Promise.all([
          Cyber.readProjectedFacts(tmp.path, op.slug),
          Cyber.readProjectedLedger(tmp.path, op.slug),
        ])

        expect(facts).toHaveLength(1)
        expect(facts[0]?.entity_kind).toBe("finding_candidate")
        expect(facts[0]?.entity_key).toBe("repo:CVE-2026-9999")
        expect(ledger).toHaveLength(1)
        expect(ledger[0]?.id).toBe("evt_1")
        expect(ledger[0]?.summary).toBe("seed projected ledger")
      },
    })
  })

  test("readProjectedRelations hydrates projected relation JSONL consistently", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Projected Relations", kind: "pentest" })
        const cyberDir = path.join(tmp.path, ".numasec", "operation", op.slug, "cyber")
        await Bun.write(
          path.join(cyberDir, "relations.jsonl"),
          [
            JSON.stringify({
              src_kind: "host",
              src_key: "api.example.test",
              relation: "serves",
              dst_kind: "http_route",
              dst_key: "GET /health",
              status: "observed",
            }),
            "",
          ].join("\n"),
        )

        const relations = await Cyber.readProjectedRelations(tmp.path, op.slug)

        expect(relations).toHaveLength(1)
        expect(relations[0]?.src_kind).toBe("host")
        expect(relations[0]?.relation).toBe("serves")
        expect(relations[0]?.dst_key).toBe("GET /health")
      },
    })
  })

  test("readProjectedState assembles a shared kernel-first snapshot from projected cyber files", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Projected State", kind: "appsec" })
        const opDir = path.join(tmp.path, ".numasec", "operation", op.slug)
        const cyberDir = path.join(opDir, "cyber")
        await Bun.write(
          path.join(cyberDir, "facts.jsonl"),
          [
            JSON.stringify({
              entity_kind: "finding_candidate",
              entity_key: "cand_1",
              fact_name: "record",
              status: "candidate",
              value_json: { title: "Candidate issue", severity: "high" },
            }),
            JSON.stringify({
              entity_kind: "knowledge_query",
              entity_key: "cve:openssl",
              fact_name: "cve_result",
              status: "observed",
              value_json: { query: "openssl", returned: 2 },
            }),
            JSON.stringify({
              entity_kind: "tool_adapter",
              entity_key: "nmap",
              fact_name: "presence",
              status: "observed",
              value_json: { name: "nmap", present: true, path: "/usr/bin/nmap" },
            }),
            JSON.stringify({
              entity_kind: "vertical",
              entity_key: "pentest",
              fact_name: "readiness",
              status: "observed",
              value_json: { id: "pentest", status: "ready", missing_required: [] },
            }),
            JSON.stringify({
              entity_kind: "runbook",
              entity_key: "appsec-triage",
              fact_name: "capsule_readiness",
              status: "observed",
              value_json: { name: "AppSec Triage", status: "ready", missing_required: [] },
            }),
            JSON.stringify({
              entity_kind: "deliverable",
              entity_key: "bundle-1",
              fact_name: "report_bundle",
              status: "verified",
              value_json: {
                bundle_dir: "/tmp/bundle-1",
                report_path: "/tmp/bundle-1/report.md",
                manifest_path: "/tmp/bundle-1/manifest.json",
                counts: { reportable_findings: 1 },
              },
            }),
            JSON.stringify({
              entity_kind: "share_bundle",
              entity_key: "share-1.tar.gz",
              fact_name: "archive",
              status: "verified",
              value_json: {
                path: "/tmp/share-1.tar.gz",
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                redacted: true,
                signed: false,
              },
            }),
            JSON.stringify({
              entity_kind: "workflow_step",
              entity_key: "runbook:appsec-triage:planned:1",
              fact_name: "step_status",
              status: "observed",
              value_json: { index: 1, tool: "scanner", outcome: "completed" },
            }),
            "",
          ].join("\n"),
        )
        await Bun.write(
          path.join(cyberDir, "relations.jsonl"),
          [
            JSON.stringify({
              src_kind: "host",
              src_key: "target.test",
              relation: "serves",
              dst_kind: "http_route",
              dst_key: "GET /health",
              status: "observed",
            }),
            "",
          ].join("\n"),
        )
        await Bun.write(
          path.join(cyberDir, "ledger.jsonl"),
          [
            JSON.stringify({
              id: "evt_1",
              operation_slug: op.slug,
              kind: "tool.completed",
              source: "scanner",
              summary: "scanner complete",
              time_created: 123,
            }),
            "",
          ].join("\n"),
        )

        const projected = await Cyber.readProjectedState(tmp.path, op.slug)

        expect(projected.findings).toHaveLength(1)
        expect(projected.findings[0]?.title).toBe("Candidate issue")
        expect(projected.knowledge).toHaveLength(1)
        expect(projected.tool_adapters).toHaveLength(1)
        expect(projected.tool_adapters[0]?.key).toBe("nmap")
        expect(projected.verticals).toHaveLength(1)
        expect(projected.verticals[0]?.key).toBe("pentest")
        expect(projected.capsules).toHaveLength(1)
        expect(projected.deliverables).toHaveLength(1)
        expect(projected.deliverables[0]?.report_path).toBe("/tmp/bundle-1/report.md")
        expect(projected.share_bundles).toHaveLength(1)
        expect(projected.share_bundles[0]?.sha256).toBe(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        expect(projected.workflow_steps).toHaveLength(1)
        expect(projected.relations).toHaveLength(1)
        expect(projected.timeline).toHaveLength(1)
        expect(projected.summary.candidate_findings).toBe(1)
        expect(projected.summary.knowledge_queries).toBe(1)
        expect(projected.summary.ready_capsules).toBe(1)
        expect(projected.summary.workflow_step_statuses).toBe(1)
      },
    })
  })

  test("summarizeFacts derives stable graph counters from cyber facts", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Summary", kind: "pentest" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "cand_1",
            fact_name: "record",
            value_json: { title: "Candidate issue" },
            writer_kind: "tool",
            status: "candidate",
            confidence: 700,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "find_1",
            fact_name: "record",
            value_json: { title: "Verified issue", replay_present: true, oracle_status: "passed" },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["ev1"],
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "observation",
            entity_key: "obs_1",
            fact_name: "record",
            value_json: { title: "Observation", removed: false },
            writer_kind: "tool",
            status: "observed",
            confidence: 900,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
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
            operation_slug: op.slug,
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
            operation_slug: op.slug,
            entity_kind: "vertical",
            entity_key: "pentest",
            fact_name: "readiness",
            value_json: { id: "pentest", status: "ready" },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 50 }))
        const summary = Cyber.summarizeFacts(facts)

        expect(summary.hosts).toBe(0)
        expect(summary.services).toBe(0)
        expect(summary.web_pages).toBe(0)
        expect(summary.identities).toBe(1)
        expect(summary.active_identities).toBe(1)
        expect(summary.tool_adapters_present).toBe(1)
        expect(summary.tool_adapters_missing).toBe(1)
        expect(summary.candidate_findings).toBe(1)
        expect(summary.findings).toBe(1)
        expect(summary.ready_verticals).toBe(1)
        expect(summary.verified_findings).toBe(1)
        expect(summary.evidence_backed_findings).toBe(1)
        expect(summary.reportable_findings).toBe(1)
        expect(summary.replay_backed_findings).toBe(1)
        expect(summary.observations_projected).toBe(1)
      },
    })
  })

  test("contextPack exposes candidate and promoted findings explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Findings", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding_candidate",
            entity_key: "repo:CVE-2026-1234",
            fact_name: "container_vulnerability",
            value_json: {
              title: "Candidate package CVE",
              description: "candidate only",
              severity: "high",
            },
            writer_kind: "parser",
            status: "candidate",
            confidence: 700,
          }),
        )
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:CVE-2026-1234",
            fact_name: "record",
            value_json: {
              title: "Confirmed package CVE",
              summary: "confirmed by replay",
              severity: "high",
              replay_present: true,
              oracle_status: "passed",
            },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["ev1"],
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Findings")
        expect(pack).toContain("### Reportable")
        expect(pack).toContain("### Suspected")
        expect(pack).toContain("Candidate package CVE")
        expect(pack).toContain("Confirmed package CVE")
        expect(pack).toContain("replay=present")
      },
    })
  })

  test("contextPack exposes persisted knowledge queries explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Knowledge Context", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "knowledge_query",
            entity_key: "cve:openssl",
            fact_name: "cve_result",
            value_json: {
              query: "openssl",
              severity: "high",
              returned: 2,
              results: [{ id: "CVE-2026-1000", severity: "high" }],
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 900,
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Knowledge")
        expect(pack).toContain("cve:openssl")
        expect(pack).toContain("returned=2")
      },
    })
  })

  test("contextPack exposes projected observations explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Observation Context", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "observation",
            entity_key: "obs_1",
            fact_name: "record",
            value_json: {
              id: "obs_1",
              subtype: "vuln",
              title: "Confirmed XSS",
              severity: "high",
              confidence: 0.9,
              status: "confirmed",
              evidence: ["sha256:obs1"],
            },
            writer_kind: "tool",
            status: "verified",
            confidence: 1000,
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Observations")
        expect(pack).toContain("Confirmed XSS")
        expect(pack).toContain("evidence=1")
      },
    })
  })

  test("contextPack marks replay-exempt findings explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Replay Exempt", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "finding",
            entity_key: "repo:manual-review",
            fact_name: "record",
            value_json: {
              title: "Manual review only",
              summary: "verified by source review",
              replay_present: false,
              replay_reason: "target state is operator-controlled",
              replay_exemption: {
                category: "operator_controlled_state",
                rationale: "target state is operator-controlled",
                domain: "appsec",
                approved_by_kind: "operator",
              },
              oracle_status: "passed",
            },
            writer_kind: "operator",
            status: "verified",
            confidence: 1000,
            evidence_refs: ["ev1"],
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("replay=exempt")
        expect(pack).toContain("replay_reason=target state is operator-controlled")
      },
    })
  })

  test("contextPack exposes deliverables explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Deliverables", kind: "appsec" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "deliverable",
            entity_key: "bundle-1",
            fact_name: "report_bundle",
            value_json: {
              report_path: "/tmp/report.md",
              counts: {
                plan: 1,
                observations: 2,
                evidence: 3,
                cyber_findings: 4,
                reportable_findings: 1,
                evidence_backed_findings: 1,
                replay_exempt_findings: 1,
              },
            },
            writer_kind: "tool",
            status: "verified",
            confidence: 1000,
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Deliverables")
        expect(pack).toContain("bundle-1")
        expect(pack).toContain("cyber_findings=4")
        expect(pack).toContain("reportable_findings=1")
        expect(pack).toContain("evidence_backed_findings=1")
        expect(pack).toContain("replay_exempt_findings=1")
      },
    })
  })

  test("contextPack exposes tool adapters and vertical readiness explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Inventory Context", kind: "pentest" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
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
            operation_slug: op.slug,
            entity_kind: "vertical",
            entity_key: "pentest",
            fact_name: "readiness",
            value_json: { id: "pentest", status: "ready" },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Tool Adapters")
        expect(pack).toContain("nmap")
        expect(pack).toContain("## Verticals")
        expect(pack).toContain("pentest")
      },
    })
  })

  test("contextPack exposes share bundles explicitly", async () => {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const op = await Operation.create({ workspace: tmp.path, label: "Shares", kind: "pentest" })
        await AppRuntime.runPromise(
          Cyber.upsertFact({
            operation_slug: op.slug,
            entity_kind: "share_bundle",
            entity_key: "share-123.tar.gz",
            fact_name: "archive",
            value_json: {
              path: "/tmp/share-123.tar.gz",
              size: 1234,
              signed: false,
              redacted: true,
            },
            writer_kind: "tool",
            status: "verified",
            confidence: 1000,
          }),
        )

        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 50 }))
        expect(pack).toContain("## Share Bundles")
        expect(pack).toContain("share-123.tar.gz")
        expect(pack).toContain("redacted=yes")
      },
    })
  })
})
