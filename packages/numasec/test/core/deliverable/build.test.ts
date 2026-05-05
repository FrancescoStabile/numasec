import { describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import path from "node:path"
import { Deliverable } from "../../../src/core/deliverable"
import { Operation } from "../../../src/core/operation"
import { tmpdir } from "../../fixture/fixture"

describe("core/deliverable", () => {
  test("build includes projected cyber state in the report and manifest counts", async () => {
    await using fixture = await tmpdir()
    const op = await Operation.create({
      workspace: fixture.path,
      label: "Deliverable",
      kind: "appsec",
      target: "https://target.test",
    })
    const opDir = Operation.opDir(fixture.path, op.slug)
    await fs.mkdir(path.join(opDir, "cyber"), { recursive: true })
    await fs.writeFile(
      path.join(opDir, "cyber", "facts.jsonl"),
      [
        JSON.stringify({
          entity_kind: "operation",
          entity_key: op.slug,
          fact_name: "operation_state",
          status: "observed",
          value_json: {
            label: "Deliverable",
            kind: "appsec",
            target: "https://target.test",
            opsec: "strict",
            in_scope: ["target.test"],
            out_of_scope: ["cdn.target.test"],
          },
        }),
        JSON.stringify({
          entity_kind: "operation",
          entity_key: op.slug,
          fact_name: "autonomy_policy",
          status: "observed",
          value_json: {
            mode: "permissioned",
          },
        }),
        JSON.stringify({
          entity_kind: "operation",
          entity_key: op.slug,
          fact_name: "scope_policy",
          status: "observed",
          value_json: {
            default: "ask",
            in_scope: ["target.test"],
            out_of_scope: ["cdn.target.test"],
            opsec: "strict",
          },
        }),
        JSON.stringify({
          entity_kind: "operation",
          entity_key: op.slug,
          fact_name: "plan_summary",
          status: "observed",
          value_json: {
            total: 2,
            done: 1,
            running: 1,
            blocked: 0,
            planned: 0,
          },
        }),
        JSON.stringify({
          entity_kind: "plan_node",
          entity_key: "pn_root",
          fact_name: "todo_state",
          status: "observed",
          value_json: {
            title: "Recon target",
            status: "done",
          },
        }),
        JSON.stringify({
          entity_kind: "plan_node",
          entity_key: "pn_child",
          fact_name: "todo_state",
          status: "observed",
          value_json: {
            title: "Validate authz hypothesis",
            parent_id: "pn_root",
            status: "running",
          },
        }),
        JSON.stringify({
          entity_kind: "knowledge_query",
          entity_key: "cve:openssl",
          fact_name: "cve_result",
          status: "observed",
          value_json: {
            query: "openssl",
            severity: "high",
            returned: 2,
          },
        }),
        JSON.stringify({
          entity_kind: "tool_adapter",
          entity_key: "nmap",
          fact_name: "presence",
          status: "observed",
          value_json: {
            present: true,
            path: "/usr/bin/nmap",
            version: "7.95",
          },
        }),
        JSON.stringify({
          entity_kind: "tool_adapter",
          entity_key: "zap",
          fact_name: "presence",
          status: "stale",
          value_json: {
            present: false,
          },
        }),
        JSON.stringify({
          entity_kind: "vertical",
          entity_key: "active-web-testing",
          fact_name: "readiness",
          status: "observed",
          value_json: {
            status: "ready",
            missing_required: [],
            missing_optional: ["Semgrep"],
          },
        }),
        JSON.stringify({
          entity_kind: "vertical",
          entity_key: "cloud-posture",
          fact_name: "readiness",
          status: "stale",
          value_json: {
            status: "unavailable",
            missing_required: ["Prowler"],
            missing_optional: [],
          },
        }),
        JSON.stringify({
          entity_kind: "observation",
          entity_key: "obs_1",
          fact_name: "record",
          status: "verified",
          value_json: {
            id: "obs_1",
            subtype: "vuln",
            title: "Projected SQL injection",
            severity: "critical",
            confidence: 0.95,
            status: "confirmed",
            note: "Verified through replay.",
            tags: ["web"],
            evidence: ["sha256:obs1"],
            created_at: Date.now(),
            updated_at: Date.now(),
          },
        }),
        JSON.stringify({
          entity_kind: "finding_candidate",
          entity_key: "target.test:CVE-2026-1000",
          fact_name: "container_vulnerability",
          status: "candidate",
          value_json: {
            title: "Outdated package",
            description: "Candidate issue",
            severity: "high",
          },
        }),
        JSON.stringify({
          entity_kind: "finding",
          entity_key: "target.test:CVE-2026-1000",
          fact_name: "record",
          status: "verified",
          value_json: {
            title: "Confirmed vulnerable package",
            summary: "Reachable in shipped image",
            severity: "high",
            replay_present: true,
            oracle_status: "passed",
          },
          evidence_refs: ["sha256:build-evidence-1"],
        }),
        JSON.stringify({
          entity_kind: "runbook",
          entity_key: "appsec-triage",
          fact_name: "capsule_readiness",
          status: "observed",
          value_json: {
            name: "AppSec Triage",
            status: "ready",
            missing_required: [],
            missing_optional: ["Semgrep"],
          },
        }),
        JSON.stringify({
          entity_kind: "runbook",
          entity_key: "container-surface",
          fact_name: "capsule_recommendation",
          status: "observed",
          value_json: {
            name: "Container Surface",
            operation_kind: "appsec",
            status: "degraded",
          },
        }),
        JSON.stringify({
          entity_kind: "runbook",
          entity_key: "appsec-triage",
          fact_name: "capsule_execution",
          status: "observed",
          value_json: {
            name: "AppSec Triage",
            status: "ready",
            invoked_via: "runbook",
            steps: 2,
            skipped: 0,
          },
        }),
        JSON.stringify({
          entity_kind: "runbook",
          entity_key: "appsec-triage",
          fact_name: "workflow_status",
          status: "observed",
          value_json: {
            steps: 2,
            skipped: 0,
            completed_steps: 1,
            failed_steps: 0,
            pending_steps: 1,
            degraded: false,
          },
        }),
        JSON.stringify({
          entity_kind: "workflow_step",
          entity_key: "runbook:appsec-triage:planned:1",
          fact_name: "step_status",
          status: "observed",
          value_json: {
            index: 1,
            tool: "scanner",
            label: "crawl target",
            outcome: "completed",
            outcome_title: "scanner complete",
          },
        }),
        "",
      ].join("\n"),
    )
    await fs.writeFile(
      path.join(opDir, "cyber", "ledger.jsonl"),
      [
        JSON.stringify({
          id: "evt_1",
          kind: "tool.completed",
          source: "scanner",
          status: "completed",
          summary: "scanner complete",
          time_created: Date.now(),
        }),
        "",
      ].join("\n"),
    )
    await fs.writeFile(
      path.join(opDir, "cyber", "relations.jsonl"),
      [
        JSON.stringify({
          src_kind: "host",
          src_key: "target.test",
          relation: "serves",
          dst_kind: "http_route",
          dst_key: "GET /api/items",
          status: "observed",
          confidence: 900,
        }),
        "",
      ].join("\n"),
    )

    const built = await Deliverable.build(fixture.path, op.slug)
    const report = await fs.readFile(built.reportPath, "utf8")
    const reportJSON = JSON.parse(await fs.readFile(path.join(built.bundleDir, "report.json"), "utf8"))

    expect(report).toContain("## Operation State")
    expect(report).toContain("## Plan")
    expect(report).toContain("[done] Recon target")
    expect(report).toContain("[running] Validate authz hypothesis")
    expect(report).toContain("opsec: `strict`")
    expect(report).toContain("autonomy: `permissioned`")
    expect(report).toContain("in_scope: `target.test`")
    expect(report).toContain("out_of_scope: `cdn.target.test`")
    expect(report).toContain("## Cyber Findings")
    expect(report).toContain("## Knowledge")
    expect(report).toContain("## Observations")
    expect(report).toContain("Projected SQL injection")
    expect(report).toContain("### Reportable Findings")
    expect(report).toContain("### Suspected Findings")
    expect(report).toContain("## Capsules")
    expect(report).toContain("### Readiness")
    expect(report).toContain("### Recommendations")
    expect(report).toContain("### Executions")
    expect(report).toContain("via=`runbook`")
    expect(report).toContain("## Deliverables")
    expect(report).toContain(`report=\`${built.reportPath}\``)
    expect(report).toContain("evidence_backed=1")
    expect(report).toContain("## Cyber Workflows")
    expect(report).toContain("## Cyber Timeline")
    expect(report).toContain("## Cyber Relations")
    expect(report).toContain("Confirmed vulnerable package")
    expect(report).not.toContain("Outdated package")
    expect(report).toContain("AppSec Triage")
    expect(report).toContain("container-surface")
    expect(report).toContain("cve:openssl")
    expect(report).toContain("## Tool Adapters")
    expect(report).toContain("### Present")
    expect(report).toContain("### Missing")
    expect(report).toContain("nmap")
    expect(report).toContain("zap")
    expect(report).toContain("## Verticals")
    expect(report).toContain("active-web-testing")
    expect(report).toContain("cloud-posture")
    expect(report).toContain("runbook:appsec-triage")
    expect(report).toContain("tool.completed")
    expect(report).toContain("## Cyber Relations")
    expect(report).toContain("_empty_")
    expect(reportJSON.operation_state.opsec).toBe("strict")
    expect(reportJSON.scope_policy.default).toBe("ask")
    expect(reportJSON.autonomy_policy.mode).toBe("permissioned")
    expect(reportJSON.tool_adapters).toHaveLength(2)
    expect(reportJSON.verticals).toHaveLength(2)
    expect(reportJSON.identities).toHaveLength(0)
    expect(reportJSON.summary.identities).toBe(0)
    expect(reportJSON.summary.active_identities).toBe(0)
    expect(reportJSON.deliverables).toHaveLength(1)
    expect(reportJSON.deliverables[0].bundle_dir).toBe(built.bundleDir)
    expect(reportJSON.share_bundles).toHaveLength(0)
    expect(built.manifest.counts.cyber_findings).toBe(2)
    expect(built.manifest.counts.observations_projected).toBe(1)
    expect(built.manifest.counts.knowledge_queries).toBe(1)
    expect(built.manifest.counts.identities).toBe(0)
    expect(built.manifest.counts.active_identities).toBe(0)
    expect(built.manifest.counts.tool_adapters_present).toBe(1)
    expect(built.manifest.counts.tool_adapters_missing).toBe(1)
    expect(built.manifest.counts.capsules).toBe(1)
    expect(built.manifest.counts.recommended_capsules).toBe(1)
    expect(built.manifest.counts.ready_capsules).toBe(1)
    expect(built.manifest.counts.degraded_capsules).toBe(0)
    expect(built.manifest.counts.unavailable_capsules).toBe(0)
    expect(built.manifest.counts.executed_capsules).toBe(1)
    expect(built.manifest.counts.ready_verticals).toBe(1)
    expect(built.manifest.counts.degraded_verticals).toBe(0)
    expect(built.manifest.counts.unavailable_verticals).toBe(1)
    expect(built.manifest.counts.reportable_findings).toBe(1)
    expect(built.manifest.counts.suspected_findings).toBe(0)
    expect(built.manifest.counts.rejected_findings).toBe(0)
    expect(built.manifest.counts.verified_findings).toBe(1)
    expect(built.manifest.counts.evidence_backed_findings).toBe(1)
    expect(built.manifest.counts.replay_backed_findings).toBe(1)
    expect(built.manifest.counts.relations_projected).toBe(0)
    expect(built.manifest.counts.workflows).toBe(1)
    expect(built.manifest.counts.completed_steps).toBe(1)
    expect(built.manifest.counts.ledger_events).toBe(1)
    expect(built.manifest.counts.context_artifacts).toBe(1)
    expect(built.manifest.counts.scope_policy_facts).toBe(1)
    expect(built.manifest.counts.operation_state_facts).toBe(1)
    expect(built.manifest.counts.autonomy_policy_facts).toBe(1)
  })
})
