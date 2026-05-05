import z from "zod"
import { Effect, Exit } from "effect"
import { readdir } from "node:fs/promises"
import path from "path"
import * as Tool from "./tool"
import { inferMode } from "./autonomy"
import { Operation, KINDS } from "@/core/operation"
import { Cyber } from "@/core/cyber"
import { activeIdentity } from "@/core/vault"
import type { OperationKind } from "@/core/operation"
import { Instance } from "@/project/instance"
import { Session } from "@/session"

const parameters = z.object({
  action: z.enum(["status", "list", "start", "graph_digest", "timeline"]).default("status"),
  label: z.string().optional().describe("Required when action = start"),
  kind: z.enum(KINDS as [string, ...string[]]).optional().describe("Required when action = start"),
  target: z.string().optional().describe("Optional target when action = start"),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

export const WorkspaceTool = Tool.define<typeof parameters, Metadata, Session.Service>(
  "workspace",
  Effect.gen(function* () {
    const session = yield* Session.Service
    return {
      description:
        "Manage the active security workspace. Use this to inspect the active operation, list operations, start a new one, inspect graph digest, or view the recent cyber timeline.",
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const workspace = Instance.directory

          if (params.action === "start") {
            if (!params.label || !params.kind) {
              return {
                title: "workspace start",
                output: "Provide both label and kind when action = start.",
                metadata: { action: "start" },
              }
            }
            const label = params.label
            const kind = params.kind as OperationKind
            yield* ctx.ask({
              permission: "workspace",
              patterns: [label],
              always: [],
              metadata: { action: "start", kind, target: params.target },
            })
            const info = yield* Effect.promise(() =>
              Operation.create({
                workspace,
                label,
                kind,
                target: params.target,
              }),
            )
            const boundary =
              (yield* Effect.promise(() => Operation.readBoundary(workspace, info.slug).catch(() => undefined))) ?? {
                default: "allow" as const,
                in_scope: [],
                out_of_scope: [],
              }
            yield* Cyber.upsertOperationState({
              slug: info.slug,
              label: info.label,
              kind: info.kind,
              target: info.target,
              opsec: info.opsec,
              in_scope: boundary.in_scope,
              out_of_scope: boundary.out_of_scope,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              source: "workspace",
              summary: `started operation ${info.slug}`,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertScopePolicy({
              operation_slug: info.slug,
              default: boundary.default === "allow" ? "allow" : "ask",
              in_scope: boundary.in_scope,
              out_of_scope: boundary.out_of_scope,
              opsec: info.opsec,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              source: "workspace",
              summary: `scope policy ${info.slug}`,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            return {
              title: `workspace · ${info.slug}`,
              output: `Started operation ${info.label} (${info.slug}) of kind ${info.kind}.`,
              metadata: { action: "start", slug: info.slug },
            }
          }

          if (params.action === "list") {
            const ops = yield* Effect.promise(() => Operation.list(workspace))
            const active = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
            const output =
              ops.length === 0
                ? "No operations."
                : ops
                    .map((op) => `${op.slug === active ? "*" : "-"} ${op.slug} · ${op.kind} · ${op.label}`)
                    .join("\n")
            return {
              title: "workspace · operations",
              output,
              metadata: { action: "list", count: ops.length },
            }
          }

          if (params.action === "graph_digest") {
            const sessionExit = yield* Effect.exit(session.get(ctx.sessionID))
            const sessionInfo = Exit.isFailure(sessionExit) ? undefined : sessionExit.value
            const autonomyMode = inferMode(sessionInfo?.permission)
            const identity = yield* Effect.promise(() => activeIdentity().catch(() => undefined)).pipe(
              Effect.catch(() => Effect.succeed(undefined)),
            )
            const [output, facts, relations] = yield* Effect.all([
              Cyber.contextPack(),
              Cyber.listFacts({ limit: 100 }).pipe(Effect.catch(() => Effect.succeed([]))),
              Cyber.listRelations({ limit: 100 }).pipe(Effect.catch(() => Effect.succeed([]))),
            ])
            const summary = Cyber.summarizeFacts(facts)
            return {
              title: "workspace · graph digest",
              output: output ?? "No active operation or no cyber context yet.",
              metadata: {
                action: "graph_digest",
                facts: facts.length,
                relations: relations.length,
                ...summary,
                autonomy_mode: autonomyMode,
                active_identity: identity?.key,
              },
            }
          }

          if (params.action === "timeline") {
            const events = yield* Cyber.listLedger({ limit: 30 })
            const output =
              events.length === 0
                ? "No cyber ledger events for the active operation."
                : events
                    .slice()
                    .reverse()
                    .map((event) => {
                      const summary = event.summary ?? JSON.stringify(event.data)
                      return `${new Date(event.time_created).toISOString()} · ${event.kind} · ${summary}`
                    })
                    .join("\n")
            return {
              title: "workspace · timeline",
              output,
              metadata: { action: "timeline", count: events.length },
            }
          }

          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))
          if (!active) {
            return {
              title: "workspace · no active operation",
              output: "No active operation.",
              metadata: { action: "status", active: false },
            }
          }
          const activeWorkflow = yield* Effect.promise(() =>
            Operation.activeWorkflow(workspace, active.slug).catch(() => undefined),
          )
          const sessionExit = yield* Effect.exit(session.get(ctx.sessionID))
          const sessionInfo = Exit.isFailure(sessionExit) ? undefined : sessionExit.value
          const autonomyMode = inferMode(sessionInfo?.permission)
          const identity = yield* Effect.promise(() => activeIdentity().catch(() => undefined)).pipe(
            Effect.catch(() => Effect.succeed(undefined)),
          )
          const workflow =
            !activeWorkflow
              ? undefined
              : yield* Effect.promise(() =>
                  Operation.readWorkflow(workspace, active.slug, activeWorkflow).catch(() => undefined),
                )
          const [digest, facts, relations, ledger, workflowFiles] = yield* Effect.all([
            Cyber.contextPack({ max_events: 8, max_facts: 12 }),
            Cyber.listFacts({ operation_slug: active.slug, limit: 200 }).pipe(Effect.catch(() => Effect.succeed([]))),
            Cyber.listRelations({ operation_slug: active.slug, limit: 200 }).pipe(Effect.catch(() => Effect.succeed([]))),
            Cyber.listLedger({ operation_slug: active.slug, limit: 200 }).pipe(Effect.catch(() => Effect.succeed([]))),
            Effect.promise(() =>
              readdir(path.join(workspace, ".numasec", "operation", active.slug, "workflow"), {
                withFileTypes: true,
              })
                .then((entries) => entries.filter((entry) => entry.isFile() && entry.name.endsWith(".json")).length)
                .catch(() => 0),
            ).pipe(Effect.catch(() => Effect.succeed(0))),
          ])
          const workflowStepFacts = facts
            .filter(
              (fact) =>
                fact.entity_kind === "workflow_step" &&
                fact.fact_name === "step_status" &&
                activeWorkflow &&
                fact.entity_key.startsWith(`${activeWorkflow.kind}:${activeWorkflow.id}:planned:`),
            )
            .sort((a, b) => {
              const ai = Number((a.value_json as { index?: number } | null)?.index ?? 0)
              const bi = Number((b.value_json as { index?: number } | null)?.index ?? 0)
              return ai - bi
            })
          const workflowStepLines = workflowStepFacts.slice(0, 12).map((fact) => {
            const value = (fact.value_json ?? {}) as {
              index?: number
              tool?: string
              label?: string
              outcome?: string
              outcome_title?: string
              outcome_error?: string
            }
            const descriptor = [value.label, value.tool ? `tool=${value.tool}` : undefined].filter(Boolean).join(" · ")
            const detail = value.outcome_title ?? value.outcome_error
            return `step ${Number(value.index ?? 0)} · ${value.outcome ?? "pending"}${descriptor ? ` · ${descriptor}` : ""}${detail ? ` · ${detail}` : ""}`
          })
          const summary = Cyber.summarizeFacts(facts)
          const identityCount = Math.max(summary.identities, identity ? 1 : 0)
          const activeIdentityCount = Math.max(summary.active_identities, identity ? 1 : 0)
          const latestDeliverable = Cyber.latestDeliverableFromFacts(facts)
          const latestShareBundle = Cyber.latestShareBundleFromFacts(facts)
          return {
            title: `workspace · ${active.slug}`,
            output: [
              `Active operation: ${active.label} (${active.slug})`,
              `Kind: ${active.kind}`,
              `Autonomy: ${autonomyMode}`,
              `Identity: ${identity?.key ?? "none"}`,
              `Facts: ${facts.length} · Relations: ${relations.length} · Ledger: ${ledger.length} · Workflows: ${workflowFiles}`,
              `Surface entities: hosts=${summary.hosts} services=${summary.services} web_pages=${summary.web_pages} routes=${summary.route_facts} identities=${identityCount} active_identities=${activeIdentityCount}`,
              `Plan nodes: ${summary.plan_nodes} · running=${summary.running_plan_nodes} done=${summary.done_plan_nodes}`,
              `Projected observations: ${summary.observations_projected}`,
              `Tool adapters: present=${summary.tool_adapters_present} missing=${summary.tool_adapters_missing}`,
              `Knowledge queries: ${summary.knowledge_queries}`,
              `Capsules: ready=${summary.ready_capsules} degraded=${summary.degraded_capsules} unavailable=${summary.unavailable_capsules} recommended=${summary.recommended_capsules} executed=${summary.executed_capsules}`,
              `Verticals: ready=${summary.ready_verticals} degraded=${summary.degraded_verticals} unavailable=${summary.unavailable_verticals}`,
              `Candidate findings: ${summary.candidate_findings} · Findings: ${summary.findings} · Reportable: ${summary.reportable_findings} · Suspected: ${summary.suspected_findings} · Rejected: ${summary.rejected_findings} · Deliverables: ${summary.deliverables} · Share bundles: ${summary.share_bundles} · Evidence-backed: ${summary.evidence_backed_findings} · Replay-backed: ${summary.replay_backed_findings} · Replay-exempt: ${summary.replay_exempt_findings}`,
              ...(latestDeliverable ? [`Latest deliverable: ${latestDeliverable.report_path ?? latestDeliverable.bundle_dir ?? latestDeliverable.key}`] : []),
              ...(latestShareBundle ? [`Latest share bundle: ${latestShareBundle.path ?? latestShareBundle.key}`] : []),
              ...(activeWorkflow
                ? [
                    `Active workflow: ${activeWorkflow.kind} ${activeWorkflow.id}`,
                    `Progress: done=${Number(workflow?.completed_steps ?? 0)} failed=${Number(workflow?.failed_steps ?? 0)} skipped=${Number(workflow?.skipped ?? 0)} pending=${Number(workflow?.pending_steps ?? 0)}`,
                    ...(workflowStepLines.length > 0 ? ["Workflow steps:", ...workflowStepLines] : []),
                  ]
                : []),
              "",
              digest ?? "_no cyber context yet_",
            ].join("\n"),
            metadata: {
              action: "status",
              slug: active.slug,
              kind: active.kind,
              active: true,
              facts: facts.length,
              relations: relations.length,
              ledger: ledger.length,
              workflows: workflowFiles,
              active_workflow: activeWorkflow?.id,
              completed_steps: Number(workflow?.completed_steps ?? 0),
              failed_steps: Number(workflow?.failed_steps ?? 0),
              pending_steps: Number(workflow?.pending_steps ?? 0),
              ...summary,
              identities: identityCount,
              active_identities: activeIdentityCount,
              autonomy_mode: autonomyMode,
              active_identity: identity?.key,
              latest_deliverable_path: latestDeliverable?.report_path ?? latestDeliverable?.bundle_dir,
              latest_share_bundle_path: latestShareBundle?.path,
            },
          }
        }),
    }
  }),
)
