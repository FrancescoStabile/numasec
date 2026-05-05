import { Effect } from "effect"
import z from "zod"
import * as Tool from "./tool"
import DESCRIPTION from "./observation.txt"
import { Observation } from "@/core/observation"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["add", "list", "status", "update", "link_evidence", "remove"]).default("list"),
  id: z.string().optional().describe("Observation id for status/update/link_evidence/remove"),
  subtype: z.enum(["vuln", "code-smell", "intel-fact", "flag", "ioc", "control-gap", "risk"]).optional(),
  title: z.string().optional(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
  confidence: z.number().min(0).max(1).optional(),
  status: z.enum(["open", "triaged", "confirmed", "resolved", "false-positive"]).optional(),
  note: z.string().optional(),
  tags: z.array(z.string()).optional(),
  evidence: z.string().optional().describe("Evidence ref to link when action = link_evidence"),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

function formatObservation(item: Observation.Observation) {
  return [
    `id: ${item.id}`,
    `subtype: ${item.subtype}`,
    `title: ${item.title}`,
    item.severity ? `severity: ${item.severity}` : undefined,
    item.confidence != null ? `confidence: ${item.confidence}` : undefined,
    `status: ${item.status}`,
    item.note ? `note: ${item.note}` : undefined,
    item.tags.length > 0 ? `tags: ${item.tags.join(", ")}` : undefined,
    item.evidence.length > 0 ? `evidence: ${item.evidence.join(", ")}` : undefined,
  ]
    .filter(Boolean)
    .join("\n")
}

async function readActiveSlug(workspace: string) {
  return Operation.activeSlug(workspace).catch(() => undefined)
}

export const ObservationTool = Tool.define<typeof parameters, Metadata, never>(
  "observation",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => readActiveSlug(workspace))
          if (!slug) {
            return {
              title: "observation · no active operation",
              output: "No active operation.",
              metadata: { action: params.action, active: false },
            }
          }

          if (params.action === "add") {
            if (!params.subtype || !params.title) {
              return {
                title: "observation add",
                output: "Provide subtype and title.",
                metadata: { action: "add", slug },
              }
            }
            const subtype = params.subtype
            const title = params.title
            const item = yield* Effect.promise(() =>
              Observation.add(workspace, slug, {
                subtype,
                title,
                severity: params.severity,
                confidence: params.confidence,
                note: params.note,
                tags: params.tags,
              }),
            )
            return {
              title: `observation · ${item.id}`,
              output: formatObservation(item),
              metadata: { action: "add", slug, id: item.id, status: item.status },
            }
          }

          const projectedItems = yield* Effect.promise(() => Observation.listProjected(workspace, slug)).pipe(
            Effect.catch(() => Effect.succeed([])),
          )
          const items = projectedItems.length > 0 ? projectedItems : yield* Effect.promise(() => Observation.list(workspace, slug))

          if (params.action === "list") {
            const counts = Observation.severityCounts(items)
            const output =
              items.length === 0
                ? "No observations."
                : [
                    `total=${items.length} critical=${counts.critical} high=${counts.high} medium=${counts.medium} low=${counts.low} info=${counts.info} unrated=${counts.none}`,
                    "",
                    ...items.map(
                      (item) =>
                        `- ${item.id} · ${item.subtype} · ${item.status}${item.severity ? ` · ${item.severity}` : ""} · ${item.title}`,
                    ),
                  ].join("\n")
            return {
              title: `observation · ${items.length}`,
              output,
              metadata: { action: "list", slug, count: items.length, counts },
            }
          }

          if (!params.id) {
            return {
              title: `observation ${params.action}`,
              output: "Provide id for this action.",
              metadata: { action: params.action, slug },
            }
          }

          const item = items.find((entry) => entry.id === params.id)
          if (!item) {
            return {
              title: `observation · ${params.id}`,
              output: "Observation not found.",
              metadata: { action: params.action, slug, id: params.id, found: false },
            }
          }

          if (params.action === "status") {
            return {
              title: `observation · ${item.id}`,
              output: formatObservation(item),
              metadata: { action: "status", slug, id: item.id, found: true, status: item.status },
            }
          }

          if (params.action === "link_evidence") {
            if (!params.evidence) {
              return {
                title: `observation link_evidence · ${item.id}`,
                output: "Provide evidence ref.",
                metadata: { action: "link_evidence", slug, id: item.id, found: true },
              }
            }
            yield* Effect.promise(() => Observation.linkEvidence(workspace, slug, item.id, params.evidence!))
            const updated =
              (yield* Effect.promise(() => Observation.getProjected(workspace, slug, item.id)).pipe(
                Effect.catch(() => Effect.succeed(undefined)),
              )) ??
              (yield* Effect.promise(() => Observation.list(workspace, slug))).find((entry) => entry.id === item.id) ??
              item
            return {
              title: `observation · ${updated.id}`,
              output: formatObservation(updated),
              metadata: { action: "link_evidence", slug, id: updated.id, evidence: params.evidence },
            }
          }

          if (params.action === "remove") {
            yield* Effect.promise(() => Observation.remove(workspace, slug, item.id))
            return {
              title: `observation removed · ${item.id}`,
              output: `Removed observation ${item.id}.`,
              metadata: { action: "remove", slug, id: item.id, removed: true },
            }
          }

          yield* Effect.promise(() =>
            Observation.update(workspace, slug, item.id, {
              title: params.title,
              severity: params.severity,
              confidence: params.confidence,
              status: params.status,
              note: params.note,
              tags: params.tags,
            }),
          )
          const updated =
            (yield* Effect.promise(() => Observation.getProjected(workspace, slug, item.id)).pipe(
              Effect.catch(() => Effect.succeed(undefined)),
            )) ??
            (yield* Effect.promise(() => Observation.list(workspace, slug))).find((entry) => entry.id === item.id) ??
            item
          return {
            title: `observation · ${updated.id}`,
            output: formatObservation(updated),
            metadata: { action: "update", slug, id: updated.id, status: updated.status },
          }
        }),
    }
  }),
)
