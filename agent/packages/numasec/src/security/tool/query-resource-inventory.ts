import z from "zod"
import { eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { canonicalSecuritySessionID } from "../security-session"
import { summarizeResourceInventory } from "../resource-inventory-summary"
import { makeToolResultEnvelope } from "./result-envelope"

export const QueryResourceInventoryTool = Tool.define("query_resource_inventory", {
  description: "Summarize shared actor/resource inventory mined from auth, http, and access-control flows.",
  parameters: z.object({
    actor: z.string().optional().describe("Optional actor filter (matches label, id, email, or role)"),
    exposure: z.enum(["all", "self", "foreign", "unknown"]).optional().describe("Optional resource exposure filter"),
    limit: z.number().int().min(1).max(500).optional().describe("Maximum resource rows to include"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, sessionID))
        .orderBy(EvidenceNodeTable.time_created)
        .all(),
    )
    const summary = summarizeResourceInventory(rows, {
      actor: params.actor,
      exposure: params.exposure,
      limit: params.limit,
    })

    return {
      title: `Resource inventory: ${summary.metrics.resource_count} candidates`,
      metadata: {
        actorCount: summary.metrics.actor_count,
        resourceCount: summary.metrics.resource_count,
        actorGroups: summary.metrics.actor_groups,
        actionCount: summary.metrics.action_count,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "resource_inventory_query",
            actor_count: summary.metrics.actor_count,
            resource_count: summary.metrics.resource_count,
            actor_groups: summary.metrics.actor_groups,
            action_count: summary.metrics.action_count,
          },
        ],
        metrics: {
          actor_count: summary.metrics.actor_count,
          resource_count: summary.metrics.resource_count,
          actor_groups: summary.metrics.actor_groups,
          action_count: summary.metrics.action_count,
        },
      }),
      output: [
        `Actors: ${summary.metrics.actor_count}`,
        `Resource candidates: ${summary.metrics.resource_count}`,
        `Actor groups: ${summary.metrics.actor_groups}`,
        "",
        JSON.stringify(
          {
            actors: summary.actors,
            by_actor: summary.by_actor,
            resources: summary.resources,
          },
          null,
          2,
        ),
      ].join("\n"),
    }
  },
})
