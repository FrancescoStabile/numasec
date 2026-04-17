import { z } from "zod"

export const NodeStatus = z.enum(["planned", "running", "done", "blocked", "skipped"])
export type NodeStatus = z.infer<typeof NodeStatus>

const base = z.object({
  at: z.number(),
  by: z.string().optional(),
})

export const Event = z.discriminatedUnion("type", [
  base.extend({
    type: z.literal("node_added"),
    id: z.string(),
    title: z.string(),
    parent_id: z.string().optional(),
    note: z.string().optional(),
  }),
  base.extend({
    type: z.literal("node_updated"),
    id: z.string(),
    title: z.string().optional(),
    status: NodeStatus.optional(),
    note: z.string().optional(),
  }),
  base.extend({
    type: z.literal("node_removed"),
    id: z.string(),
  }),
  base.extend({
    type: z.literal("node_moved"),
    id: z.string(),
    parent_id: z.string().optional(),
  }),
])

export type Event = z.infer<typeof Event>
