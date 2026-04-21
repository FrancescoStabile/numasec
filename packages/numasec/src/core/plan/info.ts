import { z } from "zod"
import type { Event, NodeStatus } from "./events"

export const Node = z.object({
  id: z.string(),
  title: z.string(),
  parent_id: z.string().optional(),
  status: z.enum(["planned", "running", "done", "blocked", "skipped"]),
  note: z.string().optional(),
  created_at: z.number(),
  updated_at: z.number(),
})
export type Node = z.infer<typeof Node>

export function project(events: Event[]): Node[] {
  const byId = new Map<string, Node>()
  const order: string[] = []
  for (const e of events) {
    if (e.type === "node_added") {
      if (byId.has(e.id)) continue
      byId.set(e.id, {
        id: e.id,
        title: e.title,
        parent_id: e.parent_id,
        status: "planned",
        note: e.note,
        created_at: e.at,
        updated_at: e.at,
      })
      order.push(e.id)
    } else if (e.type === "node_updated") {
      const n = byId.get(e.id)
      if (!n) continue
      if (e.title !== undefined) n.title = e.title
      if (e.status !== undefined) n.status = e.status
      if (e.note !== undefined) n.note = e.note
      n.updated_at = e.at
    } else if (e.type === "node_removed") {
      byId.delete(e.id)
      const i = order.indexOf(e.id)
      if (i >= 0) order.splice(i, 1)
    } else if (e.type === "node_moved") {
      const n = byId.get(e.id)
      if (!n) continue
      n.parent_id = e.parent_id
      n.updated_at = e.at
    }
  }
  return order.map((id) => byId.get(id)!).filter(Boolean)
}

export function progress(nodes: Node[]): { done: number; total: number; running: number; blocked: number } {
  return {
    done: nodes.filter((n) => n.status === "done").length,
    running: nodes.filter((n) => n.status === "running").length,
    blocked: nodes.filter((n) => n.status === "blocked").length,
    total: nodes.length,
  }
}

export type { NodeStatus }
