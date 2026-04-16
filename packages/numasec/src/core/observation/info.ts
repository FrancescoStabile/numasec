import { z } from "zod"
import { Severity, Status, Subtype, type Event } from "./events"

export const Observation = z.object({
  id: z.string(),
  subtype: Subtype,
  title: z.string(),
  severity: Severity.optional(),
  confidence: z.number().min(0).max(1).optional(),
  status: Status.default("open"),
  note: z.string().optional(),
  tags: z.array(z.string()).default([]),
  evidence: z.array(z.string()).default([]),
  created_at: z.number(),
  updated_at: z.number(),
})
export type Observation = z.infer<typeof Observation>

export function project(events: Event[]): Observation[] {
  const byId = new Map<string, Observation>()
  const order: string[] = []
  for (const e of events) {
    if (e.type === "observation_added") {
      if (byId.has(e.id)) continue
      byId.set(e.id, {
        id: e.id,
        subtype: e.subtype,
        title: e.title,
        severity: e.severity,
        confidence: e.confidence,
        status: "open",
        note: e.note,
        tags: e.tags ?? [],
        evidence: [],
        created_at: e.at,
        updated_at: e.at,
      })
      order.push(e.id)
    } else if (e.type === "observation_updated") {
      const o = byId.get(e.id)
      if (!o) continue
      if (e.title !== undefined) o.title = e.title
      if (e.severity !== undefined) o.severity = e.severity
      if (e.confidence !== undefined) o.confidence = e.confidence
      if (e.status !== undefined) o.status = e.status
      if (e.note !== undefined) o.note = e.note
      if (e.tags !== undefined) o.tags = e.tags
      o.updated_at = e.at
    } else if (e.type === "observation_removed") {
      byId.delete(e.id)
      const i = order.indexOf(e.id)
      if (i >= 0) order.splice(i, 1)
    } else if (e.type === "observation_evidence_linked") {
      const o = byId.get(e.id)
      if (!o) continue
      if (!o.evidence.includes(e.evidence)) o.evidence.push(e.evidence)
      o.updated_at = e.at
    }
  }
  return order.map((id) => byId.get(id)!).filter(Boolean)
}

export function severityCounts(items: Observation[]): Record<Severity, number> & { none: number } {
  const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0, none: 0 }
  for (const o of items) {
    if (!o.severity) out.none++
    else out[o.severity]++
  }
  return out
}

export type { Severity, Status, Subtype }
