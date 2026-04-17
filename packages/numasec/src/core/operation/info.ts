// Operation info (projected state).
//
// Rebuilt deterministically from the event stream. Any change must go through
// an event — no direct writes to the Info shape.

import { z } from "zod"
import type { Event } from "./events"

const KindId = z.enum(["security", "pentest", "appsec", "osint", "hacking"])

export const Info = z.object({
  id: z.string(),
  slug: z.string(),
  label: z.string(),
  kind: KindId,
  subject: z.record(z.string(), z.unknown()).optional(),
  boundary: z.record(z.string(), z.unknown()).optional(),
  mode: z.record(z.string(), z.string()).default({}),
  sessions: z.array(z.string()).default([]),
  status: z.enum(["active", "archived"]).default("active"),
  created_at: z.number(),
  updated_at: z.number(),
  deliverables: z
    .array(
      z.object({
        deliverable: z.string(),
        path: z.string(),
        at: z.number(),
      }),
    )
    .default([]),
})

export type Info = z.infer<typeof Info>

export function project(events: Event[]): Info | undefined {
  const first = events[0]
  if (!first || first.type !== "created") return undefined
  const info: Info = {
    id: first.id,
    slug: first.slug,
    label: first.label,
    kind: first.kind,
    mode: {},
    sessions: [],
    status: "active",
    created_at: first.at,
    updated_at: first.at,
    deliverables: [],
  }
  for (const e of events.slice(1)) {
    info.updated_at = e.at
    if (e.type === "renamed") info.label = e.label
    else if (e.type === "subject_set") info.subject = e.subject
    else if (e.type === "boundary_set") info.boundary = e.boundary
    else if (e.type === "mode_set") info.mode = e.mode
    else if (e.type === "session_attached") {
      if (!info.sessions.includes(e.session_id)) info.sessions.push(e.session_id)
    } else if (e.type === "archived") info.status = "archived"
    else if (e.type === "exported") info.deliverables.push({ deliverable: e.deliverable, path: e.path, at: e.at })
  }
  return info
}
