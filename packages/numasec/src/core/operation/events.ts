// Operation event schemas.
//
// An Operation is a purely event-sourced entity: the canonical form lives in
// events.jsonl (append-only), and meta.json is a best-effort snapshot of the
// latest projection for fast reads.

import { z } from "zod"

const KindId = z.enum(["pentest", "appsec", "osint", "hacking", "bughunt", "ctf", "research"])

const base = z.object({
  at: z.number(), // Unix ms timestamp.
  by: z.string().optional(), // Operator identity (future).
})

export const Event = z.discriminatedUnion("type", [
  base.extend({
    type: z.literal("created"),
    id: z.string(),
    slug: z.string(),
    label: z.string(),
    kind: KindId,
  }),
  base.extend({
    type: z.literal("renamed"),
    label: z.string(),
  }),
  base.extend({
    type: z.literal("subject_set"),
    subject: z.record(z.string(), z.unknown()),
  }),
  base.extend({
    type: z.literal("boundary_set"),
    boundary: z.record(z.string(), z.unknown()),
  }),
  base.extend({
    type: z.literal("mode_set"),
    mode: z.record(z.string(), z.string()),
  }),
  base.extend({
    type: z.literal("session_attached"),
    session_id: z.string(),
  }),
  base.extend({
    type: z.literal("archived"),
  }),
  base.extend({
    type: z.literal("exported"),
    deliverable: z.string(),
    path: z.string(),
  }),
])

export type Event = z.infer<typeof Event>
export type EventType = Event["type"]
