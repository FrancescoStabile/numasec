import { z } from "zod"

export const Subtype = z.enum([
  "vuln",
  "code-smell",
  "intel-fact",
  "flag",
  "ioc",
  "control-gap",
  "risk",
])
export type Subtype = z.infer<typeof Subtype>

export const Severity = z.enum(["info", "low", "medium", "high", "critical"])
export type Severity = z.infer<typeof Severity>

export const Status = z.enum(["open", "triaged", "confirmed", "resolved", "false-positive"])
export type Status = z.infer<typeof Status>

const base = z.object({ at: z.number(), by: z.string().optional() })

export const Event = z.discriminatedUnion("type", [
  base.extend({
    type: z.literal("observation_added"),
    id: z.string(),
    subtype: Subtype,
    title: z.string(),
    severity: Severity.optional(),
    confidence: z.number().min(0).max(1).optional(),
    note: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }),
  base.extend({
    type: z.literal("observation_updated"),
    id: z.string(),
    title: z.string().optional(),
    severity: Severity.optional(),
    confidence: z.number().min(0).max(1).optional(),
    status: Status.optional(),
    note: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }),
  base.extend({ type: z.literal("observation_removed"), id: z.string() }),
  base.extend({
    type: z.literal("observation_evidence_linked"),
    id: z.string(),
    evidence: z.string(),
  }),
])

export type Event = z.infer<typeof Event>
