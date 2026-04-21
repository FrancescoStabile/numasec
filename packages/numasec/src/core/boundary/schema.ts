import { z } from "zod"

export const BoundaryMode = z.enum(["allow", "deny", "ask"])
export type BoundaryMode = z.infer<typeof BoundaryMode>

export const Boundary = z.object({
  default: BoundaryMode.default("ask"),
  in_scope: z.array(z.string()).default([]),
  out_of_scope: z.array(z.string()).default([]),
})
export type Boundary = z.infer<typeof Boundary>

export const Decision = z.object({
  mode: BoundaryMode,
  reason: z.string(),
  matched: z.string().optional(),
})
export type Decision = z.infer<typeof Decision>

export const Request = z.object({
  kind: z.enum(["url", "path", "host", "raw"]),
  value: z.string(),
})
export type Request = z.infer<typeof Request>
