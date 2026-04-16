// Operation — core primitive (scaffold for Sprint 2).
//
// An Operation is the top-level unit of security work in numasec. It is a
// neutral container (not "engagement" — that would be pentest-coded) that
// wraps 1..N LLM sessions, a kind, a subject, a boundary, a plan tree,
// observations, evidence, and a deliverable pipeline.
//
// This file only declares the type shape at v1. The full event-sourced store,
// JSONL persistence, and projection layer arrive in Sprint 2.

import { z } from "zod"
import type { KindId } from "../kind"

export namespace Operation {
  export const Id = z.string().min(1).brand("OperationId")
  export type Id = z.infer<typeof Id>

  // Subject is kind-dependent. At this layer we keep it loose.
  export const Subject = z
    .object({
      kind: z.enum(["security", "pentest", "appsec", "osint", "hacking"]),
      // Kind packs narrow this further.
      data: z.record(z.string(), z.unknown()).default({}),
    })
    .strict()
  export type Subject = z.infer<typeof Subject>

  // Boundary predicates live in kind packs. Core only stores a serialized form.
  export const Boundary = z
    .object({
      kind: z.enum(["security", "pentest", "appsec", "osint", "hacking"]),
      data: z.record(z.string(), z.unknown()).default({}),
    })
    .strict()
  export type Boundary = z.infer<typeof Boundary>

  // Free-form operational modes (pentest: opsec=stealth|noisy; appsec: depth=quick|deep; …).
  export const Mode = z.record(z.string(), z.string()).default({})
  export type Mode = z.infer<typeof Mode>

  export const Info = z
    .object({
      id: Id,
      kind: z.enum(["security", "pentest", "appsec", "osint", "hacking"]),
      slug: z.string(),
      label: z.string(),
      subject: Subject.optional(),
      boundary: Boundary.optional(),
      mode: Mode,
      sessions: z.array(z.string()).default([]),
      status: z.enum(["active", "archived", "exported"]).default("active"),
      created_at: z.number(),
      updated_at: z.number(),
    })
    .strict()
  export type Info = z.infer<typeof Info>

  export function dir(rootWorkspace: string, slug: string): string {
    // Filesystem layout: <workspace>/.numasec/operation/<slug>/
    // Implementation arrives in Sprint 2.
    return `${rootWorkspace}/.numasec/operation/${slug}`
  }

  export function kindOf(op: Info): KindId {
    return op.kind
  }
}
