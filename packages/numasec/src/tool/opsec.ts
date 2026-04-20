import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./opsec.txt"
import { Operation } from "@/core/operation"
import { OPSEC_BLOCKLIST } from "@/core/boundary/guard"

const parameters = z.object({
  action: z.enum(["status", "set"]).default("status").describe("status returns current level; set writes it"),
  level: z.enum(["normal", "strict"]).optional().describe("required when action = set"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  active_op?: string
  opsec: "normal" | "strict"
  action: "status" | "set"
}

function formatStatus(active: { slug: string; label: string; opsec: "normal" | "strict" } | undefined): string {
  if (!active) return "No active operation. Start one with /pwn first."
  const lines = [
    `Active op: ${active.label} (${active.slug})`,
    `Opsec: ${active.opsec}`,
    "",
    "Blocked 3rd-party intel hosts (when strict):",
    ...OPSEC_BLOCKLIST.map((h) => `  - ${h}`),
  ]
  if (active.opsec === "strict") {
    lines.push("", "Strict mode: unmatched boundary decisions default to DENY (localhost excluded).")
  }
  return lines.join("\n")
}

export const OpsecTool = Tool.define<typeof parameters, Metadata, never>(
  "opsec",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const workspace = process.cwd()
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))

          if (params.action === "set") {
            if (!params.level) {
              return {
                title: "opsec: level required",
                output: "Provide level: \"normal\" or \"strict\" when action = set.",
                metadata: { opsec: active?.opsec ?? "normal", action: "set" as const, active_op: active?.slug },
              }
            }
            if (!active) {
              return {
                title: "opsec: no active operation",
                output: "No active operation to update. Start one with /pwn first.",
                metadata: { opsec: "normal" as const, action: "set" as const },
              }
            }
            yield* Effect.promise(() => Operation.setOpsec(workspace, active.slug, params.level!))
            const updated = yield* Effect.promise(() => Operation.read(workspace, active.slug))
            const level = updated?.opsec ?? params.level
            return {
              title: `opsec · ${level}`,
              output: formatStatus(updated ? { slug: updated.slug, label: updated.label, opsec: updated.opsec } : undefined),
              metadata: { opsec: level, action: "set" as const, active_op: active.slug },
            }
          }

          return {
            title: `opsec · ${active?.opsec ?? "normal"}`,
            output: formatStatus(active ? { slug: active.slug, label: active.label, opsec: active.opsec } : undefined),
            metadata: {
              opsec: active?.opsec ?? "normal",
              action: "status" as const,
              active_op: active?.slug,
            },
          }
        }),
    }
  }),
)
