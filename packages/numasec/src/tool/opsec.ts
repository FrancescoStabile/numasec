import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./opsec.txt"
import { Operation } from "@/core/operation"
import { OPSEC_BLOCKLIST } from "@/core/boundary/guard"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"

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
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
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
            const level = params.level
            const boundary =
              (yield* Effect.promise(() => Operation.readBoundary(workspace, active.slug).catch(() => undefined))) ?? {
                default: "allow" as const,
                in_scope: [],
                out_of_scope: [],
              }
            yield* Cyber.upsertOperationState({
              slug: active.slug,
              label: updated?.label ?? active.label,
              kind: updated?.kind ?? active.kind,
              target: updated?.target ?? active.target,
              opsec: level,
              in_scope: boundary.in_scope,
              out_of_scope: boundary.out_of_scope,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              source: "opsec",
              summary: `opsec set to ${level}`,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            return {
              title: `opsec · ${level}`,
              output: formatStatus(
                updated ? { slug: updated.slug, label: updated.label, opsec: level } : undefined,
              ),
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
