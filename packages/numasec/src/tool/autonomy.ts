import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./autonomy.txt"
import { Session } from "@/session"
import { Permission } from "@/permission"
import { Operation } from "@/core/operation"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["status", "set"]).default("status"),
  mode: z.enum(["permissioned", "auto"]).optional().describe("required when action = set"),
})

type Params = z.infer<typeof parameters>
type Metadata = {
  action: "status" | "set"
  mode?: "permissioned" | "auto" | "custom"
  rules?: number
}

function rulesForMode(mode: "permissioned" | "auto"): Permission.Ruleset {
  return [
    {
      permission: "*",
      pattern: "*",
      action: mode === "auto" ? "allow" : "ask",
    },
  ]
}

export function inferMode(ruleset?: Permission.Ruleset): "permissioned" | "auto" | "custom" {
  const wildcard = [...(ruleset ?? [])].reverse().find((rule) => rule.permission === "*" && rule.pattern === "*")
  if (!wildcard) return "custom"
  if (wildcard.action === "allow") return "auto"
  if (wildcard.action === "ask") return "permissioned"
  return "custom"
}

export const AutonomyTool = Tool.define<typeof parameters, Metadata, Session.Service>(
  "autonomy",
  Effect.gen(function* () {
    const session = yield* Session.Service

    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const current = yield* session.get(ctx.sessionID)
          const currentMode = inferMode(current.permission)

          if (params.action === "status") {
            return {
              title: `autonomy · ${currentMode}`,
              output: [
                `Autonomy mode: ${currentMode}`,
                `Rules: ${current.permission?.length ?? 0}`,
              ].join("\n"),
              metadata: {
                action: "status",
                mode: currentMode,
                rules: current.permission?.length ?? 0,
              },
            }
          }

          if (!params.mode) {
            return {
              title: "autonomy set",
              output: "Provide mode when action = set.",
              metadata: { action: "set", mode: currentMode, rules: current.permission?.length ?? 0 },
            }
          }

          yield* ctx.ask({
            permission: "autonomy",
            patterns: [params.mode],
            always: [params.mode],
            metadata: { mode: params.mode },
          })

          const permission = rulesForMode(params.mode)
          yield* session.setPermission({
            sessionID: ctx.sessionID,
            permission,
          })

          const workspace = Instance.directory
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))
          if (active) {
            const eventID = yield* Cyber.appendLedger({
              operation_slug: active.slug,
              kind: "fact.observed",
              source: "autonomy",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              summary: `autonomy set to ${params.mode}`,
              data: {
                mode: params.mode,
                rules: permission,
              },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: active.slug,
              entity_kind: "operation",
              entity_key: active.slug,
              fact_name: "autonomy_policy",
              value_json: {
                mode: params.mode,
                rules: permission,
                session_id: ctx.sessionID,
              },
              writer_kind: "operator",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          return {
            title: `autonomy · ${params.mode}`,
            output: `Autonomy mode set to ${params.mode}.`,
            metadata: {
              action: "set",
              mode: params.mode,
              rules: permission.length,
            },
          }
        }),
    }
  }),
)
