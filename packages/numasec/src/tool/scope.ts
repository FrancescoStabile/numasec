import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import { Operation } from "@/core/operation"
import { OPSEC_BLOCKLIST } from "@/core/boundary/guard"
import { Cyber } from "@/core/cyber"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z.enum(["status", "set"]).default("status"),
  level: z.enum(["normal", "strict"]).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = Record<string, unknown>

function syncScopeState(input: {
  slug: string
  label: string
  kind: string
  target?: string
  opsec: "normal" | "strict"
  in_scope: string[]
  out_of_scope: string[]
  session_id: Tool.Context["sessionID"]
  message_id: Tool.Context["messageID"]
  summary: string
}) {
  return Effect.gen(function* () {
    yield* Cyber.upsertOperationState({
      slug: input.slug,
      label: input.label,
      kind: input.kind,
      target: input.target,
      opsec: input.opsec,
      in_scope: input.in_scope,
      out_of_scope: input.out_of_scope,
      session_id: input.session_id,
      message_id: input.message_id,
      source: "scope",
      summary: input.summary,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertScopePolicy({
      operation_slug: input.slug,
      default: input.in_scope.length === 0 && input.out_of_scope.length === 0 ? "allow" : "ask",
      in_scope: input.in_scope,
      out_of_scope: input.out_of_scope,
      opsec: input.opsec,
      session_id: input.session_id,
      message_id: input.message_id,
      source: "scope",
      summary: input.summary,
    }).pipe(Effect.catch(() => Effect.succeed("")))
  })
}

function outputFor(
  active:
    | {
        slug: string
        label: string
        opsec: "normal" | "strict"
        in_scope: string[]
        out_of_scope: string[]
      }
    | undefined,
) {
  if (!active) return "No active operation."
  return [
    `Active operation: ${active.label} (${active.slug})`,
    `Scope mode: ${active.opsec}`,
    `In scope: ${active.in_scope.length}`,
    `Out of scope: ${active.out_of_scope.length}`,
    ...active.in_scope.map((item) => `- in: ${item}`),
    ...active.out_of_scope.map((item) => `- out: ${item}`),
    "",
    "Strict mode blocklist:",
    ...OPSEC_BLOCKLIST.map((host) => `- ${host}`),
  ].join("\n")
}

export const ScopeTool = Tool.define<typeof parameters, Metadata, never>(
  "scope",
  Effect.gen(function* () {
    return {
      description:
        "Inspect or change scope enforcement for the active operation. This wraps the current operation opsec control behind the future-facing scope surface.",
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const workspace = Instance.directory
          const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))
          const boundary =
            !active
              ? { default: "allow" as const, in_scope: [], out_of_scope: [] }
              : (yield* Effect.promise(() => Operation.readBoundary(workspace, active.slug).catch(() => undefined))) ?? {
                  default: "allow" as const,
                  in_scope: [],
                  out_of_scope: [],
                }
          const activeView = !active
            ? undefined
            : {
                slug: active.slug,
                label: active.label,
                opsec: active.opsec,
                in_scope: boundary.in_scope,
                out_of_scope: boundary.out_of_scope,
              }

          if (params.action === "set") {
            if (!params.level) {
              return {
                title: "scope set",
                output: "Provide level when action = set.",
                metadata: { action: "set" },
              }
            }
            if (!active) {
              return {
                title: "scope set",
                output: "No active operation.",
                metadata: { action: "set", active: false },
              }
            }
            yield* Effect.promise(() => Operation.setOpsec(workspace, active.slug, params.level!))
            const updated = yield* Effect.promise(() => Operation.read(workspace, active.slug))
            const level = params.level
            const updatedBoundary =
              (yield* Effect.promise(() => Operation.readBoundary(workspace, active.slug).catch(() => undefined))) ?? {
                default: "allow" as const,
                in_scope: [],
                out_of_scope: [],
              }
            yield* syncScopeState({
              slug: active.slug,
              label: updated?.label ?? active.label,
              kind: updated?.kind ?? active.kind,
              target: updated?.target ?? active.target,
              opsec: level,
              in_scope: updatedBoundary.in_scope,
              out_of_scope: updatedBoundary.out_of_scope,
              summary: `scope mode set to ${level}`,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            return {
              title: `scope · ${level}`,
              output: outputFor(
                updated
                  ? {
                      slug: updated.slug,
                      label: updated.label,
                      opsec: level,
                      in_scope: updatedBoundary.in_scope,
                      out_of_scope: updatedBoundary.out_of_scope,
                    }
                  : undefined,
              ),
              metadata: { action: "set", level, slug: active.slug },
            }
          }

          if (active) {
            yield* syncScopeState({
              slug: active.slug,
              label: active.label,
              kind: active.kind,
              target: active.target,
              opsec: active.opsec,
              in_scope: boundary.in_scope,
              out_of_scope: boundary.out_of_scope,
              summary: `scope status ${active.slug}`,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          return {
            title: `scope · ${active?.opsec ?? "normal"}`,
            output: outputFor(activeView),
            metadata: { action: "status", level: active?.opsec ?? "normal", slug: active?.slug },
          }
        }),
    }
  }),
)
