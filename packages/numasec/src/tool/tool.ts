import z from "zod"
import { Effect, Exit } from "effect"
import type { MessageV2 } from "../session/message-v2"
import type { Permission } from "../permission"
import type { SessionID, MessageID } from "../session/schema"
import * as Truncate from "./truncate"
import { Agent } from "@/agent/agent"
import { Cyber } from "@/core/cyber"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

interface Metadata {
  [key: string]: any
}

// TODO: remove this hack
export type DynamicDescription = (agent: Agent.Info) => Effect.Effect<string>

export type Context<M extends Metadata = Metadata> = {
  sessionID: SessionID
  messageID: MessageID
  agent: string
  abort: AbortSignal
  callID?: string
  extra?: { [key: string]: any }
  messages: MessageV2.WithParts[]
  metadata(input: { title?: string; metadata?: M }): Effect.Effect<void>
  ask(input: Omit<Permission.Request, "id" | "sessionID" | "tool">): Effect.Effect<void>
}

export interface ExecuteResult<M extends Metadata = Metadata> {
  title: string
  metadata: M
  output: string
  attachments?: Omit<MessageV2.FilePart, "id" | "sessionID" | "messageID">[]
}

export interface Def<Parameters extends z.ZodType = z.ZodType, M extends Metadata = Metadata> {
  id: string
  description: string
  parameters: Parameters
  execute(args: z.infer<Parameters>, ctx: Context): Effect.Effect<ExecuteResult<M>>
  formatValidationError?(error: z.ZodError): string
}
export type DefWithoutID<Parameters extends z.ZodType = z.ZodType, M extends Metadata = Metadata> = Omit<
  Def<Parameters, M>,
  "id"
>

export interface Info<Parameters extends z.ZodType = z.ZodType, M extends Metadata = Metadata> {
  id: string
  init: () => Effect.Effect<DefWithoutID<Parameters, M>>
}

type Init<Parameters extends z.ZodType, M extends Metadata> =
  | DefWithoutID<Parameters, M>
  | (() => Effect.Effect<DefWithoutID<Parameters, M>>)

export type InferParameters<T> =
  T extends Info<infer P, any> ? z.infer<P> : T extends Effect.Effect<Info<infer P, any>, any, any> ? z.infer<P> : never
export type InferMetadata<T> =
  T extends Info<any, infer M> ? M : T extends Effect.Effect<Info<any, infer M>, any, any> ? M : never

export type InferDef<T> =
  T extends Info<infer P, infer M>
    ? Def<P, M>
    : T extends Effect.Effect<Info<infer P, infer M>, any, any>
      ? Def<P, M>
      : never

function formatBoundary(parsed?: { default?: string; in_scope?: string[]; out_of_scope?: string[] }) {
  if (!parsed) return undefined
  const inScope = parsed.in_scope ?? []
  const outOfScope = parsed.out_of_scope ?? []
  const lines = ["## Scope"]
  if (inScope.length === 0 && outOfScope.length === 0) {
    lines.push(`- default: ${parsed.default ?? "allow"}`)
    return lines.join("\n")
  }
  lines.push(`- default: ${parsed.default ?? "ask"}`)
  if (inScope.length > 0) lines.push(...inScope.map((item) => `- in: ${item}`))
  if (outOfScope.length > 0) lines.push(...outOfScope.map((item) => `- out: ${item}`))
  return lines.join("\n")
}

function refreshDerivedContext(workspace: string) {
  return Effect.gen(function* () {
    const active = yield* Effect.promise(() => Operation.active(workspace).catch(() => undefined))
    if (!active) return
    const boundary = yield* Effect.promise(() => Operation.readBoundary(workspace, active.slug).catch(() => undefined))
    const operationBlock = [
      "Active operation",
      `slug: ${active.slug}`,
      `label: ${active.label}`,
      `kind: ${active.kind}`,
      ...(active.target ? [`target: ${active.target}`] : []),
      `opsec: ${active.opsec}`,
      "",
      formatBoundary(boundary),
    ]
      .filter(Boolean)
      .join("\n")
    const contextPack = yield* Cyber.contextPack({ operation_slug: active.slug }).pipe(
      Effect.catch(() => Effect.succeed(undefined)),
    )
    const derived = ["# Active Operation Context", "", operationBlock, contextPack].filter(Boolean).join("\n\n")
    yield* Effect.promise(() => Operation.writeContextPack(workspace, active.slug, derived)).pipe(
      Effect.catch(() => Effect.void),
    )
  })
}

function wrap<Parameters extends z.ZodType, Result extends Metadata>(
  id: string,
  init: Init<Parameters, Result>,
  truncate: Truncate.Interface,
  agents: Agent.Interface,
) {
  const workflowAware = id !== "play"
  return () =>
    Effect.gen(function* () {
      const toolInfo = typeof init === "function" ? { ...(yield* init()) } : { ...init }
      const execute = toolInfo.execute
      toolInfo.execute = (args, ctx) => {
        const attrs = {
          "tool.name": id,
          "session.id": ctx.sessionID,
          "message.id": ctx.messageID,
          ...(ctx.callID ? { "tool.call_id": ctx.callID } : {}),
        }
        return Effect.gen(function* () {
          yield* Effect.try({
            try: () => toolInfo.parameters.parse(args),
            catch: (error) => {
              if (error instanceof z.ZodError && toolInfo.formatValidationError) {
                return new Error(toolInfo.formatValidationError(error), { cause: error })
              }
              return new Error(
                `The ${id} tool was called with invalid arguments: ${error}.\nPlease rewrite the input so it satisfies the expected schema.`,
                { cause: error },
              )
            },
          })
          const callEvent = yield* Cyber.appendLedger({
              kind: "tool.called",
              source: id,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              summary: `${id} called`,
              data: {
                tool: id,
                call_id: ctx.callID,
                input: args,
              },
            })
            .pipe(Effect.catch(() => Effect.succeed("")))
          const exit = yield* Effect.exit(execute(args, ctx))
          if (Exit.isFailure(exit)) {
            yield* Cyber.appendLedger({
                kind: "tool.error",
                source: id,
                session_id: ctx.sessionID,
                message_id: ctx.messageID,
                status: "error",
                summary: `${id} failed`,
                data: {
                  tool: id,
                  call_id: ctx.callID,
                  source_event_id: callEvent,
                },
              })
              .pipe(Effect.catch(() => Effect.void))
	            if (workflowAware) {
	              const workspace = Instance.directory
	              const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
              if (slug) {
                const match = yield* Effect.promise(() =>
                  Operation.recordWorkflowStep(workspace, slug, {
                    tool: id,
                    success: false,
                    error: "tool execution failed",
                    args,
                  }).catch(() => undefined),
                ).pipe(Effect.catch(() => Effect.succeed(undefined)))
                if (match) {
                  const workflow = yield* Effect.promise(() =>
                    Operation.readWorkflow(workspace, slug, {
                      kind: match.kind,
                      id: match.id,
                    }).catch(() => undefined),
                  ).pipe(Effect.catch(() => Effect.succeed(undefined)))
                  if (workflow && Array.isArray(workflow["trace"]) && Array.isArray(workflow["skipped"])) {
                    yield* Cyber.syncWorkflowProgress({
                      operation_slug: slug,
                      workflow_kind: match.kind,
                      workflow_id: match.id,
                      trace: workflow["trace"] as Array<Record<string, unknown>>,
                      skipped: workflow["skipped"] as Array<Record<string, unknown>>,
                      completed_steps: Number(workflow["completed_steps"] ?? 0),
                      failed_steps: Number(workflow["failed_steps"] ?? 0),
                      pending_steps: Number(workflow["pending_steps"] ?? 0),
                      session_id: ctx.sessionID,
                      message_id: ctx.messageID,
                      source: "workflow",
                      summary: `${match.kind} ${match.id} progress after ${id} failure`,
                    }).pipe(Effect.catch(() => Effect.succeed("")))
                  }
                  yield* Cyber.appendLedger({
                    operation_slug: slug,
                    kind: "fact.observed",
                    source: "workflow",
                    session_id: ctx.sessionID,
                    message_id: ctx.messageID,
                    summary: `${match.kind} ${match.id} step ${match.step_index} failed via ${id}`,
                    data: {
                      workflow_kind: match.kind,
                      workflow_id: match.id,
                      step_index: match.step_index,
                      status: match.status,
                      tool: id,
                    },
	                  }).pipe(Effect.catch(() => Effect.succeed("")))
	                }
	                if (id !== "report") {
	                  yield* refreshDerivedContext(workspace).pipe(Effect.catch(() => Effect.void))
	                }
	              }
	            }
	            return yield* Effect.failCause(exit.cause)
          }
          const result = exit.value
          yield* Cyber.appendLedger({
              kind: "tool.completed",
              source: id,
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              status: "completed",
              summary: `${id} completed`,
              data: {
                tool: id,
                call_id: ctx.callID,
                source_event_id: callEvent,
                title: result.title,
                metadata: result.metadata,
              },
            })
            .pipe(Effect.catch(() => Effect.succeed("")))
	          if (workflowAware) {
	            const workspace = Instance.directory
	            const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
            if (slug) {
              const match = yield* Effect.promise(() =>
                Operation.recordWorkflowStep(workspace, slug, {
                  tool: id,
                  success: true,
                  title: result.title,
                  args,
                }).catch(() => undefined),
              ).pipe(Effect.catch(() => Effect.succeed(undefined)))
              if (match) {
                const workflow = yield* Effect.promise(() =>
                  Operation.readWorkflow(workspace, slug, {
                    kind: match.kind,
                    id: match.id,
                  }).catch(() => undefined),
                ).pipe(Effect.catch(() => Effect.succeed(undefined)))
                if (workflow && Array.isArray(workflow["trace"]) && Array.isArray(workflow["skipped"])) {
                  yield* Cyber.syncWorkflowProgress({
                    operation_slug: slug,
                    workflow_kind: match.kind,
                    workflow_id: match.id,
                    trace: workflow["trace"] as Array<Record<string, unknown>>,
                    skipped: workflow["skipped"] as Array<Record<string, unknown>>,
                    completed_steps: Number(workflow["completed_steps"] ?? 0),
                    failed_steps: Number(workflow["failed_steps"] ?? 0),
                    pending_steps: Number(workflow["pending_steps"] ?? 0),
                    session_id: ctx.sessionID,
                    message_id: ctx.messageID,
                    source: "workflow",
                    summary: `${match.kind} ${match.id} progress after ${id} completion`,
                  }).pipe(Effect.catch(() => Effect.succeed("")))
                }
                yield* Cyber.appendLedger({
                  operation_slug: slug,
                  kind: "fact.observed",
                  source: "workflow",
                  session_id: ctx.sessionID,
                  message_id: ctx.messageID,
                  summary: `${match.kind} ${match.id} step ${match.step_index} completed via ${id}`,
                  data: {
                    workflow_kind: match.kind,
                    workflow_id: match.id,
                    step_index: match.step_index,
                    status: match.status,
                    tool: id,
                  },
	                }).pipe(Effect.catch(() => Effect.succeed("")))
	              }
	              if (id !== "report") {
	                yield* refreshDerivedContext(workspace).pipe(Effect.catch(() => Effect.void))
	              }
	            }
	          }
          if (result.metadata.truncated !== undefined) {
            return result
          }
          const agent = yield* agents.get(ctx.agent)
          const truncated = yield* truncate.output(result.output, {}, agent)
          return {
            ...result,
            output: truncated.content,
            metadata: {
              ...result.metadata,
              truncated: truncated.truncated,
              ...(truncated.truncated && { outputPath: truncated.outputPath }),
            },
          }
        }).pipe(Effect.orDie, Effect.withSpan("Tool.execute", { attributes: attrs }))
      }
      return toolInfo
    })
}

export function define<Parameters extends z.ZodType, Result extends Metadata, R, ID extends string = string>(
  id: ID,
  init: Effect.Effect<Init<Parameters, Result>, never, R>,
): Effect.Effect<Info<Parameters, Result>, never, R | Truncate.Service | Agent.Service> & { id: ID } {
  return Object.assign(
    Effect.gen(function* () {
      const resolved = yield* init
      const truncate = yield* Truncate.Service
      const agents = yield* Agent.Service
      return { id, init: wrap(id, resolved, truncate, agents) }
    }),
    { id },
  )
}

export function init<P extends z.ZodType, M extends Metadata>(info: Info<P, M>): Effect.Effect<Def<P, M>> {
  return Effect.gen(function* () {
    const init = yield* info.init()
    return {
      ...init,
      id: info.id,
    }
  })
}
