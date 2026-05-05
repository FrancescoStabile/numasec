import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION_WRITE from "./todowrite.txt"
import { Todo } from "../session/todo"
import { Instance } from "../project/instance"
import { Plan } from "@/core/plan"
import { Operation } from "@/core/operation"
import { Cyber } from "@/core/cyber"

const parameters = z.object({
  todos: z.array(z.object(Todo.Info.shape)).describe("The updated todo list"),
})

function stableTodoId(content: string): string {
  let h = 5381
  for (let i = 0; i < content.length; i++) h = ((h << 5) + h + content.charCodeAt(i)) >>> 0
  return `pn_todo_${h.toString(36)}`
}

function mapTodoStatus(s: string): Plan.NodeStatus {
  if (s === "completed") return "done"
  if (s === "in_progress") return "running"
  if (s === "cancelled") return "skipped"
  return "planned"
}

async function syncTodosToPlan(todos: Todo.Info[]): Promise<{
  slug?: string
  nodes: Plan.Node[]
  removed_ids: string[]
}> {
  const dir = Instance.directory
  if (!dir) return { nodes: [], removed_ids: [] }
  const slug = await Operation.activeSlug(dir).catch(() => undefined)
  if (!slug) return { nodes: [], removed_ids: [] }
  const existing = await Plan.list(dir, slug).catch(() => [] as Plan.Node[])
  const want = todos.map((t) => ({
    id: stableTodoId(t.content),
    title: t.content,
    status: mapTodoStatus(t.status),
  }))
  const wantIds = new Set(want.map((w) => w.id))
  const removed_ids: string[] = []
  for (const w of want) {
    const cur = existing.find((n) => n.id === w.id)
    if (!cur) {
      await Plan.add(dir, slug, { id: w.id, title: w.title })
      if (w.status !== "planned") await Plan.update(dir, slug, w.id, { status: w.status })
      continue
    }
    if (cur.status !== w.status || cur.title !== w.title) {
      await Plan.update(dir, slug, w.id, {
        status: cur.status !== w.status ? w.status : undefined,
        title: cur.title !== w.title ? w.title : undefined,
      })
    }
  }
  for (const n of existing) {
    if (n.id.startsWith("pn_todo_") && !wantIds.has(n.id)) {
      await Plan.remove(dir, slug, n.id)
      removed_ids.push(n.id)
    }
  }
  return {
    slug,
    nodes: await Plan.list(dir, slug).catch(() => [] as Plan.Node[]),
    removed_ids,
  }
}

type Metadata = {
  todos: Todo.Info[]
}

export const TodoWriteTool = Tool.define<typeof parameters, Metadata, Todo.Service>(
  "todowrite",
  Effect.gen(function* () {
    const todo = yield* Todo.Service

    return {
      description: DESCRIPTION_WRITE,
      parameters,
      execute: (params: z.infer<typeof parameters>, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "todowrite",
            patterns: ["*"],
            always: ["*"],
            metadata: {},
          })

          yield* todo.update({
            sessionID: ctx.sessionID,
            todos: params.todos,
          })

          const planSync = yield* Effect.tryPromise(() => syncTodosToPlan(params.todos)).pipe(
            Effect.catch(() => Effect.succeed({ slug: undefined, nodes: [] as Plan.Node[], removed_ids: [] as string[] })),
          )
          if (planSync.slug) {
            const eventID = yield* Cyber.appendLedger({
              operation_slug: planSync.slug,
              kind: "fact.observed",
              source: "todowrite",
              session_id: ctx.sessionID,
              message_id: ctx.messageID,
              summary: `todo plan synced (${planSync.nodes.length} nodes)`,
              data: {
                nodes: planSync.nodes.length,
                done: planSync.nodes.filter((node) => node.status === "done").length,
                running: planSync.nodes.filter((node) => node.status === "running").length,
                blocked: planSync.nodes.filter((node) => node.status === "blocked").length,
                planned: planSync.nodes.filter((node) => node.status === "planned").length,
                removed_ids: planSync.removed_ids,
              },
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: planSync.slug,
              entity_kind: "operation",
              entity_key: planSync.slug,
              fact_name: "plan_summary",
              value_json: {
                total: planSync.nodes.length,
                done: planSync.nodes.filter((node) => node.status === "done").length,
                running: planSync.nodes.filter((node) => node.status === "running").length,
                blocked: planSync.nodes.filter((node) => node.status === "blocked").length,
                planned: planSync.nodes.filter((node) => node.status === "planned").length,
              },
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            for (const node of planSync.nodes) {
              yield* Cyber.upsertFact({
                operation_slug: planSync.slug,
                entity_kind: "plan_node",
                entity_key: node.id,
                fact_name: "todo_state",
                value_json: {
                  title: node.title,
                  status: node.status,
                  note: node.note,
                  parent_id: node.parent_id,
                },
                writer_kind: "tool",
                status: "observed",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
              yield* Cyber.upsertRelation({
                operation_slug: planSync.slug,
                src_kind: "operation",
                src_key: planSync.slug,
                relation: "has_plan_node",
                dst_kind: "plan_node",
                dst_key: node.id,
                writer_kind: "tool",
                status: "observed",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
            for (const removedID of planSync.removed_ids) {
              yield* Cyber.upsertFact({
                operation_slug: planSync.slug,
                entity_kind: "plan_node",
                entity_key: removedID,
                fact_name: "todo_state",
                value_json: {
                  status: "removed",
                },
                writer_kind: "tool",
                status: "stale",
                confidence: 1000,
                source_event_id: eventID || undefined,
              }).pipe(Effect.catch(() => Effect.succeed("")))
            }
          }

          return {
            title: `${params.todos.filter((x) => x.status !== "completed").length} todos`,
            output: JSON.stringify(params.todos, null, 2),
            metadata: {
              todos: params.todos,
            },
          }
        }),
    } satisfies Tool.DefWithoutID<typeof parameters, Metadata>
  }),
)
