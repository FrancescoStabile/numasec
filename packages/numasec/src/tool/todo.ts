import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION_WRITE from "./todowrite.txt"
import { Todo } from "../session/todo"
import { Instance } from "../project/instance"
import { Plan } from "@/core/plan"
import { Operation } from "@/core/operation"

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

async function syncTodosToPlan(todos: Todo.Info[]): Promise<void> {
  const dir = Instance.directory
  if (!dir) return
  const slug = await Operation.activeSlug(dir).catch(() => undefined)
  if (!slug) return
  const existing = await Plan.list(dir, slug).catch(() => [] as Plan.Node[])
  const want = todos.map((t) => ({
    id: stableTodoId(t.content),
    title: t.content,
    status: mapTodoStatus(t.status),
  }))
  const wantIds = new Set(want.map((w) => w.id))
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
    }
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

          yield* Effect.tryPromise(() => syncTodosToPlan(params.todos)).pipe(Effect.ignore)

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
