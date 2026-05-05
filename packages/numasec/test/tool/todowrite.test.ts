import { describe, expect, test } from "bun:test"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../src/agent/agent"
import { Operation } from "../../src/core/operation"
import { Cyber } from "../../src/core/cyber"
import { AppRuntime } from "../../src/effect/app-runtime"
import { Format } from "../../src/format"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Todo } from "../../src/session/todo"
import { MessageID, SessionID } from "../../src/session/schema"
import * as Truncate from "../../src/tool/truncate"
import { TodoWriteTool } from "../../src/tool/todo"
import { tmpdir } from "../fixture/fixture"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    Todo.defaultLayer,
    Session.defaultLayer,
  ),
)

function makeCtx(sessionID = SessionID.make("ses_test")) {
  return {
    sessionID,
    messageID: MessageID.make(""),
    callID: "",
    agent: "security",
    abort: AbortSignal.any([]),
    messages: [],
    metadata: () => Effect.void,
    extra: {},
    ask: () => Effect.succeed(undefined as any),
  } as any
}

async function exec(params: Record<string, unknown>, sessionID?: SessionID) {
  const ctx = makeCtx(sessionID)
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* TodoWriteTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, ctx)
    }) as any,
  )
}

async function createSession(): Promise<{ id: SessionID }> {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const session = yield* Session.Service
      return yield* session.create({ title: "todo-session" })
    }) as any,
  )
}

describe("tool/todowrite", () => {
  test("syncs todo-derived plan state into the cyber kernel", async () => {
    await using fixture = await tmpdir({ git: true })

    await Instance.provide({
      directory: fixture.path,
      fn: async () => {
        const op = await Operation.create({ workspace: fixture.path, label: "Todo Plan", kind: "appsec" })
        const session = await createSession()
        await exec({
          todos: [
            { content: "crawl target", status: "in_progress", priority: "high" },
            { content: "review findings", status: "pending", priority: "medium" },
          ],
        }, session.id)

        const facts = await AppRuntime.runPromise(Cyber.listFacts({ operation_slug: op.slug, limit: 200 }))
        const relations = await AppRuntime.runPromise(Cyber.listRelations({ operation_slug: op.slug, limit: 200 }))
        const pack = await AppRuntime.runPromise(Cyber.contextPack({ operation_slug: op.slug, max_facts: 80 }))

        expect(
          facts.some(
            (item) =>
              item.entity_kind === "operation" &&
              item.entity_key === op.slug &&
              item.fact_name === "plan_summary",
          ),
        ).toBe(true)
        expect(
          facts.some(
            (item) =>
              item.entity_kind === "plan_node" &&
              item.fact_name === "todo_state" &&
              JSON.stringify(item.value_json).includes("\"status\":\"running\""),
          ),
        ).toBe(true)
        expect(
          relations.some(
            (item) =>
              item.src_kind === "operation" &&
              item.src_key === op.slug &&
              item.relation === "has_plan_node" &&
              item.dst_kind === "plan_node",
          ),
        ).toBe(true)
        expect(pack).toContain("## Plan")
        expect(pack).toContain("crawl target")
        expect(pack).toContain("review findings")
      },
    })
  })
})
