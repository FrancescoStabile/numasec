import { describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "fs"
import { tmpdir } from "os"
import path from "path"
import { Effect, Layer, ManagedRuntime } from "effect"
import { AppFileSystem } from "@numasec/shared/filesystem"
import { Agent } from "../../../src/agent/agent"
import { AppRuntime } from "../../../src/effect/app-runtime"
import { Format } from "../../../src/format"
import { Instance } from "../../../src/project/instance"
import { Plan } from "../../../src/core/plan"
import { Operation } from "../../../src/core/operation"
import { Bus } from "../../../src/bus"
import { Truncate } from "../../../src/tool"
import { Todo } from "../../../src/session/todo"
import { Session } from "../../../src/session"
import { TodoWriteTool } from "../../../src/tool/todo"
import { MessageID, SessionID } from "../../../src/session/schema"

const runtime = ManagedRuntime.make(
  Layer.mergeAll(
    AppFileSystem.defaultLayer,
    Format.defaultLayer,
    Bus.layer,
    Truncate.defaultLayer,
    Agent.defaultLayer,
    Todo.defaultLayer,
    Session.defaultLayer,
  ),
)

function mkws() {
  const dir = mkdtempSync(path.join(tmpdir(), "numasec-plan-"))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

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

async function createSession(): Promise<{ id: SessionID }> {
  return await runtime.runPromise(
    Effect.gen(function* () {
      const session = yield* Session.Service
      return yield* session.create({ title: "plan-session" })
    }) as any,
  )
}

async function execTodo(params: Record<string, unknown>, sessionID?: SessionID) {
  const ctx = makeCtx(sessionID)
  return await runtime.runPromise(
    Effect.gen(function* () {
      const info = yield* TodoWriteTool
      const tool = yield* info.init()
      return yield* tool.execute(params as any, ctx)
    }) as any,
  )
}

describe("core/plan store", () => {
  test("listProjected and projectedSummary read plan state from the cyber kernel", async () => {
    const { dir, cleanup } = mkws()
    try {
      await Instance.provide({
        directory: dir,
        fn: async () => {
          const op = await Operation.create({ workspace: dir, label: "Projected Plan", kind: "appsec" })
          const session = await createSession()
          await execTodo(
            {
              todos: [
                { content: "crawl target", status: "in_progress", priority: "high" },
                { content: "review findings", status: "completed", priority: "medium" },
              ],
            },
            session.id,
          )
          const projected = await Plan.listProjected(dir, op.slug)
          const summary = await Plan.projectedSummary(dir, op.slug)

          expect(projected.length).toBe(2)
          expect(projected.some((item) => item.status === "running")).toBe(true)
          expect(projected.some((item) => item.status === "done")).toBe(true)
          expect(summary?.total).toBe(2)
          expect(summary?.running).toBe(1)
          expect(summary?.done).toBe(1)
        },
      })
    } finally {
      cleanup()
      await AppRuntime.dispose()
    }
  })
})
