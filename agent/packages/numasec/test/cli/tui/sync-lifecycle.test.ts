import { describe, expect, test } from "bun:test"
import {
  disposeSyncMessage,
  disposeSyncSession,
  resetSyncRuntime,
  resetSyncStore,
  type SyncLifecycleState,
} from "../../../src/cli/cmd/tui/context/sync-lifecycle"

function state(): SyncLifecycleState {
  return {
    permission: {
      "sess-a": [{}],
    },
    question: {
      "sess-a": [{}],
    },
    todo: {
      "sess-a": [{}],
    },
    session_status: {
      "sess-a": { type: "busy" },
    },
    session_diff: {
      "sess-a": [{}],
    },
    message: {
      "sess-a": [{ id: "msg-a" }, { id: "msg-b" }],
    },
    message_cursor: {
      "sess-a": "cursor-a",
    },
    message_loading: {
      "sess-a": true,
    },
    message_history: {
      "sess-a": true,
    },
    part: {
      "msg-a": [{}],
      "msg-b": [{}],
    },
    security: {
      "sess-a": { status: "ready" },
    },
    session: [{ id: "sess-a" }],
  }
}

describe("tui sync lifecycle helpers", () => {
  test("disposeSyncMessage removes the message row and orphaned parts", () => {
    const next = state()
    disposeSyncMessage({
      state: next,
      sessionID: "sess-a",
      messageID: "msg-a",
    })
    expect(next.message["sess-a"]?.map((item) => item.id)).toEqual(["msg-b"])
    expect(next.part["msg-a"]).toBeUndefined()
    expect(next.part["msg-b"]).toBeDefined()
  })

  test("disposeSyncSession clears session-scoped caches, parts, timers, and sync markers", () => {
    const next = state()
    const synced = new Set(["sess-a"])
    const queue = new Map<string, ReturnType<typeof setTimeout>>()
    queue.set("sess-a", setTimeout(() => undefined, 60_000))

    disposeSyncSession({
      state: next,
      sessionID: "sess-a",
      fullSyncedSessions: synced,
      securityQueue: queue,
    })

    expect(next.session).toEqual([])
    expect(next.permission["sess-a"]).toBeUndefined()
    expect(next.question["sess-a"]).toBeUndefined()
    expect(next.todo["sess-a"]).toBeUndefined()
    expect(next.session_status["sess-a"]).toBeUndefined()
    expect(next.session_diff["sess-a"]).toBeUndefined()
    expect(next.message["sess-a"]).toBeUndefined()
    expect(next.message_cursor["sess-a"]).toBeUndefined()
    expect(next.message_loading["sess-a"]).toBeUndefined()
    expect(next.message_history["sess-a"]).toBeUndefined()
    expect(next.security["sess-a"]).toBeUndefined()
    expect(next.part["msg-a"]).toBeUndefined()
    expect(next.part["msg-b"]).toBeUndefined()
    expect(synced.has("sess-a")).toBe(false)
    expect(queue.has("sess-a")).toBe(false)
  })

  test("resetSyncRuntime clears queued timers and sync markers", () => {
    const synced = new Set(["sess-a", "sess-b"])
    const queue = new Map<string, ReturnType<typeof setTimeout>>()
    queue.set("sess-a", setTimeout(() => undefined, 60_000))
    queue.set("sess-b", setTimeout(() => undefined, 60_000))

    resetSyncRuntime({
      securityQueue: queue,
      fullSyncedSessions: synced,
    })

    expect(queue.size).toBe(0)
    expect(synced.size).toBe(0)
  })

  test("resetSyncStore drops stale session caches on instance disposal", () => {
    const next = state()
    resetSyncStore(next)
    expect(next.permission).toEqual({})
    expect(next.question).toEqual({})
    expect(next.todo).toEqual({})
    expect(next.session_status).toEqual({})
    expect(next.session_diff).toEqual({})
    expect(next.message).toEqual({})
    expect(next.message_cursor).toEqual({})
    expect(next.message_loading).toEqual({})
    expect(next.message_history).toEqual({})
    expect(next.part).toEqual({})
    expect(next.security).toEqual({})
    expect(next.session).toEqual([])
  })
})
