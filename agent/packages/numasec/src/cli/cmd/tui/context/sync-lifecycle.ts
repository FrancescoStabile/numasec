type SyncTimer = ReturnType<typeof setTimeout>

type SyncMessage = {
  id: string
}

export type SyncLifecycleState = {
  permission: Record<string, unknown>
  question: Record<string, unknown>
  todo: Record<string, unknown>
  session_status: Record<string, unknown>
  session_diff: Record<string, unknown>
  message: Record<string, SyncMessage[]>
  message_cursor: Record<string, string | null>
  message_loading: Record<string, boolean>
  message_history: Record<string, boolean>
  part: Record<string, unknown>
  security: Record<string, unknown>
  session: SyncMessage[]
}

function clearTimer(securityQueue: Map<string, SyncTimer>, sessionID: string) {
  const timer = securityQueue.get(sessionID)
  if (!timer) return
  clearTimeout(timer)
  securityQueue.delete(sessionID)
}

export function disposeSyncMessage(input: {
  state: Pick<SyncLifecycleState, "message" | "part">
  sessionID: string
  messageID: string
}) {
  const messages = input.state.message[input.sessionID]
  if (messages) {
    const index = messages.findIndex((item) => item.id === input.messageID)
    if (index >= 0) messages.splice(index, 1)
  }
  delete input.state.part[input.messageID]
}

export function disposeSyncSession(input: {
  state: SyncLifecycleState
  sessionID: string
  fullSyncedSessions: Set<string>
  securityQueue: Map<string, SyncTimer>
}) {
  const index = input.state.session.findIndex((item) => item.id === input.sessionID)
  if (index >= 0) input.state.session.splice(index, 1)
  const messages = input.state.message[input.sessionID] ?? []
  for (const item of messages) {
    delete input.state.part[item.id]
  }
  clearTimer(input.securityQueue, input.sessionID)
  input.fullSyncedSessions.delete(input.sessionID)
  delete input.state.permission[input.sessionID]
  delete input.state.question[input.sessionID]
  delete input.state.todo[input.sessionID]
  delete input.state.session_status[input.sessionID]
  delete input.state.session_diff[input.sessionID]
  delete input.state.message[input.sessionID]
  delete input.state.message_cursor[input.sessionID]
  delete input.state.message_loading[input.sessionID]
  delete input.state.message_history[input.sessionID]
  delete input.state.security[input.sessionID]
}

export function resetSyncRuntime(input: {
  fullSyncedSessions: Set<string>
  securityQueue: Map<string, SyncTimer>
}) {
  for (const timer of input.securityQueue.values()) {
    clearTimeout(timer)
  }
  input.securityQueue.clear()
  input.fullSyncedSessions.clear()
}

export function resetSyncStore(state: SyncLifecycleState) {
  state.permission = {}
  state.question = {}
  state.todo = {}
  state.session_status = {}
  state.session_diff = {}
  state.message = {}
  state.message_cursor = {}
  state.message_loading = {}
  state.message_history = {}
  state.part = {}
  state.security = {}
  state.session = []
}
