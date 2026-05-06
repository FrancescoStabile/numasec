import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import { useSessionView } from "@tui/context/session-view"
import {
  loadOperationConsoleSnapshot,
  replayCoveredCount,
  reportStatus,
  shouldRefreshOperationConsoleSnapshotForPart,
  stabilizeOperationConsoleSnapshot,
  type OperationConsoleSnapshot,
} from "@tui/component/operation-lens/snapshot"

const id = "internal:prompt-hints"

function View(props: { api: TuiPluginApi }) {
  const theme = () => props.api.theme.current
  const sessionView = useSessionView()
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((value) => !value)
  let inflight = false
  let queued = false
  let stableSnapshot: OperationConsoleSnapshot | undefined

  const [data] = createResource<OperationConsoleSnapshot | undefined, boolean>(tick, async () => {
    if (inflight) {
      queued = true
      return stableSnapshot
    }
    inflight = true
    try {
      const next = await loadOperationConsoleSnapshot(props.api.state.path.directory)
      stableSnapshot = stabilizeOperationConsoleSnapshot(stableSnapshot, next)
      return stableSnapshot
    } finally {
      inflight = false
      if (queued) {
        queued = false
        queueMicrotask(refresh)
      }
    }
  })

  const snapshot = createMemo(() => data() ?? stableSnapshot)
  const summary = createMemo(() => snapshot()?.projected?.summary)

  const offIdle = props.api.event.on("session.idle", () => refresh())
  const offPart = props.api.event.on("message.part.updated", (evt) => {
    if (shouldRefreshOperationConsoleSnapshotForPart(evt.properties.part)) refresh()
  })
  onCleanup(() => {
    offIdle()
    offPart()
  })

  return (
    <box>
      <Show when={snapshot()?.active}>
        <Show
          when={sessionView.current === "chat"}
          fallback={
            <text fg={theme().textMuted} wrapMode="none">
              {sessionView.current === "findings" && "j/k select · e evidence · r replay · p report · esc chat"}
              {sessionView.current === "evidence" && "j/k select · 0 all · back findings · esc chat"}
              {sessionView.current === "replay" && "j/k select · 0 all · back findings · esc chat"}
              {sessionView.current === "workflow" && "j/k select · esc chat"}
              {sessionView.current === "report" && "j/k gate · esc chat"}
            </text>
          }
        >
          <text fg={theme().textMuted} wrapMode="none">
            proof {summary()?.reportable_findings ?? 0}r/{summary()?.verified_findings ?? 0}v · replay{" "}
            {snapshot() ? replayCoveredCount(snapshot()!) : 0}/{summary()?.verified_findings ?? 0} · report{" "}
            {snapshot() ? reportStatus(snapshot()!) : "cold"}
          </text>
        </Show>
      </Show>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 120,
    slots: {
      session_prompt_right() {
        return <View api={api} />
      },
    },
  })
}

const plugin: TuiPluginModule & { id: string } = {
  id,
  tui,
}

export default plugin
