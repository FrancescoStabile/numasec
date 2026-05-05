import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import { useSessionView } from "@tui/context/session-view"
import { loadOperationConsoleSnapshot, replayCoveredCount, reportStatus } from "@tui/component/operation-lens/snapshot"

const id = "internal:prompt-hints"

function View(props: { api: TuiPluginApi }) {
  const theme = () => props.api.theme.current
  const sessionView = useSessionView()
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((value) => !value)
  let inflight = false

  const [data] = createResource(tick, async () => {
    if (inflight) return undefined
    inflight = true
    try {
      return await loadOperationConsoleSnapshot(props.api.state.path.directory)
    } finally {
      inflight = false
    }
  })

  const snapshot = createMemo(() => data())
  const summary = createMemo(() => snapshot()?.projected?.summary)

  const offIdle = props.api.event.on("session.idle", () => refresh())
  const offPart = props.api.event.on("message.part.updated", () => refresh())
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
