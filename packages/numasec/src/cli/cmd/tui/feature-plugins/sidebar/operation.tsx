import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import {
  deliverableLabel,
  loadOperationConsoleSnapshot,
  replayCoveredCount,
  reportStatus,
  scopeCounts,
  scopeDecision,
  shouldRefreshOperationConsoleSnapshotForPart,
  stabilizeOperationConsoleSnapshot,
  type OperationConsoleSnapshot,
  workflowLabel,
  workflowProgress,
} from "./operation-console"

const id = "internal:sidebar-operation"

function View(props: { api: TuiPluginApi; session_id: string }) {
  const theme = () => props.api.theme.current
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
  const active = createMemo(() => snapshot()?.active)
  const summary = createMemo(() => snapshot()?.projected?.summary)
  const decision = createMemo(() => (snapshot() ? scopeDecision(snapshot()!) : undefined))
  const counts = createMemo(() => (snapshot() ? scopeCounts(snapshot()!) : { inScope: 0, outOfScope: 0 }))
  const scopeLabel = createMemo(() => {
    const mode = decision()?.mode ?? "unset"
    const count = counts()
    if (mode === "unset") return "scope unset"
    if (count.inScope === 0 && count.outOfScope === 0) return `scope default ${mode}`
    return `scope ${mode} · ${count.inScope} in / ${count.outOfScope} out`
  })
  const progress = createMemo(() => (snapshot() ? workflowProgress(snapshot()!) : { completed: 0, total: 0, failed: 0, pending: 0, degraded: false }))
  const replayCovered = createMemo(() => (snapshot() ? replayCoveredCount(snapshot()!) : 0))
  const report = createMemo(() => (snapshot() ? reportStatus(snapshot()!) : "cold"))

  const offIdle = props.api.event.on("session.idle", () => refresh())
  const offPart = props.api.event.on("message.part.updated", (evt) => {
    if (shouldRefreshOperationConsoleSnapshotForPart(evt.properties.part)) refresh()
  })
  const offStatus = props.api.event.on("session.status", () => refresh())
  onCleanup(() => {
    offIdle()
    offPart()
    offStatus()
  })

  const scopeColor = createMemo(() => {
    const mode = decision()?.mode
    if (mode === "allow") return theme().success
    if (mode === "deny") return theme().error
    return theme().warning
  })

  const reportColor = createMemo(() => {
    if (report() === "ready") return theme().success
    if (report() === "draft") return theme().warning
    return theme().textMuted
  })

  return (
    <box>
      <text fg={theme().text} wrapMode="none">
        <b>OPERATION</b>
      </text>
      <Show
        when={active()}
        fallback={
          <text fg={theme().textMuted} wrapMode="none">
            no active operation
          </text>
        }
      >
        <text fg={theme().text} wrapMode="word">
          {active()?.label}
        </text>
        <text fg={theme().textMuted} wrapMode="none">
          kind {active()?.kind} · target <span style={{ fg: theme().primary }}>{active()?.target ?? "-"}</span>
        </text>
        <text fg={scopeColor()} wrapMode="none">
          {scopeLabel()}
        </text>
        <text fg={theme().textMuted} wrapMode="none">
          opsec {active()?.opsec ?? "normal"} · auto {snapshot()?.projected?.autonomy_policy?.mode ?? "unset"}
        </text>
        <text fg={progress().degraded ? theme().warning : theme().textMuted} wrapMode="none">
          {snapshot()?.activeWorkflow?.kind ?? "workflow"} {workflowLabel(snapshot()!)} · {progress().completed}/{progress().total}
          {progress().failed > 0 ? ` · fail ${progress().failed}` : ""}
        </text>

        <text fg={theme().text} wrapMode="none">
          <b>PROOF</b>
        </text>
        <text fg={theme().textMuted} wrapMode="none">
          reportable {summary()?.reportable_findings ?? 0} · verified {summary()?.verified_findings ?? 0}
        </text>
        <text fg={theme().textMuted} wrapMode="none">
          evidence {snapshot()?.evidenceCount ?? 0} · replay {replayCovered()}/{summary()?.verified_findings ?? 0}
        </text>
        <text fg={theme().textMuted} wrapMode="none">
          suspected {summary()?.suspected_findings ?? 0} · rejected {summary()?.rejected_findings ?? 0}
        </text>
        <box flexDirection="row" gap={1}>
          <text fg={reportColor()} wrapMode="none">
            report {report()}
          </text>
          <text fg={theme().textMuted} wrapMode="none">
            {snapshot() ? deliverableLabel(snapshot()!) : "not built"}
          </text>
        </box>
      </Show>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 80,
    slots: {
      sidebar_content(_ctx, props) {
        return <View api={api} session_id={props.session_id} />
      },
    },
  })
}

const plugin: TuiPluginModule & { id: string } = {
  id,
  tui,
}

export default plugin
