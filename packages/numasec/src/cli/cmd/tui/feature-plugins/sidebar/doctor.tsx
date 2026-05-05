import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import { Doctor } from "@/core/doctor"
import type { DoctorReport } from "@/core/doctor"
import { Operation } from "@/core/operation"

const id = "internal:sidebar-doctor"

type Snapshot = {
  report: DoctorReport
  opsec: "normal" | "strict"
}

function View(props: { api: TuiPluginApi }) {
  const theme = () => props.api.theme.current
  // Boolean-flip tick — same pattern as DialogOperation to avoid createResource
  // accumulating in-flight probes (see dialog-operation.tsx:23-45 + commit 43ff009).
  const [tick, setTick] = createSignal(true)
  let inflight = false

  const [data] = createResource<Snapshot | undefined, boolean>(tick, async () => {
    if (inflight) return undefined
    inflight = true
    try {
      const directory = props.api.state.path.directory
      const report = await Doctor.probePromise(directory)
      const active = directory ? await Operation.active(directory).catch(() => undefined) : undefined
      return { report, opsec: active?.opsec ?? "normal" }
    } catch {
      return undefined
    } finally {
      inflight = false
    }
  })

  const ready = createMemo(() => data())
  const tools = createMemo(() => {
    const r = ready()?.report
    if (!r) return { present: 0, total: 0 }
    return { present: r.binaries.filter((b) => b.present).length, total: r.binaries.length }
  })
  const capability = createMemo(() => {
    const report = ready()?.report.capability
    if (!report) {
      return {
        ready: [] as string[],
        degraded: [] as string[],
        blocked: [] as string[],
        playsReady: 0,
        playsTotal: 0,
        verticalsReady: 0,
        verticalsTotal: 0,
      }
    }
    const all = [...report.plays, ...report.verticals]
    return {
      ready: all.filter((item) => item.status === "ready").map((item) => item.label),
      degraded: all.filter((item) => item.status === "degraded").map((item) => item.label),
      blocked: all.filter((item) => item.status === "unavailable").map((item) => item.label),
      playsReady: report.plays.filter((item) => item.status === "ready").length,
      playsTotal: report.plays.length,
      verticalsReady: report.verticals.filter((item) => item.status === "ready").length,
      verticalsTotal: report.verticals.length,
    }
  })
  const impact = createMemo(() => {
    const report = ready()?.report.capability
    if (!report) return ""
    const first = [...report.verticals, ...report.plays].find((item) => item.status !== "ready")
    if (!first) return "full surface available"
    const missing = [...first.missing_required, ...first.missing_optional].slice(0, 2).join(", ")
    return missing ? `${first.label} missing ${missing}` : `${first.label} degraded`
  })
  const nodeVersion = createMemo(() => {
    const v = ready()?.report.runtime.node
    if (!v) return ""
    const major = v.split(".")[0]
    return `node ${major}.x`
  })
  const toolsColor = createMemo(() => {
    const t = tools()
    if (t.total === 0) return theme().textMuted
    const ratio = t.present / t.total
    if (ratio >= 0.5) return theme().success
    if (ratio >= 0.25) return theme().warning
    return theme().error
  })
  const browserOk = createMemo(() => ready()?.report.browser.present === true)
  const vaultOk = createMemo(() => ready()?.report.vault.present === true)
  const wsOk = createMemo(() => ready()?.report.workspace.writable !== false)
  const opsecStrict = createMemo(() => ready()?.opsec === "strict")
  const offIdle = props.api.event.on("session.idle", () => setTick((value) => !value))
  const offPart = props.api.event.on("message.part.updated", () => setTick((value) => !value))
  onCleanup(() => {
    offIdle()
    offPart()
  })

  // The outer <box> is load-bearing — see dialog-operation.tsx:47-53 for why
  // a concrete opentui node (not Switch/Show) must be the top-level return.
  return (
    <box>
      <box flexDirection="row" gap={1}>
        <text fg={theme().primary} flexShrink={0}>
          ❖
        </text>
        <text fg={theme().text} wrapMode="none">
          <b>CAPABILITY</b>
        </text>
      </box>
      <Show
        when={ready()}
        fallback={
          <text fg={theme().textMuted} wrapMode="none">
            probing environment…
          </text>
        }
      >
        <box flexDirection="row" gap={1} justifyContent="space-between">
          <text fg={toolsColor()} wrapMode="none">
            {tools().present}/{tools().total} tools
          </text>
          <text fg={theme().textMuted} wrapMode="none" flexShrink={0}>
            {nodeVersion()}
          </text>
        </box>
        <box flexDirection="row" gap={1}>
          <text fg={theme().success} wrapMode="none">
            ready {capability().ready.length}
          </text>
          <text fg={capability().degraded.length > 0 ? theme().warning : theme().textMuted} wrapMode="none">
            degraded {capability().degraded.length}
          </text>
          <text fg={capability().blocked.length > 0 ? theme().error : theme().textMuted} wrapMode="none">
            blocked {capability().blocked.length}
          </text>
        </box>
        <text fg={theme().textMuted} wrapMode="none">
          plays {capability().playsReady}/{capability().playsTotal} · verticals {capability().verticalsReady}/
          {capability().verticalsTotal}
        </text>
        <text fg={capability().blocked.length > 0 ? theme().warning : theme().textMuted} wrapMode="word">
          impact {impact()}
        </text>
        <box flexDirection="row" gap={1}>
          <text fg={vaultOk() ? theme().success : theme().textMuted} wrapMode="none">
            vault {vaultOk() ? "✓" : "·"}
          </text>
          <text fg={browserOk() ? theme().success : theme().warning} wrapMode="none">
            browser {browserOk() ? "✓" : "·"}
          </text>
          <text fg={wsOk() ? theme().success : theme().error} wrapMode="none">
            · ws {wsOk() ? "✓" : "ro"}
          </text>
        </box>
        <Show when={opsecStrict()}>
          <text fg={theme().error} wrapMode="none">
            OPSEC: strict
          </text>
        </Show>
      </Show>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 140,
    slots: {
      sidebar_content(_ctx, _props) {
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
