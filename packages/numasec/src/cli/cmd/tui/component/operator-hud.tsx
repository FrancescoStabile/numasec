import { createSignal, onCleanup, Show } from "solid-js"
import { useTheme } from "@tui/context/theme"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { OperationActive } from "@/core/operation"
import { Plan } from "@/core/plan"
import { Observation } from "@/core/observation"
import { Evidence } from "@/core/evidence"
import type { Info as OpInfo } from "@/core/operation/info"

export function OperatorHud() {
  const { theme } = useTheme()
  const project = useProject()
  const [op, setOp] = createSignal<OpInfo | undefined>(undefined)
  const [planStats, setPlanStats] = createSignal<{ done: number; total: number; running: number; blocked: number }>({
    done: 0,
    total: 0,
    running: 0,
    blocked: 0,
  })
  const [obsStats, setObsStats] = createSignal<{
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
    none: number
  }>({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 })
  const [evidenceCount, setEvidenceCount] = createSignal(0)

  const refresh = async () => {
    const dir = project.instance.directory()
    if (!dir) return setOp(undefined)
    const info = await OperationActive.resolveActive(dir).catch(() => undefined)
    setOp(info)
    if (info) {
      const nodes = await Plan.list(dir, info.slug).catch(() => [])
      setPlanStats(Plan.progress(nodes))
      const items = await Observation.list(dir, info.slug).catch(() => [])
      const counts = Observation.severityCounts(items)
      setObsStats({ total: items.length, ...counts })
      const ev = await Evidence.list(dir, info.slug).catch(() => [])
      setEvidenceCount(ev.length)
    }
  }
  refresh()
  const timer = setInterval(refresh, 4000)
  onCleanup(() => clearInterval(timer))

  return (
    <Show when={op()}>
      {(current) => {
        const pack = () => Kind.byId(current().kind)
        const accent = () => {
          const p = pack()
          if (!p) return theme.primary
          return theme[p.accent] ?? theme.primary
        }
        return (
          <box flexShrink={0} gap={0} paddingRight={1}>
            <text fg={theme.textMuted}>
              <span style={{ fg: accent(), bold: true }}>
                {pack()?.glyph ?? "◆"} OPERATION
              </span>
            </text>
            <text fg={theme.text}>
              <b>{current().label}</b>
            </text>
            <text fg={theme.textMuted}>
              {current().kind} · {current().status}
            </text>
            <Show when={typeof current().subject?.["target"] === "string"}>
              <text fg={theme.textMuted}>
                <span>⌬ </span>
                <span style={{ fg: theme.text }}>{String(current().subject!["target"])}</span>
              </text>
            </Show>
            <Show when={Array.isArray(current().boundary?.["in_scope"])}>
              <text fg={theme.textMuted}>
                SCOPE{" "}
                <span style={{ fg: theme.text }}>
                  {(current().boundary!["in_scope"] as unknown[]).length} in
                </span>
                <Show when={Array.isArray(current().boundary?.["out_of_scope"])}>
                  <span style={{ fg: theme.textMuted }}>
                    {" / "}
                    {(current().boundary!["out_of_scope"] as unknown[]).length} out
                  </span>
                </Show>
              </text>
            </Show>
            <text fg={theme.textMuted}>
              RUNS <span style={{ fg: theme.text }}>{current().sessions.length}</span>
            </text>
            <Show when={planStats().total > 0}>
              <text fg={theme.textMuted}>
                PLAN{" "}
                <span style={{ fg: theme.text }}>
                  {planStats().done}/{planStats().total}
                </span>
                <Show when={planStats().running > 0}>
                  <span> · {planStats().running} running</span>
                </Show>
                <Show when={planStats().blocked > 0}>
                  <span style={{ fg: theme.error ?? theme.textMuted }}> · {planStats().blocked} blocked</span>
                </Show>
              </text>
            </Show>
            <Show when={obsStats().total > 0}>
              <text fg={theme.textMuted}>
                OBS <span style={{ fg: theme.text }}>{obsStats().total}</span>
                <Show when={obsStats().critical > 0}>
                  <span style={{ fg: theme.error ?? theme.text }}> · ◆{obsStats().critical}c</span>
                </Show>
                <Show when={obsStats().high > 0}>
                  <span style={{ fg: theme.error ?? theme.text }}> ◆{obsStats().high}h</span>
                </Show>
                <Show when={obsStats().medium > 0}>
                  <span> ◆{obsStats().medium}m</span>
                </Show>
                <Show when={obsStats().low > 0}>
                  <span> ◈{obsStats().low}l</span>
                </Show>
                <Show when={obsStats().info > 0}>
                  <span> ◇{obsStats().info}i</span>
                </Show>
              </text>
            </Show>
            <Show when={evidenceCount() > 0}>
              <text fg={theme.textMuted}>
                EV <span style={{ fg: theme.text }}>{evidenceCount()}</span>
              </text>
            </Show>
          </box>
        )
      }}
    </Show>
  )
}
