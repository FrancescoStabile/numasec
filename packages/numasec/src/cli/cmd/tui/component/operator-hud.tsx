import { createSignal, onCleanup, Show } from "solid-js"
import { useTheme } from "@tui/context/theme"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { OperationActive } from "@/core/operation"
import { Plan } from "@/core/plan"
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

  const refresh = async () => {
    const dir = project.instance.directory()
    if (!dir) return setOp(undefined)
    const info = await OperationActive.resolveActive(dir).catch(() => undefined)
    setOp(info)
    if (info) {
      const nodes = await Plan.list(dir, info.slug).catch(() => [])
      setPlanStats(Plan.progress(nodes))
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
              SESS <span style={{ fg: theme.text }}>{current().sessions.length}</span>
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
          </box>
        )
      }}
    </Show>
  )
}
