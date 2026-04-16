import { createSignal, onCleanup, Show } from "solid-js"
import { useTheme } from "@tui/context/theme"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { Operation, OperationActive } from "@/core/operation"
import type { Info as OpInfo } from "@/core/operation/info"

export function OperationHomeHint() {
  const { theme } = useTheme()
  const project = useProject()
  const [op, setOp] = createSignal<OpInfo | undefined>(undefined)
  const [count, setCount] = createSignal(0)

  const refresh = async () => {
    const dir = project.instance.directory()
    if (!dir) {
      setOp(undefined)
      setCount(0)
      return
    }
    const [active, all] = await Promise.all([
      OperationActive.resolveActive(dir).catch(() => undefined),
      Operation.list(dir).catch(() => []),
    ])
    setOp(active)
    setCount(all.filter((o) => o.status === "active").length)
  }
  refresh()
  const timer = setInterval(refresh, 4000)
  onCleanup(() => clearInterval(timer))

  return (
    <box flexShrink={0} paddingTop={1} alignItems="center">
      <Show
        when={op()}
        fallback={
          <text fg={theme.textMuted}>
            no active operation — press{" "}
            <span style={{ fg: theme.primary, bold: true }}>{"Ctrl+X O"}</span> or type{" "}
            <span style={{ fg: theme.primary }}>/operations</span>
          </text>
        }
      >
        {(current) => (
          <text fg={theme.textMuted}>
            <span style={{ fg: theme[Kind.byId(current().kind)?.accent ?? "primary"] ?? theme.primary, bold: true }}>
              {Kind.byId(current().kind)?.glyph ?? "◆"} {current().label}
            </span>
            <span> · {current().kind}</span>
            <Show when={count() > 1}>
              <span>
                {" · "}
                <span style={{ fg: theme.text }}>{count()}</span> active ops
              </span>
            </Show>
          </text>
        )}
      </Show>
    </box>
  )
}
