import { createMemo, createSignal, onCleanup, Show } from "solid-js"
import { useLocal } from "@tui/context/local"
import { useTheme } from "@tui/context/theme"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { OperationActive } from "@/core/operation"
import type { Info as OpInfo } from "@/core/operation/info"

export function OperationsBar(props: { sessionID?: string }) {
  const { theme } = useTheme()
  const local = useLocal()
  const project = useProject()

  const [activeOp, setActiveOp] = createSignal<OpInfo | undefined>(undefined)
  const refresh = async () => {
    const dir = project.instance.directory()
    if (!dir) return setActiveOp(undefined)
    const info = await OperationActive.resolveActive(dir).catch(() => undefined)
    setActiveOp(info)
  }
  refresh()
  const timer = setInterval(refresh, 4000)
  onCleanup(() => clearInterval(timer))

  const agent = createMemo(() => local.agent.current())
  const pack = createMemo(() => {
    const op = activeOp()
    if (op) return Kind.byId(op.kind)
    return Kind.byAgent(agent()?.name)
  })
  const model = createMemo(() => local.model.parsed().model)
  const opLabel = createMemo(() => activeOp()?.label ?? "new run")
  const opSlug = createMemo(() => activeOp()?.slug)
  const accent = createMemo(() => {
    const p = pack()
    if (!p) return theme.primary
    return theme[p.accent] ?? theme.primary
  })

  return (
    <box
      flexDirection="row"
      flexShrink={0}
      paddingLeft={2}
      paddingRight={2}
      gap={2}
      backgroundColor={theme.backgroundElement}
      height={1}
    >
      <text fg={accent()}>
        <span style={{ bold: true }}>◢◤</span> <span style={{ fg: theme.textMuted }}>OP</span>{" "}
        <span>{opLabel()}</span>
        <Show when={opSlug()}>
          <span style={{ fg: theme.textMuted }}> ({opSlug()})</span>
        </Show>
      </text>
      <Show when={pack()}>
        {(p) => (
          <text fg={theme.textMuted}>
            <span style={{ fg: accent(), bold: true }}>
              {p().glyph} {p().label}
            </span>
          </text>
        )}
      </Show>
      <Show when={agent()}>
        {(a) => (
          <text fg={theme.textMuted}>
            AGENT <span style={{ fg: theme.text }}>{a().name}</span>
          </text>
        )}
      </Show>
      <text fg={theme.textMuted}>
        MODEL <span style={{ fg: theme.text }}>{model()}</span>
      </text>
    </box>
  )
}
