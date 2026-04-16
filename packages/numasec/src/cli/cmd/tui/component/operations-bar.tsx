import { createMemo, Show } from "solid-js"
import { useLocal } from "@tui/context/local"
import { useTheme } from "@tui/context/theme"
import { useSync } from "@tui/context/sync"
import { Kind } from "@/core/kind"

export function OperationsBar(props: { sessionID?: string }) {
  const { theme } = useTheme()
  const local = useLocal()
  const sync = useSync()

  const session = createMemo(() => (props.sessionID ? sync.session.get(props.sessionID) : undefined))
  const agent = createMemo(() => local.agent.current())
  const pack = createMemo(() => Kind.byAgent(agent()?.name))
  const model = createMemo(() => local.model.parsed().model)
  const opLabel = createMemo(() => session()?.title?.slice(0, 32) ?? "new run")
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
