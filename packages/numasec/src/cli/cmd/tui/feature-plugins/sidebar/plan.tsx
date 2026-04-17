import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, For, Show, createSignal } from "solid-js"
import { TextAttributes } from "@opentui/core"

const id = "internal:sidebar-plan"

type TodoItem = { content: string; status: string; priority: string }

function glyphFor(status: string): string {
  switch (status) {
    case "completed":
      return "●"
    case "in_progress":
      return "◉"
    case "cancelled":
      return "✗"
    default:
      return "○"
  }
}

function colorFor(
  status: string,
  theme: { success: string; warning: string; textMuted: string; text: string },
): string {
  switch (status) {
    case "completed":
      return theme.success
    case "in_progress":
      return theme.warning
    case "cancelled":
      return theme.textMuted
    default:
      return theme.text
  }
}

function Row(props: { item: TodoItem; theme: ReturnType<TuiPluginApi["theme"]["current"] extends infer T ? () => T : never> | any }) {
  const theme = props.theme
  const color = colorFor(props.item.status, theme)
  const isCancelled = props.item.status === "cancelled"
  const isHigh = props.item.priority === "high" && props.item.status !== "completed" && props.item.status !== "cancelled"

  return (
    <box flexDirection="row" gap={1} justifyContent="space-between">
      <box flexDirection="row" gap={1} flexShrink={1}>
        <text flexShrink={0} fg={color}>
          {glyphFor(props.item.status)}
        </text>
        <text wrapMode="word" fg={color} attributes={isCancelled ? TextAttributes.STRIKETHROUGH : undefined}>
          {props.item.content}
        </text>
      </box>
      <Show when={isHigh}>
        <text flexShrink={0} fg={theme.error}>
          ⚑
        </text>
      </Show>
    </box>
  )
}

function View(props: { api: TuiPluginApi; session_id: string }) {
  const [open, setOpen] = createSignal(true)
  const theme = () => props.api.theme.current
  const list = createMemo(() => props.api.state.session.todo(props.session_id) as TodoItem[])

  const active = createMemo(() => list().filter((i) => i.status !== "cancelled"))
  const done = createMemo(() => active().filter((i) => i.status === "completed").length)
  const total = createMemo(() => active().length)

  const show = createMemo(() => list().length > 0 && list().some((i) => i.status !== "completed" && i.status !== "cancelled"))

  return (
    <Show when={show()}>
      <box>
        <box
          flexDirection="row"
          gap={1}
          justifyContent="space-between"
          onMouseDown={() => list().length > 2 && setOpen((x) => !x)}
        >
          <box flexDirection="row" gap={1} flexShrink={1}>
            <Show when={list().length > 2}>
              <text fg={theme().text} flexShrink={0}>
                {open() ? "▼" : "▶"}
              </text>
            </Show>
            <text fg={theme().text} wrapMode="none">
              <b>PLAN</b>
            </text>
          </box>
          <text fg={theme().textMuted} flexShrink={0} wrapMode="none">
            {done()}/{total()}
          </text>
        </box>
        <Show when={list().length <= 2 || open()}>
          <For each={list()}>{(item) => <Row item={item} theme={theme()} />}</For>
        </Show>
      </box>
    </Show>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 150,
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
