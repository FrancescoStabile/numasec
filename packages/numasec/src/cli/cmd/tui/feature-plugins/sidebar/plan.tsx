import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo, createResource, createSignal, For, Show, onCleanup } from "solid-js"
import { TextAttributes } from "@opentui/core"
import { Plan } from "@/core/plan"
import { Operation } from "@/core/operation"

const id = "internal:sidebar-plan"

type RowItem = {
  title: string
  status: Plan.NodeStatus
  highlight?: boolean
}

const STATUS_GLYPH: Record<Plan.NodeStatus, string> = {
  planned: "○",
  running: "◉",
  done: "●",
  blocked: "✕",
  skipped: "◇",
}

function mapTodoStatus(s: string): Plan.NodeStatus {
  if (s === "completed") return "done"
  if (s === "in_progress") return "running"
  if (s === "cancelled") return "skipped"
  return "planned"
}

function colorFor(
  status: Plan.NodeStatus,
  theme: { success: string; warning: string; textMuted: string; text: string; error: string },
): string {
  if (status === "done") return theme.success
  if (status === "running") return theme.warning
  if (status === "blocked") return theme.error
  if (status === "skipped") return theme.textMuted
  return theme.text
}

function Row(props: { item: RowItem; theme: ReturnType<TuiPluginApi["theme"]["current"] extends infer T ? () => T : never> | any }) {
  const theme = props.theme
  const color = colorFor(props.item.status, theme)
  const strike = props.item.status === "skipped"
  return (
    <box flexDirection="row" gap={1} justifyContent="space-between">
      <box flexDirection="row" gap={1} flexShrink={1}>
        <text flexShrink={0} fg={color}>
          {STATUS_GLYPH[props.item.status]}
        </text>
        <text wrapMode="word" fg={color} attributes={strike ? TextAttributes.STRIKETHROUGH : undefined}>
          {props.item.title}
        </text>
      </box>
      <Show when={props.item.highlight}>
        <text flexShrink={0} fg={theme.error}>
          ⚑
        </text>
      </Show>
    </box>
  )
}

function View(props: { api: TuiPluginApi; session_id: string }) {
  const theme = () => props.api.theme.current

  // Boolean-flip tick: integer ticks make createResource treat every refetch as a
  // new source and stack in-flight work. Same pattern as dialog-operation.tsx.
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((v) => !v)
  let inflight = false

  const [data] = createResource(tick, async () => {
    if (inflight) return { nodes: [] as Plan.Node[] }
    inflight = true
    try {
      const dir = props.api.state.path.directory
      if (!dir) return { nodes: [] as Plan.Node[] }
      const slug = await Operation.activeSlug(dir).catch(() => undefined)
      if (!slug) return { nodes: [] as Plan.Node[] }
      const nodes = await Plan.list(dir, slug).catch(() => [] as Plan.Node[])
      return { nodes }
    } finally {
      inflight = false
    }
  })

  const todos = createMemo(() => props.api.state.session.todo(props.session_id))

  const rows = createMemo<RowItem[]>(() => {
    const planNodes = data()?.nodes ?? []
    if (planNodes.length > 0) {
      return planNodes.map((n) => ({ title: n.title, status: n.status }))
    }
    // Fallback: parse TodoWrite from the current session — preserves behaviour
    // for pure Claude flows when no active operation / empty plan store.
    return todos().map((t) => ({
      title: t.content,
      status: mapTodoStatus(t.status),
      highlight:
        (t as { priority?: string }).priority === "high" &&
        t.status !== "completed" &&
        t.status !== "cancelled",
    }))
  })

  // Refresh when TodoWrite fires or when the session status changes (proxy for
  // "something in the operation may have moved"). Event-driven — no setInterval.
  const offTodo = props.api.event.on("todo.updated", () => refresh())
  const offStatus = props.api.event.on("session.idle", () => refresh())
  onCleanup(() => {
    offTodo()
    offStatus()
  })

  const [open, setOpen] = createSignal(true)
  const activeRows = createMemo(() => rows().filter((r) => r.status !== "skipped"))
  const doneCount = createMemo(() => activeRows().filter((r) => r.status === "done").length)
  const totalCount = createMemo(() => activeRows().length)
  const hasOpen = createMemo(() => rows().some((r) => r.status !== "done" && r.status !== "skipped"))
  const canCollapse = createMemo(() => rows().length > 2)

  // Top-level <box> wrapper is load-bearing — opentui's insertExpression
  // unwraps SolidJS memo functions in a loop; returning a <Show> (a memo) at
  // the top level subscribes the parent render-effect to data(), causing
  // recreation on every refetch → infinite RAM growth. See dialog-operation.tsx.
  return (
    <box>
      <Show when={rows().length > 0 && hasOpen()}>
        <box>
          <box
            flexDirection="row"
            gap={1}
            justifyContent="space-between"
            onMouseDown={() => canCollapse() && setOpen((x) => !x)}
          >
            <box flexDirection="row" gap={1} flexShrink={1}>
              <Show when={canCollapse()}>
                <text fg={theme().text} flexShrink={0}>
                  {open() ? "▼" : "▶"}
                </text>
              </Show>
              <text fg={theme().text} wrapMode="none">
                <b>PLAN</b>
              </text>
            </box>
            <text fg={theme().textMuted} flexShrink={0} wrapMode="none">
              {doneCount()}/{totalCount()}
            </text>
          </box>
          <Show when={!canCollapse() || open()}>
            <For each={rows()}>{(item) => <Row item={item} theme={theme()} />}</For>
          </Show>
        </box>
      </Show>
    </box>
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
