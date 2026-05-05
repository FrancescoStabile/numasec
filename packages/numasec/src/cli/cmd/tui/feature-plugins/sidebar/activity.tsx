import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import type { ToolPart } from "@numasec/sdk/v2"
import { createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js"
import { loadOperationConsoleSnapshot } from "./operation-console"

const id = "internal:sidebar-activity"

const MAX_ROWS = 8
const LABEL_MAX = 18
const TIME_WIDTH = 8
const OUTCOME_WIDTH = 8

export const TOOL_WHITELIST = new Set([
  "bash",
  "http_request",
  "net",
  "browser",
  "webfetch",
  "websearch",
  "grep",
  "glob",
  "codesearch",
  "interact",
  "vault",
  "crypto",
])

function truncateMid(s: string, max: number): string {
  if (s.length <= max) return s
  const head = Math.max(1, Math.floor((max - 1) / 2))
  const tail = Math.max(1, max - 1 - head)
  return s.slice(0, head) + "…" + s.slice(-tail)
}

function toStr(v: unknown): string {
  if (typeof v === "string") return v
  if (typeof v === "number" || typeof v === "boolean") return String(v)
  return ""
}

function hostOf(urlish: string): string {
  if (!urlish) return ""
  try {
    const u = new URL(urlish.includes("://") ? urlish : `http://${urlish}`)
    return u.hostname || urlish
  } catch {
    return urlish
  }
}

function pathOf(urlish: string): string {
  if (!urlish) return "/"
  try {
    const u = new URL(urlish.includes("://") ? urlish : `http://${urlish}`)
    return (u.pathname || "/") + (u.search ?? "")
  } catch {
    return urlish
  }
}

export function deriveLabel(tool: string, input: Record<string, unknown>): string {
  switch (tool) {
    case "bash": {
      const cmd = toStr(input.command).trim()
      const first = cmd.split(/\s+/).slice(0, 3).join(" ")
      return first || "bash"
    }
    case "http_request": {
      const method = toStr(input.method) || "GET"
      const url = toStr(input.url)
      return `${method} ${pathOf(url)}`
    }
    case "net": {
      const op = toStr(input.op)
      const host = toStr(input.host)
      const port = toStr(input.port)
      return `${op || "net"} ${host}${port ? `:${port}` : ""}`
    }
    case "browser": {
      const op = toStr(input.op) || toStr(input.action) || "browser"
      const url = toStr(input.url) || toStr(input.target) || ""
      return `${op} ${hostOf(url)}`.trim()
    }
    case "webfetch": {
      const url = toStr(input.url)
      return `${hostOf(url)}${pathOf(url) !== "/" ? pathOf(url) : ""}`
    }
    case "websearch": {
      return toStr(input.query) || "search"
    }
    case "grep": {
      return toStr(input.pattern) || "grep"
    }
    case "glob": {
      return toStr(input.pattern) || "glob"
    }
    case "codesearch": {
      return toStr(input.query) || "codesearch"
    }
    case "interact": {
      const a = toStr(input.action) || "interact"
      const t = toStr(input.target) || toStr(input.url) || ""
      return `${a} ${t}`.trim()
    }
    case "vault": {
      const action = toStr(input.action) || toStr(input.op) || ""
      const key = toStr(input.key) || toStr(input.name) || ""
      return `vault ${action}${key ? ` ${key}` : ""}`.trim()
    }
    case "crypto": {
      return `crypto ${toStr(input.op) || ""}`.trim()
    }
    default:
      return tool
  }
}

type Row = {
  id: string
  status: "pending" | "running" | "completed" | "error"
  label: string
  statusSuffix: string
  statusColorKey: "success" | "warning" | "error" | "info" | "muted"
  ts: number
}

function httpStatusColor(code: number): Row["statusColorKey"] {
  if (code >= 500) return "error"
  if (code >= 400) return "warning"
  if (code >= 300) return "muted"
  if (code >= 200) return "success"
  return "info"
}

function rowFromPart(part: ToolPart): Row | null {
  if (!TOOL_WHITELIST.has(part.tool)) return null
  const state = part.state
  const input = (state.input ?? {}) as Record<string, unknown>
  const label = truncateMid(deriveLabel(part.tool, input), LABEL_MAX)

  let suffix = ""
  let colorKey: Row["statusColorKey"] = "muted"
  let ts = 0

  switch (state.status) {
    case "pending": {
      ts = 0
      colorKey = "info"
      break
    }
    case "running": {
      ts = state.time?.start ?? 0
      colorKey = "info"
      break
    }
    case "completed": {
      ts = state.time?.end ?? state.time?.start ?? 0
      const meta = (state.metadata ?? {}) as Record<string, unknown>
      if (part.tool === "http_request") {
        const code = typeof meta.status === "number" ? (meta.status as number) : undefined
        if (typeof code === "number") {
          suffix = String(code)
          colorKey = httpStatusColor(code)
        } else {
          colorKey = "success"
        }
      } else if (part.tool === "bash") {
        const exit = typeof meta.exit === "number" ? (meta.exit as number) : 0
        if (exit !== 0) {
          suffix = `exit ${exit}`
          colorKey = "error"
        } else {
          colorKey = "success"
        }
      } else {
        colorKey = "success"
      }
      break
    }
    case "error": {
      ts = state.time?.end ?? 0
      colorKey = "error"
      break
    }
  }

  return {
    id: part.id,
    status: state.status,
    label,
    statusSuffix: suffix,
    statusColorKey: colorKey,
    ts,
  }
}

function timeLabel(ts: number): string {
  if (!ts) return "--:--"
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
}

function outcomeLabel(row: Row): string {
  if (row.statusSuffix) return row.statusSuffix
  if (row.status === "completed") return "done"
  if (row.status === "running") return "run"
  if (row.status === "pending") return "wait"
  return "fail"
}

function padCell(value: string, width: number, align: "left" | "right" = "left"): string {
  const clipped = value.length > width ? value.slice(0, width) : value
  return align === "right" ? clipped.padStart(width, " ") : clipped.padEnd(width, " ")
}

function View(props: { api: TuiPluginApi; session_id: string }) {
  const theme = () => props.api.theme.current
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((value) => !value)
  let inflight = false

  const messages = createMemo(() => props.api.state.session.messages(props.session_id))
  const [snapshot] = createResource(tick, async () => {
    if (inflight) return undefined
    inflight = true
    try {
      return await loadOperationConsoleSnapshot(props.api.state.path.directory)
    } finally {
      inflight = false
    }
  })

  const rows = createMemo<Row[]>(() => {
    const acc: Row[] = []
    for (const m of messages()) {
      if (m.role !== "assistant") continue
      const parts = props.api.state.part(m.id)
      for (const p of parts) {
        if (p.type !== "tool") continue
        const row = rowFromPart(p as ToolPart)
        if (row) acc.push(row)
      }
    }
    return acc.slice(-MAX_ROWS).reverse()
  })

  const timelineRows = createMemo<Row[]>(() => {
    const items = snapshot()?.timeline ?? []
    return items.slice(0, MAX_ROWS).map((item) => ({
      id: item.id,
      status: item.status === "failed" ? "error" : "completed",
      label: truncateMid(item.summary || item.kind, LABEL_MAX),
      statusSuffix:
        item.status === "failed"
          ? "fail"
          : item.kind.includes("report")
            ? "ready"
            : item.kind.includes("evidence")
              ? "evidence"
              : item.kind.includes("replay")
                ? "replay"
                : "done",
      statusColorKey:
        item.status === "failed"
          ? "error"
          : item.kind.includes("report")
            ? "success"
            : item.kind.includes("tool")
              ? "info"
              : "muted",
      ts: item.time_created,
    }))
  })

  const effectiveRows = createMemo(() => (timelineRows().length > 0 ? timelineRows() : rows()))
  const empty = createMemo(() => effectiveRows().length === 0)

  const offIdle = props.api.event.on("session.idle", () => refresh())
  const offPart = props.api.event.on("message.part.updated", () => refresh())
  onCleanup(() => {
    offIdle()
    offPart()
  })

  const colorFor = (key: Row["statusColorKey"]) => {
    const t = theme()
    switch (key) {
      case "success":
        return t.success
      case "warning":
        return t.warning
      case "error":
        return t.error
      case "info":
        return t.info
      case "muted":
        return t.textMuted
    }
  }

  return (
    <box>
      <text fg={theme().text} wrapMode="none">
        <b>ACTIVITY</b>
      </text>
      <Show
        when={!empty()}
        fallback={
          <text fg={theme().textMuted} wrapMode="none">
            idle · waiting for tool activity
          </text>
        }
      >
        <For each={effectiveRows()}>
          {(row) => (
            <box flexDirection="row" gap={1}>
              <text flexShrink={0} fg={theme().textMuted} wrapMode="none">
                {padCell(timeLabel(row.ts), TIME_WIDTH)}
              </text>
              <text flexGrow={1} flexShrink={1} wrapMode="none" fg={theme().textMuted}>
                {row.label}
              </text>
              <text flexShrink={0} fg={colorFor(row.statusColorKey)} wrapMode="none">
                {padCell(outcomeLabel(row), OUTCOME_WIDTH, "right")}
              </text>
            </box>
          )}
        </For>
      </Show>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 175,
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
