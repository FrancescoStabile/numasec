import type { AssistantMessage } from "@numasec/sdk/v2"
import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@numasec/plugin/tui"
import { createMemo } from "solid-js"

const id = "internal:sidebar-pulse"

const money = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
})

const SPARK_LEVELS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"] as const
const SPARK_WIDTH = 12
const IDLE_MS = 3000

const AGENT_SIGIL: Record<string, { glyph: string; label: string }> = {
  pentest: { glyph: "P", label: "pentest" },
  osint: { glyph: "O", label: "osint" },
  appsec: { glyph: "A", label: "appsec" },
  hacking: { glyph: "H", label: "hacking" },
  explore: { glyph: "E", label: "explore" },
  security: { glyph: "S", label: "security" },
  plan: { glyph: "∇", label: "plan" },
  build: { glyph: "B", label: "build" },
}

function sigilFor(agent: string | undefined) {
  if (!agent) return { glyph: "·", label: "agent" }
  return AGENT_SIGIL[agent] ?? { glyph: agent.charAt(0).toUpperCase(), label: agent }
}

function agentColor(agent: string | undefined, theme: any) {
  switch (agent) {
    case "pentest":
      return theme.error
    case "hacking":
      return theme.warning
    case "appsec":
      return theme.success
    case "osint":
      return theme.accent
    case "explore":
      return theme.info
    default:
      return theme.primary
  }
}

export function sparklineFor(samples: number[]): string {
  if (samples.length === 0) return SPARK_LEVELS[0].repeat(SPARK_WIDTH)
  const max = Math.max(...samples, 1)
  const padded = samples.length < SPARK_WIDTH ? Array(SPARK_WIDTH - samples.length).fill(0).concat(samples) : samples.slice(-SPARK_WIDTH)
  return padded
    .map((v) => {
      if (v <= 0) return SPARK_LEVELS[0]
      const idx = Math.min(SPARK_LEVELS.length - 1, Math.floor((v / max) * SPARK_LEVELS.length))
      return SPARK_LEVELS[idx]
    })
    .join("")
}

function formatShortNumber(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`
}

function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}h${m}m`
  if (m > 0) return `${m}m`
  return `${s}s`
}

function View(props: { api: TuiPluginApi; session_id: string }) {
  const theme = () => props.api.theme.current
  const messages = createMemo(() => props.api.state.session.messages(props.session_id))

  const assistants = createMemo(() =>
    messages().filter((item): item is AssistantMessage => item.role === "assistant"),
  )

  const cost = createMemo(() => assistants().reduce((sum, item) => sum + item.cost, 0))

  const samples = createMemo(() => {
    return assistants()
      .map((m) => m.tokens.output)
      .filter((n) => n > 0)
      .slice(-SPARK_WIDTH)
  })

  const last = createMemo(() => {
    const list = assistants()
    return list.length > 0 ? list[list.length - 1] : undefined
  })

  const rate = createMemo(() => {
    const m = last()
    if (!m || !m.time.completed || m.tokens.output <= 0) return null
    const dur = m.time.completed - m.time.created
    if (dur <= 0) return null
    return Math.round((m.tokens.output / dur) * 1000)
  })

  const idle = createMemo(() => {
    const m = last()
    if (!m) return true
    if (!m.time.completed) return false
    return Date.now() - m.time.completed > IDLE_MS
  })

  const agent = createMemo(() => last()?.agent)

  const model = createMemo(() => {
    const m = last()
    if (!m) return undefined
    return props.api.state.provider.find((p) => p.id === m.providerID)?.models[m.modelID]
  })

  const modelName = createMemo(() => {
    const m = last()
    if (!m) return ""
    return model()?.name ?? m.modelID
  })

  const contextUsage = createMemo(() => {
    const m = last()
    if (!m || m.tokens.output <= 0) return { used: 0, max: null as number | null, percent: null as number | null }
    const used = m.tokens.input + m.tokens.output + m.tokens.reasoning + m.tokens.cache.read + m.tokens.cache.write
    const max = model()?.limit.context ?? null
    const percent = max ? Math.round((used / max) * 100) : null
    return { used, max, percent }
  })

  const turns = createMemo(() => assistants().length)

  const elapsed = createMemo(() => {
    const list = messages()
    if (list.length === 0) return 0
    const first = list[0]
    return Date.now() - first.time.created
  })

  const sparkStr = createMemo(() => sparklineFor(samples()))

  return (
    <box>
      <box flexDirection="row" gap={1}>
        <text fg={theme().textMuted} wrapMode="none">
          <b>PULSE</b>
        </text>
      </box>

      <box flexDirection="row" gap={1}>
        <text fg={theme().textMuted} wrapMode="none">{modelName() || "—"}</text>
      </box>

      <box flexDirection="row" gap={1}>
        <text fg={agentColor(agent(), theme())} wrapMode="none">
          ⟨{sigilFor(agent()).glyph}⟩
        </text>
        <text fg={theme().textMuted} wrapMode="none">{sigilFor(agent()).label}</text>
      </box>

      <box flexDirection="row" gap={1} justifyContent="space-between">
        <text fg={idle() ? theme().textMuted : theme().accent} wrapMode="none">{sparkStr()}</text>
        <text fg={idle() ? theme().textMuted : theme().text} wrapMode="none" flexShrink={0}>
          {idle() ? "idle" : rate() !== null ? `${rate()} t/s` : "—"}
        </text>
      </box>

      <text fg={theme().textMuted} wrapMode="none">
        {money.format(cost())} · {turns()} turns · {formatElapsed(elapsed())}
      </text>

      <text fg={theme().textMuted} wrapMode="none">
        {formatShortNumber(contextUsage().used)}
        {contextUsage().max !== null ? `/${formatShortNumber(contextUsage().max!)}` : ""}
        {contextUsage().percent !== null ? ` (${contextUsage().percent}%)` : ""}
      </text>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 220,
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
