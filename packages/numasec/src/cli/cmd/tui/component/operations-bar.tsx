import { createMemo, createSignal, onCleanup, Show } from "solid-js"
import { useLocal } from "@tui/context/local"
import { useTheme } from "@tui/context/theme"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { OperationActive } from "@/core/operation"
import type { Info as OpInfo } from "@/core/operation/info"
import { FileWatcher } from "@/file/watcher"
import { BRAND, SCOPE, SUBJECT } from "@tui/component/glyph"

// "Mission strip" — the always-visible header that gives every numasec screenshot
// its operator-console identity. Slots, in order:
//   ◢◤ OP <label>(slug) | <kind> | TGT ⌬ <host> | SCOPE ◉ ok | OPSEC <mode> | MODEL | T+hh:mm:ss
// Slots with no value are omitted (not blank-filled) to avoid noise.
// When no operation is active, the strip degrades to a single hint line.

function pickTarget(subject: Record<string, unknown> | undefined): string | undefined {
  if (!subject) return undefined
  for (const key of ["host", "url", "target", "ip", "domain", "asset"]) {
    const v = subject[key]
    if (typeof v === "string" && v.length > 0) return v
  }
  return undefined
}

function formatElapsed(startMs: number, nowMs: number): string {
  const s = Math.max(0, Math.floor((nowMs - startMs) / 1000))
  const hh = String(Math.floor(s / 3600)).padStart(2, "0")
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0")
  const ss = String(s % 60).padStart(2, "0")
  return `${hh}:${mm}:${ss}`
}

export function OperationsBar(props: { sessionID?: string }) {
  const { theme } = useTheme()
  const local = useLocal()
  const project = useProject()

  const [activeOp, setActiveOp] = createSignal<OpInfo | undefined>(undefined)
  const [now, setNow] = createSignal(Date.now())

  const refresh = async () => {
    if (inflight) return
    inflight = true
    try {
      const dir = project.instance.directory()
      if (!dir) return setActiveOp(undefined)
      const info = await OperationActive.resolveActive(dir).catch(() => undefined)
      setActiveOp(info)
    } finally {
      inflight = false
    }
  }
  let inflight = false
  refresh()
  const opInterval = FileWatcher.hasNativeBinding() ? 4000 : 8000
  const opTimer = setInterval(refresh, opInterval)
  const tickTimer = setInterval(() => setNow(Date.now()), 1000)
  onCleanup(() => {
    clearInterval(opTimer)
    clearInterval(tickTimer)
  })

  const agent = createMemo(() => local.agent.current())
  const pack = createMemo(() => {
    const op = activeOp()
    if (op) return Kind.byId(op.kind)
    return Kind.byAgent(agent()?.name)
  })
  const model = createMemo(() => local.model.parsed().model)
  const accent = createMemo(() => {
    const p = pack()
    if (!p) return theme.primary
    return theme[p.accent] ?? theme.primary
  })

  const target = createMemo(() => pickTarget(activeOp()?.subject))
  const opsec = createMemo(() => {
    const m = activeOp()?.mode
    if (!m) return undefined
    return m.opsec ?? m.opSec ?? m.posture
  })
  const scopeOk = createMemo(() => Boolean(activeOp()?.boundary))
  const elapsed = createMemo(() => {
    const op = activeOp()
    if (!op) return undefined
    return formatElapsed(op.created_at, now())
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
      <Show
        when={activeOp()}
        fallback={
          <text fg={theme.textMuted}>
            <span style={{ fg: accent(), bold: true }}>{BRAND.wordmark}</span>{" "}
            <Show when={pack()}>
              {(p) => (
                <span style={{ fg: accent(), bold: true }}>
                  {p().glyph} {p().label}
                </span>
              )}
            </Show>
            <span> · MODEL </span>
            <span style={{ fg: theme.text }}>{model()}</span>
            <span> · </span>
            <span style={{ fg: theme.textMuted }}>no engagement</span>
            <span> · </span>
            <span style={{ fg: theme.primary, bold: true }}>Ctrl+X O</span>
            <span> to start one</span>
          </text>
        }
      >
        {(op) => (
          <>
            <text fg={accent()}>
              <span style={{ bold: true }}>◢◤</span>{" "}
              <span style={{ fg: theme.textMuted }}>OP</span>{" "}
              <span>{op().label}</span>
              <span style={{ fg: theme.textMuted }}> ({op().slug})</span>
            </text>
            <Show when={pack()}>
              {(p) => (
                <text fg={accent()}>
                  <span style={{ bold: true }}>
                    {p().glyph} {p().label}
                  </span>
                </text>
              )}
            </Show>
            <Show when={target()}>
              {(t) => (
                <text fg={theme.textMuted}>
                  <span>{SUBJECT.target}</span> TGT{" "}
                  <span style={{ fg: theme.text }}>{t()}</span>
                </text>
              )}
            </Show>
            <text fg={theme.textMuted}>
              <Show
                when={scopeOk()}
                fallback={
                  <>
                    <span style={{ fg: theme.warning }}>{SCOPE.ambiguous}</span>{" "}
                    <span>SCOPE </span>
                    <span style={{ fg: theme.warning }}>unset</span>
                  </>
                }
              >
                <span style={{ fg: theme.success }}>{SCOPE.in}</span>{" "}
                <span>SCOPE </span>
                <span style={{ fg: theme.success }}>ok</span>
              </Show>
            </text>
            <Show when={opsec()}>
              {(o) => (
                <text fg={theme.textMuted}>
                  OPSEC <span style={{ fg: theme.text }}>{String(o())}</span>
                </text>
              )}
            </Show>
            <text fg={theme.textMuted}>
              MODEL <span style={{ fg: theme.text }}>{model()}</span>
            </text>
            <Show when={elapsed()}>
              {(e) => (
                <text fg={theme.textMuted}>
                  T+<span style={{ fg: theme.text }}>{e()}</span>
                </text>
              )}
            </Show>
          </>
        )}
      </Show>
    </box>
  )
}
