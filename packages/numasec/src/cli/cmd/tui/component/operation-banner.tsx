import { createResource, createSignal, onCleanup, onMount, Show } from "solid-js"
import { useProject } from "@tui/context/project"
import { useTheme } from "@tui/context/theme"
import { Operation, type OperationInfo, type OperationKind } from "@/core/operation"

// Single-line banner for the active operation. Refreshes on a low-frequency
// interval (5s) — no busy-polling. File-level mtime is the source of truth.
const KIND_GLYPHS: Record<OperationKind, string> = {
  pentest: "◆",
  ctf: "▲",
  bughunt: "✦",
  osint: "●",
  research: "◇",
}

function relativeAge(ms: number): string {
  const d = Date.now() - ms
  if (d < 60_000) return "just now"
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`
  if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`
  return `${Math.floor(d / 86_400_000)}d ago`
}

export function OperationBanner() {
  const project = useProject()
  const { theme } = useTheme()
  const [tick, setTick] = createSignal(0)
  let inflight = false

  const [info] = createResource(tick, async (): Promise<OperationInfo | undefined> => {
    if (inflight) return
    inflight = true
    try {
      const dir = project.instance.directory()
      if (!dir) return undefined
      return await Operation.active(dir).catch(() => undefined)
    } finally {
      inflight = false
    }
  })

  let timer: ReturnType<typeof setInterval> | undefined
  onMount(() => {
    timer = setInterval(() => setTick((v) => v + 1), 5000)
  })
  onCleanup(() => {
    if (timer) clearInterval(timer)
  })

  return (
    <Show when={info()}>
      {(i) => (
        <box flexDirection="row" paddingLeft={2} paddingRight={2} flexShrink={0}>
          <text fg={theme.primary}>
            {KIND_GLYPHS[i().kind] ?? "◆"}{" "}
            <span style={{ fg: theme.text }}>
              <b>{i().label}</b>
            </span>
            <span style={{ fg: theme.textMuted }}>
              {" "}
              · {i().kind}
              {i().target ? ` · ${i().target}` : ""} · {i().lines}L · updated {relativeAge(i().updated_at)}
            </span>
          </text>
        </box>
      )}
    </Show>
  )
}
