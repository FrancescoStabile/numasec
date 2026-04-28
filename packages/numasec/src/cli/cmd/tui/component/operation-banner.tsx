import { createResource, createSignal, Show } from "solid-js"
import { useProject } from "@tui/context/project"
import { useTheme } from "@tui/context/theme"
import { Operation, type OperationInfo, type OperationKind } from "@/core/operation"

// Single-line banner for the active operation. Event-driven: fetched once on mount,
// plus explicit refresh() invocations when the app mutates the operation (create /
// activate / archive). No setInterval — polling a filesystem marker from the render
// tree reliably stacked in dev mode and we already have the dialog as the mutation
// point. See commit 43ff009 for context on the polling-induced freeze class.
const KIND_GLYPHS: Record<OperationKind, string> = {
  pentest: "◆",
  appsec: "◈",
  osint: "●",
  hacking: "✕",
  bughunt: "✦",
  ctf: "▲",
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
  // Boolean-flip tick: only two distinct source values, so createResource can never
  // stack dozens of in-flight fetches with fresh source identities.
  const [tick] = createSignal(true)
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
