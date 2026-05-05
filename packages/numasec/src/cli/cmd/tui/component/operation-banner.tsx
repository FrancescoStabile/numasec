import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import { useProject } from "@tui/context/project"
import { useTheme } from "@tui/context/theme"
import { useEvent } from "@tui/context/event"
import { type OperationKind } from "@/core/operation"
import {
  loadOperationConsoleSnapshot,
  replayCoveredCount,
  reportStatus,
  scopeDecision,
  type OperationConsoleSnapshot,
} from "@tui/feature-plugins/sidebar/operation-console"

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
  const event = useEvent()
  const { theme } = useTheme()
  // Boolean-flip tick: only two distinct source values, so createResource can never
  // stack dozens of in-flight fetches with fresh source identities.
  const [tick, setTick] = createSignal(true)
  let inflight = false

  const refresh = () => setTick((value) => !value)
  const [info] = createResource<OperationConsoleSnapshot | undefined, boolean>(tick, async () => {
    if (inflight) return
    inflight = true
    try {
      const dir = project.instance.directory()
      if (!dir) return undefined
      return await loadOperationConsoleSnapshot(dir)
    } finally {
      inflight = false
    }
  })
  const snapshot = createMemo(() => info())
  const active = createMemo(() => snapshot()?.active)

  const offIdle = event.on("session.idle", () => refresh())
  const offPart = event.on("message.part.updated", () => refresh())
  const offStatus = event.on("session.status", () => refresh())
  onCleanup(() => {
    offIdle()
    offPart()
    offStatus()
  })

  return (
    <box>
      <Show when={active()}>
        <box flexDirection="row" paddingLeft={2} paddingRight={2} flexShrink={0}>
          <text fg={theme.primary}>
            {KIND_GLYPHS[active()!.kind] ?? "◆"}{" "}
            <span style={{ fg: theme.text }}>
              <b>{active()!.label}</b>
            </span>
            <span style={{ fg: theme.textMuted }}>
              {" "}
              · {active()!.kind}
              {active()!.target ? ` · ${active()!.target}` : ""}
              {snapshot() ? (() => {
                const decision = scopeDecision(snapshot()!)
                return decision ? ` · scope ${decision.mode}` : ""
              })() : ""}
              {snapshot() && (snapshot()!.projected?.summary.verified_findings ?? 0) > 0
                ? ` · replay ${replayCoveredCount(snapshot()!)}/${snapshot()!.projected?.summary.verified_findings ?? 0}`
                : ""}
              {snapshot() ? ` · report ${reportStatus(snapshot()!)}` : ""}
              · updated {relativeAge(active()!.updated_at)}
            </span>
          </text>
        </box>
      </Show>
    </box>
  )
}
