import { createMemo, type JSX, For } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import type { SessionView } from "@tui/context/session-view"
import {
  findingsBadgeCount,
  replayCoveredCount,
  reportStatus,
  type OperationConsoleSnapshot,
  workflowProgress,
} from "./snapshot"
import { toneColor } from "./ui"

type LensBarItem = {
  id: SessionView
  name: string
  value?: string
  tone?: "normal" | "success" | "warning" | "error"
}

function items(snapshot: OperationConsoleSnapshot): LensBarItem[] {
  const report = reportStatus(snapshot)
  const workflow = workflowProgress(snapshot)
  const verified = snapshot.projected?.summary.verified_findings ?? 0
  return [
    { id: "chat", name: "CHAT" },
    { id: "findings", name: "FINDINGS", value: String(findingsBadgeCount(snapshot)) },
    { id: "evidence", name: "EVIDENCE", value: String(snapshot.evidenceCount) },
    { id: "replay", name: "REPLAY", value: `${replayCoveredCount(snapshot)}/${verified}` },
    {
      id: "workflow",
      name: "WORKFLOW",
      value: `${workflow.completed}/${workflow.total}`,
      tone: workflow.failed > 0 ? "error" : workflow.degraded ? "warning" : undefined,
    },
    {
      id: "report",
      name: "REPORT",
      value: report,
      tone: report === "ready" ? "success" : report === "draft" ? "warning" : undefined,
    },
  ]
}

export function OperationLensBar(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  view: SessionView
  onSelect: (view: SessionView) => void
}) {
  const barItems = createMemo(() => items(props.snapshot))

  return (
    <box flexDirection="row" gap={1} flexWrap="no-wrap" height={1} flexShrink={0}>
      <For each={barItems()}>
        {(item, index) => (
          <text
            fg={item.id === props.view ? props.theme.primary : toneColor(props.theme, item.tone)}
            attributes={item.id === props.view ? 1 : undefined}
            wrapMode="none"
            onMouseDown={() => props.onSelect(item.id)}
          >
            {item.id === props.view ? "[" : ""}
            {item.name}
            {item.value ? " " : ""}
            {item.value ? <span style={{ fg: item.id === props.view ? props.theme.text : toneColor(props.theme, item.tone) }}>{item.value}</span> : null}
            {item.id === props.view ? "]" : ""}
            {index() < barItems().length - 1 ? <span style={{ fg: props.theme.textMuted }}> ·</span> : null}
          </text>
        )}
      </For>
    </box>
  )
}
