import { type JSX, For } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import type { SessionView } from "@tui/context/session-view"
import {
  findingsBadgeCount,
  replayCoveredCount,
  reportStatus,
  type OperationConsoleSnapshot,
  workflowProgress,
} from "./snapshot"

type LensBarItem = {
  id: SessionView
  label: string
  tone?: "normal" | "success" | "warning" | "error"
}

function toneColor(theme: TuiThemeCurrent, tone: LensBarItem["tone"]) {
  switch (tone) {
    case "success":
      return theme.success
    case "warning":
      return theme.warning
    case "error":
      return theme.error
    default:
      return theme.textMuted
  }
}

function items(snapshot: OperationConsoleSnapshot): LensBarItem[] {
  const report = reportStatus(snapshot)
  const workflow = workflowProgress(snapshot)
  const verified = snapshot.projected?.summary.verified_findings ?? 0
  return [
    { id: "chat", label: "CHAT" },
    { id: "findings", label: `FINDINGS ${findingsBadgeCount(snapshot)}` },
    { id: "evidence", label: `EVIDENCE ${snapshot.evidenceCount}` },
    { id: "replay", label: `REPLAY ${replayCoveredCount(snapshot)}/${verified}` },
    {
      id: "workflow",
      label: `WORKFLOW ${workflow.completed}/${workflow.total}`,
      tone: workflow.failed > 0 ? "error" : workflow.degraded ? "warning" : undefined,
    },
    {
      id: "report",
      label: `REPORT ${report}`,
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
  return (
    <box flexDirection="row" gap={2} flexWrap="wrap" paddingBottom={1}>
      <For each={items(props.snapshot)}>
        {(item) => (
          <text
            fg={item.id === props.view ? props.theme.primary : toneColor(props.theme, item.tone)}
            attributes={item.id === props.view ? 1 : undefined}
            wrapMode="none"
            onMouseDown={() => props.onSelect(item.id)}
          >
            {item.label}
          </text>
        )}
      </For>
    </box>
  )
}
