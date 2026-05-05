import { Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import {
  deliverableLabel,
  numericCount,
  reportStatus,
  type OperationConsoleSnapshot,
} from "./snapshot"

export function OperationLensReport(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
}) {
  const counts = props.snapshot.deliverable?.counts
  const status = reportStatus(props.snapshot)

  return (
    <box flexDirection="column" gap={1}>
      <text fg={status === "ready" ? props.theme.success : status === "draft" ? props.theme.warning : props.theme.textMuted} wrapMode="none">
        report {status}
      </text>
      <text fg={props.theme.textMuted} wrapMode="word">
        {deliverableLabel(props.snapshot)}
      </text>
      <Show when={counts}>
        <text fg={props.theme.textMuted} wrapMode="none">
          evidence {numericCount(counts, "evidence")} · reportable {numericCount(counts, "reportable_findings")} ·
          verified {numericCount(counts, "verified_findings")}
        </text>
        <text fg={props.theme.textMuted} wrapMode="none">
          replay {numericCount(counts, "replay_backed_findings")} · workflows {numericCount(counts, "workflows")} ·
          ledger {numericCount(counts, "ledger_events")}
        </text>
      </Show>
      <Show when={!counts}>
        <text fg={props.theme.textMuted} wrapMode="none">
          not built
        </text>
      </Show>
    </box>
  )
}
