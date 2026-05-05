import { For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { type OperationConsoleSnapshot, workflowLabel, workflowProgress, workflowStepRows } from "./snapshot"

export function OperationLensWorkflow(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
}) {
  const progress = workflowProgress(props.snapshot)
  const steps = workflowStepRows(props.snapshot)

  return (
    <box flexDirection="column" gap={1}>
      <text fg={props.theme.text} wrapMode="none">
        {props.snapshot.activeWorkflow?.kind ?? "workflow"} {workflowLabel(props.snapshot)}
      </text>
      <text fg={props.theme.textMuted} wrapMode="none">
        done {progress.completed}/{progress.total} · failed {progress.failed} · pending {progress.pending}
      </text>
      <Show
        when={steps.length > 0}
        fallback={
          <text fg={props.theme.textMuted} wrapMode="none">
            no workflow steps projected
          </text>
        }
      >
        <For each={steps}>
          {(step) => (
            <text fg={step.outcome === "failed" ? props.theme.warning : props.theme.textMuted} wrapMode="word">
              {step.index}. {step.label ?? step.tool ?? "step"} · {step.outcome}
              {step.outcome_title ? ` · ${step.outcome_title}` : ""}
            </text>
          )}
        </For>
      </Show>
    </box>
  )
}
