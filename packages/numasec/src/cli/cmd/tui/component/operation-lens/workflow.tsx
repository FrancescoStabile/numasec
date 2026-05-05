import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { type OperationConsoleSnapshot, workflowLabel, workflowProgress, workflowRows } from "./snapshot"
import { LensDetail, LensEmpty, LensRow, LensTitle, statusColor, truncateMiddle } from "./ui"

export function OperationLensWorkflow(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  selectedIndex: number
}) {
  const progress = createMemo(() => workflowProgress(props.snapshot))
  const rows = createMemo(() => workflowRows(props.snapshot))
  const selected = createMemo(() => rows()[props.selectedIndex])

  return (
    <box flexDirection="column" gap={1}>
      <LensTitle
        theme={props.theme}
        title={`WORKFLOW ${props.snapshot.activeWorkflow?.kind ?? "workflow"} ${workflowLabel(props.snapshot)}`}
        summary={`done ${progress().completed}/${progress().total} · failed ${progress().failed} · pending ${progress().pending}`}
      />
      <Show when={rows().length > 0} fallback={<LensEmpty theme={props.theme} message="no workflow steps projected" />}>
        <box flexDirection="row" gap={2}>
          <text fg={props.theme.textMuted} wrapMode="none">
            #
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            State
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Tool
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Step
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Outcome
          </text>
        </box>
        <For each={rows()}>
          {(row, index) => (
            <LensRow theme={props.theme} active={index() === props.selectedIndex}>
              <text fg={props.theme.textMuted} wrapMode="none">
                {String(row.step.index).padStart(2, " ")}
              </text>
              <text fg={statusColor(props.theme, row.state)} wrapMode="none">
                {row.state.padEnd(9, " ")}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.toolLabel, 14)}
              </text>
              <text fg={index() === props.selectedIndex ? props.theme.text : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.stepLabel, 38)}
              </text>
              <text fg={row.state === "failed" ? props.theme.error : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.outcomeLabel, 24)}
              </text>
            </LensRow>
          )}
        </For>
        <Show when={selected()}>
          <LensDetail theme={props.theme}>
            <text fg={props.theme.text} wrapMode="word">
              {selected()!.stepLabel}
            </text>
            <text fg={statusColor(props.theme, selected()!.state)} wrapMode="word">
              {selected()!.state} · {selected()!.toolLabel}
            </text>
            <Show when={selected()!.step.outcome_title}>
              <text fg={props.theme.textMuted} wrapMode="word">
                {selected()!.step.outcome_title}
              </text>
            </Show>
            <Show when={selected()!.step.outcome_error}>
              <text fg={props.theme.warning} wrapMode="word">
                {selected()!.step.outcome_error}
              </text>
            </Show>
          </LensDetail>
        </Show>
      </Show>
    </box>
  )
}
