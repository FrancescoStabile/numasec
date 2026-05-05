import { Match, Switch } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import type { SessionView } from "@tui/context/session-view"
import { OperationLensEvidence } from "./evidence"
import { OperationLensFindings } from "./findings"
import { OperationLensReplay } from "./replay"
import { OperationLensReport } from "./report"
import { type OperationConsoleSnapshot } from "./snapshot"
import { OperationLensWorkflow } from "./workflow"

export function OperationLensPanel(props: {
  theme: TuiThemeCurrent
  view: SessionView
  snapshot: OperationConsoleSnapshot
  selectedFindingIndex: number
  selectedEvidenceIndex: number
  selectedReplayIndex: number
  selectedWorkflowIndex: number
  selectedReportGateIndex: number
  findingDetailOpen: boolean
  filterFindingKey?: string
}) {
  return (
    <box flexDirection="column" flexGrow={1} gap={1}>
      <Switch>
        <Match when={props.view === "findings"}>
          <OperationLensFindings
            theme={props.theme}
            snapshot={props.snapshot}
            selectedIndex={props.selectedFindingIndex}
            detailOpen={props.findingDetailOpen}
          />
        </Match>
        <Match when={props.view === "evidence"}>
          <OperationLensEvidence
            theme={props.theme}
            snapshot={props.snapshot}
            selectedIndex={props.selectedEvidenceIndex}
            filterFindingKey={props.filterFindingKey}
          />
        </Match>
        <Match when={props.view === "replay"}>
          <OperationLensReplay
            theme={props.theme}
            snapshot={props.snapshot}
            selectedIndex={props.selectedReplayIndex}
            filterFindingKey={props.filterFindingKey}
          />
        </Match>
        <Match when={props.view === "workflow"}>
          <OperationLensWorkflow
            theme={props.theme}
            snapshot={props.snapshot}
            selectedIndex={props.selectedWorkflowIndex}
          />
        </Match>
        <Match when={props.view === "report"}>
          <OperationLensReport
            theme={props.theme}
            snapshot={props.snapshot}
            selectedIndex={props.selectedReportGateIndex}
          />
        </Match>
      </Switch>
    </box>
  )
}
