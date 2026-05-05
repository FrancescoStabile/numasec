import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { findingsRows, type FindingLensRow, type OperationConsoleSnapshot } from "./snapshot"
import { LensDetail, LensEmpty, LensRow, LensTitle, severityColor, statusColor, toneColor, truncateMiddle } from "./ui"

function replayLabel(row: FindingLensRow) {
  if (row.replay === "present") return "yes"
  if (row.replay === "exempt") return "exempt"
  if (row.replay === "missing") return "no"
  return "-"
}

export function OperationLensFindings(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  selectedIndex: number
  detailOpen: boolean
}) {
  const rows = createMemo(() => findingsRows(props.snapshot))
  const selected = createMemo(() => rows()[props.selectedIndex])

  return (
    <box flexDirection="column" flexGrow={1} gap={1}>
      <LensTitle
        theme={props.theme}
        title="FINDINGS"
        summary={`proof table · ${rows().length} projected`}
      />
      <Show when={rows().length > 0} fallback={<LensEmpty theme={props.theme} message="no findings projected" />}>
        <box flexDirection="row" gap={2}>
          <text fg={props.theme.textMuted} wrapMode="none">
            Sev
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Status
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Finding
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Ev
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Replay
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Action
          </text>
        </box>
        <For each={rows()}>
          {(row, index) => (
            <LensRow theme={props.theme} active={index() === props.selectedIndex}>
              <text fg={severityColor(props.theme, row.severityCode)} wrapMode="none">
                {row.severityCode}
              </text>
              <text fg={statusColor(props.theme, row.status)} wrapMode="none">
                {row.status.padEnd(10, " ")}
              </text>
              <text fg={index() === props.selectedIndex ? props.theme.text : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.title, 56)}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {String(row.evidenceCount).padStart(2, " ")}
              </text>
              <text fg={row.replay === "missing" ? props.theme.warning : props.theme.textMuted} wrapMode="none">
                {replayLabel(row).padEnd(6, " ")}
              </text>
              <text fg={toneColor(props.theme, "primary")} wrapMode="none">
                {row.action}
              </text>
            </LensRow>
          )}
        </For>
        <Show when={props.detailOpen && selected()}>
          <LensDetail theme={props.theme}>
            <text fg={props.theme.text} wrapMode="word">
              {selected()!.title}
            </text>
            <text fg={props.theme.textMuted} wrapMode="word">
              proof {selected()!.status} · evidence {selected()!.evidenceCount} · replay {replayLabel(selected()!)}
            </text>
            <Show when={selected()!.summary}>
              <text fg={props.theme.textMuted} wrapMode="word">
                {selected()!.summary}
              </text>
            </Show>
            <Show when={selected()!.finding.oracle_status}>
              <text fg={props.theme.info} wrapMode="word">
                oracle {selected()!.finding.oracle_status}
                {selected()!.finding.oracle_reason ? ` · ${selected()!.finding.oracle_reason}` : ""}
              </text>
            </Show>
            <Show when={selected()!.finding.operator_promoted}>
              <text fg={props.theme.primary} wrapMode="none">
                operator promoted
              </text>
            </Show>
            <text fg={props.theme.textMuted} wrapMode="none">
              open evidence with `e` · replay with `r` · report with `p`
            </text>
          </LensDetail>
        </Show>
      </Show>
    </box>
  )
}
