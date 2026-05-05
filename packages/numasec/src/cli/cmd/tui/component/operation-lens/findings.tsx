import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { findingsRows, type FindingLensRow, type OperationConsoleSnapshot } from "./snapshot"

function statusColor(theme: TuiThemeCurrent, row: FindingLensRow) {
  switch (row.status) {
    case "reportable":
      return theme.success
    case "verified":
      return theme.info
    case "suspected":
      return theme.warning
    case "rejected":
      return theme.textMuted
    case "candidate":
      return theme.primary
  }
}

function severityColor(theme: TuiThemeCurrent, row: FindingLensRow) {
  switch (row.severityCode) {
    case "C":
      return theme.error
    case "H":
      return theme.warning
    case "M":
      return theme.info
    case "L":
      return theme.textMuted
    case "I":
      return theme.textMuted
    default:
      return theme.textMuted
  }
}

function replayLabel(row: FindingLensRow) {
  if (row.replay === "present") return "yes"
  if (row.replay === "exempt") return "exempt"
  if (row.replay === "missing") return "no"
  return "-"
}

function truncate(text: string, max: number) {
  if (text.length <= max) return text
  if (max <= 1) return text.slice(0, max)
  return text.slice(0, max - 1) + "…"
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
      <Show
        when={rows().length > 0}
        fallback={
          <text fg={props.theme.textMuted} wrapMode="none">
            no findings projected
          </text>
        }
      >
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
          {(row, index) => {
            const active = () => index() === props.selectedIndex
            return (
              <box
                flexDirection="row"
                gap={2}
                paddingLeft={active() ? 1 : 0}
                backgroundColor={active() ? props.theme.backgroundElement : undefined}
              >
                <text fg={severityColor(props.theme, row)} wrapMode="none">
                  {row.severityCode}
                </text>
                <text fg={statusColor(props.theme, row)} wrapMode="none">
                  {row.status.padEnd(10, " ")}
                </text>
                <text fg={active() ? props.theme.text : props.theme.textMuted} wrapMode="none">
                  {truncate(row.title, 54)}
                </text>
                <text fg={props.theme.textMuted} wrapMode="none">
                  {String(row.evidenceCount).padStart(2, " ")}
                </text>
                <text fg={row.replay === "missing" ? props.theme.warning : props.theme.textMuted} wrapMode="none">
                  {replayLabel(row).padEnd(6, " ")}
                </text>
                <text fg={props.theme.primary} wrapMode="none">
                  {row.action}
                </text>
              </box>
            )
          }}
        </For>
        <Show when={props.detailOpen && selected()}>
          <box
            flexDirection="column"
            gap={1}
            paddingLeft={1}
            paddingTop={1}
            border={["left"]}
            borderColor={props.theme.borderSubtle}
          >
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
              j/k select · enter detail · esc chat
            </text>
          </box>
        </Show>
      </Show>
    </box>
  )
}
