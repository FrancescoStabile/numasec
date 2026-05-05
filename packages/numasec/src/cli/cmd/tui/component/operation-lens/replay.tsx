import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { replayRows, type OperationConsoleSnapshot } from "./snapshot"
import { LensDetail, LensEmpty, LensRow, LensTitle, severityColor, statusColor, truncateMiddle } from "./ui"

export function OperationLensReplay(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  selectedIndex: number
  filterFindingKey?: string
}) {
  const rows = createMemo(() => replayRows(props.snapshot, { findingKey: props.filterFindingKey }))
  const selected = createMemo(() => rows()[props.selectedIndex])
  const backed = createMemo(() => rows().filter((row) => row.status === "backed").length)
  const exempt = createMemo(() => rows().filter((row) => row.status === "exempt").length)
  const missing = createMemo(() => rows().filter((row) => row.status === "missing").length)

  return (
    <box flexDirection="column" gap={1}>
      <LensTitle
        theme={props.theme}
        title="REPLAY"
        summary={`backed ${backed()} · exempt ${exempt()} · missing ${missing()}`}
      />
      <Show when={rows().length > 0} fallback={<LensEmpty theme={props.theme} message="no replay state projected" />}>
        <box flexDirection="row" gap={2}>
          <text fg={props.theme.textMuted} wrapMode="none">
            Status
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Sev
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Finding
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Artifact
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Gap
          </text>
        </box>
        <For each={rows()}>
          {(row, index) => (
            <LensRow theme={props.theme} active={index() === props.selectedIndex}>
              <text fg={statusColor(props.theme, row.status === "missing" && row.reportable ? "failed" : row.status)} wrapMode="none">
                {row.status.padEnd(7, " ")}
              </text>
              <text fg={severityColor(props.theme, row.severityCode)} wrapMode="none">
                {row.severityCode}
              </text>
              <text fg={index() === props.selectedIndex ? props.theme.text : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.title, 44)}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.compactArtifact ?? "-", 12)}
              </text>
              <text fg={row.status === "missing" ? props.theme.warning : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.gap, 34)}
              </text>
            </LensRow>
          )}
        </For>
        <Show when={selected()}>
          <LensDetail theme={props.theme}>
            <text fg={props.theme.text} wrapMode="word">
              {selected()!.title}
            </text>
            <text fg={statusColor(props.theme, selected()!.status === "missing" && selected()!.reportable ? "failed" : selected()!.status)} wrapMode="word">
              replay {selected()!.status}
            </text>
            <Show when={selected()!.artifactSha}>
              <text fg={props.theme.textMuted} wrapMode="word">
                artifact {selected()!.artifactLabel ?? selected()!.artifactSha} · {selected()!.artifactSha}
              </text>
            </Show>
            <text fg={props.theme.textMuted} wrapMode="word">
              {selected()!.gap}
            </text>
            <Show when={selected()!.oracle}>
              <text fg={props.theme.info} wrapMode="word">
                oracle {selected()!.oracle}
              </text>
            </Show>
          </LensDetail>
        </Show>
      </Show>
    </box>
  )
}
