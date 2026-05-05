import path from "path"
import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import {
  reportGateRows,
  reportStatus,
  type OperationConsoleSnapshot,
} from "./snapshot"
import { formatAge, LensDetail, LensEmpty, LensRow, LensTitle, toneColor, truncateMiddle } from "./ui"

export function OperationLensReport(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  selectedIndex: number
}) {
  const status = createMemo(() => reportStatus(props.snapshot))
  const rows = createMemo(() => reportGateRows(props.snapshot))
  const selected = createMemo(() => rows()[props.selectedIndex])
  const deliverable = createMemo(() => props.snapshot.deliverable)
  const gapRows = createMemo(() => rows().filter((row) => row.tone === "error" || row.tone === "warning"))

  return (
    <box flexDirection="column" gap={1}>
      <LensTitle
        theme={props.theme}
        title="REPORT"
        summary={`${status()} · ${deliverable()?.bundle_dir ? path.basename(deliverable()!.bundle_dir!) : "not built"}`}
      />
      <Show when={rows().length > 0} fallback={<LensEmpty theme={props.theme} message="no report state projected" />}>
        <box flexDirection="row" gap={2}>
          <text fg={props.theme.textMuted} wrapMode="none">
            Gate
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Value
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Detail
          </text>
        </box>
        <For each={rows()}>
          {(row, index) => (
            <LensRow theme={props.theme} active={index() === props.selectedIndex}>
              <text fg={props.theme.textMuted} wrapMode="none">
                {row.label.padEnd(15, " ")}
              </text>
              <text fg={toneColor(props.theme, row.tone)} wrapMode="none">
                {row.value.padEnd(18, " ")}
              </text>
              <text fg={index() === props.selectedIndex ? props.theme.text : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.detail, 42)}
              </text>
            </LensRow>
          )}
        </For>
        <Show when={selected()}>
          <LensDetail theme={props.theme}>
            <text fg={props.theme.text} wrapMode="word">
              {selected()!.label} · {selected()!.value}
            </text>
            <text fg={toneColor(props.theme, selected()!.tone)} wrapMode="word">
              {selected()!.detail}
            </text>
            <Show when={deliverable()}>
              <text fg={props.theme.textMuted} wrapMode="word">
                bundle {deliverable()?.bundle_dir ? path.basename(deliverable()!.bundle_dir!) : "-"} · manifest{" "}
                {deliverable()?.manifest_path ? path.basename(deliverable()!.manifest_path!) : "-"} · report{" "}
                {deliverable()?.report_path ? path.basename(deliverable()!.report_path!) : "-"} · format{" "}
                {deliverable()?.format ?? "md"} · updated {formatAge(deliverable()?.time_updated)}
              </text>
            </Show>
          </LensDetail>
        </Show>
        <box flexDirection="column" gap={0}>
          <text fg={props.theme.textMuted} wrapMode="none">
            gaps
          </text>
          <Show when={gapRows().length > 0} fallback={<LensEmpty theme={props.theme} message="no report-grade gaps projected" />}>
            <For each={gapRows()}>
              {(row) => (
                <text fg={toneColor(props.theme, row.tone)} wrapMode="word">
                  {row.label} · {row.detail}
                </text>
              )}
            </For>
          </Show>
        </box>
      </Show>
    </box>
  )
}
