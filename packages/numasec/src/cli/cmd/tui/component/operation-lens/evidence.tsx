import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { evidenceRows, findingByKey, type OperationConsoleSnapshot } from "./snapshot"
import {
  evidenceKindColor,
  formatAge,
  formatBytes,
  LensDetail,
  LensEmpty,
  LensRow,
  LensTitle,
  toneColor,
  truncateMiddle,
} from "./ui"

export function OperationLensEvidence(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
  selectedIndex: number
  filterFindingKey?: string
}) {
  const rows = createMemo(() => evidenceRows(props.snapshot, { findingKey: props.filterFindingKey }))
  const selected = createMemo(() => rows()[props.selectedIndex])
  const filterTitle = createMemo(() => findingByKey(props.snapshot, props.filterFindingKey)?.title ?? "all")
  const slug = createMemo(() => props.snapshot.active?.slug)

  return (
    <box flexDirection="column" gap={1}>
      <LensTitle
        theme={props.theme}
        title="EVIDENCE"
        summary={`for ${filterTitle()} · ${rows().length} refs`}
      />
      <Show when={rows().length > 0} fallback={<LensEmpty theme={props.theme} message="no evidence captured" />}>
        <box flexDirection="row" gap={2}>
          <text fg={props.theme.textMuted} wrapMode="none">
            Type
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Ref
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Finding
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Source / Label
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Age
          </text>
          <text fg={props.theme.textMuted} wrapMode="none">
            Size
          </text>
        </box>
        <For each={rows()}>
          {(row, index) => (
            <LensRow theme={props.theme} active={index() === props.selectedIndex}>
              <text fg={evidenceKindColor(props.theme, row.kind)} wrapMode="none">
                {row.kind.padEnd(7, " ")}
              </text>
              <text fg={toneColor(props.theme, row.primaryRelationKind === "replay_artifact" ? "primary" : "muted")} wrapMode="none">
                {row.compactRef.padEnd(10, " ")}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.findingTitles.join(", ") || "unlinked", 24)}
              </text>
              <text fg={index() === props.selectedIndex ? props.theme.text : props.theme.textMuted} wrapMode="none">
                {truncateMiddle(row.sourceLabel, 40)}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {formatAge(row.entry.at).padStart(3, " ")}
              </text>
              <text fg={props.theme.textMuted} wrapMode="none">
                {formatBytes(row.entry.size).padStart(6, " ")}
              </text>
            </LensRow>
          )}
        </For>
        <Show when={selected()}>
          <LensDetail theme={props.theme}>
            <text fg={props.theme.text} wrapMode="word">
              {selected()!.entry.label ?? selected()!.entry.source ?? selected()!.entry.sha256}
            </text>
            <text fg={props.theme.textMuted} wrapMode="word">
              source {selected()!.entry.source ?? "-"} · mime {selected()!.entry.mime ?? "-"} · size {formatBytes(selected()!.entry.size)}
            </text>
            <text fg={props.theme.textMuted} wrapMode="word">
              ref {selected()!.entry.sha256}.{selected()!.entry.ext} · relation {selected()!.primaryRelationKind}
            </text>
            <text fg={props.theme.textMuted} wrapMode="word">
              linked {selected()!.findingTitles.join(", ") || "unlinked"}
            </text>
            <Show when={slug()}>
              <text fg={props.theme.textMuted} wrapMode="word">
                .numasec/operation/{slug()}/evidence/{selected()!.entry.sha256}.{selected()!.entry.ext}
              </text>
            </Show>
          </LensDetail>
        </Show>
      </Show>
    </box>
  )
}
