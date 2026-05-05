import { createMemo, For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import { findingsRows, type OperationConsoleSnapshot, replayCoveredCount } from "./snapshot"

export function OperationLensReplay(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
}) {
  const rows = createMemo(() => findingsRows(props.snapshot).filter((item) => item.status !== "candidate"))
  const verified = createMemo(() => props.snapshot.projected?.summary.verified_findings ?? 0)
  const missing = createMemo(() => rows().filter((item) => item.replay === "missing"))

  return (
    <box flexDirection="column" gap={1}>
      <text fg={props.theme.text} wrapMode="none">
        replay {replayCoveredCount(props.snapshot)}/{verified()}
      </text>
      <text fg={props.theme.textMuted} wrapMode="none">
        backed {props.snapshot.projected?.summary.replay_backed_findings ?? 0} · exempt{" "}
        {props.snapshot.projected?.summary.replay_exempt_findings ?? 0} · missing {missing().length}
      </text>
      <Show
        when={missing().length > 0}
        fallback={
          <text fg={props.theme.success} wrapMode="none">
            no replay gaps in projected findings
          </text>
        }
      >
        <For each={missing().slice(0, 10)}>
          {(row) => (
            <text fg={props.theme.warning} wrapMode="word">
              {row.title}
            </text>
          )}
        </For>
      </Show>
    </box>
  )
}
