import { For, Show } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import type { OperationConsoleSnapshot } from "./snapshot"

export function OperationLensEvidence(props: {
  theme: TuiThemeCurrent
  snapshot: OperationConsoleSnapshot
}) {
  const entries = props.snapshot.evidenceEntries.slice().reverse().slice(0, 12)
  return (
    <box flexDirection="column" gap={1}>
      <text fg={props.theme.text} wrapMode="none">
        evidence {props.snapshot.evidenceCount}
      </text>
      <Show
        when={entries.length > 0}
        fallback={
          <text fg={props.theme.textMuted} wrapMode="none">
            no evidence captured
          </text>
        }
      >
        <For each={entries}>
          {(entry) => (
            <text fg={props.theme.textMuted} wrapMode="word">
              {(entry.label ?? entry.source ?? entry.sha256).slice(0, 72)} · {entry.ext} · {entry.size}b
            </text>
          )}
        </For>
      </Show>
    </box>
  )
}
