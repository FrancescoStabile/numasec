import { useSync } from "@tui/context/sync"
import { createMemo, createResource, createSignal, onCleanup, Show } from "solid-js"
import { useTheme } from "../../context/theme"
import { useTuiConfig } from "../../context/tui-config"
import { InstallationVersion } from "@/installation/version"
import { TuiPluginRuntime } from "../../plugin"
import { BRAND } from "../../component/glyph"
import { Operation } from "@/core/operation"
import { useEvent } from "@tui/context/event"

import { getScrollAcceleration } from "../../util/scroll"

export function Sidebar(props: { sessionID: string; overlay?: boolean }) {
  const sync = useSync()
  const { theme } = useTheme()
  const tuiConfig = useTuiConfig()
  const event = useEvent()
  const session = createMemo(() => sync.session.get(props.sessionID))
  const scrollAcceleration = createMemo(() => getScrollAcceleration(tuiConfig))
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((value) => !value)
  const [activeOperation] = createResource(tick, async () => {
    const directory = sync.path.directory
    if (!directory) return undefined
    return Operation.active(directory).catch(() => undefined)
  })
  const offIdle = event.on("session.idle", () => refresh())
  const offStatus = event.on("session.status", () => refresh())
  onCleanup(() => {
    offIdle()
    offStatus()
  })

  return (
    <Show when={session()}>
      <box
        border={["left"]}
        borderColor={theme.borderSubtle}
        width={43}
        height="100%"
        paddingTop={1}
        paddingBottom={1}
        paddingLeft={2}
        paddingRight={2}
        position={props.overlay ? "absolute" : "relative"}
      >
        <scrollbox
          flexGrow={1}
          scrollAcceleration={scrollAcceleration()}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: theme.background,
              foregroundColor: theme.borderActive,
            },
          }}
        >
          <box flexShrink={0} gap={1} paddingRight={1}>
            <TuiPluginRuntime.Slot
              name="sidebar_title"
              mode="single_winner"
              session_id={props.sessionID}
              title={session()!.title}
              share_url={session()!.share?.url}
            >
              <box paddingRight={1}>
                <Show when={!activeOperation()}>
                  <text fg={theme.textMuted}>
                    <b>{session()!.title}</b>
                  </text>
                </Show>
                <Show when={session()!.share?.url}>
                  <text fg={theme.textMuted}>{session()!.share!.url}</text>
                </Show>
              </box>
            </TuiPluginRuntime.Slot>
            <TuiPluginRuntime.Slot name="sidebar_content" session_id={props.sessionID} />
          </box>
        </scrollbox>

        <box flexShrink={0} gap={1} paddingTop={1}>
          <TuiPluginRuntime.Slot name="sidebar_footer" mode="single_winner" session_id={props.sessionID}>
            <text fg={theme.textMuted}>
              <span style={{ fg: theme.primary }}>{BRAND.cornerTL}{BRAND.cornerTR}</span>{" "}
              <span style={{ fg: theme.text }}>
                <b>numasec</b>
              </span>{" "}
              <span>{InstallationVersion}</span>
            </text>
          </TuiPluginRuntime.Slot>
        </box>
      </box>
    </Show>
  )
}
