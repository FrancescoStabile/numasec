import { useSync } from "@tui/context/sync"
import { createMemo, For, Match, Show, Switch } from "solid-js"
import { createStore } from "solid-js/store"
import { useTheme } from "../../context/theme"
import type { AssistantMessage } from "@numasec/sdk/v2"
import { Installation } from "@/installation"
import { useDirectory } from "../../context/directory"
import { useKV } from "../../context/kv"
import { TodoItem } from "../../component/todo-item"
import {
  fallbackChains,
  fallbackFindings,
  fallbackTarget,
  selectCurrentEndpoint,
  selectFindingSummary,
  selectChains,
  selectFindings,
  selectReportSummary,
  selectTarget,
  reportStateLabel,
} from "../../security-view-model"

export function Sidebar(props: { sessionID: string; overlay?: boolean }) {
  const sync = useSync()
  const { theme } = useTheme()
  const session = createMemo(() => sync.session.get(props.sessionID)!)
  const diff = createMemo(() => sync.data.session_diff[props.sessionID] ?? [])
  const todo = createMemo(() => sync.data.todo[props.sessionID] ?? [])
  const messages = createMemo(() => sync.data.message[props.sessionID] ?? [])
  const security = createMemo(() => sync.session.security(props.sessionID))

  const [expanded, setExpanded] = createStore({
    mcp: true,
    diff: true,
    todo: true,
    findings: true,
    chains: true,
  })

  // Sort MCP servers alphabetically for consistent display order
  const mcpEntries = createMemo(() => Object.entries(sync.data.mcp).sort(([a], [b]) => a.localeCompare(b)))

  // Count connected and error MCP servers for collapsed header display
  const connectedMcpCount = createMemo(() => mcpEntries().filter(([_, item]) => item.status === "connected").length)
  const errorMcpCount = createMemo(
    () =>
      mcpEntries().filter(
        ([_, item]) =>
          item.status === "failed" || item.status === "needs_auth" || item.status === "needs_client_registration",
      ).length,
  )

  const cost = createMemo(() => {
    const total = messages().reduce((sum, x) => sum + (x.role === "assistant" ? x.cost : 0), 0)
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(total)
  })

  const context = createMemo(() => {
    const last = messages().findLast((x) => x.role === "assistant" && x.tokens.output > 0) as AssistantMessage
    if (!last) return
    const total =
      last.tokens.input + last.tokens.output + last.tokens.reasoning + last.tokens.cache.read + last.tokens.cache.write
    const model = sync.data.provider.find((x) => x.id === last.providerID)?.models[last.modelID]
    return {
      tokens: total.toLocaleString(),
      percentage: model?.limit.context ? Math.round((total / model.limit.context) * 100) : null,
    }
  })

  const legacy = createMemo(() => security() === undefined)
  const fallbackFindingList = createMemo(() => {
    if (!legacy()) return []
    return fallbackFindings(messages(), sync.data.part)
  })
  const findingList = createMemo(() => selectFindings(security(), fallbackFindingList()))
  const findingSummary = createMemo(() => selectFindingSummary(security(), findingList()))
  const findings = createMemo(() => findingSummary().severity)
  const totalFindings = createMemo(() => findingSummary().total)
  const fallbackChainList = createMemo(() => {
    if (!legacy()) return []
    return fallbackChains(messages(), sync.data.part, fallbackFindingList())
  })
  const attackChains = createMemo(() => selectChains(security(), fallbackChainList(), findingList()))
  const fallbackTargetUrl = createMemo(() => {
    if (!legacy()) return
    return fallbackTarget(messages(), sync.data.part)
  })
  const targetUrl = createMemo(() => selectTarget(security(), fallbackTargetUrl()))
  const currentEndpointUrl = createMemo(() => selectCurrentEndpoint(security()))
  const reportSummary = createMemo(() => selectReportSummary(security()))
  const reportState = createMemo(() => {
    return reportStateLabel(reportSummary())
  })

  const directory = useDirectory()
  const kv = useKV()

  const hasProviders = createMemo(() =>
    sync.data.provider.some((x) => x.id !== "numasec" || Object.values(x.models).some((y) => y.cost?.input !== 0)),
  )
  const gettingStartedDismissed = createMemo(() => kv.get("dismissed_getting_started", false))

  return (
    <Show when={session()}>
      <box
        backgroundColor={theme.backgroundPanel}
        width={42}
        height="100%"
        paddingTop={1}
        paddingBottom={1}
        paddingLeft={2}
        paddingRight={2}
        position={props.overlay ? "absolute" : "relative"}
      >
        <scrollbox
          flexGrow={1}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: theme.background,
              foregroundColor: theme.borderActive,
            },
          }}
        >
          <box flexShrink={0} gap={1} paddingRight={1}>
            <box paddingRight={1}>
              <text fg={theme.text}>
                <b>{session().title}</b>
              </text>
            </box>
            <box>
              <text fg={theme.text}>
                <b>Context</b>
              </text>
              <text fg={theme.textMuted}>{context()?.tokens ?? 0} tokens</text>
              <text fg={theme.textMuted}>{context()?.percentage ?? 0}% used</text>
              <text fg={theme.textMuted}>{cost()} spent</text>
            </box>
            <Show when={mcpEntries().length > 0}>
              <box>
                <box
                  flexDirection="row"
                  gap={1}
                  onMouseDown={() => mcpEntries().length > 2 && setExpanded("mcp", !expanded.mcp)}
                >
                  <Show when={mcpEntries().length > 2}>
                    <text fg={theme.text}>{expanded.mcp ? "▼" : "▶"}</text>
                  </Show>
                  <text fg={theme.text}>
                    <b>MCP</b>
                    <Show when={!expanded.mcp}>
                      <span style={{ fg: theme.textMuted }}>
                        {" "}
                        ({connectedMcpCount()} active
                        {errorMcpCount() > 0 ? `, ${errorMcpCount()} error${errorMcpCount() > 1 ? "s" : ""}` : ""})
                      </span>
                    </Show>
                  </text>
                </box>
                <Show when={mcpEntries().length <= 2 || expanded.mcp}>
                  <For each={mcpEntries()}>
                    {([key, item]) => (
                      <box flexDirection="row" gap={1}>
                        <text
                          flexShrink={0}
                          style={{
                            fg: (
                              {
                                connected: theme.success,
                                failed: theme.error,
                                disabled: theme.textMuted,
                                needs_auth: theme.warning,
                                needs_client_registration: theme.error,
                              } as Record<string, typeof theme.success>
                            )[item.status],
                          }}
                        >
                          •
                        </text>
                        <text fg={theme.text} wrapMode="word">
                          {key}{" "}
                          <span style={{ fg: theme.textMuted }}>
                            <Switch fallback={item.status}>
                              <Match when={item.status === "connected"}>Connected</Match>
                              <Match when={item.status === "failed" && item}>{(val) => <i>{val().error}</i>}</Match>
                              <Match when={item.status === "disabled"}>Disabled</Match>
                              <Match when={(item.status as string) === "needs_auth"}>Needs auth</Match>
                              <Match when={(item.status as string) === "needs_client_registration"}>
                                Needs client ID
                              </Match>
                            </Switch>
                          </span>
                        </text>
                      </box>
                    )}
                  </For>
                </Show>
              </box>
            </Show>
            <Show when={targetUrl()}>
              <box>
                <text fg={theme.text}>
                  <b>Engagement Target</b>
                </text>
                <text fg={theme.textMuted}>{targetUrl()}</text>
              </box>
            </Show>
            <Show when={currentEndpointUrl() && currentEndpointUrl() !== targetUrl()}>
              <box>
                <text fg={theme.text}>
                  <b>Current Endpoint</b>
                </text>
                <text fg={theme.textMuted}>{currentEndpointUrl()}</text>
              </box>
            </Show>
            <box>
              <box
                flexDirection="row"
                gap={1}
                onMouseDown={() => totalFindings() > 0 && setExpanded("findings", !expanded.findings)}
              >
                <Show when={totalFindings() > 0}>
                  <text fg={theme.text}>{expanded.findings ? "▼" : "▶"}</text>
                </Show>
                <text fg={theme.text}>
                  <b>Findings</b>
                  <Show when={totalFindings() > 0}>
                    <span style={{ fg: theme.textMuted }}> ({totalFindings()})</span>
                  </Show>
                </text>
              </box>
              <Show when={totalFindings() === 0}>
                <text fg={theme.textMuted}>
                  No findings yet — use /scope set to start (legacy: /target)
                </text>
              </Show>
              <Show when={totalFindings() > 0 && expanded.findings}>
                <Show when={findings().critical > 0}>
                  <box flexDirection="row" gap={1}>
                    <text flexShrink={0} fg={theme.error}>●</text>
                    <text fg={theme.text}>Critical</text>
                    <text fg={theme.textMuted}>{findings().critical}</text>
                  </box>
                </Show>
                <Show when={findings().high > 0}>
                  <box flexDirection="row" gap={1}>
                    <text flexShrink={0} fg={theme.error}>●</text>
                    <text fg={theme.text}>High</text>
                    <text fg={theme.textMuted}>{findings().high}</text>
                  </box>
                </Show>
                <Show when={findings().medium > 0}>
                  <box flexDirection="row" gap={1}>
                    <text flexShrink={0} fg={theme.warning}>●</text>
                    <text fg={theme.text}>Medium</text>
                    <text fg={theme.textMuted}>{findings().medium}</text>
                  </box>
                </Show>
                <Show when={findings().low > 0}>
                  <box flexDirection="row" gap={1}>
                    <text flexShrink={0} fg={theme.success}>●</text>
                    <text fg={theme.text}>Low</text>
                    <text fg={theme.textMuted}>{findings().low}</text>
                  </box>
                </Show>
                <Show when={findings().info > 0}>
                  <box flexDirection="row" gap={1}>
                    <text flexShrink={0} fg={theme.textMuted}>●</text>
                    <text fg={theme.text}>Info</text>
                    <text fg={theme.textMuted}>{findings().info}</text>
                  </box>
                </Show>
              </Show>
            </box>
            <Show when={reportSummary()}>
              <box>
                <text fg={theme.text}>
                  <b>Readiness</b>
                </text>
                <text fg={theme.textMuted}>{reportState()}</text>
                <text fg={theme.textMuted}>
                  Verified {findingSummary().verified}
                  {findingSummary().provisional > 0 ? ` · Provisional ${findingSummary().provisional}` : ""}
                  {findingSummary().suppressed > 0 ? ` · Suppressed ${findingSummary().suppressed}` : ""}
                </text>
                <Show when={reportSummary()!.verification_debt.promotion_gaps > 0}>
                  <text fg={theme.textMuted}>
                    Promotion gaps {reportSummary()!.verification_debt.promotion_gaps}
                  </text>
                </Show>
                <Show when={reportSummary()!.verification_debt.open_critical_hypotheses > 0}>
                  <text fg={theme.textMuted}>
                    Open critical hypotheses {reportSummary()!.verification_debt.open_critical_hypotheses}
                  </text>
                </Show>
                <Show
                  when={
                    reportSummary()!.verification_debt.open_hypotheses > 0 &&
                    reportSummary()!.verification_debt.open_hypotheses !==
                      reportSummary()!.verification_debt.open_critical_hypotheses
                  }
                >
                  <text fg={theme.textMuted}>
                    Open hypotheses {reportSummary()!.verification_debt.open_hypotheses}
                  </text>
                </Show>
              </box>
            </Show>
            <Show when={attackChains().length > 0}>
              <box>
                <box
                  flexDirection="row"
                  gap={1}
                  onMouseDown={() => setExpanded("chains", !expanded.chains)}
                >
                  <text fg={theme.text}>{expanded.chains ? "▼" : "▶"}</text>
                  <text fg={theme.text}>
                    <b>Attack Chains</b>
                    <span style={{ fg: theme.textMuted }}> ({attackChains().length})</span>
                  </text>
                </box>
                <Show when={expanded.chains}>
                  <For each={attackChains()}>
                    {(chain) => (
                      <box paddingLeft={1}>
                        <text fg={chain.severity === "critical" || chain.severity === "high" ? theme.error : theme.warning} wrapMode="word">
                          ⛓ {chain.items.slice(0, 2).map(x => x.title).join(" → ")}
                        </text>
                        <For each={chain.items}>
                          {(item, i) => (
                            <text wrapMode="word">
                              <span style={{ fg: theme.textMuted }}>{i() < chain.items.length - 1 ? "├─ " : "└─ "}</span>
                              <span style={{ fg: item.sev === "critical" || item.sev === "high" ? theme.error : item.sev === "medium" ? theme.warning : theme.success }}>●</span>
                              <span style={{ fg: theme.text }}> {item.title}</span>
                            </text>
                          )}
                        </For>
                      </box>
                    )}
                  </For>
                </Show>
              </box>
            </Show>
            <Show when={todo().length > 0 && todo().some((t) => t.status !== "completed")}>
              <box>
                <box
                  flexDirection="row"
                  gap={1}
                  onMouseDown={() => todo().length > 2 && setExpanded("todo", !expanded.todo)}
                >
                  <Show when={todo().length > 2}>
                    <text fg={theme.text}>{expanded.todo ? "▼" : "▶"}</text>
                  </Show>
                  <text fg={theme.text}>
                    <b>Operator Checklist</b>
                  </text>
                </box>
                <Show when={todo().length <= 2 || expanded.todo}>
                  <For each={todo()}>{(todo) => <TodoItem status={todo.status} content={todo.content} />}</For>
                </Show>
              </box>
            </Show>
            <Show when={diff().length > 0}>
              <box>
                <box
                  flexDirection="row"
                  gap={1}
                  onMouseDown={() => diff().length > 2 && setExpanded("diff", !expanded.diff)}
                >
                  <Show when={diff().length > 2}>
                    <text fg={theme.text}>{expanded.diff ? "▼" : "▶"}</text>
                  </Show>
                  <text fg={theme.text}>
                    <b>Modified Files</b>
                  </text>
                </box>
                <Show when={diff().length <= 2 || expanded.diff}>
                  <For each={diff() || []}>
                    {(item) => {
                      return (
                        <box flexDirection="row" gap={1} justifyContent="space-between">
                          <text fg={theme.textMuted} wrapMode="none">
                            {item.file}
                          </text>
                          <box flexDirection="row" gap={1} flexShrink={0}>
                            <Show when={item.additions}>
                              <text fg={theme.diffAdded}>+{item.additions}</text>
                            </Show>
                            <Show when={item.deletions}>
                              <text fg={theme.diffRemoved}>-{item.deletions}</text>
                            </Show>
                          </box>
                        </box>
                      )
                    }}
                  </For>
                </Show>
              </box>
            </Show>
          </box>
        </scrollbox>

        <box flexShrink={0} gap={1} paddingTop={1}>
          <Show when={!hasProviders() && !gettingStartedDismissed()}>
            <box
              backgroundColor={theme.backgroundElement}
              paddingTop={1}
              paddingBottom={1}
              paddingLeft={2}
              paddingRight={2}
              flexDirection="row"
              gap={1}
            >
              <text flexShrink={0} fg={theme.text}>
                ⬖
              </text>
              <box flexGrow={1} gap={1}>
                <box flexDirection="row" justifyContent="space-between">
                  <text fg={theme.text}>
                    <b>Getting started</b>
                  </text>
                  <text fg={theme.textMuted} onMouseDown={() => kv.set("dismissed_getting_started", true)}>
                    ✕
                  </text>
                </box>
                <text fg={theme.textMuted}>
                  Connect a provider to get started, or explicitly enable Numasec public free models.
                </text>
                <text fg={theme.textMuted}>
                  Connect from 75+ providers to use other models, including Claude, GPT, Gemini etc
                </text>
                <box flexDirection="row" gap={1} justifyContent="space-between">
                  <text fg={theme.text}>Connect provider</text>
                  <text fg={theme.textMuted}>/connect</text>
                </box>
              </box>
            </box>
          </Show>
          <text>
            <span style={{ fg: theme.textMuted }}>{directory().split("/").slice(0, -1).join("/")}/</span>
            <span style={{ fg: theme.text }}>{directory().split("/").at(-1)}</span>
          </text>
          <text fg={theme.textMuted}>
            <span style={{ fg: theme.success }}>•</span> <b>numa</b>
            <span style={{ fg: theme.text }}>
              <b>sec</b>
            </span>{" "}
            <span>{Installation.VERSION}</span>
          </text>
        </box>
      </box>
    </Show>
  )
}
