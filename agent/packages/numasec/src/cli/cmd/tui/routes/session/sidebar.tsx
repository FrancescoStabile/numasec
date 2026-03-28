import { useSync } from "@tui/context/sync"
import { createMemo, For, Show, Switch, Match } from "solid-js"
import { createStore } from "solid-js/store"
import { useTheme } from "../../context/theme"
import { Locale } from "@/util/locale"
import path from "path"
import type { AssistantMessage } from "@numasec/sdk/v2"
import { Global } from "@/global"
import { Installation } from "@/installation"
import { useKeybind } from "../../context/keybind"
import { useDirectory } from "../../context/directory"
import { useKV } from "../../context/kv"
import { TodoItem } from "../../component/todo-item"

export function Sidebar(props: { sessionID: string; overlay?: boolean }) {
  const sync = useSync()
  const { theme } = useTheme()
  const session = createMemo(() => sync.session.get(props.sessionID)!)
  const diff = createMemo(() => sync.data.session_diff[props.sessionID] ?? [])
  const todo = createMemo(() => sync.data.todo[props.sessionID] ?? [])
  const messages = createMemo(() => sync.data.message[props.sessionID] ?? [])

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

  // Derive findings from tool results: save_finding, get_findings, auto-saved scanner outputs
  const findings = createMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    type SevKey = keyof typeof counts
    const seen = new Set<string>()
    const severityRe = /\b(critical|high|medium|low|info)\b/i

    const addFinding = (id: string, severity: string) => {
      if (id && seen.has(id)) return
      if (id) seen.add(id)
      const sev = severity.toLowerCase() as SevKey
      if (sev in counts) counts[sev]++
      else counts.info++
    }

    const msgs = messages()
    for (let mi = 0; mi < msgs.length; mi++) {
      const msg = msgs[mi]
      const parts = sync.data.part[msg.id]
      if (!parts) continue
      for (let pi = 0; pi < parts.length; pi++) {
        const part = parts[pi]
        if (part.type !== "tool") continue
        if (part.state.status !== "completed") continue
        const state = part.state as { output?: string }
        const out = state.output
        if (!out) continue

        // Source 1: save_finding tool outputs
        if (part.tool.includes("save_finding")) {
          try {
            const data = JSON.parse(out)
            addFinding(data.finding_id ?? "", data.severity ?? data.finding?.severity ?? "")
          } catch {
            const m = out.match(severityRe)
            if (m) addFinding("", m[1])
            else addFinding("", "info")
          }
          continue
        }

        // Source 2: get_findings tool outputs (authoritative — reads from DB)
        if (part.tool.includes("get_findings")) {
          try {
            const data = JSON.parse(out)
            const list = data.findings
            if (Array.isArray(list)) {
              for (const f of list) {
                addFinding(f.id ?? f.finding_id ?? "", f.severity ?? "")
              }
            }
          } catch { /* skip */ }
          continue
        }

        // Source 3: auto-saved findings embedded in scanner tool outputs
        try {
          const data = JSON.parse(out)
          const autoSaved = data.findings_auto_saved
          if (Array.isArray(autoSaved)) {
            for (const f of autoSaved) {
              addFinding(f.finding_id ?? "", f.severity ?? "")
            }
          }
        } catch { /* not JSON or no auto-saved */ }
      }
    }
    return counts
  })
  const totalFindings = createMemo(() => {
    const c = findings()
    return c.critical + c.high + c.medium + c.low + c.info
  })

  // Derive attack chains from save_finding, build_chains, and get_findings tool results
  const attackChains = createMemo(() => {
    const chains: Record<string, { titles: string[]; severity: string }> = {}
    const sevOrder = ["critical", "high", "medium", "low", "info"]
    for (const msg of messages()) {
      const parts = sync.data.part[msg.id] ?? []
      for (const part of parts) {
        if (part.type !== "tool" || part.state.status !== "completed") continue
        const out = (part.state as { output?: string }).output ?? ""

        // Source 1: save_finding with chain_id
        if (part.tool.includes("save_finding")) {
          try {
            const data = JSON.parse(out)
            const chainId = data.chain_id || data.finding?.chain_id
            if (!chainId) continue
            if (!chains[chainId]) chains[chainId] = { titles: [], severity: "info" }
            const title = data.title || data.finding?.title || "Finding"
            if (!chains[chainId].titles.includes(title)) chains[chainId].titles.push(title)
            const sev = (data.severity || "").toLowerCase()
            if (sevOrder.indexOf(sev) < sevOrder.indexOf(chains[chainId].severity)) {
              chains[chainId].severity = sev
            }
          } catch { /* skip */ }
          continue
        }

        // Source 2: build_chains tool output
        if (part.tool.includes("build_chains")) {
          try {
            const data = JSON.parse(out)
            const builtChains = data.chains
            if (builtChains && typeof builtChains === "object") {
              for (const [cid, fids] of Object.entries(builtChains)) {
                if (!chains[cid]) chains[cid] = { titles: [], severity: "info" }
                for (const fid of fids as string[]) {
                  if (!chains[cid].titles.includes(fid)) chains[cid].titles.push(fid)
                }
              }
            }
          } catch { /* skip */ }
          continue
        }

        // Source 3: get_findings output with chain_id on individual findings
        if (part.tool.includes("get_findings")) {
          try {
            const data = JSON.parse(out)
            const list = data.findings
            if (!Array.isArray(list)) continue
            for (const f of list) {
              const chainId = f.chain_id
              if (!chainId) continue
              if (!chains[chainId]) chains[chainId] = { titles: [], severity: "info" }
              const title = f.title || "Finding"
              if (!chains[chainId].titles.includes(title)) chains[chainId].titles.push(title)
              const sev = (f.severity || "").toLowerCase()
              if (sevOrder.indexOf(sev) < sevOrder.indexOf(chains[chainId].severity)) {
                chains[chainId].severity = sev
              }
            }
          } catch { /* skip */ }
          continue
        }
      }
    }
    return Object.entries(chains).filter(([_, c]) => c.titles.length > 1)
  })

  // Derive target URL from recon/create_session tool inputs
  const targetUrl = createMemo(() => {
    for (const msg of messages()) {
      const parts = sync.data.part[msg.id] ?? []
      for (const part of parts) {
        if (part.type !== "tool") continue
        if (!part.tool.includes("create_session") && !part.tool.includes("recon")) continue
        const state = part.state as { input?: Record<string, unknown> }
        const url = state.input?.target ?? state.input?.url ?? state.input?.base_url
        if (typeof url === "string" && url.startsWith("http")) return url
      }
    }
    return undefined
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
              <Show when={session().share?.url}>
                <text fg={theme.textMuted}>{session().share!.url}</text>
              </Show>
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
                  <b>Target</b>
                </text>
                <text fg={theme.textMuted}>{targetUrl()}</text>
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
                  No findings yet — use /target to start
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
                    {([chainId, chain]) => (
                      <box paddingLeft={1}>
                        <text fg={chain.severity === "critical" || chain.severity === "high" ? theme.error : theme.warning} wrapMode="word">
                          ⛓ {chainId}
                        </text>
                        <For each={chain.titles}>
                          {(title, i) => (
                            <text fg={theme.textMuted} wrapMode="word">
                              {i() < chain.titles.length - 1 ? "├─ " : "└─ "}{title}
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
                    <b>Todo</b>
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
                <text fg={theme.textMuted}>Numasec includes free models so you can start immediately.</text>
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
