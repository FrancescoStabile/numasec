import { createMemo, createSignal, For } from "solid-js"
import { DEFAULT_THEMES, useTheme } from "@tui/context/theme"

const themeCount = Object.keys(DEFAULT_THEMES).length
const themeTip = `Use {highlight}/themes{/highlight} or {highlight}Ctrl+X T{/highlight} to switch between ${themeCount} built-in themes`

type TipPart = { text: string; highlight: boolean }

function parse(tip: string): TipPart[] {
  const parts: TipPart[] = []
  const regex = /\{highlight\}(.*?)\{\/highlight\}/g
  const found = Array.from(tip.matchAll(regex))
  const state = found.reduce(
    (acc, match) => {
      const start = match.index ?? 0
      if (start > acc.index) {
        acc.parts.push({ text: tip.slice(acc.index, start), highlight: false })
      }
      acc.parts.push({ text: match[1], highlight: true })
      acc.index = start + match[0].length
      return acc
    },
    { parts, index: 0 },
  )

  if (state.index < tip.length) {
    parts.push({ text: tip.slice(state.index), highlight: false })
  }

  return parts
}

export function Tips() {
  const theme = useTheme().theme
  const parts = parse(TIPS[Math.floor(Math.random() * TIPS.length)])

  return (
    <box flexDirection="row" maxWidth="100%">
      <text flexShrink={0} style={{ fg: theme.warning }}>
        ● Tip{" "}
      </text>
      <text flexShrink={1}>
        <For each={parts}>
          {(part) => <span style={{ fg: part.highlight ? theme.text : theme.textMuted }}>{part.text}</span>}
        </For>
      </text>
    </box>
  )
}

const TIPS = [
  "Type {highlight}@{/highlight} followed by a filename to fuzzy search and attach files",
  "Start a message with {highlight}!{/highlight} to run shell commands directly (e.g., {highlight}!ls -la{/highlight})",
  "Run {highlight}/connect{/highlight} to add a model provider, then use {highlight}/models{/highlight} to pick the active model",
  "Use {highlight}/new{/highlight} to start a fresh session and {highlight}/sessions{/highlight} to reopen a previous one",
  "Run {highlight}/compact{/highlight} to summarize a long session when the context window gets crowded",
  "Use {highlight}/timeline{/highlight} to jump to a specific message in the current session",
  "Use {highlight}/copy{/highlight} to copy the current session transcript or {highlight}/export{/highlight} to save it as Markdown",
  "Run {highlight}/status{/highlight} to inspect provider, MCP, and system state",
  "Run {highlight}/help{/highlight} to browse available actions and key commands",
  "Run {highlight}/init{/highlight} to generate a security-oriented AGENTS.md for the current target or repo",
  "Use {highlight}/review{/highlight} to security-review local changes before you ship them",
  themeTip,
  "Use {highlight}/scope set https://target.example{/highlight} to define the engagement target and begin reconnaissance",
  "Run {highlight}/scope show{/highlight} to inspect the current target and observed surface",
  "Use {highlight}/finding list{/highlight} to review saved findings from the evidence graph",
  "Use {highlight}/evidence list{/highlight} and {highlight}/evidence show <id>{/highlight} to inspect proof behind a finding",
  "Run {highlight}/coverage{/highlight} to inspect the OWASP Top 10 coverage matrix for the current session",
  "Use {highlight}/creds{/highlight} to list credentials discovered during the run",
  "Run {highlight}/report status{/highlight} to inspect readiness, then {highlight}/report generate markdown{/highlight} for a working report or {highlight}/report generate markdown --final{/highlight} for a closure-gated final report",
  "Use {highlight}/retest run{/highlight} after remediation work to re-check saved findings",
  "Install Chromium once with {highlight}npx playwright install chromium{/highlight} to unlock browser and SPA testing",
  "Use {highlight}numasec run{/highlight} for non-interactive scripting and {highlight}numasec serve{/highlight} for headless API access",
  "Run {highlight}numasec run --continue{/highlight} to resume the last session from the CLI",
  "Run {highlight}numasec upgrade{/highlight} to update the installed binary",
]
