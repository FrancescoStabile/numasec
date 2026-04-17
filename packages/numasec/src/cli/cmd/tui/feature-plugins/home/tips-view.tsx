import { For } from "solid-js"
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
  "Start a message with {highlight}!{/highlight} to run shell commands directly (e.g., {highlight}!nmap -sV target{/highlight})",
  "Press {highlight}Tab{/highlight} to cycle between security agents (Pentest, AppSec, OSINT, etc.)",
  "Use {highlight}/mode pentest{/highlight} to switch to penetration testing mode",
  "Use {highlight}/mode osint{/highlight} to switch to OSINT and reconnaissance mode",
  "Use {highlight}/mode appsec{/highlight} for application security and code review",
  "Use {highlight}/mode hacking{/highlight} for CTF, exploit dev, and reverse engineering",
  "Use {highlight}/undo{/highlight} to revert the last message and file changes",
  "Drag and drop images or PDFs into the terminal to add them as context",
  "Press {highlight}Ctrl+V{/highlight} to paste images from your clipboard into the prompt",
  "Press {highlight}Ctrl+X E{/highlight} or {highlight}/editor{/highlight} to compose messages in your external editor",
  "Run {highlight}/models{/highlight} or {highlight}Ctrl+X M{/highlight} to see and switch between available AI models",
  themeTip,
  "Press {highlight}Ctrl+X N{/highlight} or {highlight}/new{/highlight} to start a fresh operation",
  "Use {highlight}/sessions{/highlight} or {highlight}Ctrl+X L{/highlight} to list and resume previous runs",
  "Run {highlight}/compact{/highlight} to summarize long runs near context limits",
  "Press {highlight}Ctrl+X X{/highlight} or {highlight}/export{/highlight} to save the conversation as Markdown",
  "Press {highlight}Ctrl+X Y{/highlight} to copy the assistant's last message to clipboard",
  "Press {highlight}Ctrl+P{/highlight} to see all available actions and commands",
  "Run {highlight}/connect{/highlight} to add API keys for 75+ supported LLM providers",
  "The leader key is {highlight}Ctrl+X{/highlight}; combine with other keys for quick actions",
  "Press {highlight}F2{/highlight} to quickly switch between recently used models",
  "Press {highlight}Ctrl+X B{/highlight} to show/hide the sidebar panel",
  "Use {highlight}PageUp{/highlight}/{highlight}PageDown{/highlight} to navigate through conversation history",
  "Press {highlight}Shift+Enter{/highlight} or {highlight}Ctrl+J{/highlight} to add newlines in your prompt",
  "Press {highlight}Escape{/highlight} to stop the AI mid-response",
  "Drop a {highlight}.numasec.md{/highlight} in your project root to give the agent persistent target context",
  "numasec has full shell access — run {highlight}nmap{/highlight}, {highlight}sqlmap{/highlight}, {highlight}nuclei{/highlight}, {highlight}burp{/highlight}, anything",
  "Run numasec inside {highlight}Kali Linux{/highlight} for instant access to 600+ security tools",
  "Use {highlight}@agent-name{/highlight} in prompts to invoke specialized subagents",
  "Press {highlight}Ctrl+X Right/Left{/highlight} to cycle through parent and child runs",
  "Create {highlight}numasec.json{/highlight} for server settings and {highlight}tui.json{/highlight} for TUI settings",
  "Place TUI settings in {highlight}~/.config/numasec/tui.json{/highlight} for global config",
  "Configure local or remote MCP servers in the {highlight}mcp{/highlight} config section",
  "Add {highlight}.md{/highlight} files to {highlight}.numasec/command/{/highlight} to define reusable custom prompts",
  "Use {highlight}$ARGUMENTS{/highlight}, {highlight}$1{/highlight}, {highlight}$2{/highlight} in custom commands for dynamic input",
  "Add {highlight}.md{/highlight} files to {highlight}.numasec/agent/{/highlight} for specialized AI personas",
  "Configure per-agent permissions for {highlight}edit{/highlight}, {highlight}bash{/highlight}, and {highlight}webfetch{/highlight} tools",
  'Use patterns like {highlight}"nmap *": "allow"{/highlight} for granular bash permissions',
  'Set {highlight}"rm -rf *": "deny"{/highlight} to block destructive commands',
  "Override global tool settings per agent configuration",
  "Permission {highlight}doom_loop{/highlight} prevents infinite tool call loops",
  "Permission {highlight}external_directory{/highlight} protects files outside project",
  "Use {highlight}--print-logs{/highlight} flag to see detailed logs in stderr",
  "Press {highlight}Ctrl+X G{/highlight} or {highlight}/timeline{/highlight} to jump to specific messages",
  "Press {highlight}Ctrl+X S{/highlight} or {highlight}/status{/highlight} to see system status info",
  "Run {highlight}/help{/highlight} to show the help dialog",
  "Use {highlight}/review{/highlight} to review uncommitted changes, branches, or PRs",
  "Use {highlight}/rename{/highlight} to rename the current run",
  "Create JSON theme files in {highlight}.numasec/themes/{/highlight} directory",
  "Commit your project's {highlight}AGENTS.md{/highlight} file to Git for team sharing",
  ...(process.platform === "win32"
    ? ["Press {highlight}Ctrl+Z{/highlight} to undo changes in your prompt"]
    : ["Press {highlight}Ctrl+Z{/highlight} to suspend the terminal and return to your shell"]),
]
