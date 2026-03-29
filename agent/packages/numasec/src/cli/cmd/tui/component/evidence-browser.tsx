import { TextAttributes } from "@opentui/core"
import { useTerminalDimensions, useKeyboard } from "@opentui/solid"
import { createMemo, Show } from "solid-js"
import { useSync } from "@tui/context/sync"
import { useTheme } from "../context/theme"
import { useDialog } from "@tui/ui/dialog"
import { DialogSelect, type DialogSelectOption } from "@tui/ui/dialog-select"
import type { Part } from "@numasec/sdk/v2"

type Finding = {
  id: string
  title: string
  severity: string
  url: string
  parameter: string
  payload: string
  evidence: string
  cwe_id: string
  owasp_category: string
  confidence: string
  chain_id: string
  tool_used: string
  description: string
  cvss_score: string
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

function severityColor(severity: string, theme: ReturnType<typeof useTheme>["theme"]) {
  const sev = severity.toLowerCase()
  if (sev === "critical") return theme.error
  if (sev === "high") return theme.error
  if (sev === "medium") return theme.warning
  if (sev === "low") return theme.success
  return theme.textMuted
}

function severityIcon(severity: string) {
  const sev = severity.toLowerCase()
  if (sev === "critical") return "🔴"
  if (sev === "high") return "🟠"
  if (sev === "medium") return "🟡"
  if (sev === "low") return "🟢"
  return "⚪"
}

function parseFinding(raw: Record<string, unknown>): Finding {
  return {
    id: String(raw.id ?? raw.finding_id ?? ""),
    title: String(raw.title ?? "Untitled"),
    severity: String(raw.severity ?? "info"),
    url: String(raw.url ?? ""),
    parameter: String(raw.parameter ?? ""),
    payload: String(raw.payload ?? ""),
    evidence: String(raw.evidence ?? raw.description ?? ""),
    cwe_id: String(raw.cwe_id ?? raw.cwe ?? ""),
    owasp_category: String(raw.owasp_category ?? ""),
    confidence: String(raw.confidence ?? ""),
    chain_id: String(raw.chain_id ?? ""),
    tool_used: String(raw.tool_used ?? ""),
    description: String(raw.description ?? ""),
    cvss_score: String(raw.cvss_score ?? ""),
  }
}

function extractFindings(
  messages: readonly { id: string; role: string }[],
  parts: Record<string, Part[]>,
): Finding[] {
  const results: Finding[] = []
  const seen = new Set<string>()

  const addFinding = (raw: Record<string, unknown>) => {
    const finding = parseFinding(raw)
    if (finding.id && seen.has(finding.id)) return
    if (finding.id) seen.add(finding.id)
    results.push(finding)
  }

  for (const msg of messages) {
    const msgParts = parts[msg.id]
    if (!msgParts) continue

    for (const part of msgParts) {
      if (part.type !== "tool") continue
      if (part.state.status !== "completed") continue
      const out = (part.state as { output?: string }).output
      if (!out) continue

      // get_findings is the authoritative source
      if (part.tool.includes("get_findings")) {
        try {
          const data = JSON.parse(out)
          const list = data.findings
          if (Array.isArray(list)) {
            for (const f of list) addFinding(f)
          }
        } catch { /* skip */ }
        continue
      }

      // save_finding outputs
      if (part.tool.includes("save_finding")) {
        try {
          const data = JSON.parse(out)
          addFinding(data.finding ?? data)
        } catch { /* skip */ }
        continue
      }

      // auto-saved findings from scanner outputs
      try {
        const data = JSON.parse(out)
        const autoSaved = data.findings_auto_saved
        if (Array.isArray(autoSaved)) {
          for (const f of autoSaved) addFinding(f)
        }
      } catch { /* skip */ }
    }
  }

  results.sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity.toLowerCase())
    const bi = SEVERITY_ORDER.indexOf(b.severity.toLowerCase())
    return ai - bi
  })

  return results
}

export function EvidenceBrowser(props: { sessionID: string; findingID?: string }) {
  const sync = useSync()
  const dialog = useDialog()
  const { theme } = useTheme()

  const messages = createMemo(() => sync.data.message[props.sessionID] ?? [])
  const allFindings = createMemo(() => extractFindings(messages(), sync.data.part))

  const initial = allFindings().find((f) => f.id === props.findingID)

  // If a specific finding was requested, jump straight to detail view
  if (props.findingID && initial) {
    return <EvidenceDetail finding={initial} sessionID={props.sessionID} />
  }

  const options = createMemo((): DialogSelectOption<string>[] => {
    return allFindings().map((finding) => ({
      title: `${severityIcon(finding.severity)} ${finding.title}`,
      value: finding.id || finding.title,
      description: [finding.url, finding.cwe_id, finding.owasp_category].filter(Boolean).join(" │ "),
      gutter: (
        <text fg={severityColor(finding.severity, theme)} attributes={TextAttributes.BOLD}>
          {finding.severity.toUpperCase().padEnd(8)}
        </text>
      ),
      onSelect: () => {
        dialog.replace(() => <EvidenceDetail finding={finding} sessionID={props.sessionID} />)
      },
    }))
  })

  return (
    <Show
      when={allFindings().length > 0}
      fallback={
        <box paddingLeft={2} paddingRight={2} gap={1} paddingBottom={1}>
          <box flexDirection="row" justifyContent="space-between">
            <text fg={theme.text} attributes={TextAttributes.BOLD}>
              Evidence Browser
            </text>
            <text fg={theme.textMuted} onMouseUp={() => dialog.clear()}>
              esc
            </text>
          </box>
          <text fg={theme.textMuted}>No findings yet — use /target to start a scan</text>
        </box>
      }
    >
      <DialogSelect title="Evidence Browser" options={options()} />
    </Show>
  )
}

function EvidenceDetail(props: { finding: Finding; sessionID: string }) {
  const { theme } = useTheme()
  const dialog = useDialog()
  const dimensions = useTerminalDimensions()

  const sev = () => props.finding.severity.toLowerCase()
  const color = () => severityColor(sev(), theme)
  const width = () => Math.min(dimensions().width - 4, 76)
  const innerWidth = () => width() - 4
  const separator = () => "─".repeat(innerWidth())

  useKeyboard((evt) => {
    if (evt.name === "escape" || (evt.ctrl && evt.name === "c")) {
      evt.preventDefault()
      dialog.replace(() => <EvidenceBrowser sessionID={props.sessionID} />)
    }
  })

  return (
    <box paddingLeft={2} paddingRight={2} gap={0} paddingBottom={1}>
      {/* Header */}
      <box flexDirection="row" justifyContent="space-between">
        <text fg={theme.text} attributes={TextAttributes.BOLD}>
          Evidence: {props.finding.title}
        </text>
        <text fg={theme.textMuted} onMouseUp={() => dialog.replace(() => <EvidenceBrowser sessionID={props.sessionID} />)}>
          esc
        </text>
      </box>

      {/* Severity / CWE / OWASP / Confidence row */}
      <box flexDirection="row" gap={2} paddingTop={1}>
        <text fg={color()} attributes={TextAttributes.BOLD}>
          {severityIcon(sev())} {props.finding.severity.toUpperCase()}
        </text>
        <Show when={props.finding.cwe_id}>
          <text fg={theme.info}>{props.finding.cwe_id}</text>
        </Show>
        <Show when={props.finding.owasp_category}>
          <text fg={theme.accent}>{props.finding.owasp_category}</text>
        </Show>
        <Show when={props.finding.confidence}>
          <text fg={theme.textMuted}>⚡ {props.finding.confidence}</text>
        </Show>
      </box>

      {/* URL */}
      <Show when={props.finding.url}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>URL</text>
          <text fg={theme.text} wrapMode="word">{props.finding.url}</text>
        </box>
      </Show>

      {/* Parameter + Tool row */}
      <box flexDirection="row" gap={3} paddingTop={1}>
        <Show when={props.finding.parameter}>
          <box>
            <text fg={theme.textMuted}>Parameter</text>
            <text fg={theme.warning}>{props.finding.parameter}</text>
          </box>
        </Show>
        <Show when={props.finding.tool_used}>
          <box>
            <text fg={theme.textMuted}>Tool</text>
            <text fg={theme.text}>{props.finding.tool_used}</text>
          </box>
        </Show>
        <Show when={props.finding.cvss_score}>
          <box>
            <text fg={theme.textMuted}>CVSS</text>
            <text fg={theme.text}>{String(props.finding.cvss_score)}</text>
          </box>
        </Show>
      </box>

      {/* Payload section */}
      <Show when={props.finding.payload}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>
            ─ Payload {separator().slice(10)}
          </text>
          <box backgroundColor={theme.backgroundElement} paddingLeft={1} paddingRight={1} paddingTop={0} paddingBottom={0}>
            <text fg={theme.syntaxString} wrapMode="word">
              {props.finding.payload}
            </text>
          </box>
        </box>
      </Show>

      {/* Evidence section */}
      <Show when={props.finding.evidence}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>
            ─ Evidence {separator().slice(11)}
          </text>
          <box backgroundColor={theme.backgroundElement} paddingLeft={1} paddingRight={1} paddingTop={0} paddingBottom={0}>
            <text fg={theme.text} wrapMode="word">
              {props.finding.evidence}
            </text>
          </box>
        </box>
      </Show>

      {/* Description (if different from evidence) */}
      <Show when={props.finding.description && props.finding.description !== props.finding.evidence}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>
            ─ Description {separator().slice(15)}
          </text>
          <text fg={theme.text} wrapMode="word">
            {props.finding.description}
          </text>
        </box>
      </Show>

      {/* Chain info */}
      <Show when={props.finding.chain_id}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>
            ─ Chain {separator().slice(9)}
          </text>
          <text fg={theme.warning} wrapMode="word">
            ⛓ {props.finding.chain_id}
          </text>
        </box>
      </Show>

      {/* Finding ID */}
      <Show when={props.finding.id}>
        <box paddingTop={1}>
          <text fg={theme.textMuted}>
            ID: {props.finding.id}
          </text>
        </box>
      </Show>
    </box>
  )
}
