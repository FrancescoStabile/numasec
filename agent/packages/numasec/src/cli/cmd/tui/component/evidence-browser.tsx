import { TextAttributes } from "@opentui/core"
import { useTerminalDimensions, useKeyboard } from "@opentui/solid"
import { createMemo, Show } from "solid-js"
import { useSync } from "@tui/context/sync"
import { useTheme } from "../context/theme"
import { useDialog } from "@tui/ui/dialog"
import { DialogSelect, type DialogSelectOption } from "@tui/ui/dialog-select"
import {
  fallbackFindings,
  selectFindings,
  type SecurityFinding,
} from "../security-view-model"

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

export function EvidenceBrowser(props: { sessionID: string; findingID?: string }) {
  const sync = useSync()
  const dialog = useDialog()
  const { theme } = useTheme()

  const messages = createMemo(() => sync.data.message[props.sessionID] ?? [])
  const security = createMemo(() => sync.session.security(props.sessionID))
  const legacy = createMemo(() => security() === undefined)
  const fallbackFindingList = createMemo(() => {
    if (!legacy()) return []
    return fallbackFindings(messages(), sync.data.part)
  })
  const allFindings = createMemo(() => selectFindings(security(), fallbackFindingList()))

  const initial = createMemo(() => {
    if (!props.findingID) return undefined
    return allFindings().find((f) => f.id === props.findingID)
  })

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
      when={!initial()}
      fallback={<EvidenceDetail finding={initial()!} sessionID={props.sessionID} />}
    >
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
            <text fg={theme.textMuted}>No findings yet — use /scope set to start a scan (legacy: /target)</text>
          </box>
        }
      >
        <DialogSelect title="Evidence Browser" options={options()} />
      </Show>
    </Show>
  )
}

function EvidenceDetail(props: { finding: SecurityFinding; sessionID: string }) {
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
