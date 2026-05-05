import type { JSX } from "solid-js"
import type { TuiThemeCurrent } from "@numasec/plugin/tui"
import type { EvidenceKind, FindingLensStatus, ReplayLensStatus, ReportGateTone, WorkflowLensState } from "./snapshot"

export function truncateMiddle(text: string, max: number) {
  if (text.length <= max) return text
  if (max <= 3) return text.slice(0, max)
  const head = Math.ceil((max - 1) / 2)
  const tail = Math.floor((max - 1) / 2)
  return `${text.slice(0, head)}...${text.slice(text.length - tail)}`
}

export function formatAge(at?: number) {
  if (!at) return "-"
  const delta = Date.now() - at
  if (delta < 60_000) return `${Math.max(1, Math.floor(delta / 1000))}s`
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m`
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h`
  return `${Math.floor(delta / 86_400_000)}d`
}

export function formatBytes(size?: number) {
  if (size === undefined) return "-"
  if (size < 1024) return `${size}b`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(size < 10 * 1024 ? 1 : 0)}k`
  return `${(size / (1024 * 1024)).toFixed(1)}m`
}

export function toneColor(theme: TuiThemeCurrent, tone?: ReportGateTone | "info" | "primary" | "normal") {
  switch (tone) {
    case "success":
      return theme.success
    case "warning":
      return theme.warning
    case "error":
      return theme.error
    case "info":
      return theme.info
    case "primary":
      return theme.primary
    case "normal":
      return theme.textMuted
    default:
      return theme.textMuted
  }
}

export function severityColor(theme: TuiThemeCurrent, severityCode: string) {
  switch (severityCode) {
    case "C":
      return theme.error
    case "H":
      return theme.warning
    case "M":
      return theme.info
    case "L":
    case "I":
      return theme.textMuted
    default:
      return theme.textMuted
  }
}

export function statusColor(
  theme: TuiThemeCurrent,
  status: FindingLensStatus | ReplayLensStatus | WorkflowLensState | undefined,
) {
  switch (status) {
    case "reportable":
    case "backed":
    case "completed":
      return theme.success
    case "verified":
    case "exempt":
      return theme.info
    case "suspected":
    case "missing":
    case "pending":
      return theme.warning
    case "failed":
      return theme.error
    case "candidate":
    case "active":
      return theme.primary
    default:
      return theme.textMuted
  }
}

export function evidenceKindColor(theme: TuiThemeCurrent, kind: EvidenceKind) {
  switch (kind) {
    case "replay":
      return theme.primary
    case "http":
      return theme.info
    case "browser":
      return theme.warning
    case "file":
      return theme.text
    case "tool":
      return theme.success
    case "artifact":
      return theme.textMuted
  }
}

export function LensTitle(props: {
  theme: TuiThemeCurrent
  title: string
  summary?: string
}) {
  return (
    <box flexDirection="column" gap={0}>
      <text fg={props.theme.text} wrapMode="none">
        {props.title}
      </text>
      {props.summary ? (
        <text fg={props.theme.textMuted} wrapMode="none">
          {props.summary}
        </text>
      ) : null}
    </box>
  )
}

export function LensRow(props: {
  theme: TuiThemeCurrent
  active?: boolean
  children: JSX.Element
}) {
  return (
    <box
      flexDirection="row"
      gap={2}
      paddingLeft={props.active ? 1 : 0}
      backgroundColor={props.active ? props.theme.backgroundElement : undefined}
    >
      {props.children}
    </box>
  )
}

export function LensEmpty(props: {
  theme: TuiThemeCurrent
  message: string
}) {
  return (
    <text fg={props.theme.textMuted} wrapMode="none">
      {props.message}
    </text>
  )
}

export function LensDetail(props: {
  theme: TuiThemeCurrent
  children: JSX.Element
}) {
  return (
    <box
      flexDirection="column"
      gap={1}
      paddingLeft={1}
      paddingTop={1}
      border={["left"]}
      borderColor={props.theme.borderSubtle}
    >
      {props.children}
    </box>
  )
}
