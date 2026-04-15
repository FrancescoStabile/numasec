import type { MessageV2 } from "./message-v2"
import type { SessionID } from "./schema"
import { readEngagementTruth } from "../security/report/readiness"

const BLOCKED = "REPORT_BLOCKED_INCOMPLETE_STATE"
const NO_TOOL = "REPORT_DRAFT_BLOCKED_NO_CANONICAL_TOOL"
const INCOMPLETE = "REPORT_DRAFT_BLOCKED_REPORT_NOT_COMPLETED"
const REOPENED = "REPORT_FINAL_SNAPSHOT_REOPENED"
const SECURITY_AGENT = new Set(["pentest", "report", "hunt", "scanner"])
const REPORT_TITLE = [
  /\bpenetration test report\b/i,
  /\bsecurity assessment report\b/i,
  /\bpentest summary\b/i,
]
const REPORT_SECTION = [
  /\bexecutive summary\b/i,
  /\bdetailed findings\b/i,
  /\bcoverage matrix\b/i,
  /\bremediation roadmap\b/i,
  /\bkey vulnerabilities\b/i,
  /\brecommendations\b/i,
  /\battack paths\b/i,
]
const CLAIM_REWRITE = [
  [/\bfinal security assessment report\b/gi, "working security assessment summary"],
  [/\bsecurity assessment report\b/gi, "working security assessment summary"],
  [/\bpenetration test report\b/gi, "working pentest summary"],
  [/\bassessment summary\b/gi, "working assessment status"],
  [/\bgenerated reports?\b/gi, "report status"],
  [/\bfinal report\b/gi, "working report"],
  [/\bfinal findings\b/gi, "current findings"],
  [/\bpentest complete\b/gi, "pentest status update"],
  [/\bassessment complete\b/gi, "assessment status update"],
  [/\breport complete\b/gi, "report status update"],
  [/\btesting (?:is )?complete\b/gi, "testing remains in progress"],
  [/\bverified findings?\b/gi, "observed findings"],
  [/\brisk score\b/gi, "working risk view"],
] as const

const REPORT_TOOLS = new Set(["generate_report", "finalize_report"])

function canonicalReportPart(part: MessageV2.Part): part is MessageV2.ToolPart {
  return part.type === "tool" && REPORT_TOOLS.has(part.tool)
}

function renderedReport(parts: MessageV2.ToolPart[]) {
  const part = parts.findLast((item) => {
    if (item.state.status !== "completed") return false
    if (item.state.metadata?.blocked_code === BLOCKED) return false
    const rendered = item.state.metadata?.reportRendered ?? item.state.metadata?.report_rendered
    return rendered === "working" || rendered === "final"
  })
  if (!part || part.state.status !== "completed") return
  const rendered = part.state.metadata?.reportRendered ?? part.state.metadata?.report_rendered
  if (rendered === "working" || rendered === "final") return rendered
}

function reportToolName(part: MessageV2.ToolPart) {
  if (part.tool === "finalize_report") return "finalize_report"
  return "generate_report"
}

export function reportGuardTurnParts(input: {
  messages: MessageV2.WithParts[]
  parentID: string
  messageID: string
}) {
  const parts: MessageV2.Part[] = []
  for (const message of input.messages) {
    if (message.info.role !== "assistant") continue
    if (message.info.parentID !== input.parentID) continue
    parts.push(...message.parts)
    if (message.info.id === input.messageID) break
  }
  return parts
}

export function blockedReportSummary(parts: MessageV2.Part[]) {
  const items = parts.filter(canonicalReportPart)
  const blocked = items.findLast(
    (part) => part.state.status === "completed" && part.state.metadata?.blocked_code === BLOCKED,
  )
  if (!blocked) return

  const lines = [BLOCKED, "Final report remains blocked by readiness policy.", "Do not treat this assessment as final."]

  if (blocked && blocked.state.status === "completed") {
    const closure = blocked.state.metadata?.closure ?? {}
    const reasons = Array.isArray(blocked.state.metadata?.truthReasons) ? blocked.state.metadata.truthReasons : []
    if (typeof closure.hypothesis_open === "number") {
      lines.push(`Open hypotheses: ${closure.hypothesis_open}`)
    }
    if (typeof closure.hypothesis_critical_open === "number") {
      lines.push(`Open critical hypotheses: ${closure.hypothesis_critical_open}`)
    }
    for (const item of reasons) {
      if (typeof item !== "string" || !item.trim()) continue
      lines.push(`- ${item}`)
    }
  }

  lines.push(
    "Return blockers only until readiness debt is closed, or render a working report with finalize_report mode=working or generate_report.",
    "Use report_status to inspect readiness separately from rendering, or rerun finalize_report in working mode.",
  )
  return lines.join("\n")
}

function successfulReport(parts: MessageV2.ToolPart[]) {
  return renderedReport(parts) !== undefined
}

function blockedReport(parts: MessageV2.ToolPart[]) {
  return parts.some((part) => part.state.status === "completed" && part.state.metadata?.blocked_code === BLOCKED)
}

function incompleteReport(parts: MessageV2.ToolPart[]) {
  return parts.findLast((part) => {
    if (part.state.status === "pending") return true
    if (part.state.status === "running") return true
    return part.state.status === "error"
  })
}

function reportShape(text: string) {
  const title = REPORT_TITLE.some((item) => item.test(text))
  let section = 0
  for (const item of REPORT_SECTION) {
    if (!item.test(text)) continue
    section += 1
  }
  if (title && section >= 1) return true
  return section >= 3
}

function incompleteReportSummary(parts: MessageV2.ToolPart[]) {
  const part = incompleteReport(parts)
  if (!part) return
  const name = reportToolName(part)

  const lines = [
    INCOMPLETE,
    `${name} was requested but did not complete in this turn.`,
    "Do not present Executive Summary, Detailed Findings, Coverage Matrix, Recommendations, or report completion claims without a successful generate_report or finalize_report result.",
  ]

  if (part.state.status === "error" && part.state.error.trim()) {
    lines.push(`Tool status: ${part.state.error.trim()}`)
  }

  if (part.state.status === "pending") {
    lines.push(`Tool status: ${name} was still pending at text close.`)
  }

  if (part.state.status === "running") {
    lines.push(`Tool status: ${name} was still running at text close.`)
  }

  lines.push(`Rerun ${name} after the remaining tool work is done, or return blockers and verification notes only.`)
  return lines.join("\n")
}

function reopenedReportSummary(sessionID: SessionID) {
  const truth = readEngagementTruth(sessionID)
  const lines = [
    REOPENED,
    "A prior final report snapshot exists, but the session changed after it.",
    "Do not treat this assessment as final.",
  ]
  if (truth.final_report.exported_revision !== null) {
    lines.push(`Final export revision: ${truth.final_report.exported_revision}`)
  }
  if (truth.final_report.exported_at !== null) {
    lines.push(`Final export time: ${truth.final_report.exported_at}`)
  }
  lines.push(`Current report state: ${truth.readiness.state}`)
  for (const item of truth.readiness.truth_reasons) {
    if (!item.trim()) continue
    lines.push(`- ${item}`)
  }
  lines.push("Run report_status to inspect the current session truth, or rerun finalize_report after closing the new debt.")
  return lines.join("\n")
}

function demoteCanonicalClaims(text: string, state: "absent" | "blocked" | "incomplete" | "working" | "reopened") {
  let value = text
  let changed = false
  for (const item of CLAIM_REWRITE) {
    const next = value.replace(item[0], item[1])
    if (next === value) continue
    value = next
    changed = true
  }
  if (!changed) return
  if (state === "absent" && /^\s*working assessment status\b/i.test(value)) {
    return value.replace(/^\s*working assessment status\b/i, "Working assessment status")
  }
  if (state === "absent" && /^\s*working pentest summary\b/i.test(value)) {
    return value.replace(/^\s*working pentest summary\b/i, "Working pentest summary")
  }
  if (state === "absent") return `Working assessment status\n\n${value}`
  value = value.replace(/^\s*working assessment status\b\s*/i, "").replace(/^\s*working pentest summary\b\s*/i, "").trimStart()
  if (state === "working") return `Working assessment status — only a working report exists for the current session state.\n\n${value}`
  if (state === "blocked") return `Working assessment status — final export is still blocked by readiness debt.\n\n${value}`
  if (state === "reopened") return `Working assessment status — session reopened after the last final report snapshot.\n\n${value}`
  return `Working assessment status — report rendering did not complete in this turn.\n\n${value}`
}

export function reportGuardSummary(parts: MessageV2.Part[], text: string, agent: string, sessionID?: SessionID) {
  if (!SECURITY_AGENT.has(agent)) return
  if (!text.trim()) return
  const items = parts.filter(canonicalReportPart)
  const rendered = renderedReport(items)
  const state = sessionID && readEngagementTruth(sessionID).final_report.state === "reopened"
    ? "reopened"
    : rendered === "working"
      ? "working"
      : rendered === "final"
        ? "final"
        : blockedReport(items)
          ? "blocked"
          : incompleteReport(items)
            ? "incomplete"
            : "absent"
  if (!reportShape(text)) {
    if (state === "final") return
    return demoteCanonicalClaims(text, state)
  }
  if (state === "reopened" && sessionID) return reopenedReportSummary(sessionID)
  if (successfulReport(items)) return
  if (state === "blocked") return blockedReportSummary(parts)
  if (state === "incomplete") return incompleteReportSummary(items)
  return [
    NO_TOOL,
    "No canonical report render result exists for this turn.",
    "Do not present Executive Summary, Detailed Findings, Coverage Matrix, Recommendations, or report completion claims without a successful generate_report or finalize_report result.",
    "Run finalize_report, generate_report (working mode is the default), or report_status, or return blockers and verification notes only.",
  ].join("\n")
}
