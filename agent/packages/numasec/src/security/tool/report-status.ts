import z from "zod"
import { Tool } from "../../tool/tool"
import { canonicalSecuritySessionID } from "../security-session"
import { readEngagementTruth, readOperationalPhase } from "../report/readiness"
import { makeToolResultEnvelope } from "./result-envelope"
import { Database, eq } from "../../storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../evidence.sql"
import { FindingTable } from "../security.sql"

type EvidenceRow = (typeof EvidenceNodeTable)["$inferSelect"]
type FindingRow = (typeof FindingTable)["$inferSelect"]

function readPayload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) return input as Record<string, unknown>
  return {}
}

function verificationPassed(row: EvidenceRow) {
  const payload = readPayload(row.payload)
  if (typeof payload.passed === "boolean") return payload.passed
  return row.status === "confirmed"
}

function verificationControl(row: EvidenceRow) {
  const payload = readPayload(row.payload)
  if (typeof payload.control === "string") return payload.control
  return "neutral"
}

function supportRows(nodeID: string, map: Map<string, EvidenceRow>, edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>) {
  const out = new Map<string, EvidenceRow>()
  for (const edge of edges) {
    if (edge.to_node_id !== nodeID) continue
    if (edge.relation !== "supports") continue
    const row = map.get(edge.from_node_id)
    if (!row) continue
    out.set(row.id, row)
  }
  return Array.from(out.values())
}

function targetFromRow(
  row: EvidenceRow | undefined,
  map: Map<string, EvidenceRow>,
  edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>,
): {
  url: string
  method: string
} {
  if (!row) return { url: "", method: "" }
  const direct = readPayload(row.payload)
  const request = readPayload(direct.request)
  const url = String(request.url ?? direct.url ?? direct.asset_ref ?? "")
  const method = String(request.method ?? direct.method ?? "")
  if (url || method) return { url, method }
  for (const item of supportRows(row.id, map, edges)) {
    const next = targetFromRow(item, map, edges)
    if (!next.url && !next.method) continue
    return next
  }
  return { url: "", method: "" }
}

function provisionalMissing(row: FindingRow, map: Map<string, EvidenceRow>, edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>) {
  const severity = row.severity.toLowerCase()
  const contractRequired = severity === "high" || severity === "critical"
  if (!contractRequired) return ["promotion_review"]
  const refs = row.evidence
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
  const evidenceRows = refs.map((item) => map.get(item)).filter(Boolean) as EvidenceRow[]
  const positiveOK = evidenceRows.some((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative")
  let negativeOK = false
  if (row.source_hypothesis_id) {
    for (const edge of edges) {
      if (edge.from_node_id !== row.source_hypothesis_id) continue
      if (edge.relation !== "verifies") continue
      const candidate = map.get(edge.to_node_id)
      if (!candidate || candidate.type !== "verification") continue
      if (!verificationPassed(candidate)) continue
      if (verificationControl(candidate) !== "negative") continue
      negativeOK = true
      break
    }
  }
  const impactOK = evidenceRows.some((item) =>
    supportRows(item.id, map, edges).some((support) => support.type === "artifact" || support.type === "observation"),
  )
  const missing: string[] = []
  if (!positiveOK) missing.push("positive_verification")
  if (!negativeOK) missing.push("negative_control")
  if (!impactOK) missing.push("impact_evidence")
  return missing
}

function nextAction(kind: string, missing: string[], params: { hypothesisID?: string; findingID?: string; verificationNodeID?: string }) {
  if (kind === "open_hypothesis") {
    return `Resolve or confirm hypothesis ${params.hypothesisID ?? ""} before mode=final.`
  }
  if (missing.includes("positive_verification")) {
    return "Run verify_assertion with persist=true for exploit success, then rerun finalize_finding."
  }
  if (missing.includes("negative_control")) {
    return "Run create_control_case or verify_assertion for a benign control, then rerun finalize_finding."
  }
  if (missing.includes("impact_evidence")) {
    return "Record a concrete impact artifact and rerun finalize_finding."
  }
  if (kind === "promotion_gap") {
    if (params.hypothesisID) return `Call finalize_finding for hypothesis ${params.hypothesisID} so this verification is promoted or resolved.`
    return `Review verification ${params.verificationNodeID ?? ""} and either promote it into a finding or suppress it.`
  }
  return `Rerun finalize_finding for finding ${params.findingID ?? ""} to close the remaining promotion debt.`
}

function nextOperatorCommand(kind: string, params: { hypothesisID?: string; findingID?: string }) {
  if (kind === "provisional_finding" && params.findingID) return `/finding finalize ${params.findingID}`
  if (kind === "open_hypothesis") return "/verify next"
  if (kind === "promotion_gap") return "/verify next"
  return "/report finalize"
}

function blockers(sessionID: string, readiness: ReturnType<typeof readEngagementTruth>["readiness"]) {
  const rows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(eq(EvidenceNodeTable.session_id, sessionID as any))
      .all(),
  )
  const edges = Database.use((db) =>
    db
      .select()
      .from(EvidenceEdgeTable)
      .where(eq(EvidenceEdgeTable.session_id, sessionID as any))
      .all(),
  )
  const map = new Map<string, EvidenceRow>(rows.map((item) => [item.id, item]))
  const out: Array<Record<string, unknown>> = []
  for (const hypothesisID of readiness.closure.hypothesis_open_ids) {
    const row = map.get(hypothesisID)
    const target = targetFromRow(row, map, edges)
    out.push({
      id: `open-hypothesis:${hypothesisID}`,
      kind: "open_hypothesis",
      hypothesis_id: hypothesisID,
      title: String(readPayload(row?.payload).statement ?? "Open hypothesis"),
      url: target.url,
      method: target.method,
      missing_contract_parts: [],
      next_minimal_action: nextAction("open_hypothesis", [], { hypothesisID }),
      next_operator_command: nextOperatorCommand("open_hypothesis", { hypothesisID }),
    })
  }
  for (const finding of readiness.projection.provisional.slice(0, 20)) {
    const missing = provisionalMissing(finding, map, edges)
    out.push({
      id: `provisional-finding:${finding.id}`,
      kind: "provisional_finding",
      finding_id: finding.id,
      hypothesis_id: finding.source_hypothesis_id,
      title: finding.title,
      severity: finding.severity,
      url: finding.url,
      method: finding.method,
      missing_contract_parts: missing,
      next_minimal_action: nextAction("provisional_finding", missing, {
        hypothesisID: finding.source_hypothesis_id,
        findingID: finding.id,
      }),
      next_operator_command: nextOperatorCommand("provisional_finding", {
        hypothesisID: finding.source_hypothesis_id,
        findingID: finding.id,
      }),
    })
  }
  for (const verificationNodeID of readiness.projection.promotion_gap_ids.slice(0, 20)) {
    const row = map.get(verificationNodeID)
    let hypothesisID = ""
    for (const edge of edges) {
      if (edge.to_node_id !== verificationNodeID) continue
      if (edge.relation !== "verifies") continue
      hypothesisID = edge.from_node_id
      break
    }
    const target = targetFromRow(row, map, edges)
    out.push({
      id: `promotion-gap:${verificationNodeID}`,
      kind: "promotion_gap",
      hypothesis_id: hypothesisID,
      verification_node_id: verificationNodeID,
      title: String(readPayload(row?.payload).title ?? readPayload(row?.payload).predicate ?? "Verification not promoted into a finding"),
      url: target.url,
      method: target.method,
      missing_contract_parts: ["finding_promotion"],
      next_minimal_action: nextAction("promotion_gap", ["finding_promotion"], {
        hypothesisID,
        verificationNodeID,
      }),
      next_operator_command: nextOperatorCommand("promotion_gap", { hypothesisID }),
    })
  }
  return out
}

const DESCRIPTION = `Show current report readiness and remaining closure debt.
Use this before strict/final export or when you need to explain why a report is still a working draft.`

export const ReportStatusTool = Tool.define("report_status", {
  description: DESCRIPTION,
  parameters: z.object({
    include_ids: z.boolean().optional().describe("Include open hypothesis ids and promotion gap ids in the text output"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const truth = readEngagementTruth(sessionID)
    const readiness = truth.readiness
    const operationalPhase = readOperationalPhase(sessionID)
    const blockerList = blockers(sessionID, readiness)
    const state = readiness.state === "final_ready" ? "FINAL_READY" : readiness.state === "working_draft" ? "WORKING_DRAFT" : "EMPTY"
    const output = [
      `Report readiness: ${state}`,
      `Operational phase: ${operationalPhase.toUpperCase()}`,
      `Working report ready: ${readiness.working_ready ? "yes" : "no"}`,
      `Final report ready: ${readiness.final_ready ? "yes" : "no"}`,
      `Final snapshot state: ${truth.final_report.state.toUpperCase()}`,
      `Verified findings: ${readiness.projection.counts.verified}`,
      `Provisional findings: ${readiness.projection.provisional.length}`,
      `Promotion gaps: ${readiness.projection.counts.promotion_gaps}`,
      `Open hypotheses: ${readiness.closure.hypothesis_open}`,
      `Open critical hypotheses: ${readiness.closure.hypothesis_critical_open}`,
      ...(readiness.truth_reasons.length > 0 ? readiness.truth_reasons.map((item) => `- ${item}`) : ["- Final readiness satisfied"]),
      ...(blockerList.length > 0
        ? [
            "Structured blockers:",
            ...blockerList.map((item) => {
              const missing = Array.isArray(item.missing_contract_parts) ? item.missing_contract_parts.join(", ") : ""
              const command = String(item.next_operator_command ?? "")
              return `- ${String(item.kind)} ${String(item.title)}${missing ? ` [missing: ${missing}]` : ""} -> ${String(item.next_minimal_action)}${command ? ` | command: ${command}` : ""}`
            }),
          ]
        : []),
      readiness.final_ready
        ? "Recommended command: /report generate markdown --final"
        : "Recommended command: /report generate markdown (working) or close the remaining debt before --final",
      ...(params.include_ids
        ? [
            `Open hypothesis ids: ${readiness.closure.hypothesis_open_ids.join(", ") || "(none)"}`,
            `Promotion gap ids: ${readiness.projection.promotion_gap_ids.join(", ") || "(none)"}`,
          ]
        : []),
    ].join("\n")

    return {
      title: `Report readiness: ${state.toLowerCase()}`,
      metadata: {
        state: readiness.state,
        workingReady: readiness.working_ready,
        finalReady: readiness.final_ready,
        operationalPhase,
        truthReasons: readiness.truth_reasons,
        finalSnapshot: truth.final_report,
        closure: readiness.closure,
        projection: readiness.projection.counts,
        promotionGapIds: readiness.projection.promotion_gap_ids,
        blockers: blockerList,
      } as any,
      envelope: makeToolResultEnvelope({
        status: readiness.final_ready ? "ok" : "inconclusive",
        observations: [
          {
            type: "report_readiness",
            state: readiness.state,
            working_ready: readiness.working_ready,
            final_ready: readiness.final_ready,
          },
        ],
        metrics: {
          verified_findings: readiness.projection.counts.verified,
          provisional_findings: readiness.projection.provisional.length,
          promotion_gaps: readiness.projection.counts.promotion_gaps,
          open_hypotheses: readiness.closure.hypothesis_open,
          open_critical_hypotheses: readiness.closure.hypothesis_critical_open,
          blocker_count: blockerList.length,
        },
      }),
      output,
    }
  },
})
