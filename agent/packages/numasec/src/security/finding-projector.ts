import { and, eq } from "../storage/db"
import type { SessionID } from "../session/schema"
import { Database } from "../storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "./evidence.sql"
import { enrichFinding } from "./enrichment/enrich"
import { FindingEvaluators } from "./finding-evaluator/registry"
import type { FindingCandidate } from "./finding-evaluator/base"
import { passed, payload } from "./finding-evaluator/base"
import { FindingTable } from "./security.sql"
import { canonicalSecuritySessionID } from "./security-session"

function stateRank(value: string) {
  if (value === "verified") return 0
  if (value === "provisional") return 1
  if (value === "suppressed") return 2
  if (value === "refuted") return 3
  return 4
}

function pick(left: FindingCandidate, right: FindingCandidate) {
  const state = stateRank(left.state) - stateRank(right.state)
  if (state < 0) return left
  if (state > 0) return right
  if (left.confidence >= right.confidence) return left
  return right
}

function refs(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
}

export function projectFindings(sessionID: SessionID) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  const nodes = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(eq(EvidenceNodeTable.session_id, currentSessionID))
      .all(),
  )
  const edges = Database.use((db) =>
    db
      .select()
      .from(EvidenceEdgeTable)
      .where(eq(EvidenceEdgeTable.session_id, currentSessionID))
      .all(),
  )
  const rows = Database.use((db) =>
    db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.session_id, currentSessionID))
      .all(),
  )

  const manual = rows.filter((row) => row.manual_override || row.tool_used !== "finding_projector")
  const manualRoots = new Set<string>()
  const resolvedHypotheses = new Set<string>()
  const used = new Set<string>()
  for (const row of manual) {
    if (row.root_cause_key) manualRoots.add(row.root_cause_key)
    if (row.source_hypothesis_id) resolvedHypotheses.add(row.source_hypothesis_id)
    for (const ref of refs(row.evidence)) used.add(ref)
  }

  const map = new Map<string, FindingCandidate>()
  for (const evaluator of FindingEvaluators) {
      const list = evaluator.evaluate({
        sessionID: currentSessionID,
        nodes,
        edges,
        findings: rows,
    })
    for (const item of list) {
      if (manualRoots.has(item.root_cause_key)) continue
      const current = map.get(item.root_cause_key)
      if (!current) {
        map.set(item.root_cause_key, item)
        continue
      }
      map.set(item.root_cause_key, pick(current, item))
    }
  }

  const projected = Array.from(map.values())
  for (const item of projected) {
    if (item.source_hypothesis_id) resolvedHypotheses.add(item.source_hypothesis_id)
    for (const nodeID of item.node_ids) used.add(nodeID)
    for (const ref of item.evidence_refs) used.add(ref)
    for (const ref of item.negative_control_refs) used.add(ref)
    for (const ref of item.impact_refs) used.add(ref)
  }

  const verificationHypotheses = new Map<string, Set<string>>()
  for (const edge of edges) {
    if (edge.relation !== "verifies") continue
    const list = verificationHypotheses.get(edge.to_node_id) ?? new Set<string>()
    list.add(edge.from_node_id)
    verificationHypotheses.set(edge.to_node_id, list)
  }

  Database.transaction((db) => {
    db
      .delete(FindingTable)
      .where(and(eq(FindingTable.session_id, currentSessionID), eq(FindingTable.tool_used, "finding_projector")))
      .run()

    for (const item of projected) {
      const enriched = enrichFinding({
        sessionID: currentSessionID,
        title: item.title,
        severity: item.severity,
        description: item.description,
        url: item.url,
        method: item.method,
        parameter: item.parameter,
        payload: item.payload,
        confidence: item.confidence,
      })
      db
        .insert(FindingTable)
        .values({
          id: enriched.id,
          session_id: currentSessionID,
          title: item.title,
          severity: item.severity,
          description: item.description,
          evidence: item.evidence_refs.join(","),
          confirmed: item.state === "verified",
          false_positive: item.state === "suppressed" || item.state === "refuted",
          state: item.state,
          family: item.family,
          source_hypothesis_id: item.source_hypothesis_id,
          root_cause_key: item.root_cause_key,
          suppression_reason: item.suppression_reason,
          reportable: item.reportable,
          manual_override: false,
          url: item.url,
          method: item.method,
          parameter: item.parameter,
          payload: item.payload,
          confidence: item.confidence,
          remediation_summary: item.remediation,
          cwe_id: enriched.cweId,
          cvss_score: enriched.cvssScore,
          cvss_vector: enriched.cvssVector,
          owasp_category: enriched.owaspCategory,
          attack_technique: enriched.attackTechnique,
          tool_used: "finding_projector",
        })
        .onConflictDoUpdate({
          target: FindingTable.id,
          set: {
            title: item.title,
            severity: item.severity,
            description: item.description,
            evidence: item.evidence_refs.join(","),
            confirmed: item.state === "verified",
            false_positive: item.state === "suppressed" || item.state === "refuted",
            state: item.state,
            family: item.family,
            source_hypothesis_id: item.source_hypothesis_id,
            root_cause_key: item.root_cause_key,
            suppression_reason: item.suppression_reason,
            reportable: item.reportable,
            manual_override: false,
            url: item.url,
            method: item.method,
            parameter: item.parameter,
            payload: item.payload,
            confidence: item.confidence,
            remediation_summary: item.remediation,
            cwe_id: enriched.cweId,
            cvss_score: enriched.cvssScore,
            cvss_vector: enriched.cvssVector,
            owasp_category: enriched.owaspCategory,
            attack_technique: enriched.attackTechnique,
            tool_used: "finding_projector",
            time_updated: Date.now(),
          },
        })
        .run()
    }
  })

  const all = Database.use((db) =>
    db
      .select()
      .from(FindingTable)
      .where(eq(FindingTable.session_id, currentSessionID))
      .all(),
  )

  const gaps = nodes
    .filter((row) => row.type === "verification")
    .filter((row) => {
      const value = payload(row)
      return typeof value.family === "string" && value.family.length > 0 && passed(row)
    })
    .map((row) => row.id)
    .filter((id) => !used.has(id))
    .filter((id) => {
      const linked = verificationHypotheses.get(id)
      if (!linked || linked.size === 0) return true
      for (const hypothesisID of linked) {
        if (resolvedHypotheses.has(hypothesisID)) return false
      }
      return true
    })

  const counts = {
    raw: all.length,
    verified: all.filter((row) => row.state === "verified").length,
    provisional: all.filter((row) => row.state === "provisional").length,
    suppressed: all.filter((row) => row.state === "suppressed").length,
    refuted: all.filter((row) => row.state === "refuted").length,
    reportable: all.filter((row) => row.reportable).length,
    promotion_gaps: gaps.length,
  }

  return {
    rows: all,
    counts,
    promotion_gap_ids: gaps,
  }
}
