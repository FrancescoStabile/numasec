import z from "zod"
import { Effect } from "effect"
import { and, eq, inArray } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { FindingTable } from "../security.sql"
import { enrichFinding, generateFindingId, normalizeSeverity } from "../enrichment/enrich"
import { EvidenceGraphStore } from "../evidence-store"
import { makeToolResultEnvelope } from "./result-envelope"

type EvidenceNodeID = (typeof EvidenceNodeTable)["$inferInsert"]["id"]

function nodeID(value: string): EvidenceNodeID {
  return value as EvidenceNodeID
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const

type Severity = (typeof SEVERITY_ORDER)[number]

function readPayload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
}

function collectText(input: unknown, out: string[]) {
  if (typeof input === "string") {
    out.push(input)
    return
  }
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) collectText(item, out)
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    collectText(value[key], out)
  }
}

function hasImpactSignal(input: unknown): boolean {
  if (!input || typeof input !== "object") return false
  if (Array.isArray(input)) {
    for (const item of input) {
      if (hasImpactSignal(item)) return true
    }
    return false
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    const item = value[key]
    if (typeof item === "number" && item > 0 && /(leak|record|count|affected|created|updated|deleted|exposed|dump)/i.test(key)) {
      return true
    }
    if (hasImpactSignal(item)) return true
  }
  return false
}

function verificationPassed(row: (typeof EvidenceNodeTable)["$inferSelect"]): boolean {
  const payload = readPayload(row.payload)
  if (typeof payload.passed === "boolean") return payload.passed
  return row.status === "confirmed"
}

function verificationControl(row: (typeof EvidenceNodeTable)["$inferSelect"]): string {
  const payload = readPayload(row.payload)
  if (typeof payload.control === "string") return payload.control
  return "neutral"
}

function impactEvidenceStrong(rows: Array<(typeof EvidenceNodeTable)["$inferSelect"]>): boolean {
  if (rows.length === 0) return false
  const signal = rows.some((row) => hasImpactSignal(row.payload))
  if (signal) return true
  const text: string[] = []
  for (const row of rows) {
    collectText(row.payload, text)
  }
  if (text.length === 0) return false
  const value = text.join("\n").toLowerCase()
  const deny = /(permission_denied|forbidden|unauthorized|not found|\b403\b|\b404\b|denied|blocked)/i.test(value)
  const positive = /(idtoken|token issued|created|updated|deleted|exfiltrat|leak|dump|admin|\b200\b|success)/i.test(value)
  if (deny && !positive) return false
  return true
}

function severityStep(value: string, shift: number): Severity {
  const index = SEVERITY_ORDER.indexOf(normalizeSeverity(value) as Severity)
  const next = index < 0 ? 2 : Math.min(SEVERITY_ORDER.length - 1, index + shift)
  return SEVERITY_ORDER[next]
}

const DESCRIPTION = `Create or update a finding from a validated hypothesis and evidence.
Writes both graph-native finding node and legacy finding projection for compatibility.`

export const UpsertFindingTool = Tool.define("upsert_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    hypothesis_id: z.string().describe("Hypothesis node id"),
    title: z.string().describe("Finding title"),
    severity: z.string().describe("Finding severity"),
    impact: z.string().describe("Business or technical impact"),
    evidence_refs: z.array(z.string()).min(1).describe("Evidence node ids supporting the finding"),
    negative_control_refs: z.array(z.string()).optional().describe("Verification node ids for negative controls"),
    impact_refs: z.array(z.string()).optional().describe("Evidence node ids demonstrating concrete impact"),
    taxonomy_tags: z.array(z.string()).optional().describe("Optional taxonomy tags"),
    confidence: z.number().min(0).max(1).optional().describe("Finding confidence"),
    status: z.string().optional().describe("Finding status"),
    strict_assertion: z.boolean().optional().describe("Fail instead of downgrade when assertion contract is incomplete"),
    url: z.string().optional().describe("Affected URL"),
    method: z.string().optional().describe("HTTP method"),
    parameter: z.string().optional().describe("Affected parameter"),
    payload: z.string().optional().describe("Payload used in validation"),
    tool_used: z.string().optional().describe("Producer tool id"),
    remediation: z.string().optional().describe("Remediation summary"),
  }),
  async execute(params, ctx) {
    const hypothesis = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(
          and(
            eq(EvidenceNodeTable.session_id, ctx.sessionID),
            eq(EvidenceNodeTable.id, nodeID(params.hypothesis_id)),
            eq(EvidenceNodeTable.type, "hypothesis"),
          ),
        )
        .get(),
    )
    if (!hypothesis) {
      throw new Error("upsert_finding requires an existing hypothesis node")
    }

    const required = new Set<string>()
    for (const item of params.evidence_refs) required.add(item)
    for (const item of params.negative_control_refs ?? []) required.add(item)
    for (const item of params.impact_refs ?? []) required.add(item)
    const refList = Array.from(required)

    const refs = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(
          and(
            eq(EvidenceNodeTable.session_id, ctx.sessionID),
            inArray(EvidenceNodeTable.id, refList.map(nodeID)),
          ),
        )
        .all(),
    )
    if (refs.length !== refList.length) {
      throw new Error("upsert_finding received one or more unknown evidence references")
    }
    const refMap = new Map<string, (typeof refs)[number]>(refs.map((item) => [item.id, item]))
    const evidenceRows = params.evidence_refs.map((item) => refMap.get(item)).filter(Boolean) as (typeof refs)[number][]
    const negativeRows = (params.negative_control_refs ?? [])
      .map((item) => refMap.get(item))
      .filter(Boolean) as (typeof refs)[number][]
    const impactRows = (params.impact_refs ?? []).map((item) => refMap.get(item)).filter(Boolean) as (typeof refs)[number][]

    const verification = evidenceRows.some((item) => item.type === "verification")
    if (!verification) {
      throw new Error(
        "upsert_finding requires at least one verification evidence node. Next step: run verify_assertion with persist=true and pass the returned verification node in evidence_refs.",
      )
    }

    const requestedSeverity = normalizeSeverity(params.severity)
    const requestedConfidence = params.confidence ?? 0.7
    const contractRequired = requestedSeverity === "critical" || requestedSeverity === "high"
    const positiveOK = evidenceRows.some((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative")
    const negativeOK = negativeRows.some((item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) === "negative")
    const impactOK = impactEvidenceStrong(impactRows)
    const missing: string[] = []
    if (contractRequired && !positiveOK) missing.push("positive_verification")
    if (contractRequired && !negativeOK) missing.push("negative_control")
    if (contractRequired && !impactOK) missing.push("impact_evidence")
    const suggestions: string[] = []
    if (missing.includes("positive_verification")) suggestions.push("run verify_assertion for exploit success (control=positive)")
    if (missing.includes("negative_control")) suggestions.push("run verify_assertion for control case (control=negative) and pass node in negative_control_refs")
    if (missing.includes("impact_evidence")) suggestions.push("record concrete impact artifact (data change/exposure or measurable business impact) and pass in impact_refs")
    if (contractRequired && params.strict_assertion && missing.length > 0) {
      throw new Error(`upsert_finding assertion contract incomplete: ${missing.join(", ")}. Next steps: ${suggestions.join("; ")}`)
    }
    const severity = contractRequired ? severityStep(requestedSeverity, missing.length) : (requestedSeverity as Severity)
    const speculative = /\b(could|might|may|potential|future|possible)\b/i.test(params.impact)
    const confidenceBase = contractRequired ? Math.max(0.2, requestedConfidence - missing.length * 0.2) : requestedConfidence
    const confidenceCap = !impactOK && speculative ? 0.65 : !impactOK && contractRequired ? 0.75 : 1
    const confidence = Math.min(confidenceBase, confidenceCap)
    const contractStatus = missing.length === 0 ? "complete" : "incomplete"
    const url = params.url ?? ""
    const method = params.method ?? "GET"
    const parameter = params.parameter ?? ""
    const impact = params.impact

    const findingID = generateFindingId({
      method,
      url,
      parameter,
      title: params.title,
      severity,
    })

    const enrichment = enrichFinding({
      title: params.title,
      severity,
      description: impact,
      url,
      parameter,
    })

    const existing = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, findingID))
        .get(),
    )

    if (!existing) {
      Database.use((db) =>
        db
          .insert(FindingTable)
          .values({
            id: findingID,
            session_id: ctx.sessionID,
            title: params.title,
            severity,
            description: impact,
            evidence: params.evidence_refs.join(","),
            confirmed: confidence >= 0.8 && contractStatus === "complete",
            url,
            method,
            parameter,
            payload: params.payload ?? "",
            confidence,
            tool_used: params.tool_used ?? "upsert_finding",
            remediation_summary: params.remediation ?? "",
            cwe_id: enrichment.cweId ?? "",
            cvss_score: enrichment.cvssScore,
            cvss_vector: enrichment.cvssVector ?? "",
            owasp_category: enrichment.owaspCategory ?? "",
            attack_technique: enrichment.attackTechnique ?? "",
          })
          .run(),
      )
    }

    if (existing) {
      Database.use((db) =>
        db
          .update(FindingTable)
            .set({
              title: params.title,
              severity,
              description: impact,
              evidence: params.evidence_refs.join(","),
              confirmed: confidence >= 0.8 && contractStatus === "complete",
              url,
              method,
              parameter,
            payload: params.payload ?? "",
            confidence,
            tool_used: params.tool_used ?? existing.tool_used,
            remediation_summary: params.remediation ?? existing.remediation_summary,
            cwe_id: enrichment.cweId ?? existing.cwe_id,
            cvss_score: enrichment.cvssScore ?? existing.cvss_score,
            cvss_vector: enrichment.cvssVector ?? existing.cvss_vector,
            owasp_category: enrichment.owaspCategory ?? existing.owasp_category,
            attack_technique: enrichment.attackTechnique ?? existing.attack_technique,
            time_updated: Date.now(),
          })
          .where(eq(FindingTable.id, findingID))
          .run(),
      )
    }

    const node = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
            type: "finding",
            fingerprint: findingID,
            status: params.status ?? (contractStatus === "complete" ? "active" : "needs_verification"),
            confidence,
            sourceTool: params.tool_used ?? "upsert_finding",
            payload: {
              finding_id: findingID,
              title: params.title,
              severity,
              impact,
              url,
              method,
              parameter,
              taxonomy_tags: params.taxonomy_tags ?? [],
              evidence_refs: params.evidence_refs,
              negative_control_refs: params.negative_control_refs ?? [],
              impact_refs: params.impact_refs ?? [],
              assertion_contract: {
                required: contractRequired,
                status: contractStatus,
                missing,
                suggestions,
                requested_severity: requestedSeverity,
                effective_severity: severity,
                requested_confidence: requestedConfidence,
                effective_confidence: confidence,
                positive_verification: positiveOK,
                negative_control: negativeOK,
                impact_evidence: impactOK,
                confidence_cap: confidenceCap,
              },
              cwe_id: enrichment.cweId ?? "",
              owasp_category: enrichment.owaspCategory ?? "",
            },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertEdge({
          sessionID: ctx.sessionID,
          fromNodeID: params.hypothesis_id,
          toNodeID: node.id,
          relation: "establishes",
          weight: 1,
          metadata: {
            source: "upsert_finding",
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    for (const ref of params.evidence_refs) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertEdge({
            sessionID: ctx.sessionID,
            fromNodeID: ref,
            toNodeID: node.id,
            relation: "supports",
            weight: 1,
            metadata: {
              source: "upsert_finding",
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    for (const ref of params.negative_control_refs ?? []) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertEdge({
            sessionID: ctx.sessionID,
            fromNodeID: ref,
            toNodeID: node.id,
            relation: "controls",
            weight: 1,
            metadata: {
              source: "upsert_finding",
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    for (const ref of params.impact_refs ?? []) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertEdge({
            sessionID: ctx.sessionID,
            fromNodeID: ref,
            toNodeID: node.id,
            relation: "demonstrates_impact",
            weight: 1,
            metadata: {
              source: "upsert_finding",
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    return {
      title: `Finding ${findingID}`,
      metadata: {
        findingID,
        nodeID: node.id,
        severity,
        confidence,
        assertionContract: {
          required: contractRequired,
          status: contractStatus,
          missing,
          suggestions,
          requestedSeverity,
          effectiveSeverity: severity,
        },
      } as any,
      envelope: makeToolResultEnvelope({
        status: contractStatus === "complete" ? "ok" : "inconclusive",
        observations: [
          {
            type: "finding",
            finding_id: findingID,
            finding_node_id: node.id,
            severity,
            confidence,
          },
        ],
        verifications: [
          {
            type: "assertion_contract",
            required: contractRequired,
            status: contractStatus,
            missing: missing.join(","),
            requested_severity: requestedSeverity,
            effective_severity: severity,
          },
        ],
        links: [
          {
            relation: "establishes",
            from_node_id: params.hypothesis_id,
            to_node_id: node.id,
          },
          ...params.evidence_refs.map((item) => ({
            relation: "supports",
            from_node_id: item,
            to_node_id: node.id,
          })),
          ...(params.negative_control_refs ?? []).map((item) => ({
            relation: "controls",
            from_node_id: item,
            to_node_id: node.id,
          })),
          ...(params.impact_refs ?? []).map((item) => ({
            relation: "demonstrates_impact",
            from_node_id: item,
            to_node_id: node.id,
          })),
        ],
        metrics: {
          assertion_contract_missing: missing.length,
          assertion_contract_complete: contractStatus === "complete" ? 1 : 0,
        },
      }),
      output: [
        `Finding ID: ${findingID}`,
        `Finding node: ${node.id}`,
        `Severity: ${severity}`,
        `Confidence: ${confidence}`,
        `Evidence refs: ${params.evidence_refs.length}`,
        `Assertion contract: ${contractStatus}`,
        missing.length > 0 ? `Missing checks: ${missing.join(", ")}` : "Missing checks: none",
      ].join("\n"),
    }
  },
})
