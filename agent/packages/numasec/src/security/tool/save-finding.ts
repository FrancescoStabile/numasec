/**
 * Tool: save_finding
 *
 * Persist a security finding with auto-enrichment (CWE, CVSS, OWASP).
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { Database, eq, and } from "../../storage/db"
import { FindingTable, type FindingID, type TargetID } from "../security.sql"
import { enrichFinding, generateFindingId, normalizeSeverity } from "../enrichment/enrich"

const DESCRIPTION = `Save a security finding. Auto-enriches with CWE, CVSS 3.1, OWASP category, and MITRE ATT&CK.
Call this IMMEDIATELY when you discover a vulnerability — don't wait until the end.

The finding gets a deterministic ID based on method+url+parameter+title (dedup-safe).
Enrichment is automatic: you provide title/severity/description, the system adds CWE/CVSS/OWASP.

IMPORTANT: Always provide evidence (HTTP requests/responses, payloads that worked).
Without evidence, findings are unverifiable and may be dismissed as false positives.`

export const SaveFindingTool = Tool.define("save_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    title: z.string().describe("Finding title (e.g. 'SQL Injection in login parameter')"),
    severity: z.string().describe("Severity: critical, high, medium, low, info"),
    description: z.string().describe("What the vulnerability is and why it matters"),
    url: z.string().describe("Affected URL"),
    method: z.string().default("GET").describe("HTTP method"),
    parameter: z.string().default("").describe("Affected parameter"),
    payload: z.string().default("").describe("Payload that triggered the finding"),
    evidence: z.string().describe("Evidence: request/response data proving the vulnerability"),
    confidence: z.number().min(0).max(1).default(0.5).describe("Confidence score 0-1"),
    tool_used: z.string().default("").describe("Tool that found this"),
    remediation: z.string().default("").describe("Remediation advice"),
    confirmed: z.boolean().default(false).describe("Has this been confirmed/exploited?"),
  }),
  async execute(params, ctx) {
    const severity = normalizeSeverity(params.severity)
    const findingId = generateFindingId({ method: params.method, url: params.url, parameter: params.parameter, title: params.title, severity })

    // Auto-enrich
    const enrichment = enrichFinding({
      title: params.title,
      severity,
      description: params.description,
      url: params.url,
      parameter: params.parameter,
    })

    // Dedup check
    const existing = Database.use((db) =>
      db.select().from(FindingTable).where(eq(FindingTable.id, findingId)).get(),
    )

    if (existing) {
      return {
        title: `Finding already saved: ${params.title}`,
        metadata: { id: findingId, duplicate: true } as any,
        output: `Finding ${findingId} already exists. Skipping duplicate.`,
      }
    }

    // Insert
    Database.use((db) =>
      db
        .insert(FindingTable)
        .values({
          id: findingId,
          session_id: ctx.sessionID,
          title: params.title,
          severity,
          description: params.description,
          url: params.url,
          method: params.method,
          parameter: params.parameter,
          payload: params.payload,
          evidence: params.evidence,
          confidence: params.confidence,
          tool_used: params.tool_used,
          remediation_summary: params.remediation,
          confirmed: params.confirmed,
          cwe_id: enrichment.cweId ?? "",
          cvss_score: enrichment.cvssScore,
          cvss_vector: enrichment.cvssVector ?? "",
          owasp_category: enrichment.owaspCategory ?? "",
          attack_technique: enrichment.attackTechnique ?? "",
        })
        .run(),
    )

    const lines = [
      `Finding saved: ${findingId}`,
      `Title: ${params.title}`,
      `Severity: ${severity}`,
      `CWE: ${enrichment.cweId ?? "N/A"}`,
      `CVSS: ${enrichment.cvssScore?.toFixed(1) ?? "N/A"} ${enrichment.cvssVector ?? ""}`,
      `OWASP: ${enrichment.owaspCategory ?? "N/A"}`,
      `ATT&CK: ${enrichment.attackTechnique ?? "N/A"}`,
    ]

    return {
      title: `✓ Saved: ${params.title} (${severity})`,
      metadata: {
        id: findingId,
        severity,
        cwe: enrichment.cweId,
        cvss: enrichment.cvssScore,
        owasp: enrichment.owaspCategory,
      } as any,
      output: lines.join("\n"),
    }
  },
})
