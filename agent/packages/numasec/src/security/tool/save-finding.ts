/**
 * Tool: save_finding
 *
 * Persist a security finding with auto-enrichment (CWE, CVSS, OWASP).
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { EvidenceGraphStore } from "../evidence-store"
import { Effect } from "effect"
import { UpsertFindingTool } from "./upsert-finding"

const DESCRIPTION = `Save a security finding. Auto-enriches with CWE, CVSS 3.1, OWASP category, and MITRE ATT&CK.
Call this IMMEDIATELY when you discover a vulnerability — don't wait until the end.

The finding gets a deterministic per-session ID based on method+url+parameter+title (dedup-safe within a run).
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
    const hypothesis = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
          type: "hypothesis",
          sourceTool: "save_finding",
          confidence: Math.max(0.2, Math.min(0.9, params.confidence)),
          status: params.confirmed ? "confirmed" : "open",
          payload: {
            statement: params.title,
            predicate: params.description,
            asset_ref: params.url,
            legacy_tool: "save_finding",
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    const artifact = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
          type: "artifact",
          sourceTool: params.tool_used || "save_finding",
          confidence: Math.max(0.2, params.confidence),
          status: "active",
          payload: {
            evidence: params.evidence,
            url: params.url,
            method: params.method,
            parameter: params.parameter,
            payload: params.payload,
            remediation: params.remediation,
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    const verification = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
          type: "verification",
          sourceTool: "save_finding",
          confidence: Math.max(0.2, params.confidence),
          status: params.confirmed || params.confidence >= 0.8 ? "confirmed" : "open",
          payload: {
            predicate: params.title,
            control: "positive",
            passed: params.confirmed || params.confidence >= 0.8,
            evidence_refs: [artifact.id],
            reason: "legacy save_finding wrapper verification",
          },
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    const impl = await UpsertFindingTool.init()
    const out = await impl.execute(
      {
        hypothesis_id: hypothesis.id,
        title: params.title,
        severity: params.severity,
        impact: params.description,
        evidence_refs: [verification.id],
        impact_refs: [artifact.id],
        confidence: params.confidence,
        status: params.confirmed ? "confirmed" : "active",
        url: params.url,
        method: params.method,
        parameter: params.parameter,
        payload: params.payload,
        tool_used: params.tool_used || "save_finding",
        remediation: params.remediation,
      } as never,
      ctx,
    )

    const findingID = typeof (out.metadata as any).findingID === "string" ? (out.metadata as any).findingID : ""
    const severity = typeof (out.metadata as any).severity === "string" ? (out.metadata as any).severity : params.severity

    return {
      title: `✓ Saved: ${params.title} (${String(severity).toLowerCase()})`,
      metadata: {
        id: findingID,
        severity,
        wrappedBy: "save_finding",
        assertionContract: (out.metadata as any).assertionContract ?? {},
      } as any,
      envelope: out.envelope,
      output: out.output,
    }
  },
})
