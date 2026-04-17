import z from "zod"
import { Effect } from "effect"
import { and, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { EvidenceGraphStore } from "../evidence-store"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Create or update a hypothesis node in the evidence graph.
Use this primitive to keep hypothesis lifecycle explicit and traceable.`

export const UpsertHypothesisTool = Tool.define("upsert_hypothesis", {
  description: DESCRIPTION,
  parameters: z.object({
    statement: z.string().describe("Human-readable hypothesis statement"),
    predicate: z.string().describe("Testable predicate representation"),
    asset_ref: z.string().optional().describe("Optional target asset reference"),
    tags: z.array(z.string()).optional().describe("Optional hypothesis tags"),
    confidence: z.number().min(0).max(1).optional().describe("Hypothesis confidence"),
    status: z.string().optional().describe("Hypothesis status (open, probing, refuted, confirmed)"),
    hypothesis_id: z.string().optional().describe("Optional deterministic hypothesis identifier"),
    supersedes_node_id: z.string().optional().describe("Existing hypothesis node superseded by this one"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const hypotheses = params.hypothesis_id
      ? Database.use((db) =>
          db
            .select({
              id: EvidenceNodeTable.id,
              fingerprint: EvidenceNodeTable.fingerprint,
            })
            .from(EvidenceNodeTable)
            .where(
              and(
                eq(EvidenceNodeTable.session_id, sessionID),
                eq(EvidenceNodeTable.type, "hypothesis"),
              ),
            )
            .all(),
        )
      : undefined
    const existing = hypotheses?.find((item) => item.id === params.hypothesis_id || item.fingerprint === params.hypothesis_id)
    const row = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID,
          type: "hypothesis",
          confidence: params.confidence ?? 0.3,
          status: params.status ?? "open",
          fingerprint: existing?.fingerprint ?? params.hypothesis_id,
          payload: {
            statement: params.statement,
            predicate: params.predicate,
            asset_ref: params.asset_ref ?? "",
            tags: params.tags ?? [],
            hypothesis_id: existing?.id ?? params.hypothesis_id ?? "",
          },
          sourceTool: "upsert_hypothesis",
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    const superseded = params.supersedes_node_id
    if (superseded && superseded !== row.id) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.supersedeNode({
            sessionID,
            supersededNodeID: superseded,
            supersedingNodeID: row.id,
            reason: "hypothesis revision",
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    return {
      title: `Hypothesis ${row.id}`,
      metadata: {
        nodeID: row.id,
        fingerprint: row.fingerprint,
        status: row.status,
        confidence: row.confidence,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "hypothesis",
            hypothesis_node_id: row.id,
            status: row.status,
            confidence: row.confidence,
          },
        ],
      }),
      output: [
        `Hypothesis node: ${row.id}`,
        `Status: ${row.status}`,
        `Confidence: ${row.confidence}`,
        `Statement: ${params.statement}`,
      ].join("\n"),
    }
  },
})
