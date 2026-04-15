import z from "zod"
import { desc, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceEdgeTable, EvidenceNodeTable } from "../evidence.sql"
import { canonicalSecuritySessionID } from "../security-session"
import { UpsertFindingTool } from "./upsert-finding"

function readPayload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
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

function strings(row: (typeof EvidenceNodeTable)["$inferSelect"]) {
  const out: string[] = []
  collectText(row.payload, out)
  return out
}

function supportRows(
  row: (typeof EvidenceNodeTable)["$inferSelect"],
  map: Map<string, (typeof EvidenceNodeTable)["$inferSelect"]>,
  edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>,
) {
  const out = new Map<string, (typeof EvidenceNodeTable)["$inferSelect"]>()
  for (const edge of edges) {
    if (edge.to_node_id !== row.id) continue
    if (edge.relation !== "supports") continue
    const item = map.get(edge.from_node_id)
    if (!item) continue
    out.set(item.id, item)
  }
  const payload = readPayload(row.payload)
  const refs = Array.isArray(payload.evidence_refs) ? payload.evidence_refs : []
  for (const item of refs) {
    if (typeof item !== "string") continue
    const node = map.get(item)
    if (!node) continue
    out.set(node.id, node)
  }
  return Array.from(out.values())
}

function targetText(
  row: (typeof EvidenceNodeTable)["$inferSelect"],
  map: Map<string, (typeof EvidenceNodeTable)["$inferSelect"]>,
  edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>,
) {
  const out = strings(row)
  for (const item of supportRows(row, map, edges)) {
    out.push(...strings(item))
  }
  return out.join("\n").toLowerCase()
}

function narrow(
  list: Array<(typeof EvidenceNodeTable)["$inferSelect"]>,
  map: Map<string, (typeof EvidenceNodeTable)["$inferSelect"]>,
  edges: Array<(typeof EvidenceEdgeTable)["$inferSelect"]>,
  target: {
    url: string
    method: string
  },
) {
  if (list.length <= 1) return list
  if (!target.url && !target.method) return []
  const out = list.filter((item) => {
    const text = targetText(item, map, edges)
    if (target.url && !text.includes(target.url)) return false
    if (target.method && !text.includes(target.method)) return false
    return true
  })
  return out
}

function appendUnique(out: string[], list: string[]) {
  const known = new Set(out)
  for (const item of list) {
    if (known.has(item)) continue
    known.add(item)
    out.push(item)
  }
}

const DESCRIPTION = `Confirm a finding in one shot from recent evidence.
Auto-selects verification/control/impact evidence when not explicitly provided, then delegates to upsert_finding.`

export const ConfirmFindingTool = Tool.define("confirm_finding", {
  description: DESCRIPTION,
  parameters: z.object({
    hypothesis_id: z.string().describe("Hypothesis node id"),
    title: z.string().describe("Finding title"),
    severity: z.string().describe("Finding severity"),
    impact: z.string().describe("Business or technical impact"),
    evidence_refs: z.array(z.string()).optional().describe("Optional evidence refs; auto-suggested when omitted"),
    negative_control_refs: z.array(z.string()).optional().describe("Optional negative control refs; auto-suggested when omitted"),
    impact_refs: z.array(z.string()).optional().describe("Optional impact refs; auto-suggested when omitted"),
    lookback_limit: z.number().int().min(20).max(500).optional().describe("Recent evidence window for auto-suggestions"),
    confidence: z.number().min(0).max(1).optional(),
    status: z.string().optional(),
    target_finding_id: z.string().optional().describe("Optional existing finding id to update in place"),
    root_cause_key: z.string().optional().describe("Optional stable root cause key for update and dedup semantics"),
    strict_assertion: z.boolean().optional(),
    url: z.string().optional(),
    method: z.string().optional(),
    parameter: z.string().optional(),
    payload: z.string().optional(),
    tool_used: z.string().optional(),
    remediation: z.string().optional(),
    taxonomy_tags: z.array(z.string()).optional(),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, sessionID))
        .orderBy(desc(EvidenceNodeTable.time_updated))
        .all(),
    )
    const edges = Database.use((db) =>
      db
        .select()
        .from(EvidenceEdgeTable)
        .where(eq(EvidenceEdgeTable.session_id, sessionID))
        .all(),
    )
    const map = new Map<string, (typeof EvidenceNodeTable)["$inferSelect"]>(rows.map((item) => [item.id, item]))
    const hypothesis = map.get(params.hypothesis_id)
    const target = {
      url: String(params.url || readPayload(hypothesis?.payload).asset_ref || "").toLowerCase(),
      method: String(params.method ?? "").toLowerCase(),
    }

    const known = new Set<string>([params.hypothesis_id])
    const queue: Array<{ id: string; depth: number }> = [{ id: params.hypothesis_id, depth: 0 }]
    while (queue.length > 0) {
      const item = queue.shift()
      if (!item) continue
      if (item.depth >= 2) continue
      for (const edge of edges) {
        if (edge.from_node_id !== item.id && edge.to_node_id !== item.id) continue
        const next = edge.from_node_id === item.id ? edge.to_node_id : edge.from_node_id
        if (known.has(next)) continue
        known.add(next)
        queue.push({
          id: next,
          depth: item.depth + 1,
        })
      }
    }
    const recent = rows.slice(0, params.lookback_limit ?? 200)
    const verified = recent.filter((row) => row.status === "confirmed")
    const scoped = recent.filter((row) => known.has(row.id))
    const scopedVerified = scoped.filter((row) => row.status === "confirmed")

    const evidence = Array.from(new Set(params.evidence_refs ?? []))
    const negative = Array.from(new Set(params.negative_control_refs ?? []))
    const impact = Array.from(new Set(params.impact_refs ?? []))

    if (evidence.length === 0) {
      const candidates = scopedVerified.filter(
        (item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative",
      )
      const scoped = narrow(candidates, map, edges, target)
      const picked = scoped.length > 0 ? scoped : candidates
      if (picked.length > 0) appendUnique(evidence, picked.map((item) => item.id))
      if (picked.length === 0) {
        const fallback = verified.filter(
          (item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) !== "negative",
        )
        const narrowed = narrow(fallback, map, edges, target)
        if (narrowed.length > 0) appendUnique(evidence, narrowed.map((item) => item.id))
        if (narrowed.length === 0 && fallback.length === 1) evidence.push(fallback[0]!.id)
        if (narrowed.length === 0 && fallback.length > 1) {
          throw new Error(
            `confirm_finding found multiple positive verification candidates in session scope: ${fallback.map((item) => item.id).join(", ")}. Pass evidence_refs explicitly or provide url/method to narrow the target.`,
          )
        }
      }
    }
    if (negative.length === 0) {
      const candidates = scopedVerified.filter(
        (item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) === "negative",
      )
      const scoped = narrow(candidates, map, edges, target)
      const picked = scoped.length > 0 ? scoped : candidates
      if (picked.length > 0) appendUnique(negative, picked.map((item) => item.id))
      if (picked.length === 0) {
        const fallback = verified.filter(
          (item) => item.type === "verification" && verificationPassed(item) && verificationControl(item) === "negative",
        )
        const narrowed = narrow(fallback, map, edges, target)
        if (narrowed.length > 0) appendUnique(negative, narrowed.map((item) => item.id))
        if (narrowed.length === 0 && fallback.length === 1) negative.push(fallback[0]!.id)
        if (narrowed.length === 0 && fallback.length > 1) {
          throw new Error(
            `confirm_finding found multiple negative control candidates in session scope: ${fallback.map((item) => item.id).join(", ")}. Pass negative_control_refs explicitly or provide url/method to narrow the target.`,
          )
        }
      }
    }
    if (impact.length === 0) {
      for (const item of evidence) {
        const row = map.get(item)
        if (!row) continue
        for (const ref of supportRows(row, map, edges)) {
          if (ref.type !== "artifact" && ref.type !== "observation") continue
          impact.push(ref.id)
        }
      }
      if (impact.length === 0) {
        const candidates = narrow(
          scoped.filter((item) => item.type === "artifact" || item.type === "observation"),
          map,
          edges,
          target,
        )
        if (candidates.length === 1) impact.push(candidates[0]!.id)
      }
      if (impact.length === 0) {
        const fallback = narrow(
          recent.filter((item) => item.type === "artifact" || item.type === "observation"),
          map,
          edges,
          target,
        )
        if (fallback.length === 1) impact.push(fallback[0]!.id)
      }
    }

    if (evidence.length === 0) {
      throw new Error("confirm_finding could not auto-select positive verification evidence in hypothesis scope. Run verify_assertion with hypothesis_id/persist=true or pass evidence_refs explicitly.")
    }

    const impl = await UpsertFindingTool.init()
    const out = await impl.execute(
      {
        hypothesis_id: params.hypothesis_id,
        title: params.title,
        severity: params.severity,
        impact: params.impact,
        evidence_refs: evidence,
        negative_control_refs: negative,
        impact_refs: impact,
        taxonomy_tags: params.taxonomy_tags,
        confidence: params.confidence,
        status: params.status,
        target_finding_id: params.target_finding_id,
        root_cause_key: params.root_cause_key,
        strict_assertion: params.strict_assertion,
        url: params.url,
        method: params.method,
        parameter: params.parameter,
        payload: params.payload,
        tool_used: params.tool_used ?? "confirm_finding",
        remediation: params.remediation,
      } as never,
      ctx,
    )

    return {
      title: out.title,
      metadata: {
        ...(out.metadata as any),
        auto_selected: {
          evidence_refs: evidence,
          negative_control_refs: negative,
          impact_refs: impact,
        },
      } as any,
      envelope: out.envelope,
      output: out.output,
    }
  },
})
