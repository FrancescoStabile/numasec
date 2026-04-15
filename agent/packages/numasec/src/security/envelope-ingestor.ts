import { Effect } from "effect"
import type { SessionID } from "../session/schema"
import { DEFAULT_INLINE_BYTES, encodeArtifactPayload, makeArtifactReference, persistEvidenceArtifact, shouldPersistArtifact } from "./artifact-store"
import { EvidenceGraphStore, createEvidenceFingerprint } from "./evidence-store"
import type { ToolResultEnvelope } from "./tool/result-envelope"

type Item = Record<string, any>

export type IngestedToolEnvelope = {
  artifacts: number
  observations: number
  verifications: number
  external: number
  artifactNodeIDs: string[]
  observationNodeIDs: string[]
  verificationNodeIDs: string[]
  nodeIDsByKey: Record<string, string>
}

function key(kind: string, item: Item, index: number) {
  const value = item.key
  if (typeof value === "string" && value.length > 0) return value
  return `${kind}:${index}`
}

function relation(kind: string) {
  if (kind === "verification") return "verifies"
  return "observes"
}

function nodeType(kind: string) {
  if (kind === "artifact") return "artifact"
  if (kind === "verification") return "verification"
  return "observation"
}

function status(kind: string, item: Item) {
  if (typeof item.status === "string" && item.status.length > 0) return item.status
  if (kind === "verification") return item.passed === true ? "confirmed" : "open"
  return "active"
}

function confidence(item: Item) {
  if (typeof item.confidence === "number") return item.confidence
  return 0.7
}

function resolve(map: Map<string, string>, item: Item, fieldKey: string, fieldNode: string) {
  const value = item[fieldNode]
  if (typeof value === "string" && value.length > 0) return value
  const ref = item[fieldKey]
  if (typeof ref === "string" && ref.length > 0) return map.get(ref) ?? ""
  return ""
}

async function maybeExternalize(sessionID: SessionID, tool: string, payload: Record<string, unknown>) {
  const text = encodeArtifactPayload(payload)
  const bytes = new TextEncoder().encode(text).length
  if (!shouldPersistArtifact(bytes, "auto", DEFAULT_INLINE_BYTES)) {
    return {
      payload,
      stored: false,
    }
  }
  const artifact = await persistEvidenceArtifact({
    sessionID,
    payload,
    sourceTool: tool,
  })
  return {
    payload: {
      artifact: makeArtifactReference(artifact),
      schema_version: "tool_envelope_ref_v1",
      payload_preview: artifact.preview,
    },
    stored: true,
  }
}

async function upsert(
  sessionID: SessionID,
  tool: string,
  kindValue: string,
  item: Item,
  index: number,
  title: string,
  metadata: Record<string, unknown>,
) {
  const local = key(kindValue, item, index)
  const base = {
    ...item,
    schema_version: "tool_envelope_v1",
    envelope_kind: kindValue,
    tool,
    tool_title: title,
    tool_metadata: metadata,
  }
  const stored = await maybeExternalize(sessionID, tool, base)
  const fingerprint = typeof item.fingerprint === "string" && item.fingerprint.length > 0
    ? item.fingerprint
    : createEvidenceFingerprint({
        tool,
        kind: kindValue,
        item: base,
      })
  const row = Effect.runSync(
    EvidenceGraphStore.use((store) =>
      store.upsertNode({
        sessionID,
        type: nodeType(kindValue),
        payload: stored.payload,
        fingerprint,
        sourceTool: tool,
        confidence: confidence(item),
        status: status(kindValue, item),
      }),
    ).pipe(Effect.provide(EvidenceGraphStore.layer)),
  )
  return {
    key: local,
    row,
    stored: stored.stored,
  }
}

export async function ingestToolEnvelope(input: {
  sessionID: SessionID
  tool: string
  title: string
  metadata?: Record<string, unknown>
  envelope: ToolResultEnvelope
}): Promise<IngestedToolEnvelope> {
  const map = new Map<string, string>()
  const meta = input.metadata ?? {}
  let artifacts = 0
  let observations = 0
  let verifications = 0
  let external = 0
  const artifactNodeIDs: string[] = []
  const observationNodeIDs: string[] = []
  const verificationNodeIDs: string[] = []

  const register = async (kindValue: "artifact" | "observation" | "verification", list: Item[]) => {
    let index = 0
    for (const item of list) {
      const node = await upsert(input.sessionID, input.tool, kindValue, item, index++, input.title, meta)
      map.set(node.key, node.row.id)
      if (node.stored) external += 1
      if (kindValue === "artifact") {
        artifacts += 1
        artifactNodeIDs.push(node.row.id)
      }
      if (kindValue === "observation") {
        observations += 1
        observationNodeIDs.push(node.row.id)
      }
      if (kindValue === "verification") {
        verifications += 1
        verificationNodeIDs.push(node.row.id)
      }
    }
  }

  await register("artifact", input.envelope.artifacts)
  await register("observation", input.envelope.observations)
  await register("verification", input.envelope.verifications)

  const link = (fromNodeID: string, toNodeID: string, kindValue: string, item: Item) =>
    Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertEdge({
          sessionID: input.sessionID,
          fromNodeID,
          toNodeID,
          relation: kindValue,
          weight: typeof item.weight === "number" ? item.weight : 1,
          metadata: typeof item.metadata === "object" && item.metadata && !Array.isArray(item.metadata) ? item.metadata : {},
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

  const all = [
    ...input.envelope.artifacts.map((item, index) => ({ kind: "artifact", item, key: key("artifact", item, index) })),
    ...input.envelope.observations.map((item, index) => ({ kind: "observation", item, key: key("observation", item, index) })),
    ...input.envelope.verifications.map((item, index) => ({ kind: "verification", item, key: key("verification", item, index) })),
  ]

  for (const entry of all) {
    const nodeID = map.get(entry.key) ?? ""
    if (!nodeID) continue
    const hypothesisID = typeof entry.item.hypothesis_id === "string" ? entry.item.hypothesis_id : ""
    if (hypothesisID) {
      link(hypothesisID, nodeID, typeof entry.item.relation === "string" && entry.item.relation.length > 0 ? entry.item.relation : relation(entry.kind), entry.item)
    }
    const parentNodeID = resolve(map, entry.item, "parent_key", "parent_node_id")
    if (parentNodeID) {
      link(parentNodeID, nodeID, typeof entry.item.parent_relation === "string" && entry.item.parent_relation.length > 0 ? entry.item.parent_relation : "derives", entry.item)
    }
    if (entry.kind === "verification") {
      const evidenceKeys = Array.isArray(entry.item.evidence_keys) ? entry.item.evidence_keys : []
      for (const value of evidenceKeys) {
        if (typeof value !== "string") continue
        const fromNodeID = map.get(value) ?? ""
        if (!fromNodeID) continue
        link(fromNodeID, nodeID, "supports", entry.item)
      }
      const evidenceNodeIDs = Array.isArray(entry.item.evidence_node_ids) ? entry.item.evidence_node_ids : []
      for (const value of evidenceNodeIDs) {
        if (typeof value !== "string" || value.length === 0) continue
        link(value, nodeID, "supports", entry.item)
      }
    }
  }

  for (const item of input.envelope.links) {
    const fromNodeID = resolve(map, item, "from_key", "from_node_id")
    const toNodeID = resolve(map, item, "to_key", "to_node_id")
    const kindValue = typeof item.relation === "string" && item.relation.length > 0 ? item.relation : "relates"
    if (!fromNodeID || !toNodeID) continue
    link(fromNodeID, toNodeID, kindValue, item)
  }

  return {
    artifacts,
    observations,
    verifications,
    external,
    artifactNodeIDs,
    observationNodeIDs,
    verificationNodeIDs,
    nodeIDsByKey: Object.fromEntries(map.entries()),
  }
}
