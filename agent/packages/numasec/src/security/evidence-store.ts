import { createHash } from "crypto"
import { and, eq } from "drizzle-orm"
import { Effect, Layer, Schema, ServiceMap } from "effect"
import { Database } from "../storage/db"
import {
  EvidenceEdgeTable,
  EvidenceNodeTable,
  EvidenceRunTable,
} from "./evidence.sql"
import type { SessionID } from "../session/schema"
import { canonicalSecuritySessionID } from "./security-session"

export class EvidenceGraphStoreError extends Schema.TaggedErrorClass<EvidenceGraphStoreError>()(
  "EvidenceGraphStoreError",
  {
    message: Schema.String,
    cause: Schema.Unknown,
  },
) {}

export type EvidenceNodeRow = (typeof EvidenceNodeTable)["$inferSelect"]
export type EvidenceEdgeRow = (typeof EvidenceEdgeTable)["$inferSelect"]
export type EvidenceRunRow = (typeof EvidenceRunTable)["$inferSelect"]
type EvidenceNodeID = (typeof EvidenceNodeTable)["$inferInsert"]["id"]
type EvidenceEdgeID = (typeof EvidenceEdgeTable)["$inferInsert"]["id"]
type EvidenceRunID = (typeof EvidenceRunTable)["$inferInsert"]["id"]

type DbClient = Parameters<typeof Database.use>[0] extends (db: infer T) => unknown ? T : never
type DbTransactionCallback<A> = Parameters<typeof Database.transaction<A>>[0]

function stableEncode(input: unknown): string {
  if (input === null) return "null"
  if (input === undefined) return "undefined"
  if (typeof input !== "object") return JSON.stringify(input)
  if (Array.isArray(input)) {
    const items: string[] = []
    for (const item of input) {
      items.push(stableEncode(item))
    }
    return `[${items.join(",")}]`
  }
  const value = input as Record<string, unknown>
  const keys = Object.keys(value).sort()
  const items: string[] = []
  for (const key of keys) {
    items.push(`${JSON.stringify(key)}:${stableEncode(value[key])}`)
  }
  return `{${items.join(",")}}`
}

export function createEvidenceFingerprint(input: unknown): string {
  const value = stableEncode(input)
  return createHash("sha256").update(value).digest("hex")
}

function createNodeID(sessionID: SessionID, type: string, fingerprint: string): string {
  const value = `${sessionID}:${type}:${fingerprint}`
  const hash = createHash("sha256").update(value).digest("hex").slice(0, 16).toUpperCase()
  return `ENOD-${hash}`
}

function createEdgeID(sessionID: SessionID, fromNodeID: string, toNodeID: string, relation: string): EvidenceEdgeID {
  const value = `${sessionID}:${fromNodeID}:${toNodeID}:${relation}`
  const hash = createHash("sha256").update(value).digest("hex").slice(0, 16).toUpperCase()
  return `EEDG-${hash}` as EvidenceEdgeID
}

function nodeID(value: string): EvidenceNodeID {
  return value as EvidenceNodeID
}

function edgeID(value: string): EvidenceEdgeID {
  return value as EvidenceEdgeID
}

function runID(value: string): EvidenceRunID {
  return value as EvidenceRunID
}

export namespace EvidenceGraphStore {
  export interface UpsertNodeInput {
    sessionID: SessionID
    type: string
    payload: Record<string, unknown>
    sourceTool?: string
    confidence?: number
    status?: string
    fingerprint?: string
  }

  export interface UpsertEdgeInput {
    sessionID: SessionID
    fromNodeID: string
    toNodeID: string
    relation: string
    weight?: number
    metadata?: Record<string, unknown>
  }

  export interface UpsertRunInput {
    id: string
    sessionID: SessionID
    plannerState: string
    hypothesisID: string
    status: string
    attempts: number
    notes?: Record<string, unknown>
  }

  export interface SupersedeNodeInput {
    sessionID: SessionID
    supersededNodeID: string
    supersedingNodeID: string
    reason?: string
  }

  export interface Service {
    readonly upsertNode: (input: UpsertNodeInput) => Effect.Effect<EvidenceNodeRow, EvidenceGraphStoreError>
    readonly upsertEdge: (input: UpsertEdgeInput) => Effect.Effect<EvidenceEdgeRow, EvidenceGraphStoreError>
    readonly supersedeNode: (input: SupersedeNodeInput) => Effect.Effect<EvidenceEdgeRow, EvidenceGraphStoreError>
    readonly upsertRun: (input: UpsertRunInput) => Effect.Effect<EvidenceRunRow, EvidenceGraphStoreError>
    readonly listNodes: (sessionID: SessionID) => Effect.Effect<EvidenceNodeRow[], EvidenceGraphStoreError>
    readonly listEdges: (sessionID: SessionID) => Effect.Effect<EvidenceEdgeRow[], EvidenceGraphStoreError>
  }
}

export class EvidenceGraphStore extends ServiceMap.Service<EvidenceGraphStore, EvidenceGraphStore.Service>()(
  "@numasec/EvidenceGraphStore",
) {
  static readonly layer: Layer.Layer<EvidenceGraphStore> = Layer.effect(
    EvidenceGraphStore,
    Effect.gen(function* () {
      const query = <A>(f: DbTransactionCallback<A>) =>
        Effect.try({
          try: () => Database.use(f),
          catch: (cause) => new EvidenceGraphStoreError({ message: "Database operation failed", cause }),
        })

      const upsertNode = Effect.fn("EvidenceGraphStore.upsertNode")((input: EvidenceGraphStore.UpsertNodeInput) =>
        query((db: DbClient) => {
          const sessionID = canonicalSecuritySessionID(input.sessionID)
          const fingerprint = input.fingerprint ?? createEvidenceFingerprint({ type: input.type, payload: input.payload })
          const id = createNodeID(sessionID, input.type, fingerprint)
          db
            .insert(EvidenceNodeTable)
            .values({
              id: nodeID(id),
              session_id: sessionID,
              type: input.type,
              fingerprint,
              status: input.status ?? "active",
              confidence: input.confidence ?? 0.5,
              payload: input.payload,
              source_tool: input.sourceTool ?? "",
            })
            .onConflictDoUpdate({
              target: [EvidenceNodeTable.session_id, EvidenceNodeTable.type, EvidenceNodeTable.fingerprint],
              set: {
                status: input.status ?? "active",
                confidence: input.confidence ?? 0.5,
                payload: input.payload,
                source_tool: input.sourceTool ?? "",
                time_updated: Date.now(),
              },
            })
            .run()

          const row = db
            .select()
            .from(EvidenceNodeTable)
            .where(
              and(
                eq(EvidenceNodeTable.session_id, sessionID),
                eq(EvidenceNodeTable.type, input.type),
                eq(EvidenceNodeTable.fingerprint, fingerprint),
              ),
            )
            .get()
          if (row) return row
          throw new Error("Evidence node not found after upsert")
        }),
      )

      const upsertEdge = Effect.fn("EvidenceGraphStore.upsertEdge")((input: EvidenceGraphStore.UpsertEdgeInput) =>
        query((db: DbClient) => {
          const sessionID = canonicalSecuritySessionID(input.sessionID)
          const id = createEdgeID(sessionID, input.fromNodeID, input.toNodeID, input.relation)
          db
            .insert(EvidenceEdgeTable)
            .values({
              id: edgeID(id),
              session_id: sessionID,
              from_node_id: nodeID(input.fromNodeID),
              to_node_id: nodeID(input.toNodeID),
              relation: input.relation,
              weight: input.weight ?? 1,
              metadata: input.metadata ?? {},
            })
            .onConflictDoUpdate({
              target: [
                EvidenceEdgeTable.session_id,
                EvidenceEdgeTable.from_node_id,
                EvidenceEdgeTable.to_node_id,
                EvidenceEdgeTable.relation,
              ],
              set: {
                weight: input.weight ?? 1,
                metadata: input.metadata ?? {},
                time_updated: Date.now(),
              },
            })
            .run()

          const row = db
            .select()
            .from(EvidenceEdgeTable)
            .where(
              and(
                eq(EvidenceEdgeTable.session_id, sessionID),
                eq(EvidenceEdgeTable.from_node_id, nodeID(input.fromNodeID)),
                eq(EvidenceEdgeTable.to_node_id, nodeID(input.toNodeID)),
                eq(EvidenceEdgeTable.relation, input.relation),
              ),
            )
            .get()
          if (row) return row
          throw new Error("Evidence edge not found after upsert")
        }),
      )

      const supersedeNode = Effect.fn("EvidenceGraphStore.supersedeNode")((input: EvidenceGraphStore.SupersedeNodeInput) =>
        Effect.gen(function* () {
          const sessionID = canonicalSecuritySessionID(input.sessionID)
          const reason = input.reason ?? ""
          const edge = yield* upsertEdge({
            sessionID,
            fromNodeID: input.supersedingNodeID,
            toNodeID: input.supersededNodeID,
            relation: "supersedes",
            metadata: { reason },
            weight: 1,
          })

          yield* query((db: DbClient) =>
            db
              .update(EvidenceNodeTable)
              .set({
                status: "superseded",
                invalidated_at: Date.now(),
                invalidation_reason: reason,
              })
              .where(
                and(
                  eq(EvidenceNodeTable.session_id, sessionID),
                  eq(EvidenceNodeTable.id, nodeID(input.supersededNodeID)),
                ),
              )
              .run(),
          ).pipe(Effect.asVoid)

          return edge
        }),
      )

      const upsertRun = Effect.fn("EvidenceGraphStore.upsertRun")((input: EvidenceGraphStore.UpsertRunInput) =>
        query((db: DbClient) => {
          const sessionID = canonicalSecuritySessionID(input.sessionID)
          db
            .insert(EvidenceRunTable)
            .values({
              id: runID(input.id),
              session_id: sessionID,
              planner_state: input.plannerState,
              hypothesis_id: input.hypothesisID,
              status: input.status,
              attempts: input.attempts,
              notes: input.notes ?? {},
            })
            .onConflictDoUpdate({
              target: EvidenceRunTable.id,
              set: {
                planner_state: input.plannerState,
                hypothesis_id: input.hypothesisID,
                status: input.status,
                attempts: input.attempts,
                notes: input.notes ?? {},
                time_updated: Date.now(),
              },
            })
            .run()

          const row = db.select().from(EvidenceRunTable).where(eq(EvidenceRunTable.id, runID(input.id))).get()
          if (row) return row
          throw new Error("Evidence run not found after upsert")
        }),
      )

      const listNodes = Effect.fn("EvidenceGraphStore.listNodes")((sessionID: SessionID) =>
        query((db: DbClient) =>
          db
            .select()
            .from(EvidenceNodeTable)
            .where(eq(EvidenceNodeTable.session_id, canonicalSecuritySessionID(sessionID)))
            .all(),
        ),
      )

      const listEdges = Effect.fn("EvidenceGraphStore.listEdges")((sessionID: SessionID) =>
        query((db: DbClient) =>
          db
            .select()
            .from(EvidenceEdgeTable)
            .where(eq(EvidenceEdgeTable.session_id, canonicalSecuritySessionID(sessionID)))
            .all(),
        ),
      )

      return EvidenceGraphStore.of({
        upsertNode,
        upsertEdge,
        supersedeNode,
        upsertRun,
        listNodes,
        listEdges,
      })
    }),
  )
}
