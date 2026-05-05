import { appendFile, mkdir, readFile, writeFile } from "fs/promises"
import path from "path"
import { CyberFactTable, CyberLedgerTable, CyberRelationTable } from "@/core/cyber/cyber.sql"
import { Instance } from "@/project/instance"
import { and, Database, desc, eq } from "@/storage"
import { Event, type Severity, type Status, type Subtype } from "./events"
import { project, severityCounts, type Observation } from "./info"

const FILE = "observations.jsonl"
const SNAP = "observations.json"

function obsDir(workspace: string, slug: string) {
  return path.join(workspace, ".numasec", "operation", slug)
}

async function readEvents(workspace: string, slug: string): Promise<Event[]> {
  const p = path.join(obsDir(workspace, slug), FILE)
  const raw = await readFile(p, "utf8").catch(() => "")
  if (!raw) return []
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => Event.parse(JSON.parse(l)))
}

async function append(workspace: string, slug: string, event: Event): Promise<void> {
  const dir = obsDir(workspace, slug)
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, FILE), JSON.stringify(event) + "\n", "utf8")
  const items = project(await readEvents(workspace, slug))
  await writeFile(
    path.join(dir, SNAP),
    JSON.stringify({ items, counts: severityCounts(items) }, null, 2),
    "utf8",
  )
}

function projectionDir(workspace: string, slug: string) {
  return path.join(obsDir(workspace, slug), "cyber")
}

async function appendProjectionLine(
  workspace: string,
  slug: string,
  filename: string,
  record: Record<string, unknown>,
) {
  const dir = projectionDir(workspace, slug)
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, filename), JSON.stringify(record) + "\n", "utf8")
}

function makeID(prefix: string) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
}

function cyberStatus(status: Status): "observed" | "verified" | "rejected" | "stale" {
  if (status === "confirmed") return "verified"
  if (status === "false-positive") return "rejected"
  if (status === "resolved") return "stale"
  return "observed"
}

function parseProjectedObservation(value: unknown, idHint?: string): Observation | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  if (input.removed) return undefined
  const id = typeof input.id === "string" ? input.id : idHint
  const subtype = input.subtype
  const title = input.title
  const status = input.status
  if (!id) return undefined
  if (
    subtype !== "vuln" &&
    subtype !== "code-smell" &&
    subtype !== "intel-fact" &&
    subtype !== "flag" &&
    subtype !== "ioc" &&
    subtype !== "control-gap" &&
    subtype !== "risk"
  ) return undefined
  if (typeof title !== "string" || !title) return undefined
  if (
    status !== "open" &&
    status !== "triaged" &&
    status !== "confirmed" &&
    status !== "resolved" &&
    status !== "false-positive"
  ) return undefined
  return {
    id,
    subtype,
    title,
    severity:
      input.severity === "info" ||
      input.severity === "low" ||
      input.severity === "medium" ||
      input.severity === "high" ||
      input.severity === "critical"
        ? input.severity
        : undefined,
    confidence: typeof input.confidence === "number" ? input.confidence : undefined,
    status,
    note: typeof input.note === "string" ? input.note : undefined,
    tags: Array.isArray(input.tags) ? input.tags.filter((item): item is string => typeof item === "string") : [],
    evidence: Array.isArray(input.evidence)
      ? input.evidence.filter((item): item is string => typeof item === "string")
      : [],
    created_at: typeof input.created_at === "number" ? input.created_at : 0,
    updated_at: typeof input.updated_at === "number" ? input.updated_at : 0,
  }
}

async function appendObservationProjection(
  workspace: string,
  slug: string,
  observation: Observation,
  summary: string,
) {
  await Instance.provide({
    directory: workspace,
    fn: async () => {
      const now = Date.now()
      const projectID = Instance.project.id
      const eventID = makeID("cled")
      Database.use((db) =>
        db
          .insert(CyberLedgerTable)
          .values({
            id: eventID,
            project_id: projectID,
            operation_slug: slug,
            kind: observation.status === "confirmed" ? "fact.verified" : "fact.observed",
            source: "observation",
            status: observation.status,
            summary,
            evidence_refs: observation.evidence,
            data: {
              id: observation.id,
              subtype: observation.subtype,
              title: observation.title,
              severity: observation.severity ?? null,
              confidence: observation.confidence ?? null,
              status: observation.status,
              note: observation.note ?? null,
              tags: observation.tags,
              evidence: observation.evidence,
              created_at: observation.created_at,
              updated_at: observation.updated_at,
            },
            time_created: now,
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "ledger.jsonl", {
        id: eventID,
        project_id: projectID,
        operation_slug: slug,
        kind: observation.status === "confirmed" ? "fact.verified" : "fact.observed",
        source: "observation",
        status: observation.status,
        summary,
        evidence_refs: observation.evidence,
        data: {
          id: observation.id,
          subtype: observation.subtype,
          title: observation.title,
          severity: observation.severity ?? null,
          confidence: observation.confidence ?? null,
          status: observation.status,
          note: observation.note ?? null,
          tags: observation.tags,
          evidence: observation.evidence,
          created_at: observation.created_at,
          updated_at: observation.updated_at,
        },
        time_created: now,
      })
      const factID = makeID("cfct")
      Database.use((db) =>
        db
          .insert(CyberFactTable)
          .values({
            id: factID,
            project_id: projectID,
            operation_slug: slug,
            entity_kind: "observation",
            entity_key: observation.id,
            fact_name: "record",
            value_json: {
              id: observation.id,
              subtype: observation.subtype,
              title: observation.title,
              severity: observation.severity,
              confidence: observation.confidence,
              status: observation.status,
              note: observation.note,
              tags: observation.tags,
              evidence: observation.evidence,
              created_at: observation.created_at,
              updated_at: observation.updated_at,
            },
            writer_kind: "tool",
            status: cyberStatus(observation.status),
            confidence: observation.confidence != null ? Math.round(observation.confidence * 1000) : 1000,
            source_event_id: eventID,
            evidence_refs: observation.evidence,
            time_created: now,
            time_updated: now,
          })
          .onConflictDoUpdate({
            target: [
              CyberFactTable.project_id,
              CyberFactTable.operation_slug,
              CyberFactTable.entity_kind,
              CyberFactTable.entity_key,
              CyberFactTable.fact_name,
            ],
            set: {
              value_json: {
                id: observation.id,
                subtype: observation.subtype,
                title: observation.title,
                severity: observation.severity,
                confidence: observation.confidence,
                status: observation.status,
                note: observation.note,
                tags: observation.tags,
                evidence: observation.evidence,
                created_at: observation.created_at,
                updated_at: observation.updated_at,
              },
              writer_kind: "tool",
              status: cyberStatus(observation.status),
              confidence: observation.confidence != null ? Math.round(observation.confidence * 1000) : 1000,
              source_event_id: eventID,
              evidence_refs: observation.evidence,
              time_updated: now,
            },
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "facts.jsonl", {
        id: factID,
        project_id: projectID,
        operation_slug: slug,
        entity_kind: "observation",
        entity_key: observation.id,
        fact_name: "record",
        value_json: {
          id: observation.id,
          subtype: observation.subtype,
          title: observation.title,
          severity: observation.severity,
          confidence: observation.confidence,
          status: observation.status,
          note: observation.note,
          tags: observation.tags,
          evidence: observation.evidence,
          created_at: observation.created_at,
          updated_at: observation.updated_at,
        },
        writer_kind: "tool",
        status: cyberStatus(observation.status),
        confidence: observation.confidence != null ? Math.round(observation.confidence * 1000) : 1000,
        source_event_id: eventID,
        evidence_refs: observation.evidence,
        time_created: now,
        time_updated: now,
      })
    },
  })
}

async function markObservationRemoved(workspace: string, slug: string, id: string) {
  await Instance.provide({
    directory: workspace,
    fn: async () => {
      const now = Date.now()
      const projectID = Instance.project.id
      const eventID = makeID("cled")
      Database.use((db) =>
        db
          .insert(CyberLedgerTable)
          .values({
            id: eventID,
            project_id: projectID,
            operation_slug: slug,
            kind: "fact.observed",
            source: "observation",
            status: "removed",
            summary: `observation removed ${id}`,
            data: { id, removed: true },
            time_created: now,
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "ledger.jsonl", {
        id: eventID,
        project_id: projectID,
        operation_slug: slug,
        kind: "fact.observed",
        source: "observation",
        status: "removed",
        summary: `observation removed ${id}`,
        data: { id, removed: true },
        time_created: now,
      })
      const factID = makeID("cfct")
      Database.use((db) =>
        db
          .insert(CyberFactTable)
          .values({
            id: factID,
            project_id: projectID,
            operation_slug: slug,
            entity_kind: "observation",
            entity_key: id,
            fact_name: "record",
            value_json: { id, removed: true },
            writer_kind: "tool",
            status: "stale",
            confidence: 1000,
            source_event_id: eventID,
            time_created: now,
            time_updated: now,
          })
          .onConflictDoUpdate({
            target: [
              CyberFactTable.project_id,
              CyberFactTable.operation_slug,
              CyberFactTable.entity_kind,
              CyberFactTable.entity_key,
              CyberFactTable.fact_name,
            ],
            set: {
              value_json: { id, removed: true },
              writer_kind: "tool",
              status: "stale",
              confidence: 1000,
              source_event_id: eventID,
              time_updated: now,
            },
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "facts.jsonl", {
        id: factID,
        project_id: projectID,
        operation_slug: slug,
        entity_kind: "observation",
        entity_key: id,
        fact_name: "record",
        value_json: { id, removed: true },
        writer_kind: "tool",
        status: "stale",
        confidence: 1000,
        source_event_id: eventID,
        time_created: now,
        time_updated: now,
      })
    },
  })
}

async function linkObservationEvidenceProjection(
  workspace: string,
  slug: string,
  observationID: string,
  evidence: string,
) {
  await Instance.provide({
    directory: workspace,
    fn: async () => {
      const now = Date.now()
      const projectID = Instance.project.id
      const eventID = makeID("cled")
      Database.use((db) =>
        db
          .insert(CyberLedgerTable)
          .values({
            id: eventID,
            project_id: projectID,
            operation_slug: slug,
            kind: "relation.observed",
            source: "observation",
            status: "linked",
            summary: `observation evidence ${observationID} -> ${evidence}`,
            evidence_refs: [evidence],
            data: { observation_id: observationID, evidence },
            time_created: now,
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "ledger.jsonl", {
        id: eventID,
        project_id: projectID,
        operation_slug: slug,
        kind: "relation.observed",
        source: "observation",
        status: "linked",
        summary: `observation evidence ${observationID} -> ${evidence}`,
        evidence_refs: [evidence],
        data: { observation_id: observationID, evidence },
        time_created: now,
      })
      const relationID = makeID("crel")
      Database.use((db) =>
        db
          .insert(CyberRelationTable)
          .values({
            id: relationID,
            project_id: projectID,
            operation_slug: slug,
            src_kind: "observation",
            src_key: observationID,
            relation: "supported_by",
            dst_kind: "evidence_artifact",
            dst_key: evidence,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID,
            evidence_refs: [evidence],
            time_created: now,
            time_updated: now,
          })
          .onConflictDoUpdate({
            target: [
              CyberRelationTable.project_id,
              CyberRelationTable.operation_slug,
              CyberRelationTable.src_kind,
              CyberRelationTable.src_key,
              CyberRelationTable.relation,
              CyberRelationTable.dst_kind,
              CyberRelationTable.dst_key,
            ],
            set: {
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID,
              evidence_refs: [evidence],
              time_updated: now,
            },
          })
          .run(),
      )
      await appendProjectionLine(workspace, slug, "relations.jsonl", {
        id: relationID,
        project_id: projectID,
        operation_slug: slug,
        src_kind: "observation",
        src_key: observationID,
        relation: "supported_by",
        dst_kind: "evidence_artifact",
        dst_key: evidence,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID,
        evidence_refs: [evidence],
        time_created: now,
        time_updated: now,
      })
    },
  })
}

export async function list(workspace: string, slug: string): Promise<Observation[]> {
  return project(await readEvents(workspace, slug))
}

export async function listProjected(workspace: string, slug: string): Promise<Observation[]> {
  return await Instance.provide({
    directory: workspace,
    fn: async () => {
      const projectID = Instance.project.id
      const rows = Database.use((db) =>
        db
          .select()
          .from(CyberFactTable)
          .where(
            and(
              eq(CyberFactTable.project_id, projectID),
              eq(CyberFactTable.operation_slug, slug),
              eq(CyberFactTable.entity_kind, "observation"),
              eq(CyberFactTable.fact_name, "record"),
            ),
          )
          .orderBy(desc(CyberFactTable.time_updated))
          .all(),
      )
      const seen = new Set<string>()
      const out: Observation[] = []
      for (const row of rows) {
        if (seen.has(row.entity_key)) continue
        seen.add(row.entity_key)
        const parsed = parseProjectedObservation(row.value_json, row.entity_key)
        if (parsed) out.push(parsed)
      }
      return out.sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id))
    },
  })
}

export async function getProjected(workspace: string, slug: string, id: string): Promise<Observation | undefined> {
  const items = await listProjected(workspace, slug)
  return items.find((item) => item.id === id)
}

export async function add(
  workspace: string,
  slug: string,
  input: {
    subtype: Subtype
    title: string
    severity?: Severity
    confidence?: number
    note?: string
    tags?: string[]
    id?: string
  },
): Promise<Observation> {
  const id = input.id ?? `obs_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
  const at = Date.now()
  await append(workspace, slug, {
    type: "observation_added",
    at,
    id,
    subtype: input.subtype,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    note: input.note,
    tags: input.tags,
  })
  const observation: Observation = {
    id,
    subtype: input.subtype,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    status: "open",
    note: input.note,
    tags: input.tags ?? [],
    evidence: [],
    created_at: at,
    updated_at: at,
  }
  await appendObservationProjection(workspace, slug, observation, `observation added ${id}`)
  return observation
}

export async function update(
  workspace: string,
  slug: string,
  id: string,
  patch: {
    title?: string
    severity?: Severity
    confidence?: number
    status?: Status
    note?: string
    tags?: string[]
  },
): Promise<void> {
  await append(workspace, slug, { type: "observation_updated", at: Date.now(), id, ...patch })
  const observation = (await list(workspace, slug)).find((item) => item.id === id)
  if (!observation) return
  await appendObservationProjection(workspace, slug, observation, `observation updated ${id}`)
}

export async function remove(workspace: string, slug: string, id: string): Promise<void> {
  await append(workspace, slug, { type: "observation_removed", at: Date.now(), id })
  await markObservationRemoved(workspace, slug, id)
}

export async function linkEvidence(
  workspace: string,
  slug: string,
  id: string,
  evidence: string,
): Promise<void> {
  await append(workspace, slug, {
    type: "observation_evidence_linked",
    at: Date.now(),
    id,
    evidence,
  })
  await linkObservationEvidenceProjection(workspace, slug, id, evidence)
  const observation = (await list(workspace, slug)).find((item) => item.id === id)
  if (!observation) return
  await appendObservationProjection(workspace, slug, observation, `observation evidence linked ${id}`)
}

export { severityCounts }
export type { Observation, Severity, Status, Subtype }
