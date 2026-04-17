import { appendFile, mkdir, readFile, writeFile } from "fs/promises"
import path from "path"
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

export async function list(workspace: string, slug: string): Promise<Observation[]> {
  return project(await readEvents(workspace, slug))
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
  return {
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
}

export async function remove(workspace: string, slug: string, id: string): Promise<void> {
  await append(workspace, slug, { type: "observation_removed", at: Date.now(), id })
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
}

export { severityCounts }
export type { Observation, Severity, Status, Subtype }
