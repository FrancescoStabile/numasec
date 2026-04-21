import { appendFile, mkdir, readFile, writeFile } from "fs/promises"
import path from "path"
import { Event, type NodeStatus } from "./events"
import { project, progress, type Node } from "./info"

const FILE = "plan.jsonl"
const SNAP = "plan.json"

function planDir(workspace: string, slug: string) {
  return path.join(workspace, ".numasec", "operation", slug)
}

async function readEvents(workspace: string, slug: string): Promise<Event[]> {
  const p = path.join(planDir(workspace, slug), FILE)
  const raw = await readFile(p, "utf8").catch(() => "")
  if (!raw) return []
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => Event.parse(JSON.parse(l)))
}

async function append(workspace: string, slug: string, event: Event): Promise<void> {
  const dir = planDir(workspace, slug)
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, FILE), JSON.stringify(event) + "\n", "utf8")
  const nodes = project(await readEvents(workspace, slug))
  await writeFile(path.join(dir, SNAP), JSON.stringify({ nodes, progress: progress(nodes) }, null, 2), "utf8")
}

export async function list(workspace: string, slug: string): Promise<Node[]> {
  return project(await readEvents(workspace, slug))
}

export async function add(
  workspace: string,
  slug: string,
  input: { title: string; parent_id?: string; note?: string; id?: string },
): Promise<Node> {
  const id = input.id ?? `pn_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
  const at = Date.now()
  await append(workspace, slug, {
    type: "node_added",
    at,
    id,
    title: input.title,
    parent_id: input.parent_id,
    note: input.note,
  })
  return {
    id,
    title: input.title,
    parent_id: input.parent_id,
    status: "planned",
    note: input.note,
    created_at: at,
    updated_at: at,
  }
}

export async function update(
  workspace: string,
  slug: string,
  id: string,
  patch: { title?: string; status?: NodeStatus; note?: string },
): Promise<void> {
  await append(workspace, slug, { type: "node_updated", at: Date.now(), id, ...patch })
}

export async function remove(workspace: string, slug: string, id: string): Promise<void> {
  await append(workspace, slug, { type: "node_removed", at: Date.now(), id })
}

export async function move(
  workspace: string,
  slug: string,
  id: string,
  parent_id?: string,
): Promise<void> {
  await append(workspace, slug, { type: "node_moved", at: Date.now(), id, parent_id })
}

export { progress }
export type { Node, NodeStatus }
