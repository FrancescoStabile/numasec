import { appendFile, mkdir, readFile, writeFile } from "fs/promises"
import path from "path"
import { CyberFactTable } from "@/core/cyber/cyber.sql"
import { Instance } from "@/project/instance"
import { and, Database, desc, eq } from "@/storage"
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

function parseProjectedNode(value: unknown, idHint?: string): Node | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  const id = idHint
  const title = input.title
  const status = input.status
  if (!id || typeof title !== "string" || !title) return undefined
  if (
    status !== "planned" &&
    status !== "running" &&
    status !== "done" &&
    status !== "blocked" &&
    status !== "skipped"
  ) return undefined
  return {
    id,
    title,
    parent_id: typeof input.parent_id === "string" ? input.parent_id : undefined,
    status,
    note: typeof input.note === "string" ? input.note : undefined,
    created_at: 0,
    updated_at: 0,
  }
}

export async function list(workspace: string, slug: string): Promise<Node[]> {
  return project(await readEvents(workspace, slug))
}

export async function listProjected(workspace: string, slug: string): Promise<Node[]> {
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
              eq(CyberFactTable.entity_kind, "plan_node"),
              eq(CyberFactTable.fact_name, "todo_state"),
            ),
          )
          .orderBy(desc(CyberFactTable.time_updated))
          .all(),
      )
      const seen = new Set<string>()
      const out: Node[] = []
      for (const row of rows) {
        if (seen.has(row.entity_key)) continue
        seen.add(row.entity_key)
        const parsed = parseProjectedNode(row.value_json, row.entity_key)
        if (parsed) out.push(parsed)
      }
      return out.sort((a, b) => a.id.localeCompare(b.id))
    },
  })
}

export async function projectedSummary(
  workspace: string,
  slug: string,
): Promise<{ total: number; done: number; running: number; blocked: number; planned: number } | undefined> {
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
              eq(CyberFactTable.entity_kind, "operation"),
              eq(CyberFactTable.entity_key, slug),
              eq(CyberFactTable.fact_name, "plan_summary"),
            ),
          )
          .orderBy(desc(CyberFactTable.time_updated))
          .all(),
      )
      const row = rows[0]
      if (!row || !row.value_json || typeof row.value_json !== "object" || Array.isArray(row.value_json)) return undefined
      const value = row.value_json as Record<string, unknown>
      return {
        total: Number(value.total ?? 0),
        done: Number(value.done ?? 0),
        running: Number(value.running ?? 0),
        blocked: Number(value.blocked ?? 0),
        planned: Number(value.planned ?? 0),
      }
    },
  })
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
