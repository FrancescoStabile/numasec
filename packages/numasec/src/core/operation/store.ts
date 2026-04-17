// Operation store — append-only JSONL persistence on the workspace filesystem.
//
// Layout:
//   <workspace>/.numasec/operation/<slug>/events.jsonl   (canonical)
//   <workspace>/.numasec/operation/<slug>/meta.json      (projection snapshot)
//   <workspace>/.numasec/operation/<slug>/sessions/      (per-attached-session artifacts; reserved)
//   <workspace>/.numasec/operation/<slug>/deliverable/   (report outputs; reserved)
//
// Kept intentionally simple: no locking, no multi-writer semantics. Team mode
// and concurrent-safe event logs are Phase 2 concerns.

import { appendFile, mkdir, readFile, readdir, writeFile } from "fs/promises"
import { existsSync } from "fs"
import path from "path"
import { Event } from "./events"
import { Info, project } from "./info"

export const ROOT_DIRNAME = ".numasec"

function safeSlug(input: string): string {
  const s = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
  return s || "op"
}

function generateId(): string {
  return `op_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
}

function rootDir(workspace: string): string {
  return path.join(workspace, ROOT_DIRNAME, "operation")
}

export function opDir(workspace: string, slug: string): string {
  return path.join(rootDir(workspace), slug)
}

async function readEvents(dir: string): Promise<Event[]> {
  const file = path.join(dir, "events.jsonl")
  if (!existsSync(file)) return []
  const raw = await readFile(file, "utf8")
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((line) => Event.parse(JSON.parse(line)))
}

async function writeSnapshot(dir: string, info: Info): Promise<void> {
  await writeFile(path.join(dir, "meta.json"), JSON.stringify(info, null, 2))
}

export async function append(workspace: string, slug: string, event: Event): Promise<Info> {
  const dir = opDir(workspace, slug)
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, "events.jsonl"), JSON.stringify(event) + "\n")
  const events = await readEvents(dir)
  const info = project(events)
  if (!info) throw new Error(`operation ${slug} has no created event`)
  await writeSnapshot(dir, info)
  return info
}

export interface CreateInput {
  slug?: string
  label: string
  kind: Info["kind"]
}

export async function create(workspace: string, input: CreateInput): Promise<Info> {
  const slug = await uniqueSlug(workspace, input.slug ?? input.label)
  const event: Event = {
    type: "created",
    at: Date.now(),
    id: generateId(),
    slug,
    label: input.label,
    kind: input.kind,
  }
  return await append(workspace, slug, event)
}

async function uniqueSlug(workspace: string, seed: string): Promise<string> {
  const base = safeSlug(seed)
  const root = rootDir(workspace)
  await mkdir(root, { recursive: true })
  const existing = new Set(await readdir(root).catch(() => [] as string[]))
  if (!existing.has(base)) return base
  for (let i = 2; i < 1000; i++) {
    const candidate = `${base}-${i}`
    if (!existing.has(candidate)) return candidate
  }
  return `${base}-${Date.now()}`
}

export async function get(workspace: string, slug: string): Promise<Info | undefined> {
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return undefined
  const events = await readEvents(dir)
  return project(events)
}

export async function list(workspace: string): Promise<Info[]> {
  const root = rootDir(workspace)
  if (!existsSync(root)) return []
  const slugs = await readdir(root)
  const infos = await Promise.all(slugs.map((s) => get(workspace, s)))
  return infos
    .filter((x): x is Info => !!x)
    .sort((a, b) => b.updated_at - a.updated_at)
}

export async function rename(workspace: string, slug: string, label: string): Promise<Info> {
  return append(workspace, slug, { type: "renamed", at: Date.now(), label })
}

export async function archive(workspace: string, slug: string): Promise<Info> {
  return append(workspace, slug, { type: "archived", at: Date.now() })
}

export async function attachSession(workspace: string, slug: string, sessionID: string): Promise<Info> {
  return append(workspace, slug, { type: "session_attached", at: Date.now(), session_id: sessionID })
}

export async function setSubject(workspace: string, slug: string, subject: Record<string, unknown>): Promise<Info> {
  return append(workspace, slug, { type: "subject_set", at: Date.now(), subject })
}

export async function setBoundary(workspace: string, slug: string, boundary: Record<string, unknown>): Promise<Info> {
  return append(workspace, slug, { type: "boundary_set", at: Date.now(), boundary })
}

export async function setMode(workspace: string, slug: string, mode: Record<string, string>): Promise<Info> {
  return append(workspace, slug, { type: "mode_set", at: Date.now(), mode })
}

export async function recordExport(
  workspace: string,
  slug: string,
  deliverable: string,
  exportedPath: string,
): Promise<Info> {
  return append(workspace, slug, {
    type: "exported",
    at: Date.now(),
    deliverable,
    path: exportedPath,
  })
}
