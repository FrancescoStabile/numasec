// Active operation resolver.
//
// Tracks the "current" operation for a workspace via a small marker file.
// This is intentionally decoupled from the session lifecycle: switching
// active op does not disturb open sessions; new sessions created after a
// switch attach to the new op.

import { existsSync } from "fs"
import { mkdir, readFile, writeFile, rm } from "fs/promises"
import path from "path"
import { ROOT_DIRNAME, get, list } from "./store"
import type { Info } from "./info"

function markerPath(workspace: string): string {
  return path.join(workspace, ROOT_DIRNAME, "active")
}

export async function getActiveSlug(workspace: string): Promise<string | undefined> {
  const p = markerPath(workspace)
  if (!existsSync(p)) return undefined
  const raw = (await readFile(p, "utf8")).trim()
  return raw || undefined
}

export async function setActive(workspace: string, slug: string): Promise<void> {
  const p = markerPath(workspace)
  await mkdir(path.dirname(p), { recursive: true })
  await writeFile(p, slug)
}

export async function clearActive(workspace: string): Promise<void> {
  const p = markerPath(workspace)
  if (existsSync(p)) await rm(p)
}

export async function getActive(workspace: string): Promise<Info | undefined> {
  const slug = await getActiveSlug(workspace)
  if (!slug) return undefined
  const info = await get(workspace, slug)
  if (info && info.status === "archived") return undefined
  return info
}

// Resolve active op, falling back to most-recent non-archived op if marker missing.
export async function resolveActive(workspace: string): Promise<Info | undefined> {
  const explicit = await getActive(workspace)
  if (explicit) return explicit
  const all = await list(workspace)
  return all.find((o) => o.status === "active")
}
