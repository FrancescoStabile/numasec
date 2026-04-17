// One-shot migration from Operation v1 (event-sourced) to v3 (single markdown file).
//
// Runs at boot. Detects each legacy operation directory under
// <workspace>/.numasec/operation/<slug>/ that contains `events.jsonl` or v1-only
// files, renames them into <slug>/_legacy/, and writes a fresh numasec.md
// skeleton with a `## Historical notes` section pointing at _legacy/.
// Idempotent: if `_legacy/` already exists, skips.

import { existsSync } from "fs"
import { mkdir, readdir, rename, writeFile } from "fs/promises"
import path from "path"
import { OP_FILENAME, ROOT_DIRNAME, opDir } from "./operation"

const V1_MARKERS = ["events.jsonl", "meta.json"]

function skeletonWithHistorical(slug: string): string {
  return `# Operation: ${slug} (migrated)
kind: pentest · started: ${new Date().toISOString().slice(0, 10)}

<!--
Migrated from a previous Operations v1 event store. The raw v1 files were
preserved under _legacy/ in this directory for reference.
-->

## Scope
- in:
- out:

## Stack & Endpoints
_none yet_

## Defenses observed
_none yet_

## Findings
_none yet_

## Attempts
_none yet_

## Todos
_none yet_

## Historical notes
- Migrated from v1 on ${new Date().toISOString()}. Raw event log and projections live in \`_legacy/\`.
`
}

async function migrateSlug(workspace: string, slug: string): Promise<void> {
  const dir = opDir(workspace, slug)
  const legacyDir = path.join(dir, "_legacy")
  if (existsSync(legacyDir)) return
  const entries = await readdir(dir, { withFileTypes: true })
  const hasV1 = entries.some((e) => e.isFile() && V1_MARKERS.includes(e.name))
  const hasNew = entries.some((e) => e.isFile() && e.name === OP_FILENAME)
  if (!hasV1 || hasNew) return

  await mkdir(legacyDir, { recursive: true })
  for (const entry of entries) {
    if (entry.name === "_legacy") continue
    if (entry.name === OP_FILENAME) continue
    await rename(path.join(dir, entry.name), path.join(legacyDir, entry.name))
  }
  await writeFile(path.join(dir, OP_FILENAME), skeletonWithHistorical(slug), "utf8")
}

export async function migrate(workspace: string): Promise<void> {
  const root = path.join(workspace, ROOT_DIRNAME, "operation")
  if (!existsSync(root)) return
  const entries = await readdir(root, { withFileTypes: true })
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    if (entry.name === "_legacy") continue
    await migrateSlug(workspace, entry.name).catch(() => undefined)
  }
}
