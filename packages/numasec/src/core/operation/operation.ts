// Operation v3 — single markdown file per engagement.
//
// Layout:
//   <workspace>/.numasec/operation/<slug>/numasec.md      (the fascicule — auto-loaded as system instruction)
//   <workspace>/.numasec/operation/<slug>/evidence/       (agent-dropped attachments; referenced from numasec.md)
//   <workspace>/.numasec/operation/<slug>/report-<ts>.md  (outputs of /report)
//   <workspace>/.numasec/operation/active                 (marker file: contents = slug of active op)
//
// No event sourcing, no SQLite, no projection. The markdown file IS the state.
// The agent maintains it using its existing edit/write/read tools.

import { existsSync } from "fs"
import { mkdir, readFile, readdir, rm, stat, writeFile } from "fs/promises"
import path from "path"
import { migrate } from "./migration"

const migrated = new Set<string>()

async function ensureMigrated(workspace: string): Promise<void> {
  if (migrated.has(workspace)) return
  migrated.add(workspace)
  await migrate(workspace).catch(() => undefined)
}

export const ROOT_DIRNAME = ".numasec"
export const OP_FILENAME = "numasec.md"

export type Kind = "pentest" | "appsec" | "osint" | "hacking" | "bughunt" | "ctf" | "research"

export type AgentID = "security" | "pentest" | "appsec" | "osint" | "hacking"

// Default primary agent for each operation kind. The taxonomy mixes workflow
// labels (bughunt, ctf, research) with agent specializations (pentest, appsec,
// osint, hacking). The UI and /pwn heuristic call KIND_AGENT to decide which
// agent should be active when a new operation starts.
export const KIND_AGENT: Record<Kind, AgentID> = {
  pentest: "pentest",
  appsec: "appsec",
  osint: "osint",
  hacking: "hacking",
  bughunt: "pentest",
  ctf: "hacking",
  research: "security",
}

export const KINDS: ReadonlyArray<Kind> = [
  "pentest",
  "appsec",
  "osint",
  "hacking",
  "bughunt",
  "ctf",
  "research",
] as const

export function defaultAgentFor(kind: Kind): AgentID {
  return KIND_AGENT[kind]
}

export type Opsec = "normal" | "strict"

export const OPSECS: ReadonlyArray<Opsec> = ["normal", "strict"] as const

export interface Info {
  slug: string
  label: string
  kind: Kind
  target?: string
  opsec: Opsec
  created_at: number
  updated_at: number
  active: boolean
  lines: number
}

function rootDir(workspace: string) {
  return path.join(workspace, ROOT_DIRNAME, "operation")
}

export function opDir(workspace: string, slug: string) {
  return path.join(rootDir(workspace), slug)
}

export function opFile(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), OP_FILENAME)
}

function activeMarker(workspace: string) {
  return path.join(rootDir(workspace), "active")
}

export function safeSlug(input: string): string {
  const s = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
  return s || "op"
}

async function uniqueSlug(workspace: string, base: string): Promise<string> {
  const tried = safeSlug(base)
  if (!existsSync(opDir(workspace, tried))) return tried
  const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "").slice(0, 12)
  return `${tried}-${stamp}`
}

function skeleton(input: { label: string; kind: Kind; target?: string; opsec?: Opsec; createdAt: Date }): string {
  const date = input.createdAt.toISOString().slice(0, 10)
  const targetHost = (() => {
    if (!input.target) return ""
    try {
      return new URL(input.target).hostname
    } catch {
      return input.target
    }
  })()
  const scopeIn = targetHost ? `- in: ${targetHost}` : "- in:"
  const targetLine = input.target ? ` · target: ${input.target}` : ""
  const opsecLine = input.opsec && input.opsec !== "normal" ? ` · opsec: ${input.opsec}` : ""
  return `# Operation: ${input.label}
kind: ${input.kind}${targetLine}${opsecLine} · started: ${date}

<!--
This is your living engagement notebook. The AI agent updates it automatically
as it probes the target. You can edit it at any time in $EDITOR — changes persist.
Promote proposed findings by changing [proposed] to [confirmed]; use [dismissed] to drop.
Keep this file under ~1000 lines; summarize old Attempts into a Historical summary when it grows.
-->

## Scope
${scopeIn}
- out:

## Stack & Endpoints
_nothing learned yet — will populate as the agent probes_

## Defenses observed
_nothing observed yet_

## Findings
_none yet_

## Attempts
_none yet_

## Todos
_none yet_
`
}

export async function create(input: {
  workspace: string
  label: string
  kind: Kind
  target?: string
  opsec?: Opsec
}): Promise<Info> {
  const slug = await uniqueSlug(input.workspace, input.label)
  const dir = opDir(input.workspace, slug)
  await mkdir(path.join(dir, "evidence"), { recursive: true })
  const now = new Date()
  const content = skeleton({
    label: input.label,
    kind: input.kind,
    target: input.target,
    opsec: input.opsec,
    createdAt: now,
  })
  await writeFile(opFile(input.workspace, slug), content, "utf8")
  await activate(input.workspace, slug)
  return {
    slug,
    label: input.label,
    kind: input.kind,
    target: input.target,
    opsec: input.opsec ?? "normal",
    created_at: now.getTime(),
    updated_at: now.getTime(),
    active: true,
    lines: content.split("\n").length,
  }
}

export async function activate(workspace: string, slug: string): Promise<void> {
  const marker = activeMarker(workspace)
  await mkdir(path.dirname(marker), { recursive: true })
  await writeFile(marker, slug, "utf8")
}

export async function deactivate(workspace: string): Promise<void> {
  const marker = activeMarker(workspace)
  if (existsSync(marker)) await rm(marker)
}

export async function activeSlug(workspace: string): Promise<string | undefined> {
  await ensureMigrated(workspace)
  const marker = activeMarker(workspace)
  if (!existsSync(marker)) return undefined
  const slug = (await readFile(marker, "utf8")).trim()
  if (!slug) return undefined
  if (!existsSync(opFile(workspace, slug))) return undefined
  return slug
}

export async function archive(workspace: string, slug: string): Promise<void> {
  const current = await activeSlug(workspace)
  if (current === slug) await deactivate(workspace)
}

async function parseHeader(content: string, fallback: { slug: string; createdAt: number }): Promise<{
  label: string
  kind: Kind
  target?: string
  opsec: Opsec
}> {
  const firstLine = content.split("\n", 1)[0] ?? ""
  const label = firstLine.replace(/^#\s*Operation:\s*/, "").trim() || fallback.slug
  const metaLine = content.split("\n")[1] ?? ""
  const kindMatch = metaLine.match(/kind:\s*(\S+)/)
  const targetMatch = metaLine.match(/target:\s*(\S+)/)
  const opsecMatch = metaLine.match(/opsec:\s*(\S+)/)
  const rawKind = (kindMatch?.[1] ?? "pentest") as Kind
  const kind: Kind = KINDS.includes(rawKind) ? rawKind : "pentest"
  const rawOpsec = (opsecMatch?.[1] ?? "normal") as Opsec
  const opsec: Opsec = OPSECS.includes(rawOpsec) ? rawOpsec : "normal"
  return { label, kind, target: targetMatch?.[1], opsec }
}

export async function read(workspace: string, slug: string): Promise<Info | undefined> {
  const file = opFile(workspace, slug)
  if (!existsSync(file)) return undefined
  const [content, st] = await Promise.all([readFile(file, "utf8"), stat(file)])
  const active = (await activeSlug(workspace)) === slug
  const header = await parseHeader(content, { slug, createdAt: st.birthtimeMs })
  return {
    slug,
    label: header.label,
    kind: header.kind,
    target: header.target,
    opsec: header.opsec,
    created_at: st.birthtimeMs,
    updated_at: st.mtimeMs,
    active,
    lines: content.split("\n").length,
  }
}

export async function list(workspace: string): Promise<Info[]> {
  await ensureMigrated(workspace)
  const root = rootDir(workspace)
  if (!existsSync(root)) return []
  const entries = await readdir(root, { withFileTypes: true })
  const slugs = entries.filter((e) => e.isDirectory()).map((e) => e.name)
  const infos = await Promise.all(slugs.map((slug) => read(workspace, slug).catch(() => undefined)))
  return infos.filter((i): i is Info => Boolean(i)).sort((a, b) => b.updated_at - a.updated_at)
}

export async function active(workspace: string): Promise<Info | undefined> {
  const slug = await activeSlug(workspace)
  if (!slug) return undefined
  return read(workspace, slug)
}

export async function touch(workspace: string, slug: string): Promise<void> {
  const file = opFile(workspace, slug)
  if (!existsSync(file)) return
  const now = new Date()
  // mtime update without rewriting content: append-read-trim is heavy; use utimes equivalent
  const content = await readFile(file, "utf8")
  await writeFile(file, content, "utf8")
  void now
}

export async function readMarkdown(workspace: string, slug: string): Promise<string | undefined> {
  const file = opFile(workspace, slug)
  if (!existsSync(file)) return undefined
  return readFile(file, "utf8")
}

// Rewrites the meta line (2nd line) of numasec.md to set or unset `opsec: <level>`.
// Level "normal" is the default and is stored by removing any explicit opsec marker.
export async function setOpsec(workspace: string, slug: string, level: Opsec): Promise<void> {
  const file = opFile(workspace, slug)
  if (!existsSync(file)) return
  const content = await readFile(file, "utf8")
  const lines = content.split("\n")
  const meta = lines[1] ?? ""
  const stripped = meta
    .replace(/\s*·\s*opsec:\s*\S+/g, "")
    .replace(/^opsec:\s*\S+\s*·?\s*/, "")
  if (level === "normal") {
    lines[1] = stripped
  } else {
    const startedIdx = stripped.search(/·\s*started:/)
    if (startedIdx >= 0) {
      lines[1] = stripped.slice(0, startedIdx) + `· opsec: ${level} ` + stripped.slice(startedIdx)
    } else {
      lines[1] = `${stripped} · opsec: ${level}`
    }
  }
  await writeFile(file, lines.join("\n"), "utf8")
}
