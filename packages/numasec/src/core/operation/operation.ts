// Operation state and projections.
//
// Layout:
//   <workspace>/.numasec/operation/<slug>/numasec.md         (optional legacy notebook / projection)
//   <workspace>/.numasec/operation/<slug>/cyber/             (kernel projections: ledger/facts/relations)
//   <workspace>/.numasec/operation/<slug>/workflow/          (workflow projections)
//   <workspace>/.numasec/operation/<slug>/context/           (derived prompt-facing context)
//   <workspace>/.numasec/operation/<slug>/evidence/          (evidence artifacts)
//   <workspace>/.numasec/operation/<slug>/deliverable/       (report bundles)
//   <workspace>/.numasec/operation/active                    (marker file: contents = slug of active op)
//
// Markdown is not the canonical source of truth.
// Canonical state lives in the cyber kernel plus derived projections.
// The notebook is now optional and treated as a compatibility/export surface.

import { existsSync } from "fs"
import { appendFile, mkdir, readFile, readdir, rm, stat, writeFile } from "fs/promises"
import path from "path"
import { migrate } from "./migration"
import { parseScope } from "./scope"
import type { Boundary } from "../boundary/schema"
import { Instance } from "@/project/instance"
import { and, Database, desc, eq } from "@/storage"
import { CyberFactTable, CyberLedgerTable, CyberRelationTable } from "../cyber/cyber.sql"

const migrated = new Set<string>()

async function ensureMigrated(workspace: string): Promise<void> {
  if (migrated.has(workspace)) return
  migrated.add(workspace)
  await migrate(workspace).catch(() => undefined)
}

export const ROOT_DIRNAME = ".numasec"
export const OP_FILENAME = "numasec.md"
const ACTIVITY_FILENAME = ".activity.json"
const DERIVED_NOTEBOOK_MARKER = "Derived markdown projection from the cyber kernel."

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

export type ProjectedOperationState = {
  label?: string
  kind?: Kind
  target?: string
  opsec?: Opsec
  in_scope?: string[]
  out_of_scope?: string[]
}

export type ProjectedScopePolicy = Boundary

export type ProjectedAutonomyPolicy = {
  mode?: string
  rules?: unknown
  session_id?: string
}

function inferredScopeFromTarget(target?: string): string[] {
  if (!target) return []
  try {
    return [new URL(target).hostname].filter(Boolean)
  } catch {
    return [target].filter(Boolean)
  }
}

function rootDir(workspace: string) {
  return path.join(workspace, ROOT_DIRNAME, "operation")
}

export function opDir(workspace: string, slug: string) {
  return path.join(rootDir(workspace), slug)
}

function sessionDir(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), "sessions")
}

function workflowDir(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), "workflow")
}

function contextDir(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), "context")
}

function workflowFile(workspace: string, slug: string, kind: "play" | "runbook", id: string) {
  return path.join(workflowDir(workspace, slug), `${kind}-${safeSlug(id)}.json`)
}

function contextFile(workspace: string, slug: string) {
  return path.join(contextDir(workspace, slug), "active-context.md")
}

function cyberFactsFile(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), "cyber", "facts.jsonl")
}

function activeWorkflowFile(workspace: string, slug: string) {
  return path.join(workflowDir(workspace, slug), "active.json")
}

export function opFile(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), OP_FILENAME)
}

function activeMarker(workspace: string) {
  return path.join(rootDir(workspace), "active")
}

function activityFile(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), ACTIVITY_FILENAME)
}

function cyberDir(workspace: string, slug: string) {
  return path.join(opDir(workspace, slug), "cyber")
}

function cyberLedgerFile(workspace: string, slug: string) {
  return path.join(cyberDir(workspace, slug), "ledger.jsonl")
}

function cyberRelationsFile(workspace: string, slug: string) {
  return path.join(cyberDir(workspace, slug), "relations.jsonl")
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

async function newestMTime(target: string): Promise<number> {
  const st = await stat(target)
  if (!st.isDirectory()) return st.mtimeMs
  let latest = st.mtimeMs
  const entries = await readdir(target, { withFileTypes: true }).catch(() => [])
  for (const entry of entries) {
    const child = path.join(target, entry.name)
    const childMTime = await newestMTime(child).catch(() => 0)
    if (childMTime > latest) latest = childMTime
  }
  return latest
}

function cyberID(prefix: string) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
}

async function writeInitialCyberKernelState(input: {
  workspace: string
  slug: string
  label: string
  kind: Kind
  target?: string
  opsec: Opsec
  createdAt: number
}) {
  const inferredScope = inferredScopeFromTarget(input.target)
  await Instance.provide({
    directory: input.workspace,
    fn: async () => {
      const projectID = Instance.project.id
      const eventID = cyberID("cled")
      const operationStateID = cyberID("cfact")
      const scopePolicyID = cyberID("cfact")
      const relationID = input.target ? cyberID("crel") : undefined
      const ledger: typeof CyberLedgerTable.$inferInsert = {
        id: eventID,
        project_id: projectID,
        operation_slug: input.slug,
        kind: "operation.note",
        source: "operation",
        status: "completed",
        summary: `operation created ${input.slug}`,
        data: {
          label: input.label,
          kind: input.kind,
          target: input.target ?? null,
          opsec: input.opsec,
        },
        time_created: input.createdAt,
      }
      const facts: Array<typeof CyberFactTable.$inferInsert> = [
        {
          id: operationStateID,
          project_id: projectID,
          operation_slug: input.slug,
          entity_kind: "operation",
          entity_key: input.slug,
          fact_name: "operation_state",
          status: "observed",
          writer_kind: "tool",
          confidence: 1000,
          source_event_id: eventID,
          time_created: input.createdAt,
          time_updated: input.createdAt,
          value_json: {
            label: input.label,
            kind: input.kind,
            target: input.target,
            opsec: input.opsec,
            in_scope: inferredScope,
            out_of_scope: [],
          },
        },
        {
          id: scopePolicyID,
          project_id: projectID,
          operation_slug: input.slug,
          entity_kind: "operation",
          entity_key: input.slug,
          fact_name: "scope_policy",
          status: "observed",
          writer_kind: "tool",
          confidence: 1000,
          source_event_id: eventID,
          time_created: input.createdAt,
          time_updated: input.createdAt,
          value_json: {
            default: inferredScope.length > 0 ? "ask" : "allow",
            in_scope: inferredScope,
            out_of_scope: [],
            opsec: input.opsec,
          },
        },
      ]
      const relations: Array<typeof CyberRelationTable.$inferInsert> = input.target
        ? [
            {
              id: relationID!,
              project_id: projectID,
              operation_slug: input.slug,
              src_kind: "operation",
              src_key: input.slug,
              relation: "targets",
              dst_kind: "target",
              dst_key: input.target,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID,
              time_created: input.createdAt,
              time_updated: input.createdAt,
            },
          ]
        : []
      Database.use((db) => {
        db.insert(CyberLedgerTable).values(ledger).onConflictDoNothing().run()
        for (const fact of facts) {
          db.insert(CyberFactTable)
            .values(fact)
            .onConflictDoUpdate({
              target: [
                CyberFactTable.project_id,
                CyberFactTable.operation_slug,
                CyberFactTable.entity_kind,
                CyberFactTable.entity_key,
                CyberFactTable.fact_name,
              ],
              set: {
                value_json: fact.value_json,
                writer_kind: fact.writer_kind,
                status: fact.status,
                confidence: fact.confidence,
                source_event_id: fact.source_event_id,
                evidence_refs: fact.evidence_refs,
                expires_at: fact.expires_at,
                time_updated: fact.time_updated,
              },
            })
            .run()
        }
        for (const relation of relations) {
          db.insert(CyberRelationTable)
            .values(relation)
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
                writer_kind: relation.writer_kind,
                status: relation.status,
                confidence: relation.confidence,
                source_event_id: relation.source_event_id,
                evidence_refs: relation.evidence_refs,
                time_updated: relation.time_updated,
              },
            })
            .run()
        }
      })
      await mkdir(cyberDir(input.workspace, input.slug), { recursive: true })
      await writeFile(cyberFactsFile(input.workspace, input.slug), facts.map((item) => JSON.stringify(item)).join("\n") + "\n", "utf8")
      await writeFile(cyberLedgerFile(input.workspace, input.slug), `${JSON.stringify(ledger)}\n`, "utf8")
      await writeFile(
        cyberRelationsFile(input.workspace, input.slug),
        relations.length > 0 ? relations.map((item) => JSON.stringify(item)).join("\n") + "\n" : "",
        "utf8",
      )
    },
  })
}

function initialContextPack(input: {
  slug: string
  label: string
  kind: Kind
  target?: string
  opsec: Opsec
  in_scope: string[]
  out_of_scope: string[]
}): string {
  return [
    "# Active Operation Context",
    "",
    `slug: ${input.slug}`,
    `label: ${input.label}`,
    `kind: ${input.kind}`,
    `target: ${input.target ?? "-"}`,
    `opsec: ${input.opsec}`,
    "",
    "## Scope",
    ...input.in_scope.map((item) => `- in: ${item}`),
    ...(input.in_scope.length === 0 ? ["- in:"] : []),
    ...input.out_of_scope.map((item) => `- out: ${item}`),
    ...(input.out_of_scope.length === 0 ? ["- out:"] : []),
    "",
    "## Kernel Summary",
    "- routes: 0",
    "- observations: 0",
    "- findings: 0",
    "- workflows: 0",
    "",
  ].join("\n")
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
  const inferredScope = inferredScopeFromTarget(input.target)
  await writeInitialCyberKernelState({
    workspace: input.workspace,
    slug,
    label: input.label,
    kind: input.kind,
    target: input.target,
    opsec: input.opsec ?? "normal",
    createdAt: now.getTime(),
  })
  await mkdir(contextDir(input.workspace, slug), { recursive: true })
  await writeFile(
    contextFile(input.workspace, slug),
    initialContextPack({
      slug,
      label: input.label,
      kind: input.kind,
      target: input.target,
      opsec: input.opsec ?? "normal",
      in_scope: inferredScope,
      out_of_scope: [],
    }),
    "utf8",
  )
  await writeFile(
    activityFile(input.workspace, slug),
    JSON.stringify({ touched_at: now.getTime(), source: "create" }, null, 2),
    "utf8",
  )
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
    lines: 0,
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
  if (!existsSync(opDir(workspace, slug))) return undefined
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

async function readProjectedOperationState(workspace: string, slug: string): Promise<
  ProjectedOperationState | undefined
> {
  return readProjectedOperationFact(workspace, slug, "operation_state", (projected) => {
    const kind =
      typeof projected.kind === "string" && KINDS.includes(projected.kind as Kind) ? (projected.kind as Kind) : undefined
    const opsec =
      typeof projected.opsec === "string" && OPSECS.includes(projected.opsec as Opsec)
        ? (projected.opsec as Opsec)
        : undefined
    return {
      label: typeof projected.label === "string" ? projected.label : undefined,
      kind,
      target: typeof projected.target === "string" ? projected.target : undefined,
      opsec,
      in_scope: Array.isArray(projected.in_scope)
        ? projected.in_scope.filter((item): item is string => typeof item === "string")
        : undefined,
      out_of_scope: Array.isArray(projected.out_of_scope)
        ? projected.out_of_scope.filter((item): item is string => typeof item === "string")
        : undefined,
    }
  })
}

async function readProjectedOperationFact<T>(
  workspace: string,
  slug: string,
  factName: "operation_state" | "scope_policy" | "autonomy_policy",
  parse: (projected: Record<string, unknown>) => T | undefined,
): Promise<T | undefined> {
  const parseValue = (value: unknown) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
    return parse(value as Record<string, unknown>)
  }
  const file = cyberFactsFile(workspace, slug)
  if (existsSync(file)) {
    const raw = await readFile(file, "utf8").catch(() => "")
    if (raw) {
      let latest: Record<string, unknown> | undefined
      for (const line of raw.split(/\r?\n/)) {
        if (!line.trim()) continue
        try {
          const parsed = JSON.parse(line) as Record<string, unknown>
          if (
            parsed["entity_kind"] === "operation" &&
            parsed["entity_key"] === slug &&
            parsed["fact_name"] === factName
          ) {
            latest = parsed
          }
        } catch {}
      }
      const parsed = parseValue(latest?.["value_json"])
      if (parsed) return parsed
    }
  }

  const query = async () =>
    Database.use((db) =>
      db
        .select()
        .from(CyberFactTable)
        .where(
          and(
            eq(CyberFactTable.operation_slug, slug),
            eq(CyberFactTable.entity_kind, "operation"),
            eq(CyberFactTable.entity_key, slug),
            eq(CyberFactTable.fact_name, factName),
          ),
        )
        .orderBy(desc(CyberFactTable.time_updated), desc(CyberFactTable.time_created))
        .get(),
    )

  const record = await (async () => {
    try {
      return await query()
    } catch {
      return await Instance.provide({
        directory: workspace,
        fn: () => query(),
      }).catch(() => undefined)
    }
  })()

  return parseValue(record?.value_json)
}

export async function readProjectedState(workspace: string, slug: string): Promise<ProjectedOperationState | undefined> {
  return readProjectedOperationState(workspace, slug)
}

export async function readProjectedScopePolicy(
  workspace: string,
  slug: string,
): Promise<ProjectedScopePolicy | undefined> {
  return readProjectedOperationFact(workspace, slug, "scope_policy", (projected) => ({
    default: projected.default === "allow" ? "allow" : "ask",
    in_scope: Array.isArray(projected.in_scope)
      ? projected.in_scope.filter((item): item is string => typeof item === "string")
      : [],
    out_of_scope: Array.isArray(projected.out_of_scope)
      ? projected.out_of_scope.filter((item): item is string => typeof item === "string")
      : [],
  }))
}

export async function readProjectedAutonomyPolicy(
  workspace: string,
  slug: string,
): Promise<ProjectedAutonomyPolicy | undefined> {
  return readProjectedOperationFact(workspace, slug, "autonomy_policy", (projected) => ({
    mode: typeof projected.mode === "string" ? projected.mode : undefined,
    rules: projected.rules,
    session_id: typeof projected.session_id === "string" ? projected.session_id : undefined,
  }))
}

// Backward-compatible alias for callers (e.g. core/deliverable/build.ts) that still use `get`.
export const get = (workspace: string, slug: string) => read(workspace, slug)

export async function read(workspace: string, slug: string): Promise<Info | undefined> {
  const file = opFile(workspace, slug)
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return undefined
  const [content, dirStat, projected, updatedAt] = await Promise.all([
    existsSync(file) ? readFile(file, "utf8").catch(() => "") : Promise.resolve(""),
    stat(dir),
    readProjectedOperationState(workspace, slug).catch(() => undefined),
    newestMTime(dir).catch(() => stat(dir).then((entry) => entry.mtimeMs).catch(() => Date.now())),
  ])
  const active = (await activeSlug(workspace)) === slug
  const header = content
    ? await parseHeader(content, { slug, createdAt: dirStat.birthtimeMs })
    : {
        label: slug,
        kind: "pentest" as Kind,
        target: undefined,
        opsec: "normal" as Opsec,
      }
  return {
    slug,
    label: projected?.label ?? header.label,
    kind: projected?.kind ?? header.kind,
    target: projected?.target ?? header.target,
    opsec: projected?.opsec ?? header.opsec,
    created_at: dirStat.birthtimeMs,
    updated_at: updatedAt,
    active,
    lines: content ? content.split("\n").length : 0,
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
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return
  await writeFile(
    activityFile(workspace, slug),
    JSON.stringify({ touched_at: Date.now(), source: "touch" }, null, 2),
    "utf8",
  )
}

export async function attachSession(workspace: string, slug: string, sessionID: string): Promise<void> {
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return
  const sessions = sessionDir(workspace, slug)
  await mkdir(sessions, { recursive: true })
  await writeFile(
    path.join(sessions, `${sessionID}.json`),
    JSON.stringify({ session_id: sessionID, attached_at: Date.now() }, null, 2),
    "utf8",
  )
  await touch(workspace, slug)
}

export async function writeWorkflow(
  workspace: string,
  slug: string,
  input: { kind: "play" | "runbook"; id: string; payload: Record<string, unknown> },
): Promise<void> {
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return
  const workflows = workflowDir(workspace, slug)
  await mkdir(workflows, { recursive: true })
  await writeFile(
    workflowFile(workspace, slug, input.kind, input.id),
    JSON.stringify(
      {
        kind: input.kind,
        id: input.id,
        updated_at: Date.now(),
        ...input.payload,
      },
      null,
      2,
    ),
    "utf8",
  )
  await touch(workspace, slug)
}

export async function writeContextPack(workspace: string, slug: string, content: string): Promise<void> {
  const dir = opDir(workspace, slug)
  if (!existsSync(dir)) return
  const targetDir = contextDir(workspace, slug)
  await mkdir(targetDir, { recursive: true })
  await writeFile(contextFile(workspace, slug), content, "utf8")
  await touch(workspace, slug)
}

export async function readContextPack(workspace: string, slug: string): Promise<string | undefined> {
  const file = contextFile(workspace, slug)
  if (!existsSync(file)) return undefined
  return readFile(file, "utf8").catch(() => undefined)
}

export async function readBoundary(workspace: string, slug: string): Promise<Boundary | undefined> {
  const projected = await readProjectedScopePolicy(workspace, slug).catch(() => undefined)
  if (projected) return projected
  const markdown = await readMarkdown(workspace, slug).catch(() => undefined)
  if (!markdown) return undefined
  return parseScope(markdown)
}

export async function readWorkflow(
  workspace: string,
  slug: string,
  input: { kind: "play" | "runbook"; id: string },
): Promise<Record<string, unknown> | undefined> {
  const file = workflowFile(workspace, slug, input.kind, input.id)
  if (!existsSync(file)) return undefined
  const raw = await readFile(file, "utf8").catch(() => "")
  if (!raw) return undefined
  try {
    return JSON.parse(raw) as Record<string, unknown>
  } catch {
    return undefined
  }
}

export async function setActiveWorkflow(
  workspace: string,
  slug: string,
  input: { kind: "play" | "runbook"; id: string },
): Promise<void> {
  const workflows = workflowDir(workspace, slug)
  await mkdir(workflows, { recursive: true })
  await writeFile(
    activeWorkflowFile(workspace, slug),
    JSON.stringify({ kind: input.kind, id: input.id, at: Date.now() }, null, 2),
    "utf8",
  )
  await touch(workspace, slug)
}

export async function activeWorkflow(
  workspace: string,
  slug: string,
): Promise<{ kind: "play" | "runbook"; id: string } | undefined> {
  const file = activeWorkflowFile(workspace, slug)
  if (!existsSync(file)) return undefined
  const raw = await readFile(file, "utf8").catch(() => "")
  if (!raw) return undefined
  try {
    const parsed = JSON.parse(raw) as { kind?: string; id?: string }
    if ((parsed.kind === "play" || parsed.kind === "runbook") && typeof parsed.id === "string" && parsed.id) {
      return { kind: parsed.kind, id: parsed.id }
    }
  } catch {}
  return undefined
}

function matchesPlannedArgs(expected: unknown, actual: unknown): boolean {
  if (expected === undefined) return true
  if (expected === null || actual === null) return expected === actual
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return false
    if (expected.length > actual.length) return false
    return expected.every((item, index) => matchesPlannedArgs(item, actual[index]))
  }
  if (typeof expected === "object") {
    if (!actual || typeof actual !== "object" || Array.isArray(actual)) return false
    return Object.entries(expected).every(([key, value]) =>
      matchesPlannedArgs(value, (actual as Record<string, unknown>)[key]),
    )
  }
  return expected === actual
}

export async function recordWorkflowStep(
  workspace: string,
  slug: string,
  input: { tool: string; success: boolean; title?: string; error?: string; args?: unknown },
): Promise<{ kind: "play" | "runbook"; id: string; step_index: number; status: "completed" | "failed" } | undefined> {
  const active = await activeWorkflow(workspace, slug)
  if (!active) return undefined
  const workflow = await readWorkflow(workspace, slug, active)
  if (!workflow) return undefined
  const trace = Array.isArray(workflow["trace"]) ? structuredClone(workflow["trace"]) as Array<Record<string, unknown>> : []
  const skipped = Array.isArray(workflow["skipped"]) ? workflow["skipped"] as Array<Record<string, unknown>> : []
  const unresolved = trace
    .map((step, index) => ({ step, index }))
    .filter(({ step }) => {
      if (step["kind"] !== "tool") return false
      if (step["tool"] !== input.tool) return false
      return step["outcome"] === undefined
    })
  const matchedByArgs = unresolved.find(({ step }) =>
    matchesPlannedArgs(step["args"], input.args),
  )
  const index = matchedByArgs?.index ?? unresolved[0]?.index ?? -1
  if (index < 0) return undefined
  if (!trace[index]) return undefined
  const original = trace[index]
  if (
    original["kind"] !== "tool" ||
    original["tool"] !== input.tool ||
    original["outcome"] !== undefined
  ) {
    return undefined
  }
  trace[index] = {
    ...original,
    outcome: input.success ? "completed" : "failed",
    outcome_at: Date.now(),
    ...(input.title ? { outcome_title: input.title } : {}),
    ...(input.error ? { outcome_error: input.error } : {}),
    ...(input.args !== undefined ? { last_args: input.args } : {}),
  }
  for (let stepIndex = 0; stepIndex < trace.length; stepIndex += 1) {
    const step = trace[stepIndex]
    if (!step || step["kind"] === "tool" || step["outcome"] !== undefined) continue
    const laterResolvedToolExists = trace.slice(stepIndex + 1).some((candidate) => {
      if (!candidate || candidate["kind"] !== "tool") return false
      return candidate["outcome"] === "completed" || candidate["outcome"] === "failed"
    })
    if (!laterResolvedToolExists) continue
    trace[stepIndex] = {
      ...step,
      outcome: "skipped",
      outcome_at: Date.now(),
      outcome_error: "skipped by agent",
    }
    skipped.push({
      index: stepIndex + 1,
      kind: step["kind"],
      label: step["label"],
      reason: "skipped by agent",
    })
  }
  const completed = trace.filter((step) => step["outcome"] === "completed").length
  const failed = trace.filter((step) => step["outcome"] === "failed").length
  const skippedCount = trace.filter((step) => step["outcome"] === "skipped").length
  await writeWorkflow(workspace, slug, {
    kind: active.kind,
    id: active.id,
    payload: {
      ...workflow,
      trace,
      skipped,
      completed_steps: completed,
      failed_steps: failed,
      pending_steps: Math.max(0, trace.length - completed - failed - skippedCount),
    },
  })
  return {
    kind: active.kind,
    id: active.id,
    step_index: index + 1,
    status: input.success ? "completed" : "failed",
  }
}

export async function readMarkdown(workspace: string, slug: string): Promise<string | undefined> {
  const file = opFile(workspace, slug)
  if (existsSync(file)) {
    const content = await readFile(file, "utf8").catch(() => undefined)
    if (content && !content.includes(DERIVED_NOTEBOOK_MARKER)) return content
  }
  return renderProjectedMarkdown(workspace, slug)
}

async function renderProjectedMarkdown(workspace: string, slug: string): Promise<string | undefined> {
  const info = await read(workspace, slug)
  if (!info) return undefined
  const [scope, autonomy, context, projected] = await Promise.all([
    readProjectedScopePolicy(workspace, slug).catch(() => undefined),
    readProjectedAutonomyPolicy(workspace, slug).catch(() => undefined),
    readContextPack(workspace, slug).catch(() => undefined),
    import("../cyber").then(({ Cyber }) => Cyber.readProjectedState(workspace, slug)).catch(() => undefined),
  ])
  const started = new Date(info.created_at).toISOString().slice(0, 10)
  const scopeIn = scope?.in_scope?.length ? scope.in_scope.join(", ") : "-"
  const scopeOut = scope?.out_of_scope?.length ? scope.out_of_scope.join(", ") : "-"
  const kernel = projected?.summary
  const capsuleLine = kernel
    ? `ready=${kernel.ready_capsules} degraded=${kernel.degraded_capsules} unavailable=${kernel.unavailable_capsules} recommended=${kernel.recommended_capsules} executed=${kernel.executed_capsules}`
    : "-"
  const activeIdentityKeys =
    projected?.identities
      .filter((item) => item.fact_name === "active" && item.active)
      .map((item) => item.key)
      .sort() ?? []
  const latestDeliverable = projected?.deliverables[0]
  const latestShareBundle = projected?.share_bundles[0]
  const identityLine = kernel
    ? `descriptors=${kernel.identities} active=${kernel.active_identities}${activeIdentityKeys.length > 0 ? ` (${activeIdentityKeys.join(", ")})` : ""}`
    : "-"
  const toolAdapterLine = kernel
    ? `present=${kernel.tool_adapters_present} missing=${kernel.tool_adapters_missing}`
    : "-"
  const verticalLine = kernel
    ? `ready=${kernel.ready_verticals} degraded=${kernel.degraded_verticals} unavailable=${kernel.unavailable_verticals}`
    : "-"
  const knowledgeLine = kernel ? `queries=${kernel.knowledge_queries}` : "-"
  const deliverableLine = kernel
    ? `deliverables=${kernel.deliverables} share_bundles=${kernel.share_bundles}${latestDeliverable?.report_path ? ` latest_report=${latestDeliverable.report_path}` : ""}${latestShareBundle?.path ? ` latest_share=${latestShareBundle.path}` : ""}`
    : "-"
  const completedSteps =
    projected?.workflow_steps.filter((item) => item.outcome === "completed").length ??
    projected?.workflows.reduce((sum, item) => sum + (item.completed_steps ?? 0), 0) ??
    0
  return [
    `# Operation: ${info.label}`,
    `kind: ${info.kind}${info.target ? ` · target: ${info.target}` : ""} · opsec: ${info.opsec} · started: ${started}`,
    "",
    "<!--",
    DERIVED_NOTEBOOK_MARKER,
    "This file was generated because the legacy notebook is absent.",
    "-->",
    "",
    "## Scope",
    `- in: ${scopeIn}`,
    `- out: ${scopeOut}`,
    "",
    "## Operation State",
    `- active: ${info.active ? "yes" : "no"}`,
    `- autonomy: ${autonomy?.mode ?? "-"}`,
    "",
    "## Kernel Summary",
    kernel
      ? `- routes: ${kernel.route_facts}\n- observations: ${kernel.observations_projected}\n- workflows: ${projected?.workflows.length ?? 0}\n- completed_steps: ${completedSteps}\n- findings: ${kernel.findings}\n- candidate_findings: ${kernel.candidate_findings}`
      : "- unavailable",
    "",
    "## Reportability",
    kernel
      ? `- reportable: ${kernel.reportable_findings}\n- suspected: ${kernel.suspected_findings}\n- rejected: ${kernel.rejected_findings}\n- verified: ${kernel.verified_findings}\n- evidence_backed: ${kernel.evidence_backed_findings}\n- replay_backed: ${kernel.replay_backed_findings}\n- replay_exempt: ${kernel.replay_exempt_findings}`
      : "- unavailable",
    "",
    "## Capsules",
    `- ${capsuleLine}`,
    "",
    "## Identities",
    `- ${identityLine}`,
    "",
    "## Knowledge",
    `- ${knowledgeLine}`,
    "",
    "## Tool Runtime",
    `- adapters: ${toolAdapterLine}`,
    `- verticals: ${verticalLine}`,
    "",
    "## Exports",
    `- ${deliverableLine}`,
    "",
    "## Context Pack",
    context?.trim() || "_not generated yet_",
    "",
  ].join("\n")
}

// Rewrites the meta line (2nd line) of numasec.md to set or unset `opsec: <level>`.
// Level "normal" is the default and is stored by removing any explicit opsec marker.
export async function setOpsec(workspace: string, slug: string, level: Opsec): Promise<void> {
  const file = opFile(workspace, slug)
  if (existsSync(file)) {
    const content = await readFile(file, "utf8")
    if (!content.includes(DERIVED_NOTEBOOK_MARKER)) {
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
  }

  const [info, projectedState, scope] = await Promise.all([
    read(workspace, slug).catch(() => undefined),
    readProjectedState(workspace, slug).catch(() => undefined),
    readProjectedScopePolicy(workspace, slug).catch(() => undefined),
  ])
  const now = Date.now()
  const operationState = {
    entity_kind: "operation",
    entity_key: slug,
    fact_name: "operation_state",
    status: "observed",
    writer_kind: "tool",
    time_created: now,
    time_updated: now,
    value_json: {
      label: projectedState?.label ?? info?.label ?? slug,
      kind: projectedState?.kind ?? info?.kind ?? "pentest",
      target: projectedState?.target ?? info?.target,
      opsec: level,
      in_scope: projectedState?.in_scope ?? scope?.in_scope ?? [],
      out_of_scope: projectedState?.out_of_scope ?? scope?.out_of_scope ?? [],
    },
  }
  const scopePolicy = {
    entity_kind: "operation",
    entity_key: slug,
    fact_name: "scope_policy",
    status: "observed",
    writer_kind: "tool",
    time_created: now,
    time_updated: now,
    value_json: {
      default: scope?.default ?? (((projectedState?.in_scope?.length ?? 0) > 0 || (projectedState?.out_of_scope?.length ?? 0) > 0) ? "ask" : "allow"),
      in_scope: scope?.in_scope ?? projectedState?.in_scope ?? [],
      out_of_scope: scope?.out_of_scope ?? projectedState?.out_of_scope ?? [],
      opsec: level,
    },
  }
  await mkdir(cyberDir(workspace, slug), { recursive: true })
  await appendFile(
    cyberFactsFile(workspace, slug),
    `${JSON.stringify(operationState)}\n${JSON.stringify(scopePolicy)}\n`,
    "utf8",
  )
  await touch(workspace, slug)
}
