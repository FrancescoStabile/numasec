import z from "zod"
import { Effect } from "effect"
import { gunzipSync } from "node:zlib"
import fs from "node:fs"
import * as Tool from "./tool"
import DESCRIPTION from "./cve.txt"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"
// Bundle lives at repo-root `assets/cve/index.json.gz` and is embedded via
// Bun's `type: "file"` import so the compiled binary ships with it.
import BUNDLE_PATH from "../../../../assets/cve/index.json.gz" with { type: "file" }

type Severity = "low" | "medium" | "high" | "critical"

type Entry = {
  id: string
  severity: Severity
  cvss: number
  summary: string
  cpe: string[]
  published: string
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

const parameters = z.object({
  query: z.string().min(1).describe("CVE id, vendor/product name, or keyword. Case-insensitive substring match against id, summary, and cpe entries."),
  severity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Filter results to this severity or higher."),
  limit: z.coerce.number().int().min(1).max(50).optional().describe("Max results to return (default 10, max 50)."),
})

type Params = z.infer<typeof parameters>

type Cache =
  | { kind: "ready"; entries: Entry[] }
  | { kind: "missing"; reason: string }

let cache: Cache | undefined

function loadBundle(): Cache {
  if (cache) return cache
  try {
    if (!fs.existsSync(BUNDLE_PATH)) {
      cache = {
        kind: "missing",
        reason:
          "CVE bundle not shipped with this build — run `gh workflow run cve-refresh` or wait for the scheduled refresh",
      }
      return cache
    }
    const gz = fs.readFileSync(BUNDLE_PATH)
    const raw = gunzipSync(gz).toString("utf8")
    const parsed = JSON.parse(raw) as Entry[]
    cache = { kind: "ready", entries: parsed }
    return cache
  } catch (err) {
    cache = {
      kind: "missing",
      reason: `CVE bundle failed to load (${(err as Error).message}) — run \`gh workflow run cve-refresh\` or wait for the scheduled refresh`,
    }
    return cache
  }
}

function matches(entry: Entry, q: string): boolean {
  if (entry.id.toLowerCase().includes(q)) return true
  if (entry.summary.toLowerCase().includes(q)) return true
  for (const cpe of entry.cpe) if (cpe.toLowerCase().includes(q)) return true
  return false
}

function search(params: Params, entries: Entry[]): Entry[] {
  const q = params.query.trim().toLowerCase()
  const minRank = params.severity ? SEVERITY_RANK[params.severity] : 0
  const filtered = entries.filter((e) => SEVERITY_RANK[e.severity] >= minRank && matches(e, q))
  filtered.sort((a, b) => {
    const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    if (rank !== 0) return rank
    return b.published.localeCompare(a.published)
  })
  return filtered.slice(0, params.limit ?? 10)
}

type Metadata = {
  available: boolean
  reason?: string
  returned?: number
  total_indexed?: number
}

export const CVETool = Tool.define<typeof parameters, Metadata, never>(
  "cve",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "cve",
            patterns: [params.query],
            always: ["*"],
            metadata: { query: params.query, severity: params.severity ?? null },
          })

          const bundle = loadBundle()
          if (bundle.kind === "missing") {
            const metadata: Metadata = { available: false, reason: bundle.reason }
            return {
              title: `cve: unavailable`,
              output: JSON.stringify({ available: false, reason: bundle.reason }, null, 2),
              metadata,
            }
          }

          const hits = search(params, bundle.entries)
          const metadata: Metadata = {
            available: true,
            returned: hits.length,
            total_indexed: bundle.entries.length,
          }
          const output = JSON.stringify(
            {
              available: true,
              total_indexed: bundle.entries.length,
              returned: hits.length,
              query: params.query,
              severity_floor: params.severity ?? null,
              results: hits,
            },
            null,
            2,
          )
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(workspace, slug, output, {
                    mime: "application/json",
                    ext: "json",
                    label: `cve ${params.query}`,
                    source: "cve",
                  }),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "cve",
            summary: `cve lookup ${params.query}: ${hits.length} hit${hits.length === 1 ? "" : "s"}`,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            evidence_refs: evidenceRefs,
            data: {
              query: params.query,
              severity: params.severity ?? null,
              returned: hits.length,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          for (const hit of hits) {
            yield* Cyber.upsertFact({
              entity_kind: "cve",
              entity_key: hit.id,
              fact_name: "details",
              value_json: hit,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              src_kind: "knowledge_query",
              src_key: `cve:${params.query}`,
              relation: "matched",
              dst_kind: "cve",
              dst_key: hit.id,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }
          return {
            title: `cve: ${hits.length} hit${hits.length === 1 ? "" : "s"} for "${params.query}"`,
            output,
            metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
