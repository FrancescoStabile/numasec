import z from "zod"
import { Effect } from "effect"
import { and, eq, inArray } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { EvidenceGraphStore } from "../evidence-store"
import { canonicalSecuritySessionID } from "../security-session"
import { makeToolResultEnvelope } from "./result-envelope"

type EvidenceNodeID = (typeof EvidenceNodeTable)["$inferInsert"]["id"]

function nodeID(value: string): EvidenceNodeID {
  return value as EvidenceNodeID
}

const DESCRIPTION = `Extract typed observations from artifact text or artifact nodes.
Supports deterministic extractors for URL, status code, server header, and keyword matches.`

const EXTRACTOR = z.enum(["url", "status_code", "server_header", "keyword"])
const SKIP_TEXT_KEYS = new Set(["sha256", "artifact_id", "path", "relative_path", "mime_type", "source_tool"])

function collectText(input: unknown, out: string[]) {
  if (typeof input === "string") {
    out.push(input)
    return
  }
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) {
      collectText(item, out)
    }
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    if (SKIP_TEXT_KEYS.has(key)) continue
    collectText(value[key], out)
  }
}

function collectStructured(input: unknown, statusOut: string[], urlOut: string[], serverOut: string[]) {
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) {
      collectStructured(item, statusOut, urlOut, serverOut)
    }
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    const field = key.toLowerCase()
    const item = value[key]
    if (field === "headers" && item && typeof item === "object" && !Array.isArray(item)) {
      const headers = item as Record<string, unknown>
      for (const name of Object.keys(headers)) {
        if (name.toLowerCase() !== "server") continue
        const header = headers[name]
        if (typeof header === "string" && header.trim().length > 0) serverOut.push(header.trim())
      }
    }
    if (field === "server" && typeof item === "string" && item.trim().length > 0) {
      serverOut.push(item.trim())
    }
    if ((field === "url" || field === "uri" || field === "endpoint") && typeof item === "string" && item.startsWith("http")) {
      urlOut.push(item)
    }
    if (field === "status" || field === "status_code" || field === "statuscode" || field === "response_status" || field === "http_status") {
      if (typeof item === "number" && item >= 100 && item <= 599) statusOut.push(String(Math.floor(item)))
      if (typeof item === "string") {
        const parsed = Number(item.trim())
        if (Number.isInteger(parsed) && parsed >= 100 && parsed <= 599) statusOut.push(String(parsed))
      }
    }
    collectStructured(item, statusOut, urlOut, serverOut)
  }
}

type Observation = {
  key: string
  value: string
  extractor: z.infer<typeof EXTRACTOR>
}

function runExtractor(text: string, extractor: z.infer<typeof EXTRACTOR>, keyword: string): Observation[] {
  const rows: Observation[] = []
  if (extractor === "url") {
    const re = /https?:\/\/[^\s"'<>)]+/gi
    let match: RegExpExecArray | null
    while ((match = re.exec(text)) !== null) {
      rows.push({ key: "url", value: match[0], extractor })
    }
    return rows
  }
  if (extractor === "status_code") {
    const patterns = [
      /HTTP\/[0-9.]+\s+([1-5][0-9]{2})/gi,
      /(?:^|[\s{,"'])status(?:_code|code)?[\s"']*[:=]\s*([1-5][0-9]{2})\b/gi,
      /status\s+code\s+([1-5][0-9]{2})\b/gi,
    ]
    for (const re of patterns) {
      let match: RegExpExecArray | null
      while ((match = re.exec(text)) !== null) {
        rows.push({ key: "status_code", value: match[1], extractor })
      }
    }
    return rows
  }
  if (extractor === "server_header") {
    const patterns = [/(?:^|\n)\s*server:\s*([^\n\r]+)/gi, /"server"\s*:\s*"([^"]+)"/gi]
    let match: RegExpExecArray | null
    for (const re of patterns) {
      while ((match = re.exec(text)) !== null) {
        rows.push({ key: "server_header", value: match[1].trim(), extractor })
      }
    }
    return rows
  }
  if (!keyword) return rows
  const needle = keyword.toLowerCase()
  if (text.toLowerCase().includes(needle)) {
    rows.push({ key: "keyword", value: keyword, extractor })
  }
  return rows
}

export const ExtractObservationTool = Tool.define("extract_observation", {
  description: DESCRIPTION,
  parameters: z.object({
    artifact_refs: z.array(z.string()).optional().describe("Artifact node ids"),
    text: z.string().optional().describe("Raw text to extract from"),
    extractors: z.array(EXTRACTOR).optional().describe("Extractor list"),
    keyword: z.string().optional().describe("Keyword used by keyword extractor"),
    persist: z.boolean().optional().describe("Persist extracted observations as nodes"),
  }),
  async execute(params, ctx) {
    const sessionID = canonicalSecuritySessionID(ctx.sessionID)
    const source: string[] = []
    const statusHints: string[] = []
    const urlHints: string[] = []
    const serverHints: string[] = []
    if (params.text) source.push(params.text)

    const refs = params.artifact_refs
    if (refs && refs.length > 0) {
      const nodes = Database.use((db) =>
        db
          .select()
          .from(EvidenceNodeTable)
          .where(
            and(
              eq(EvidenceNodeTable.session_id, sessionID),
              inArray(EvidenceNodeTable.id, refs.map(nodeID)),
            ),
          )
          .all(),
      )
      for (const item of nodes) {
        collectText(item.payload, source)
        collectStructured(item.payload, statusHints, urlHints, serverHints)
      }
    }

    if (source.length === 0 && statusHints.length === 0 && urlHints.length === 0 && serverHints.length === 0) {
      return {
        title: "No extraction source",
        metadata: { observations: 0 } as any,
        envelope: makeToolResultEnvelope({
          status: "inconclusive",
          observations: [
            {
              type: "observation_extract",
              count: 0,
            },
          ],
        }),
        output: "Provide text or artifact_refs for extract_observation.",
      }
    }

    const extractors: z.infer<typeof EXTRACTOR>[] =
      params.extractors && params.extractors.length > 0 ? params.extractors : ["url", "status_code"]
    const keyword = params.keyword ?? ""

    const observations: Observation[] = []
    for (const extractor of extractors) {
      if (extractor === "status_code") {
        for (const value of statusHints) {
          observations.push({ key: "status_code", value, extractor })
        }
      }
      if (extractor === "url") {
        for (const value of urlHints) {
          observations.push({ key: "url", value, extractor })
        }
      }
      if (extractor === "server_header") {
        for (const value of serverHints) {
          observations.push({ key: "server_header", value, extractor })
        }
      }
    }
    for (const text of source) {
      for (const extractor of extractors) {
        const rows = runExtractor(text, extractor, keyword)
        for (const row of rows) {
          observations.push(row)
        }
      }
    }

    const dedup = new Set<string>()
    const unique: Observation[] = []
    for (const item of observations) {
      const key = `${item.extractor}:${item.key}:${item.value}`
      if (dedup.has(key)) continue
      dedup.add(key)
      unique.push(item)
    }

    const persist = params.persist !== false
    const nodeIDs: string[] = []
    if (persist) {
      for (const item of unique) {
        const row = Effect.runSync(
          EvidenceGraphStore.use((store) =>
            store.upsertNode({
              sessionID,
              type: "observation",
              confidence: 0.7,
              status: "active",
              sourceTool: "extract_observation",
              payload: {
                key: item.key,
                value: item.value,
                extractor: item.extractor,
              },
            }),
          ).pipe(Effect.provide(EvidenceGraphStore.layer)),
        )
        nodeIDs.push(row.id)
      }
    }

    return {
      title: `Extracted ${unique.length} observation(s)`,
      metadata: {
        count: unique.length,
        persisted: persist,
      } as any,
      envelope: makeToolResultEnvelope({
        status: unique.length > 0 ? "ok" : "inconclusive",
        observations: unique.map((item, idx) => ({
          type: "observation",
          index: idx,
          key: item.key,
          value: item.value,
          extractor: item.extractor,
          node_id: nodeIDs[idx],
        })),
        metrics: {
          count: unique.length,
        },
      }),
      output: JSON.stringify(
        {
          count: unique.length,
          observations: unique,
          node_ids: nodeIDs,
        },
        null,
        2,
      ),
    }
  },
})
