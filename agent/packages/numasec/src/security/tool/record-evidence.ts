import z from "zod"
import { Effect } from "effect"
import { Tool } from "../../tool/tool"
import { EvidenceGraphStore } from "../evidence-store"
import {
  DEFAULT_INLINE_BYTES,
  encodeArtifactPayload,
  makeArtifactReference,
  persistEvidenceArtifact,
  shouldPersistArtifact,
} from "../artifact-store"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Record or upsert one evidence node in the canonical graph.
Use this primitive whenever an observation, artifact, hypothesis, or finding must be persisted.`

function normalizeHeaders(input: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  const keys = Object.keys(input).sort((left, right) => left.localeCompare(right))
  for (const key of keys) {
    out[key.toLowerCase()] = input[key] ?? ""
  }
  return out
}

function replayFromRequest(input: {
  url?: string
  method?: string
  headers?: Record<string, string>
  body?: string
}): string {
  const method = (input.method ?? "GET").toUpperCase()
  const url = input.url ?? ""
  const parts: string[] = [`curl -i -X ${method}`]
  if (url) parts.push(`'${url.replace(/'/g, "'\\''")}'`)
  const headers = input.headers ?? {}
  const names = Object.keys(headers).sort((left, right) => left.localeCompare(right))
  for (const name of names) {
    parts.push(`-H '${name}: ${(headers[name] ?? "").replace(/'/g, "'\\''")}'`)
  }
  if (input.body) {
    parts.push(`--data-raw '${input.body.replace(/'/g, "'\\''")}'`)
  }
  return parts.join(" ")
}

function parsePayload(params: {
  payload?: Record<string, unknown>
  payload_text?: string
  payload_json?: string
}): Record<string, unknown> {
  const base: Record<string, unknown> = {}
  if (params.payload) {
    for (const key of Object.keys(params.payload)) base[key] = params.payload[key]
  }
  if (typeof params.payload_text === "string" && params.payload_text.length > 0) {
    base.payload_text = params.payload_text
  }
  if (typeof params.payload_json === "string" && params.payload_json.length > 0) {
    try {
      const parsed = JSON.parse(params.payload_json)
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("payload_json must decode to a JSON object")
      }
      base.payload_json = parsed
    } catch (cause) {
      throw new Error(`record_evidence payload_json parse failed: ${String(cause)}`)
    }
  }
  return base
}

export const RecordEvidenceTool = Tool.define("record_evidence", {
  description: DESCRIPTION,
  parameters: z
    .object({
      type: z.string().describe("Evidence node type: observation, artifact, hypothesis, finding, etc."),
      payload: z.record(z.string(), z.any()).optional().describe("Structured node payload"),
      payload_text: z.string().optional().describe("Raw text payload (ergonomic path for long evidence)"),
      payload_json: z.string().optional().describe("Stringified JSON payload (ergonomic path for long evidence)"),
      request: z
        .object({
          url: z.string().optional(),
          method: z.string().optional(),
          headers: z.record(z.string(), z.string()).optional(),
          body: z.string().optional(),
        })
        .optional()
        .describe("Optional canonical request block"),
      response: z
        .object({
          status: z.number().int().optional(),
          headers: z.record(z.string(), z.string()).optional(),
          body: z.string().optional(),
        })
        .optional()
        .describe("Optional canonical response block"),
      replay: z.string().optional().describe("Optional reproducible replay snippet"),
      fingerprint: z.string().optional().describe("Deterministic fingerprint (auto-generated if omitted)"),
      source_tool: z.string().optional().describe("Tool that produced this evidence"),
      confidence: z.number().min(0).max(1).optional().describe("Confidence score 0..1"),
      status: z.string().optional().describe("Node status, default active"),
      artifact_mode: z
        .enum(["auto", "inline", "external"])
        .optional()
        .describe("Artifact storage mode: auto stores large payloads externally"),
      max_inline_bytes: z.number().int().min(512).max(1024 * 1024).optional().describe("Inline payload size threshold"),
    })
    .refine((item) => {
      if (item.payload) return true
      if (item.payload_text) return true
      if (item.payload_json) return true
      return false
    }, "record_evidence requires payload, payload_text, or payload_json"),
  async execute(params, ctx) {
    const mode = params.artifact_mode ?? "auto"
    const maxInlineBytes = params.max_inline_bytes ?? DEFAULT_INLINE_BYTES
    const payload = parsePayload({
      payload: params.payload,
      payload_text: params.payload_text,
      payload_json: params.payload_json,
    })
    if (params.request) {
      payload.request = {
        url: params.request.url ?? "",
        method: params.request.method ?? "",
        headers: normalizeHeaders(params.request.headers ?? {}),
        body: params.request.body ?? "",
      }
    }
    if (params.response) {
      payload.response = {
        status: params.response.status ?? 0,
        headers: normalizeHeaders(params.response.headers ?? {}),
        body: params.response.body ?? "",
      }
    }
    if (params.replay) payload.replay = params.replay
    if (!params.replay && params.request) payload.replay = replayFromRequest(params.request)
    payload.schema_version = "evidence_payload_v2"

    const payloadText = encodeArtifactPayload(payload)
    const payloadBytes = new TextEncoder().encode(payloadText).length
    const external = shouldPersistArtifact(payloadBytes, mode, maxInlineBytes)

    let artifact: Awaited<ReturnType<typeof persistEvidenceArtifact>> | undefined
    let content = payload
    if (external) {
      artifact = await persistEvidenceArtifact({
        sessionID: ctx.sessionID,
        payload,
        sourceTool: params.source_tool,
      })
      content = makeArtifactReference(artifact)
    }

    const row = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
          type: params.type,
          payload: content,
          fingerprint: params.fingerprint ?? artifact?.sha256,
          sourceTool: params.source_tool,
          confidence: params.confidence,
          status: params.status,
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    return {
      title: `Evidence node: ${row.type} (${row.id})`,
      metadata: {
        id: row.id,
        type: row.type,
        status: row.status,
        fingerprint: row.fingerprint,
        payloadBytes,
        artifactID: artifact?.id ?? "",
        artifactStored: external,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "evidence_node",
            node_id: row.id,
            node_type: row.type,
            status: row.status,
            fingerprint: row.fingerprint,
          },
        ],
        artifacts: artifact
          ? [
              {
                type: "evidence_artifact",
                artifact_id: artifact.id,
                sha256: artifact.sha256,
                size_bytes: artifact.size_bytes,
                mime_type: artifact.mime_type,
                path: artifact.relative_path,
              },
            ]
          : [],
        metrics: {
          payload_bytes: payloadBytes,
          artifact_stored: artifact ? 1 : 0,
        },
      }),
      output: [
        `Node ID: ${row.id}`,
        `Type: ${row.type}`,
        `Status: ${row.status}`,
        `Fingerprint: ${row.fingerprint}`,
        `Payload bytes: ${payloadBytes}`,
        `Artifact: ${artifact ? `${artifact.id} (${artifact.relative_path})` : "inline"}`,
      ].join("\n"),
    }
  },
})
