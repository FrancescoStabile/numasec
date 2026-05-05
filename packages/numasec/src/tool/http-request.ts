import z from "zod"
import { Effect } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import * as Tool from "./tool"
import DESCRIPTION from "./http-request.txt"
import { Guard, ScopeDeniedError } from "@/core/boundary"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { activeIdentity } from "@/core/vault"
import { Instance } from "@/project/instance"

const MAX_BODY = 8000
const EVIDENCE_BODY = 64_000
const DEFAULT_TIMEOUT = 15_000
const MAX_TIMEOUT = 120_000

const parameters = z.object({
  url: z.string().describe("The URL to request"),
  method: z
    .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    .default("GET")
    .describe("HTTP method"),
  headers: z.record(z.string(), z.string()).optional().describe("Request headers as key-value pairs"),
  body: z.string().optional().describe("Request body (for POST/PUT/PATCH)"),
  cookies: z.string().optional().describe("Cookie header value"),
  timeout: z.number().optional().describe("Timeout in milliseconds (default 15000)"),
  follow_redirects: z.boolean().optional().describe("Follow redirects (default true)"),
})

function shell(value: string) {
  return value.replace(/'/g, "'\\''")
}

function replay(input: {
  url: string
  method: string
  headers?: Record<string, string>
  body?: string
  cookies?: string
}) {
  const parts: string[] = [`curl -i -X ${input.method}`]
  parts.push(`'${shell(input.url)}'`)
  const headers = input.headers ?? {}
  const names = Object.keys(headers).sort((a, b) => a.localeCompare(b))
  for (const name of names) {
    parts.push(`-H '${shell(name)}: ${shell(headers[name] ?? "")}'`)
  }
  if (input.cookies) {
    parts.push(`-H 'Cookie: ${shell(input.cookies)}'`)
  }
  if (input.body) {
    parts.push(`--data-raw '${shell(input.body)}'`)
  }
  return parts.join(" ")
}

export const HttpRequestTool = Tool.define(
  "http_request",
  Effect.gen(function* () {
    const http = yield* HttpClient.HttpClient

    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: z.infer<typeof parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
            throw new Error("URL must start with http:// or https://")
          }

          const scope = yield* Effect.tryPromise({
            try: () => Guard.checkUrl(Instance.directory, params.url),
            catch: (e) => (e instanceof ScopeDeniedError ? e : new Error(String(e))),
          })
          const identity = yield* Effect.promise(() => activeIdentity().catch(() => undefined))

          yield* ctx.ask({
            permission: "http_request",
            patterns: [params.url],
            always: [],
            metadata: {
              url: params.url,
              method: params.method,
              scope: scope.mode,
              scope_reason: scope.reason,
              scope_matched: scope.matched,
              active_identity: identity?.key,
              active_identity_mode: identity?.mode,
            },
          })

          const timeout = Math.min(params.timeout ?? DEFAULT_TIMEOUT, MAX_TIMEOUT)
          const merged: Record<string, string> = { ...(identity?.headers ?? {}), ...(params.headers ?? {}) }
          if (identity?.cookies && !params.cookies) merged["Cookie"] = identity.cookies
          if (params.cookies) merged["Cookie"] = params.cookies

          const request = HttpClientRequest.make(params.method)(params.url).pipe(
            HttpClientRequest.setHeaders(merged),
            (req) => (params.body ? HttpClientRequest.bodyText(req, params.body) : req),
          )

          const start = Date.now()

          const response = yield* http.execute(request).pipe(
            Effect.timeoutOrElse({
              duration: timeout,
              orElse: () => Effect.die(new Error(`Request timed out after ${timeout}ms`)),
            }),
          )
          const elapsed = Date.now() - start

          const body = yield* response.text
          const status = response.status
          const headers = response.headers

          const headerLines = Object.entries(headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n")

          const preview =
            body.length > MAX_BODY
              ? body.slice(0, MAX_BODY) + `\n... (truncated, ${body.length} bytes total)`
              : body

          const curl = replay({
            url: params.url,
            method: params.method,
            headers: params.headers,
            body: params.body,
            cookies: params.cookies,
          })

          const output = [
            `HTTP ${status}`,
            `URL: ${params.url}`,
            `Elapsed: ${elapsed}ms`,
            "",
            "── Response Headers ──",
            headerLines,
            "",
            "── Response Body ──",
            preview,
            "",
            "── Replay ──",
            curl,
          ]
            .filter(Boolean)
            .join("\n")

          const workspace = Instance.directory
          const target = new URL(params.url)
          const hostKey = target.hostname
          const port = target.port || (target.protocol === "https:" ? "443" : "80")
          const serviceKey = `${hostKey}:${port}`
          const routeKey = `${target.origin}${target.pathname || "/"}`
          const responseContentType =
            Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1] ?? null
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(
                    workspace,
                    slug,
                    JSON.stringify(
                      {
                        request: {
                          url: params.url,
                          method: params.method,
                          headers: merged,
                          cookies: merged["Cookie"],
                          body: params.body,
                          active_identity: identity?.key,
                        },
                        response: {
                          status,
                          headers,
                          body: body.slice(0, EVIDENCE_BODY),
                          body_truncated: body.length > EVIDENCE_BODY,
                          body_length: body.length,
                          elapsed_ms: elapsed,
                        },
                        replay: curl,
                      },
                      null,
                      2,
                    ),
                    {
                      mime: "application/json",
                      ext: "json",
                      label: `${params.method} ${routeKey}`,
                      source: "http_request",
                    },
                  ),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "http_request",
            status: `${status}`,
            summary: `${params.method} ${routeKey} -> ${status}`,
            evidence_refs: evidenceRefs,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            data: {
              host: hostKey,
              service: serviceKey,
              route: routeKey,
              method: params.method,
              status,
              elapsed_ms: elapsed,
              content_type: responseContentType,
              active_identity: identity?.key,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "host",
            entity_key: hostKey,
            fact_name: "last_seen_url",
            value_json: target.origin,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "service",
            entity_key: serviceKey,
            fact_name: "transport",
            value_json: target.protocol.replace(":", ""),
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertFact({
            entity_kind: "http_route",
            entity_key: routeKey,
            fact_name: "last_response",
            value_json: {
              method: params.method,
              status,
              content_type: responseContentType,
              elapsed_ms: elapsed,
            },
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertRelation({
            src_kind: "host",
            src_key: hostKey,
            relation: "exposes",
            dst_kind: "service",
            dst_key: serviceKey,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          yield* Cyber.upsertRelation({
            src_kind: "service",
            src_key: serviceKey,
            relation: "serves",
            dst_kind: "http_route",
            dst_key: routeKey,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: eventID || undefined,
            evidence_refs: evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed("")))
          if (identity?.key) {
            yield* Cyber.upsertRelation({
              src_kind: "identity",
              src_key: identity.key,
              relation: "used_on",
              dst_kind: "http_route",
              dst_key: routeKey,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          return {
            title: `${params.method} ${params.url} → ${status}`,
            metadata: {
              status,
              elapsed,
              contentLength: body.length,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
