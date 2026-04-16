import z from "zod"
import { Effect } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import * as Tool from "./tool"
import DESCRIPTION from "./http-request.txt"

const MAX_BODY = 8000
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

          yield* ctx.ask({
            permission: "http_request",
            patterns: [params.url],
            always: [],
            metadata: { url: params.url, method: params.method },
          })

          const timeout = Math.min(params.timeout ?? DEFAULT_TIMEOUT, MAX_TIMEOUT)
          const merged: Record<string, string> = { ...(params.headers ?? {}) }
          if (params.cookies) {
            merged["Cookie"] = params.cookies
          }

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
