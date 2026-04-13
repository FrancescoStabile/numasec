/**
 * Tool: http_request
 *
 * Raw HTTP request tool for security testing. Full control over method,
 * headers, body, cookies.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { httpRequest } from "../http-client"
import { makeToolResultEnvelope } from "./result-envelope"

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
  const names = Object.keys(headers).sort((left, right) => left.localeCompare(right))
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

function hasSqliPayloadSignal(value: string) {
  return /('(?:\s*--|\s+or\s+|%27)|union\s+select|sleep\s*\(|waitfor\s+delay|\)\)\s*or\s*\()/i.test(value)
}

function hasAuthSuccessSignal(value: string) {
  return /"authentication"\s*:|"token"\s*:|"session"\s*:|welcome|login succeeded|auth/i.test(value)
}

function hasVerboseErrorSignal(value: string) {
  if (/\n\s*at\s+[^\n]+/i.test(value)) return true
  if (/sequelizedatabaseerror|sqlite_error|postgreserror|mysql/i.test(value)) return true
  if (/<pre>[\s\S]*error[\s\S]*<\/pre>/i.test(value)) return true
  return false
}

const DESCRIPTION = `Make an HTTP request to a target URL. Use for:
- Sending crafted requests during security testing
- Testing specific endpoints with custom headers/body
- Verifying vulnerabilities with proof-of-concept payloads
- Checking server responses to malformed input

Returns: status code, headers, body, redirect chain, elapsed time.`

export const HttpRequestTool = Tool.define("http_request", {
  description: DESCRIPTION,
  parameters: z.object({
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
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "http_request",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url, method: params.method } as Record<string, any>,
    })

    const response = await httpRequest(params.url, {
      method: params.method,
      headers: params.headers,
      body: params.body,
      cookies: params.cookies,
      timeout: params.timeout,
      followRedirects: params.follow_redirects,
    })

    const headerLines = Object.entries(response.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n")

    const bodyPreview = response.body.length > 8000
      ? response.body.slice(0, 8000) + `\n... (truncated, ${response.body.length} bytes total)`
      : response.body

    const output = [
      `HTTP ${response.status} ${response.statusText}`,
      `URL: ${response.url}`,
      `Elapsed: ${response.elapsed}ms`,
      response.redirectChain.length > 0 ? `Redirect chain: ${response.redirectChain.join(" → ")} → ${response.url}` : "",
      "",
      "── Response Headers ──",
      headerLines,
      "",
      "── Response Body ──",
      bodyPreview,
    ]
      .filter(Boolean)
      .join("\n")

    const artifacts = [
      {
        key: "exchange",
        subtype: "http_exchange",
        request: {
          url: params.url,
          method: params.method,
          headers: params.headers ?? {},
          body: params.body ?? "",
          cookies: params.cookies ?? "",
        },
        response: {
          url: response.url,
          status: response.status,
          status_text: response.statusText,
          headers: response.headers,
          body: response.body,
          elapsed: response.elapsed,
          redirect_chain: response.redirectChain,
        },
        replay: replay({
          url: params.url,
          method: params.method,
          headers: params.headers,
          body: params.body,
          cookies: params.cookies,
        }),
      },
    ]

    const verifications: Record<string, any>[] = []
    const lower = response.body.toLowerCase()
    const origin = params.headers?.Origin ?? params.headers?.origin ?? ""
    const acao = response.headers["access-control-allow-origin"] ?? ""
    const acac = response.headers["access-control-allow-credentials"] ?? ""
    if (origin && acao === origin && acac === "true") {
      verifications.push({
        key: "cors-dangerous-reflection",
        family: "cors",
        kind: "credentialed_reflection",
        title: "Credentialed CORS origin reflection on sensitive endpoint",
        technical_severity: "high",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        evidence_keys: ["exchange"],
      })
    }
    if (acao === "*" && acac === "true") {
      verifications.push({
        key: "cors-dangerous-wildcard",
        family: "cors",
        kind: "wildcard_with_credentials",
        title: "Wildcard CORS with credentials enabled",
        technical_severity: "high",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        evidence_keys: ["exchange"],
      })
    }
    if (
      response.status === 200 &&
      (response.url.endsWith("/metrics") || lower.includes("process_cpu_user_seconds_total") || lower.includes("# help"))
    ) {
      verifications.push({
        key: "metrics-public",
        family: "metrics",
        kind: "prometheus_public",
        title: "Prometheus metrics exposed without authentication",
        technical_severity: "medium",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        evidence_keys: ["exchange"],
      })
    }
    const payload = `${params.url}\n${params.body ?? ""}`.toLowerCase()
    if (
      response.status >= 500 &&
      (lower.includes("sqlite") || lower.includes("mysql") || lower.includes("postgres") || lower.includes("oracle") || lower.includes("sql")) &&
      (payload.includes("union select") || payload.includes("'") || payload.includes("sleep(") || payload.includes("waitfor"))
    ) {
      verifications.push({
        key: "sqli-db-error",
        family: "sql_injection",
        kind: "db_error_signature",
        title: "SQL injection indicated by database error after crafted request",
        technical_severity: "high",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        parameter: "",
        payload: params.body ?? "",
        evidence_keys: ["exchange"],
      })
    }
    if (response.status >= 200 && response.status < 300 && hasSqliPayloadSignal(params.body ?? params.url) && hasAuthSuccessSignal(response.body)) {
      verifications.push({
        key: "sqli-auth-bypass",
        family: "sql_injection",
        kind: "auth_bypass",
        title: "SQL injection payload yielded authentication success",
        technical_severity: "critical",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        parameter: "",
        payload: params.body ?? "",
        evidence:
          "A suspicious SQL injection payload returned a successful authenticated response containing token/session markers.",
        evidence_keys: ["exchange"],
      })
    }
    if (response.status >= 500 && hasVerboseErrorSignal(response.body)) {
      verifications.push({
        key: "error-disclosure-stacktrace",
        family: "error_disclosure",
        kind: "stacktrace",
        title: "Verbose stack trace disclosed in HTTP response",
        technical_severity: "low",
        passed: true,
        control: "positive",
        url: response.url,
        method: params.method,
        evidence: "The response exposed verbose error details or a stack trace to the client.",
        evidence_keys: ["exchange"],
      })
    }

    return {
      title: `${params.method} ${params.url} → ${response.status}`,
      metadata: {
        status: response.status,
        elapsed: response.elapsed,
        contentLength: response.body.length,
        redirects: response.redirectChain.length,
      },
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts,
        verifications,
        metrics: {
          status: response.status,
          elapsed_ms: response.elapsed,
          content_length: response.body.length,
          redirects: response.redirectChain.length,
        },
      }),
      output,
    }
  },
})
