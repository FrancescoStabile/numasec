/**
 * Tool: http_request
 *
 * Raw HTTP request tool for security testing. Full control over method,
 * headers, body, cookies.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { inventoryCandidates } from "../resource-inference"
import {
  actorIdentityFromMaterial,
  actorSessionRequest,
  httpAuthMaterial,
  mergeActorSession,
} from "../runtime/actor-session-store"
import {
  failureObservation,
  recoveryObservation,
} from "../runtime/execution-failure"
import { executeHttpWithRecovery } from "../runtime/http-execution"
import { persistEngagementTarget } from "../target-store"
import { hasAuthSuccessSignal, hasSqliPayloadSignal, hasVerboseErrorSignal } from "../http-signals"
import { makeToolResultEnvelope } from "./result-envelope"

function shell(value: string) {
  return value.replace(/'/g, "'\\''")
}

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
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
    actor_session_id: z.string().optional().describe("Optional shared actor session ID for automatic auth hydration"),
    actor_label: z.string().optional().describe("Optional shared actor label used to derive actor_session_id when omitted"),
    timeout: z.number().optional().describe("Timeout in milliseconds (default 15000)"),
    follow_redirects: z.boolean().optional().describe("Follow redirects (default true)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "http_request",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, method: params.method } as Record<string, any>,
    })
    persistEngagementTarget({
      sessionID: ctx.sessionID,
      url: params.url,
      source: "http_request",
    })

    const seeded = await mergeActorSession({
      sessionID: ctx.sessionID,
      actorSessionID: params.actor_session_id,
      actorLabel: params.actor_label,
      material: httpAuthMaterial({
        actorLabel: params.actor_label,
        url: params.url,
        requestHeaders: params.headers,
        requestCookies: params.cookies,
      }),
    })
    const auth = actorSessionRequest(seeded, params.headers, params.cookies)
    const execution = await executeHttpWithRecovery({
      sessionID: ctx.sessionID,
      toolName: "http_request",
      action: params.method,
      actorSessionID: seeded.actorSessionID,
      url: params.url,
      request: {
        method: params.method,
        headers: auth.headers,
        body: params.body,
        cookies: auth.cookies || undefined,
        timeout: params.timeout,
        followRedirects: params.follow_redirects,
      },
    })
    const response = execution.response
    const stored = await mergeActorSession({
      sessionID: ctx.sessionID,
      actorSessionID: seeded.actorSessionID,
      actorLabel: seeded.actorLabel,
      material: httpAuthMaterial({
        actorLabel: seeded.actorLabel,
        url: response.url,
        requestHeaders: auth.headers,
        requestCookies: auth.cookies,
        responseHeaders: response.headers,
        responseBody: response.body,
        setCookies: response.setCookies,
      }),
    })
    const actor = actorIdentityFromMaterial(stored)

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
      execution.profile ? `Execution profile: ${execution.profile.status} (pacing=${execution.profile.pacing_ms}ms jitter=${execution.profile.jitter_ms}ms retry_budget=${execution.profile.retry_budget})` : "",
      execution.failure ? `Failure: ${execution.failure.code} (${execution.failure.message})` : "",
      execution.recovery ? `Recovery: ${execution.recovery.strategy} after ${execution.recovery.attempts} attempt(s)` : "",
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
          headers: auth.headers,
          body: params.body ?? "",
          cookies: auth.cookies ?? "",
        },
        response: {
          url: response.url,
          status: response.status,
          status_text: response.statusText,
          headers: response.headers,
          set_cookies: response.setCookies,
          body: response.body,
          elapsed: response.elapsed,
          redirect_chain: response.redirectChain,
        },
        replay: replay({
          url: params.url,
          method: params.method,
          headers: auth.headers,
          body: params.body,
          cookies: auth.cookies,
        }),
      },
    ]

    const observations: Record<string, any>[] = []
    if (execution.failure) observations.push(failureObservation(execution.failure))
    if (execution.recovery) observations.push(recoveryObservation(execution.recovery))
    let actorKey = ""
    if (actor.id || actor.email || actor.role) {
      actorKey = `actor-${slug(actor.email || actor.id || actor.label)}`
      observations.push({
        key: actorKey,
        family: "actor_inventory",
        kind: "observed_actor",
        actor_label: actor.label,
        actor_id: actor.id,
        actor_email: actor.email,
        actor_role: actor.role,
        privileged: actor.privileged,
        source: actor.source,
        actor_session_id: stored.actorSessionID,
        url: params.url,
        method: params.method,
      })
    }
    const candidates = inventoryCandidates(response.body, actor.id || actor.email || actor.role ? actor : undefined).slice(0, 20)
    let index = 0
    for (const item of candidates) {
      observations.push({
        key: `resource-${slug(new URL(response.url).pathname || "root")}-${slug(item.id || item.email || item.owner || item.tenant || String(index++))}-${item.exposure}`,
        family: "resource_inventory",
        kind: "candidate",
        url: response.url,
        method: params.method,
        source_kind: item.source,
        actor_id: actor.id,
        actor_email: actor.email,
        actor_role: actor.role,
        actor_session_id: stored.actorSessionID,
        resource_id: item.id,
        resource_email: item.email,
        owner_id: item.owner,
        tenant_id: item.tenant,
        creator_id: item.creator,
        resource_role: item.role,
        resource_state: item.state,
        exposure: item.exposure,
        parent_key: actorKey || undefined,
      })
    }

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
        actorSessionID: stored.actorSessionID,
        failureCode: execution.failure?.code,
        recoveryAttempts: execution.recovery?.attempts ?? 0,
        targetProfileStatus: execution.profile?.status,
        },
      envelope: makeToolResultEnvelope({
        status: execution.failure ? (execution.failure.retryable ? "retryable_error" : "inconclusive") : "ok",
        artifacts,
        observations,
        verifications,
        metrics: {
          status: response.status,
          elapsed_ms: response.elapsed,
          content_length: response.body.length,
          redirects: response.redirectChain.length,
          inventory_candidates: candidates.length,
          recovery_attempts: execution.recovery?.attempts ?? 0,
          pacing_ms: execution.profile?.pacing_ms ?? 0,
          retry_budget: execution.profile?.retry_budget ?? 0,
        },
        error: execution.failure
          ? {
              code: execution.failure.code,
              message: execution.failure.message,
            }
          : undefined,
      }),
      output,
    }
  },
})
