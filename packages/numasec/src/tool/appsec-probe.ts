import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./appsec-probe.txt"
import { Guard, ScopeDeniedError } from "@/core/boundary"
import { Cyber } from "@/core/cyber"
import type { Fact } from "@/core/cyber/cyber"
import { Evidence } from "@/core/evidence"
import { autoEnrichKnowledge } from "@/core/knowledge"
import { Observation } from "@/core/observation"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

const MAX_BODY = 64_000
const DEFAULT_TIMEOUT = 15_000
const MAX_TIMEOUT = 120_000
const EVIL_ORIGIN = "https://evil.example"

const check = z.enum(["sqli_search", "xss_search", "broken_auth_jwt", "idor_basket", "weak_cors"])

const parameters = z.object({
  target: z.string().min(1).describe("absolute HTTP(S) URL to probe"),
  checks: z.array(check).optional().describe("optional subset of AppSec checks to run"),
  timeout: z.number().int().min(500).max(MAX_TIMEOUT).optional().describe("per-request timeout in milliseconds"),
})

type Check = z.infer<typeof check>
type Params = z.infer<typeof parameters>

type ProbeResult = {
  check: Check
  label: string
  method: string
  url: string
  status?: number
  headers: Record<string, string>
  body_preview?: string
  body_length?: number
  elapsed_ms?: number
  replay: string
  error?: string
}

type Candidate = {
  id: Check
  key: string
  title: string
  route: string
  severity: "info" | "low" | "medium" | "high" | "critical"
  confidence: number
  rationale: string
  signals: Record<string, unknown>
}

type ProbePlanItem = {
  check: Check
  label: string
  path: string
  route: string
  method?: string
  headers?: Record<string, string>
  body?: string
}

type ObservedRoute = {
  url: string
  route: string
}

type ObservedForm = {
  action: string
  method: string
  source?: string
  inputs: Array<Record<string, unknown>>
}

type Metadata = {
  target: string
  checks: Check[]
  candidates: number
  evidence?: string
  active_operation?: string
}

export const _deps = {
  fetch: (url: string, init: RequestInit) => fetch(url, init),
}

function normalizeTarget(target: string) {
  const parsed = new URL(target)
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("target must start with http:// or https://")
  }
  parsed.hash = ""
  return parsed
}

function shell(value: string) {
  return value.replace(/'/g, "'\\''")
}

function replay(input: { method: string; url: string; headers?: Record<string, string>; body?: string }) {
  const parts = [`curl -i -X ${input.method}`, `'${shell(input.url)}'`]
  const headers = input.headers ?? {}
  for (const name of Object.keys(headers).sort((a, b) => a.localeCompare(b))) {
    parts.push(`-H '${shell(name)}: ${shell(headers[name] ?? "")}'`)
  }
  if (input.body) parts.push(`--data-raw '${shell(input.body)}'`)
  return parts.join(" ")
}

function headersObject(headers: Headers) {
  const out: Record<string, string> = {}
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value
  })
  return out
}

function routeExists(result: ProbeResult) {
  return result.status !== undefined && result.status !== 404 && result.status !== 405
}

function includesAny(input: string | undefined, values: string[]) {
  const lower = (input ?? "").toLowerCase()
  return values.some((value) => lower.includes(value.toLowerCase()))
}

function candidateKey(origin: string, id: Check) {
  return `${origin}:${id}`
}

function routeUrl(origin: string, path: string) {
  return new URL(path, origin).href
}

function uniqueChecks(input?: Check[]) {
  const selected = input?.length ? input : check.options
  return [...new Set(selected)]
}

function asObject(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined
}

function routePathFromUrl(url: string) {
  try {
    const parsed = new URL(url)
    return `${parsed.pathname || "/"}${parsed.search}`
  } catch {
    return url
  }
}

function sameOrigin(origin: string, url: string) {
  try {
    return new URL(url).origin === origin
  } catch {
    return false
  }
}

function normalizeMethod(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim().toUpperCase() : "GET"
}

function routeKeywords(route: string, values: string[]) {
  const lower = route.toLowerCase()
  return values.some((value) => lower.includes(value))
}

function firstNamedInput(inputs: Array<Record<string, unknown>>, predicate: (input: Record<string, unknown>) => boolean) {
  for (const input of inputs) {
    if (!predicate(input)) continue
    if (typeof input.name === "string" && input.name) return input.name
    if (typeof input.id === "string" && input.id) return input.id
  }
  return undefined
}

function textInputName(inputs: Array<Record<string, unknown>>) {
  return firstNamedInput(inputs, (input) => {
    const type = typeof input.type === "string" ? input.type.toLowerCase() : ""
    return !["hidden", "password", "submit", "button", "checkbox", "radio", "file"].includes(type)
  })
}

function passwordInputName(inputs: Array<Record<string, unknown>>) {
  return firstNamedInput(inputs, (input) => {
    const type = typeof input.type === "string" ? input.type.toLowerCase() : ""
    return type === "password"
  })
}

function emailLikeInputName(inputs: Array<Record<string, unknown>>) {
  return firstNamedInput(inputs, (input) => {
    const type = typeof input.type === "string" ? input.type.toLowerCase() : ""
    const name =
      typeof input.name === "string" ? input.name : typeof input.id === "string" ? input.id : typeof input.placeholder === "string" ? input.placeholder : ""
    return type === "email" || /email|user|login|account|name/i.test(name)
  })
}

async function request(input: {
  origin: string
  check: Check
  label: string
  path: string
  method?: string
  headers?: Record<string, string>
  body?: string
  timeout: number
  abort: AbortSignal
}): Promise<ProbeResult> {
  const url = routeUrl(input.origin, input.path)
  const method = input.method ?? "GET"
  const headers = {
    Accept: "application/json,text/html,*/*",
    "User-Agent": "numasec-appsec-probe/1.2",
    ...(input.body ? { "Content-Type": "application/json" } : {}),
    ...(input.headers ?? {}),
  }
  const curl = replay({ method, url, headers, body: input.body })
  const started = Date.now()
  try {
    const signal = AbortSignal.any([input.abort, AbortSignal.timeout(input.timeout)])
    const response = await _deps.fetch(url, {
      method,
      headers,
      body: input.body,
      redirect: "manual",
      signal,
    })
    const body = await response.text()
    return {
      check: input.check,
      label: input.label,
      method,
      url,
      status: response.status,
      headers: headersObject(response.headers),
      body_preview: body.slice(0, MAX_BODY),
      body_length: body.length,
      elapsed_ms: Date.now() - started,
      replay: curl,
    }
  } catch (error) {
    return {
      check: input.check,
      label: input.label,
      method,
      url,
      headers: {},
      replay: curl,
      error: error instanceof Error ? error.message : String(error),
      elapsed_ms: Date.now() - started,
    }
  }
}

function dedupeRoutes(routes: ObservedRoute[]) {
  const seen = new Set<string>()
  return routes.filter((route) => {
    if (seen.has(route.url)) return false
    seen.add(route.url)
    return true
  })
}

function routeFromFact(fact: Fact): ObservedRoute | undefined {
  if (fact.entity_kind !== "http_route") return undefined
  const value = asObject(fact.value_json)
  return {
    url: fact.entity_key,
    route: typeof value?.route === "string" && value.route ? value.route : routePathFromUrl(fact.entity_key),
  }
}

function formFromFact(fact: Fact): ObservedForm | undefined {
  if (fact.entity_kind !== "http_form" || fact.fact_name !== "shape") return undefined
  const value = asObject(fact.value_json)
  if (!value) return undefined
  if (typeof value.action !== "string" || !value.action) return undefined
  return {
    action: value.action,
    method: normalizeMethod(value.method),
    source: typeof value.source === "string" ? value.source : undefined,
    inputs: Array.isArray(value.inputs)
      ? value.inputs
          .map((item) => asObject(item))
          .filter((item): item is Record<string, unknown> => Boolean(item))
      : [],
  }
}

async function observedSurface(workspace: string, slug: string, target: URL) {
  const facts = await Cyber.readProjectedFacts(workspace, slug).catch(() => [])
  const routes = dedupeRoutes(
    facts
      .map(routeFromFact)
      .filter((item): item is ObservedRoute => Boolean(item))
      .filter((item) => sameOrigin(target.origin, item.url)),
  )
  const forms = facts
    .map(formFromFact)
    .filter((item): item is ObservedForm => Boolean(item))
    .filter((item) => sameOrigin(target.origin, item.action))
  return { routes, forms }
}

function buildProbePlan(origin: string, routes: ObservedRoute[], forms: ObservedForm[]) {
  const plan: ProbePlanItem[] = []
  const skipped: string[] = []

  const reflectedForm = forms.find((form) => {
    const method = normalizeMethod(form.method)
    return ["GET", "POST"].includes(method) && Boolean(textInputName(form.inputs))
  })
  const reflectedRoute = routes.find((route) => {
    try {
      const url = new URL(route.url)
      if ([...url.searchParams.keys()].length > 0) return true
    } catch {}
    return routeKeywords(route.route, ["search", "query", "find", "filter"])
  })

  if (reflectedForm) {
    const payloadField = textInputName(reflectedForm.inputs) ?? "q"
    const method = normalizeMethod(reflectedForm.method)
    if (method === "GET") {
      const sqlUrl = new URL(reflectedForm.action, origin)
      sqlUrl.searchParams.set(payloadField, "' OR 1=1--")
      const xssUrl = new URL(reflectedForm.action, origin)
      xssUrl.searchParams.set(payloadField, "<script>numasec-xss</script>")
      plan.push({
        check: "sqli_search",
        label: `SQLi candidate probe on observed form ${routePathFromUrl(reflectedForm.action)}`,
        path: `${sqlUrl.pathname}${sqlUrl.search}`,
        route: routePathFromUrl(reflectedForm.action),
      })
      plan.push({
        check: "xss_search",
        label: `XSS candidate probe on observed form ${routePathFromUrl(reflectedForm.action)}`,
        path: `${xssUrl.pathname}${xssUrl.search}`,
        route: routePathFromUrl(reflectedForm.action),
      })
    } else {
      plan.push({
        check: "sqli_search",
        label: `SQLi candidate probe on observed form ${routePathFromUrl(reflectedForm.action)}`,
        path: routePathFromUrl(reflectedForm.action),
        route: routePathFromUrl(reflectedForm.action),
        method,
        body: JSON.stringify({ [payloadField]: "' OR 1=1--" }),
      })
      plan.push({
        check: "xss_search",
        label: `XSS candidate probe on observed form ${routePathFromUrl(reflectedForm.action)}`,
        path: routePathFromUrl(reflectedForm.action),
        route: routePathFromUrl(reflectedForm.action),
        method,
        body: JSON.stringify({ [payloadField]: "<script>numasec-xss</script>" }),
      })
    }
  } else if (reflectedRoute) {
    const route = new URL(reflectedRoute.url)
    const queryKey = [...route.searchParams.keys()][0] ?? "q"
    const sqlUrl = new URL(route.href)
    const xssUrl = new URL(route.href)
    sqlUrl.searchParams.set(queryKey, "' OR 1=1--")
    xssUrl.searchParams.set(queryKey, "<script>numasec-xss</script>")
    plan.push({
      check: "sqli_search",
      label: `SQLi candidate probe on observed route ${reflectedRoute.route}`,
      path: `${sqlUrl.pathname}${sqlUrl.search}`,
      route: reflectedRoute.route,
    })
    plan.push({
      check: "xss_search",
      label: `XSS candidate probe on observed route ${reflectedRoute.route}`,
      path: `${xssUrl.pathname}${xssUrl.search}`,
      route: reflectedRoute.route,
    })
  } else {
    skipped.push("No observed reflective input surface for SQLi/XSS probes.")
  }

  const authForm = forms.find((form) => {
    const route = routePathFromUrl(form.action)
    return Boolean(passwordInputName(form.inputs)) && routeKeywords(route, ["login", "auth", "signin", "session", "token"])
  })
  if (authForm) {
    const identityField = emailLikeInputName(authForm.inputs) ?? "username"
    const passwordField = passwordInputName(authForm.inputs) ?? "password"
    plan.push({
      check: "broken_auth_jwt",
      label: `Broken-auth/JWT review probe on observed auth surface ${routePathFromUrl(authForm.action)}`,
      path: routePathFromUrl(authForm.action),
      route: routePathFromUrl(authForm.action),
      method: normalizeMethod(authForm.method),
      body: JSON.stringify({
        [identityField]: "numasec-probe@example.invalid",
        [passwordField]: "numasec-probe",
      }),
    })
  } else {
    skipped.push("No observed auth form for broken-auth/JWT probe.")
  }

  const idorRoute = routes.find((route) => /\/\d+(?:\/|$)|[?&](?:id|user|account|item|object|basket)=\d+/i.test(route.url))
  if (idorRoute) {
    const routeUrlValue = new URL(idorRoute.url)
    const next = new URL(routeUrlValue.href)
    if (next.pathname.match(/\/\d+(?=\/|$)/)) {
      next.pathname = next.pathname.replace(/\/\d+(?=\/|$)/, "/1")
    } else {
      for (const [key, value] of next.searchParams.entries()) {
        if (/^\d+$/.test(value) && /id|user|account|item|object|basket/i.test(key)) {
          next.searchParams.set(key, "1")
          break
        }
      }
    }
    plan.push({
      check: "idor_basket",
      label: `IDOR/BOLA candidate probe on observed object route ${idorRoute.route}`,
      path: `${next.pathname}${next.search}`,
      route: idorRoute.route,
    })
  } else {
    skipped.push("No observed object route with a numeric identifier for IDOR probe.")
  }

  const corsRoute = routes[0]
  if (corsRoute) {
    plan.push({
      check: "weak_cors",
      label: `CORS policy probe on observed route ${corsRoute.route}`,
      path: routePathFromUrl(corsRoute.url),
      route: corsRoute.route,
      headers: { Origin: EVIL_ORIGIN },
    })
  } else {
    skipped.push("No observed same-origin route for CORS probe.")
  }

  return { plan, skipped }
}

function analyze(origin: string, results: ProbeResult[]): Candidate[] {
  const byCheck = new Map(results.map((item) => [item.check, item]))
  const candidates: Candidate[] = []

  const sqli = byCheck.get("sqli_search")
  if (sqli && routeExists(sqli)) {
    const body = sqli.body_preview ?? ""
    const sqlSignal = includesAny(body, ["sqlite", "sql syntax", "sequelize", "near \"", "database error"])
    candidates.push({
      id: "sqli_search",
      key: candidateKey(origin, "sqli_search"),
      title: `SQL injection candidate on observed surface ${routePathFromUrl(sqli.url)}`,
      route: routePathFromUrl(sqli.url),
      severity: sqlSignal ? "high" : "medium",
      confidence: sqlSignal ? 760 : 620,
      rationale:
        "An observed input surface responded to a SQL-oriented probe payload. Treat this as candidate SQL injection until replay or promotion confirms exploitability.",
      signals: {
        status: sqli.status,
        sql_error_shape: sqlSignal,
        route: routePathFromUrl(sqli.url),
        probe: "OR 1=1",
      },
    })
  }

  const xss = byCheck.get("xss_search")
  if (xss && routeExists(xss)) {
    const body = xss.body_preview ?? ""
    const reflected = body.includes("numasec-xss") || body.includes("<script")
    candidates.push({
      id: "xss_search",
      key: candidateKey(origin, "xss_search"),
      title: `XSS candidate on observed surface ${routePathFromUrl(xss.url)}`,
      route: routePathFromUrl(xss.url),
      severity: reflected ? "medium" : "low",
      confidence: reflected ? 720 : 520,
      rationale:
        "An observed input surface was probed with an XSS marker payload. This is a candidate cross-site scripting finding and needs browser replay before reportable promotion.",
      signals: {
        status: xss.status,
        reflected_marker: reflected,
        route: routePathFromUrl(xss.url),
        marker: "numasec-xss",
      },
    })
  }

  const login = byCheck.get("broken_auth_jwt")
  if (login && routeExists(login)) {
    const headers = JSON.stringify(login.headers)
    const body = login.body_preview ?? ""
    const jwtSignal = includesAny(headers + "\n" + body, ["jwt", "bearer", "token", "authorization"])
    candidates.push({
      id: "broken_auth_jwt",
      key: candidateKey(origin, "broken_auth_jwt"),
      title: `Broken auth / JWT weakness candidate on observed auth surface ${routePathFromUrl(login.url)}`,
      route: routePathFromUrl(login.url),
      severity: jwtSignal ? "medium" : "low",
      confidence: jwtSignal ? 700 : 540,
      rationale:
        "An observed authentication surface exists for auth/JWT review. This records a broken-auth/JWT candidate for follow-up checks such as token handling, weak algorithms, and session validation.",
      signals: {
        status: login.status,
        jwt_or_token_signal: jwtSignal,
        route: routePathFromUrl(login.url),
      },
    })
  }

  const basket = byCheck.get("idor_basket")
  if (basket && routeExists(basket)) {
    candidates.push({
      id: "idor_basket",
      key: candidateKey(origin, "idor_basket"),
      title: `IDOR / broken object level authorization candidate on observed route ${routePathFromUrl(basket.url)}`,
      route: routePathFromUrl(basket.url),
      severity: basket.status === 200 ? "high" : "medium",
      confidence: basket.status === 200 ? 760 : 560,
      rationale:
        "An observed object route responded to a direct identifier probe. This is a candidate IDOR/BOLA finding until authenticated replay confirms authorization bypass.",
      signals: {
        status: basket.status,
        route: routePathFromUrl(basket.url),
      },
    })
  }

  const cors = byCheck.get("weak_cors")
  const acao = cors?.headers["access-control-allow-origin"]
  const acac = cors?.headers["access-control-allow-credentials"]
  const permissiveCors = Boolean(acao && (acao === "*" || acao === EVIL_ORIGIN))
  if (cors && routeExists(cors) && permissiveCors) {
    candidates.push({
      id: "weak_cors",
      key: candidateKey(origin, "weak_cors"),
      title: `Weak CORS policy candidate on observed route ${routePathFromUrl(cors.url)}`,
      route: routePathFromUrl(cors.url),
      severity: acac?.toLowerCase() === "true" ? "medium" : "low",
      confidence: 760,
      rationale:
        "The target returned a permissive Access-Control-Allow-Origin policy for an untrusted Origin. This is a weak CORS candidate pending replay.",
      signals: {
        status: cors.status,
        "access-control-allow-origin": acao,
        "access-control-allow-credentials": acac,
      },
    })
  }

  return candidates
}

function routesFor(origin: string, plan: ProbePlanItem[], timeout: number, abort: AbortSignal) {
  return plan.map((item) =>
    request({
      origin,
      check: item.check,
      label: item.label,
      path: item.path,
      method: item.method,
      headers: item.headers,
      body: item.body,
      timeout,
      abort,
    }),
  )
}

function renderOutput(input: {
  origin: string
  checks: Check[]
  skipped: string[]
  results: ProbeResult[]
  candidates: Candidate[]
  evidence?: string
  slug?: string
}) {
  const lines: string[] = []
  lines.push(`# appsec probe ${input.origin}`)
  lines.push(`operation: ${input.slug ?? "none"}`)
  lines.push(`checks: ${input.checks.join(", ")}`)
  lines.push(`evidence: ${input.evidence ?? "not stored"}`)
  lines.push("")
  lines.push("## Probe Plan")
  if (input.results.length === 0 && input.skipped.length === 0) {
    lines.push("- none")
  } else {
    for (const result of input.results) {
      lines.push(`- ${result.check} · ${result.label}`)
    }
    for (const skipped of input.skipped) lines.push(`- skipped · ${skipped}`)
  }
  lines.push("")
  lines.push("## Candidate Findings")
  if (input.candidates.length === 0) {
    lines.push("- none")
  } else {
    for (const candidate of input.candidates) {
      lines.push(
        `- ${candidate.severity} · ${candidate.title} · route=${candidate.route} · confidence=${candidate.confidence}/1000`,
      )
      lines.push(`  rationale: ${candidate.rationale}`)
    }
  }
  lines.push("")
  lines.push("## Probe Responses")
  for (const result of input.results) {
    lines.push(
      `- ${result.check} · ${result.method} ${result.url} · status=${result.status ?? "error"} · ${result.error ?? `${result.body_length ?? 0} bytes`}`,
    )
  }
  return lines.join("\n")
}

function anonymousIdentityDescriptor(origin: string) {
  return {
    mode: "anonymous",
    header_keys: [],
    has_cookies: false,
    target: origin,
    note: "Unauthenticated baseline identity for AppSec probing. No secret material is stored.",
  }
}

export const AppsecProbeTool = Tool.define<typeof parameters, Metadata, never>(
  "appsec_probe",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const target = normalizeTarget(params.target)
          const origin = target.origin
          const checks = uniqueChecks(params.checks)
          const timeout = Math.min(params.timeout ?? DEFAULT_TIMEOUT, MAX_TIMEOUT)
          const scope = yield* Effect.tryPromise({
            try: () => Guard.checkUrl(Instance.directory, origin),
            catch: (e) => (e instanceof ScopeDeniedError ? e : new Error(String(e))),
          })
          yield* ctx.ask({
            permission: "appsec_probe",
            patterns: [origin],
            always: [origin],
            metadata: {
              target: origin,
              checks,
              scope: scope.mode,
              scope_reason: scope.reason,
              scope_matched: scope.matched,
            },
          })

          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const surface = slug ? yield* Effect.promise(() => observedSurface(workspace, slug, target)) : { routes: [], forms: [] }
          const probePlanDraft = buildProbePlan(origin, surface.routes, surface.forms)
          const probePlan = probePlanDraft.plan.filter((item) => checks.includes(item.check))
          const skipped = probePlanDraft.skipped
          const results = yield* Effect.promise(() => Promise.all(routesFor(origin, probePlan, timeout, ctx.abort)))
          const candidates = analyze(origin, results)
          const evidence =
            !slug
              ? undefined
              : yield* Effect.promise(() =>
                  Evidence.put(
                    workspace,
                    slug,
                    JSON.stringify(
                      {
                        target: origin,
                        checks,
                        observed_routes: surface.routes.map((item) => item.route),
                        observed_forms: surface.forms.map((item) => ({
                          action: routePathFromUrl(item.action),
                          method: item.method,
                          source: item.source,
                        })),
                        skipped,
                        probe_plan: probePlan,
                        results,
                        candidates,
                        note:
                          "Candidate findings are not confirmed vulnerabilities. Promote only after replay or a structured replay exemption.",
                      },
                      null,
                      2,
                    ),
                    {
                      mime: "application/json",
                      ext: "json",
                      label: `appsec probe ${origin}`,
                      source: "appsec_probe",
                    },
                  ),
                )
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            operation_slug: slug,
            kind: "fact.observed",
            source: "appsec_probe",
            status: "completed",
            summary: `appsec probe ${origin}`,
            evidence_refs: evidenceRefs,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            data: {
              target: origin,
              checks,
              probes: results.length,
              candidates: candidates.length,
              skipped,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))

          if (slug) {
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "identity",
              entity_key: "anonymous",
              fact_name: "descriptor",
              value_json: anonymousIdentityDescriptor(origin),
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "identity",
              entity_key: "anonymous",
              fact_name: "active",
              value_json: true,
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              operation_slug: slug,
              src_kind: "operation",
              src_key: slug,
              relation: "uses_identity",
              dst_kind: "identity",
              dst_key: "anonymous",
              writer_kind: "tool",
              status: "observed",
              confidence: 1000,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          if (slug && evidence) {
            const obs = yield* Effect.promise(() =>
              Observation.add(workspace, slug, {
                subtype: candidates.length > 0 ? "risk" : "intel-fact",
                title: `AppSec web probe completed for ${origin}`,
                severity: candidates.some((item) => item.severity === "high") ? "high" : candidates.length > 0 ? "medium" : "info",
                confidence: candidates.length > 0 ? 0.7 : 0.5,
                note: `${candidates.length} candidate findings from ${results.length} probes.`,
                tags: ["appsec", "dast", "candidate"],
              }),
            )
            yield* Effect.promise(() => Observation.linkEvidence(workspace, slug, obs.id, evidence.sha256))
          }
          yield* autoEnrichKnowledge({
            workspace,
            operation_slug: slug,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            source: "appsec_probe",
            items: [
              ...(surface.forms.length > 0
                ? [
                    {
                      intent: "tradecraft" as const,
                      action: "safe_next_actions" as const,
                      query: "observed web forms SQL injection XSS CSRF safe verification",
                      observed_refs: surface.forms.slice(0, 5).map((form) => `http_form:${form.method}:${routePathFromUrl(form.action)}`),
                      limit: 3,
                    },
                  ]
                : []),
              ...(surface.routes.some((route) => /\/\d+(?:\/|$)|[?&](?:id|user|account|object|basket)=/i.test(route.url))
                ? [
                    {
                      intent: "tradecraft" as const,
                      action: "safe_next_actions" as const,
                      query: "IDOR BOLA numeric object route safe replay verification",
                      observed_refs: surface.routes.slice(0, 5).map((route) => `http_route:${route.url}`),
                      limit: 3,
                    },
                  ]
                : []),
              ...(candidates.length > 0
                ? [
                    {
                      intent: "methodology" as const,
                      action: "safe_next_actions" as const,
                      query: candidates.map((candidate) => candidate.title).join(" "),
                      observed_refs: candidates.map((candidate) => `finding_candidate:${candidate.key}`),
                      limit: 5,
                    },
                  ]
                : []),
            ],
          }).pipe(Effect.catch(() => Effect.succeed(undefined)))

          for (const result of results) {
            let path = "/"
            try {
              path = new URL(result.url).pathname || "/"
            } catch {}
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "http_route",
              entity_key: result.url,
              fact_name: `appsec_probe:${result.check}`,
              value_json: {
                method: result.method,
                status: result.status ?? null,
                route: path,
                label: result.label,
                error: result.error ?? null,
              },
              writer_kind: "tool",
              status: result.status === undefined ? "stale" : "observed",
              confidence: result.status === undefined ? 300 : 900,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          for (const candidate of candidates) {
            yield* Cyber.upsertFact({
              operation_slug: slug,
              entity_kind: "finding_candidate",
              entity_key: candidate.key,
              fact_name: candidate.id,
              value_json: {
                ...candidate,
                target: origin,
                evidence_refs: evidenceRefs ?? [],
                reportability: "candidate_only",
                replay_required_for_promotion: true,
              },
              writer_kind: "parser",
              status: "candidate",
              confidence: candidate.confidence,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
            yield* Cyber.upsertRelation({
              operation_slug: slug,
              src_kind: "http_route",
              src_key: routeUrl(origin, candidate.route),
              relation: "has_candidate_finding",
              dst_kind: "finding_candidate",
              dst_key: candidate.key,
              writer_kind: "parser",
              status: "candidate",
              confidence: candidate.confidence,
              source_event_id: eventID || undefined,
              evidence_refs: evidenceRefs,
            }).pipe(Effect.catch(() => Effect.succeed("")))
          }

          return {
            title: `appsec probe · ${origin}`,
            output: renderOutput({
              origin,
              checks,
              skipped,
              results,
              candidates,
              evidence: evidence?.sha256,
              slug,
            }),
            metadata: {
              target: origin,
              checks,
              candidates: candidates.length,
              evidence: evidence?.sha256,
              active_operation: slug,
            },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
