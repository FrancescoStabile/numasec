/**
 * Tool: browser
 *
 * Playwright-based browser automation for security testing.
 * Handles DOM XSS detection, SPA interaction, screenshot capture,
 * authenticated crawling, and JavaScript execution in page context.
 *
 * Requires: Playwright JS package plus Chromium browser binaries.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { actionTarget, inferActionKind, inferActionResourceUrl } from "../action-inference"
import { inferActorIdentity } from "../actor-inference"
import {
  actorSessionRequest,
  actorSessionSummary,
  browserAuthMaterial,
  httpAuthMaterial,
  mergeActorSession,
} from "../runtime/actor-session-store"
import {
  classifyBrowserFailure,
  failureObservation,
  recoveryObservation,
  type ExecutionFailure,
  type RecoveryTelemetry,
} from "../runtime/execution-failure"
import {
  applyTargetProfile,
  noteTargetSignal,
} from "../runtime/target-profile-store"
import {
  type BrowserNetworkEvent,
  type BrowserSessionInfo,
  prepareBrowserSession,
  recentBrowserNetwork,
  recordBrowserExecutionAttempt,
  resetBrowserSession,
  syncBrowserSession,
} from "../runtime/browser-runtime"
import { collectJsonLeafPaths } from "../scanner/json-path"
import { Scope } from "../scope"
import { persistEngagementTarget } from "../target-store"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Automate a headless browser for security testing. Use for:
- Navigating to pages that require JavaScript rendering (SPAs)
- Testing DOM-based XSS by injecting payloads and checking execution
- Filling forms and clicking buttons programmatically
- Taking screenshots of application state
- Evaluating JavaScript in the page context
- Interacting with authenticated sessions by seeding cookies, headers, or storage
- Reusing a persistent browser actor session across multiple calls via actor_label or actor_session_id
- Mining deterministic workflow actions from forms, buttons, links, and data-endpoint attributes

Actions: navigate, click, fill, screenshot, evaluate, get_cookies.

NOTE: Requires the Playwright JS package and Chromium browser binaries. Reuse
the same actor_label or actor_session_id to keep browser state across calls.
If not available, returns an error — use http_request instead for static pages.

NEXT STEPS after browser results:
- Query query_resource_inventory to inspect browser-mined routes/resources
- If you found a DOM XSS sink, try more payloads with evaluate
- If the page has forms, use fill + click to test them
- If you need to prove a finding, take a screenshot`

export interface BrowserCookieInput {
  name: string
  value: string
  domain?: string
  path?: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: string
}

export interface BrowserFormFieldInput {
  name: string
  value: string
  type?: string
}

export interface BrowserFormInput {
  action: string
  method?: string
  enctype?: string
  submit_label?: string
  fields?: BrowserFormFieldInput[]
}

export interface BrowserActionInput {
  url: string
  method?: string
  source_kind?: string
  action_kind?: string
  target_state?: string
  resource_url?: string
  content_type?: string
  body?: string
  label?: string
  fields?: BrowserFormFieldInput[]
  disabled?: boolean
}

export interface BrowserNetworkInput {
  url: string
  method?: string
  status?: number
  initiator_url?: string
  resource_type?: string
  content_type?: string
  body?: string
  failure?: string
  action_kind?: string
  target_state?: string
  resource_url?: string
}

export interface BrowserInventorySnapshot {
  page_url: string
  page_title: string
  actor_session_id?: string
  browser_session_id?: string
  page_id?: string
  navigation_index?: number
  actor_label?: string
  headers?: Record<string, string>
  cookies: BrowserCookieInput[]
  local_storage?: Record<string, string>
  session_storage?: Record<string, string>
  links?: string[]
  forms?: BrowserFormInput[]
  actions?: BrowserActionInput[]
  network?: BrowserNetworkInput[]
  resources?: string[]
}

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : ""
  return ""
}

function object(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return
  return input as Record<string, unknown>
}

function parseJson(input: string): unknown {
  const value = input.trim()
  if (!value) return
  if (!value.startsWith("{") && !value.startsWith("[")) return
  try {
    return JSON.parse(value)
  } catch {
    return
  }
}

function collectStrings(input: unknown, out: string[]) {
  if (typeof input === "string") {
    out.push(input)
    const parsed = parseJson(input)
    if (parsed !== undefined) collectStrings(parsed, out)
    return
  }
  if (typeof input === "number" || typeof input === "boolean") {
    out.push(String(input))
    return
  }
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) {
      collectStrings(item, out)
    }
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    collectStrings(value[key], out)
  }
}

function key(input: string) {
  return input.replace(/[^a-z0-9]+/gi, "").toLowerCase()
}

function scan(input: unknown, names: Set<string>): string {
  if (!input || typeof input !== "object") return ""
  if (Array.isArray(input)) {
    for (const item of input) {
      const value = scan(item, names)
      if (value) return value
    }
    return ""
  }
  const row = input as Record<string, unknown>
  for (const item of Object.keys(row)) {
    if (!names.has(key(item))) continue
    const value = text(row[item])
    if (value) return value
  }
  for (const item of Object.keys(row)) {
    const value = scan(row[item], names)
    if (value) return value
  }
  return ""
}

function cookieHeader(cookies: BrowserCookieInput[]) {
  return cookies.map((item) => `${item.name}=${item.value}`).join("; ")
}

function storageValues(snapshot: BrowserInventorySnapshot) {
  const out: string[] = []
  const local = snapshot.local_storage ?? {}
  const localKeys = Object.keys(local)
  for (const item of localKeys) {
    collectStrings(local[item], out)
  }
  const session = snapshot.session_storage ?? {}
  const sessionKeys = Object.keys(session)
  for (const item of sessionKeys) {
    collectStrings(session[item], out)
  }
  return out
}

function storageObjects(snapshot: BrowserInventorySnapshot) {
  const out: Record<string, unknown>[] = []
  const push = (input: unknown) => {
    const value = object(input)
    if (value) out.push(value)
    const parsed = typeof input === "string" ? parseJson(input) : undefined
    const nested = object(parsed)
    if (nested) out.push(nested)
  }
  const local = snapshot.local_storage ?? {}
  const localKeys = Object.keys(local)
  for (const item of localKeys) {
    push(local[item])
  }
  const session = snapshot.session_storage ?? {}
  const sessionKeys = Object.keys(session)
  for (const item of sessionKeys) {
    push(session[item])
  }
  return out
}

function storageToken(snapshot: BrowserInventorySnapshot) {
  const values = storageValues(snapshot)
  for (const item of values) {
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(item)) return item
  }
  return ""
}

function inferBrowserActor(snapshot: BrowserInventorySnapshot) {
  const token = storageToken(snapshot)
  const headers = token
    ? {
        ...(snapshot.headers ?? {}),
        authorization: `Bearer ${token}`,
      }
    : snapshot.headers
  const actor = inferActorIdentity({
    label: "browser",
    headers,
    cookies: cookieHeader(snapshot.cookies),
  })
  const objects = storageObjects(snapshot)
  const fallback = inferActorIdentity({
    label: "browser",
    cookies: cookieHeader(snapshot.cookies),
    actor_id: scan(objects, new Set(["sub", "id", "userid", "user_id"])),
    actor_email: scan(objects, new Set(["email", "mail", "username"])),
    actor_role: scan(objects, new Set(["role", "roles"])),
  })
  if (!actor.id && !actor.email && !actor.role) {
    if (!fallback.id && !fallback.email && !fallback.role) return fallback
    return {
      ...fallback,
      source: "browser_storage",
    }
  }
  if (!fallback.id && !fallback.email && !fallback.role) return actor
  return {
    ...actor,
    id: actor.id || fallback.id,
    email: actor.email || fallback.email,
    role: actor.role || fallback.role,
    privileged: actor.privileged || fallback.privileged,
    source: actor.source === "cookie" && (fallback.email || fallback.role) ? "cookie+browser_storage" : actor.source,
  }
}

function normalizeUrl(base: string, input: string) {
  try {
    const value = new URL(input, base)
    if (value.protocol !== "http:" && value.protocol !== "https:") return ""
    return value.toString()
  } catch {
    return ""
  }
}

function sameOrigin(base: string, input: string) {
  const left = normalizeUrl(base, base)
  const right = normalizeUrl(base, input)
  if (!left || !right) return false
  return new URL(left).origin === new URL(right).origin
}

function resourceID(url: string) {
  try {
    const value = new URL(url)
    const params = ["resource_id", "resourceid", "project_id", "projectid", "user_id", "userid", "account_id", "accountid", "id"]
    for (const item of params) {
      const next = value.searchParams.get(item) ?? ""
      if (next) return next
    }
    const parts = value.pathname.split("/").filter(Boolean)
    let index = parts.length - 1
    while (index >= 0) {
      const item = parts[index] ?? ""
      if (/^\d+$/.test(item)) return item
      if (/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(item)) return item
      index -= 1
    }
  } catch {
    return ""
  }
  return ""
}

function selfRoute(url: string, actor: ReturnType<typeof inferBrowserActor>) {
  if (!actor.id && !actor.email) return false
  const value = new URL(url)
  const lower = value.pathname.toLowerCase()
  if (actor.email && (value.toString().toLowerCase().includes(actor.email.toLowerCase()) || value.searchParams.get("email") === actor.email)) {
    return true
  }
  const userish = /(\/users?\/|\/accounts?\/|\/profiles?\/|\/members?\/|\/me(\/|$))/i.test(lower)
  if (!actor.id || !userish) return false
  if (value.searchParams.get("user_id") === actor.id) return true
  if (value.searchParams.get("userid") === actor.id) return true
  if (value.searchParams.get("account_id") === actor.id) return true
  return resourceID(url) === actor.id
}

function routeMethod(input: string) {
  const value = input.toUpperCase()
  if (value === "POST" || value === "PUT" || value === "PATCH" || value === "DELETE") return value
  return "GET"
}

function fieldsBody(input?: BrowserFormFieldInput[]) {
  const fields = input ?? []
  if (fields.length === 0) return ""
  const body = new URLSearchParams()
  for (const item of fields) {
    if (!item.name) continue
    body.append(item.name, item.value ?? "")
  }
  return body.toString()
}

function formBody(input: BrowserFormInput) {
  return fieldsBody(input.fields)
}

function parameterNames(
  url: string,
  contentType: string,
  body: string,
  fields?: BrowserFormFieldInput[],
) {
  const out = new Set<string>()
  try {
    const value = new URL(url)
    for (const item of Array.from(value.searchParams.keys())) {
      if (!item) continue
      out.add(item)
    }
  } catch {}
  const type = contentType.toLowerCase()
  const textBody = body.trim()
  const parsed = parseJson(textBody)
  if ((type.includes("application/json") || (!type && parsed !== undefined)) && parsed !== undefined) {
    for (const item of collectJsonLeafPaths(parsed)) {
      if (!item) continue
      out.add(item)
    }
  }
  if (
    type.includes("application/x-www-form-urlencoded") ||
    type.includes("multipart/form-data") ||
    (!type && parsed === undefined && textBody.includes("="))
  ) {
    const params = new URLSearchParams(textBody)
    for (const item of Array.from(params.keys())) {
      if (!item) continue
      out.add(item)
    }
  }
  for (const item of fields ?? []) {
    if (!item.name) continue
    out.add(item.name)
  }
  return Array.from(out)
}

export function buildBrowserInventoryEnvelope(snapshot: BrowserInventorySnapshot) {
  const observations: Record<string, any>[] = []
  const actor = inferBrowserActor(snapshot)
  let actorKey = ""
  if (actor.id || actor.email || actor.role) {
    actorKey = `actor-browser-${slug(actor.email || actor.id || actor.label)}`
    observations.push({
      key: actorKey,
      family: "actor_inventory",
      kind: "browser_actor",
      actor_label: actor.label,
      actor_id: actor.id,
      actor_email: actor.email,
      actor_role: actor.role,
      privileged: actor.privileged,
      source: actor.source,
      actor_session_id: snapshot.actor_session_id,
      browser_session_id: snapshot.browser_session_id,
      page_id: snapshot.page_id,
      navigation_index: snapshot.navigation_index,
      runtime_actor_label: snapshot.actor_label,
      url: snapshot.page_url,
      page_title: snapshot.page_title,
      cookie_count: snapshot.cookies.length,
    })
  }

  const routes = new Map<string, {
    url: string
    method: string
    source_kind: string
    action_kind: string
    target_state: string
    resource_url: string
    request_content_type: string
    request_body: string
    response_status: number
    initiator_url: string
    resource_type: string
      failure: string
      action_label: string
      form_enctype: string
      form_body: string
      submit_label: string
      form_fields: BrowserFormFieldInput[]
      parameter_names: string[]
  }>()
  const addRoute = (url: string, method: string, sourceKind: string, extra?: Partial<{
    action_kind: string
    target_state: string
    resource_url: string
      request_content_type: string
      request_body: string
      response_status: number
      initiator_url: string
      resource_type: string
      failure: string
       action_label: string
       form_enctype: string
       form_body: string
       submit_label: string
       form_fields: BrowserFormFieldInput[]
       parameter_names: string[]
  }>) => {
    if (!url) return
    if (!sameOrigin(snapshot.page_url, url)) return
    const next = normalizeUrl(snapshot.page_url, url)
    if (!next) return
    const key = `${method} ${next}`
    const current = routes.get(key)
    const row = {
      url: next,
      method,
      source_kind: sourceKind,
      action_kind: extra?.action_kind ?? "",
      target_state: extra?.target_state ?? "",
      resource_url: extra?.resource_url ?? "",
      request_content_type: extra?.request_content_type ?? "",
      request_body: extra?.request_body ?? "",
      response_status: extra?.response_status ?? 0,
      initiator_url: extra?.initiator_url ?? "",
      resource_type: extra?.resource_type ?? "",
      failure: extra?.failure ?? "",
      action_label: extra?.action_label ?? "",
      form_enctype: extra?.form_enctype ?? "",
      form_body: extra?.form_body ?? "",
      submit_label: extra?.submit_label ?? "",
      form_fields: extra?.form_fields ?? [],
      parameter_names:
        extra?.parameter_names ??
        parameterNames(next, extra?.request_content_type ?? "", extra?.request_body ?? "", extra?.form_fields),
    }
    if (!current) {
      routes.set(key, row)
      return
    }
    routes.set(key, {
      ...current,
      source_kind: current.action_kind ? current.source_kind : row.action_kind ? row.source_kind : current.source_kind,
      action_kind: current.action_kind || row.action_kind,
      target_state: current.target_state || row.target_state,
      resource_url: current.resource_url || row.resource_url,
      request_content_type: current.request_content_type || row.request_content_type,
      request_body: current.request_body || row.request_body,
      response_status: current.response_status || row.response_status,
      initiator_url: current.initiator_url || row.initiator_url,
      resource_type: current.resource_type || row.resource_type,
      failure: current.failure || row.failure,
      action_label: current.action_label || row.action_label,
      form_enctype: current.form_enctype || row.form_enctype,
      form_body: current.form_body || row.form_body,
      submit_label: current.submit_label || row.submit_label,
      form_fields: current.form_fields.length > 0 ? current.form_fields : row.form_fields,
      parameter_names: Array.from(new Set([...current.parameter_names, ...row.parameter_names])),
    })
  }

  addRoute(snapshot.page_url, "GET", "browser_page")
  for (const item of snapshot.links ?? []) {
    addRoute(item, "GET", "browser_link")
  }
  for (const item of snapshot.forms ?? []) {
    const actionUrl = normalizeUrl(snapshot.page_url, item.action)
    const kind = inferActionKind(actionUrl || item.action, item.submit_label)
    addRoute(actionUrl || item.action, routeMethod(item.method ?? "GET"), "browser_form", {
      action_kind: kind,
      target_state: actionTarget(kind),
      resource_url: inferActionResourceUrl(actionUrl || item.action, kind),
      request_content_type: text(item.enctype),
      request_body: formBody(item),
      action_label: text(item.submit_label),
      form_enctype: text(item.enctype),
      form_body: formBody(item),
      submit_label: text(item.submit_label),
      form_fields: item.fields ?? [],
    })
  }
  for (const item of snapshot.actions ?? []) {
    if (item.disabled) continue
    const actionUrl = normalizeUrl(snapshot.page_url, item.url)
    const label = text(item.label)
    const kind = text(item.action_kind) || inferActionKind(actionUrl || item.url, label)
    addRoute(actionUrl || item.url, routeMethod(item.method ?? "GET"), text(item.source_kind) || "browser_action", {
      action_kind: kind,
      target_state: text(item.target_state) || actionTarget(kind),
      resource_url: text(item.resource_url) || inferActionResourceUrl(actionUrl || item.url, kind),
      request_content_type: text(item.content_type),
      request_body: text(item.body) || fieldsBody(item.fields),
      action_label: label,
      form_enctype: text(item.content_type),
      form_body: text(item.body) || fieldsBody(item.fields),
      submit_label: label,
      form_fields: item.fields ?? [],
    })
  }
  for (const item of snapshot.network ?? []) {
    const actionUrl = normalizeUrl(snapshot.page_url, item.url)
    const label = text(item.action_kind)
    const kind = text(item.action_kind) || inferActionKind(actionUrl || item.url, label)
    addRoute(actionUrl || item.url, routeMethod(item.method ?? "GET"), "browser_network", {
      action_kind: kind,
      target_state: text(item.target_state) || actionTarget(kind),
      resource_url: text(item.resource_url) || inferActionResourceUrl(actionUrl || item.url, kind),
      request_content_type: text(item.content_type),
      request_body: text(item.body),
      response_status: Number(item.status ?? 0),
      initiator_url: text(item.initiator_url),
      resource_type: text(item.resource_type),
      failure: text(item.failure),
      action_label: label,
      form_enctype: text(item.content_type),
      form_body: text(item.body),
      submit_label: label,
      form_fields: [],
    })
  }
  for (const item of snapshot.resources ?? []) {
    addRoute(item, "", "browser_request")
  }

  let index = 0
  let actions = 0
  for (const item of routes.values()) {
    const id = resourceID(item.url)
    if (item.action_kind) actions += 1
    observations.push({
      key: `browser-resource-${slug(new URL(item.url).pathname || "root")}-${slug(id || String(index++))}-${item.source_kind}`,
      family: "resource_inventory",
      kind: item.action_kind ? "action_candidate" : "candidate",
      url: item.url,
      method: item.method,
      source_kind: item.source_kind,
      actor_id: actor.id,
      actor_email: actor.email,
      actor_role: actor.role,
      actor_session_id: snapshot.actor_session_id,
      browser_session_id: snapshot.browser_session_id,
      page_id: snapshot.page_id,
      navigation_index: snapshot.navigation_index,
      resource_id: id,
      exposure: selfRoute(item.url, actor) ? "self" : "unknown",
      parent_key: actorKey || undefined,
      action_kind: item.action_kind || undefined,
      action_target_state: item.target_state || undefined,
      resource_url: item.resource_url || undefined,
      request_content_type: item.request_content_type || undefined,
      request_body: item.request_body || undefined,
      response_status: item.response_status || undefined,
      initiator_url: item.initiator_url || undefined,
      resource_type: item.resource_type || undefined,
      failure: item.failure || undefined,
      action_label: item.action_label || undefined,
      form_enctype: item.form_enctype || undefined,
      form_body: item.form_body || undefined,
      submit_label: item.submit_label || undefined,
      form_fields: item.form_fields.length > 0 ? item.form_fields : undefined,
      parameter_names: item.parameter_names.length > 0 ? item.parameter_names : undefined,
    })
  }

  return makeToolResultEnvelope({
    status: "ok",
    artifacts:
      (snapshot.network ?? []).length > 0
        ? [
            {
              key: "browser-network",
              subtype: "browser_network_trace",
              requests: snapshot.network,
            },
          ]
        : [],
    observations,
    metrics: {
      actor_candidates: actorKey ? 1 : 0,
      resource_candidates: routes.size,
      action_candidates: actions,
      network_requests: (snapshot.network ?? []).length,
      cookies: snapshot.cookies.length,
      links: (snapshot.links ?? []).length,
      forms: (snapshot.forms ?? []).length,
      resources: (snapshot.resources ?? []).length,
      local_storage_keys: Object.keys(snapshot.local_storage ?? {}).length,
      session_storage_keys: Object.keys(snapshot.session_storage ?? {}).length,
    },
  })
}

function cookieSeed(url: string, input: string) {
  const base = new URL(url)
  const out: Array<{
    name: string
    value: string
    domain: string
    path: string
    secure: boolean
    httpOnly: boolean
  }> = []
  for (const item of input.split(";")) {
    const value = item.trim()
    const index = value.indexOf("=")
    if (index <= 0) continue
    out.push({
      name: value.slice(0, index).trim(),
      value: value.slice(index + 1).trim(),
      domain: base.hostname,
      path: "/",
      secure: base.protocol === "https:",
      httpOnly: false,
    })
  }
  return out
}

const BrowserParameters = z.object({
  action: z
    .enum(["navigate", "click", "fill", "screenshot", "evaluate", "get_cookies"])
    .describe("Browser action to perform"),
  actor_session_id: z.string().optional().describe("Optional persistent browser actor session ID to reuse across calls"),
  actor_label: z.string().optional().describe("Optional logical actor label used to derive a persistent browser session when actor_session_id is omitted"),
  reset_session: z.boolean().optional().describe("When true, resets the persistent browser actor session before running this action"),
  url: z.string().optional().describe("URL to navigate to. When provided for non-navigate actions, the page is loaded first in the same invocation."),
  selector: z.string().optional().describe("CSS selector for click/fill actions"),
  value: z.string().optional().describe("Value for fill action or JS code for evaluate"),
  timeout: z.number().optional().describe("Action timeout in ms (default 30000)"),
  headers: z.record(z.string(), z.string()).optional().describe("Optional headers to seed authenticated browser requests"),
  cookies: z.string().optional().describe("Optional raw Cookie header to seed browser session"),
  local_storage: z.record(z.string(), z.string()).optional().describe("Optional localStorage key/value seed"),
  session_storage: z.record(z.string(), z.string()).optional().describe("Optional sessionStorage key/value seed"),
})

type BrowserParams = z.infer<typeof BrowserParameters>

async function seedStorage(page: any, params: BrowserParams) {
  const local = params.local_storage ?? {}
  const session = params.session_storage ?? {}
  if (Object.keys(local).length === 0 && Object.keys(session).length === 0) return
  await page.addInitScript((value: { local: Record<string, string>; session: Record<string, string> }) => {
    const localKeys = Object.keys(value.local)
    for (const item of localKeys) {
      window.localStorage.setItem(item, value.local[item] ?? "")
    }
    const sessionKeys = Object.keys(value.session)
    for (const item of sessionKeys) {
      window.sessionStorage.setItem(item, value.session[item] ?? "")
    }
  }, {
    local,
    session,
  })
  const url = page.url()
  if (!url || url.startsWith("about:")) return
  await page.evaluate((value: { local: Record<string, string>; session: Record<string, string> }) => {
    const localKeys = Object.keys(value.local)
    for (const item of localKeys) {
      window.localStorage.setItem(item, value.local[item] ?? "")
    }
    const sessionKeys = Object.keys(value.session)
    for (const item of sessionKeys) {
      window.sessionStorage.setItem(item, value.session[item] ?? "")
    }
  }, {
    local,
    session,
  }).catch(() => undefined)
}

async function collectSnapshot(
  page: any,
  context: any,
  params: BrowserParams,
  runtime?: BrowserSessionInfo,
  network?: BrowserNetworkEvent[],
) {
  const title = await page.title().catch(() => "")
    const values = await page.evaluate(() => {
      const actionTarget = (kind: string) => {
        if (kind === "add") return "added"
        if (kind === "approve") return "approved"
        if (kind === "claim") return "claimed"
        if (kind === "change") return "changed"
        if (kind === "close") return "closed"
        if (kind === "complete") return "completed"
        if (kind === "create") return "created"
        if (kind === "delete") return "deleted"
        if (kind === "disable") return "disabled"
        if (kind === "enable") return "enabled"
        if (kind === "publish") return "published"
        if (kind === "remove") return "removed"
        if (kind === "save") return "saved"
        if (kind === "send") return "sent"
        if (kind === "submit") return "submitted"
        if (kind === "update") return "updated"
        if (kind === "verify") return "verified"
        if (kind === "activate") return "active"
        if (kind === "archive") return "archived"
        return ""
      }
      const actionKind = (url: string, label: string) => {
        const text = `${url} ${label}`.toLowerCase()
        if (text.includes("add")) return "add"
        if (text.includes("approve")) return "approve"
        if (text.includes("claim")) return "claim"
        if (text.includes("change")) return "change"
        if (text.includes("close")) return "close"
        if (text.includes("complete")) return "complete"
        if (text.includes("create")) return "create"
        if (text.includes("delete")) return "delete"
        if (text.includes("disable")) return "disable"
        if (text.includes("enable")) return "enable"
        if (text.includes("publish")) return "publish"
        if (text.includes("remove")) return "remove"
        if (text.includes("save")) return "save"
        if (text.includes("send")) return "send"
        if (text.includes("submit")) return "submit"
        if (text.includes("update")) return "update"
        if (text.includes("verify")) return "verify"
        if (text.includes("activate")) return "activate"
        if (text.includes("archive")) return "archive"
      return ""
    }
    const data = (item: Element, name: string) => item.getAttribute(`data-${name}`) ?? ""
    const disabled = (item: Element) => {
      if (item.getAttribute("aria-disabled") === "true") return true
      const value = item.getAttribute("class") ?? ""
      const parts = value
        .split(/\s+/)
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean)
      for (const part of parts) {
        if (part === "disabled" || part === "is-disabled") return true
        if (
          (part.endsWith("-disabled") || part.endsWith("_disabled")) &&
          !part.startsWith("not-") &&
          !part.startsWith("not_") &&
          !part.startsWith("un-") &&
          !part.startsWith("un_")
        ) return true
      }
      if ("disabled" in item) {
        const row = item as HTMLButtonElement | HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
        if (row.disabled) return true
      }
      return false
    }
    const label = (item: Element) => {
      if (item instanceof HTMLButtonElement) {
        return item.innerText.trim() || item.getAttribute("aria-label") || item.getAttribute("title") || data(item, "action")
      }
      if (item instanceof HTMLInputElement) {
        return item.value || item.getAttribute("aria-label") || item.getAttribute("title") || data(item, "action")
      }
      if (item instanceof HTMLAnchorElement) {
        return item.innerText.trim() || item.getAttribute("aria-label") || item.getAttribute("title") || data(item, "action")
      }
      return item.getAttribute("aria-label") || item.getAttribute("title") || data(item, "action")
    }
    const readFields = (form: HTMLFormElement | null) => {
      const out: BrowserFormFieldInput[] = []
      if (!form) return out
      const fields = Array.from(form.querySelectorAll("input[name], select[name], textarea[name]"))
      for (const field of fields) {
        if (field instanceof HTMLInputElement) {
          const type = field.type || "text"
          if ((type === "checkbox" || type === "radio") && !field.checked) continue
          out.push({
            name: field.name,
            value: field.value ?? "",
            type,
          })
          continue
        }
        if (field instanceof HTMLSelectElement) {
          out.push({
            name: field.name,
            value: field.value ?? "",
            type: "select",
          })
          continue
        }
        if (!(field instanceof HTMLTextAreaElement)) continue
        out.push({
          name: field.name,
          value: field.value ?? "",
          type: "textarea",
        })
      }
      return out.slice(0, 30)
    }
    const jsonBody = (fields: BrowserFormFieldInput[]) => {
      const out: Record<string, string> = {}
      for (const item of fields) {
        if (!item.name) continue
        out[item.name] = item.value ?? ""
      }
      return Object.keys(out).length > 0 ? JSON.stringify(out) : ""
    }
    const local: Record<string, string> = {}
    let index = 0
    while (index < window.localStorage.length) {
      const key = window.localStorage.key(index)
      if (key) local[key] = window.localStorage.getItem(key) ?? ""
      index += 1
    }
    const session: Record<string, string> = {}
    index = 0
    while (index < window.sessionStorage.length) {
      const key = window.sessionStorage.key(index)
      if (key) session[key] = window.sessionStorage.getItem(key) ?? ""
      index += 1
    }
    const links = Array.from(document.querySelectorAll("a[href]"))
      .map((item) => item instanceof HTMLAnchorElement ? item.href : "")
      .filter(Boolean)
      .slice(0, 200)
    const forms = Array.from(document.querySelectorAll("form"))
      .map((item) => item instanceof HTMLFormElement
        ? {
            action: item.action || window.location.href,
            method: item.method || "GET",
            enctype: item.enctype || "application/x-www-form-urlencoded",
            fields: readFields(item),
            submit_label: (() => {
              const field = item.querySelector('button[type="submit"], input[type="submit"]')
              if (field instanceof HTMLButtonElement) return field.innerText.trim()
              if (field instanceof HTMLInputElement) return field.value ?? ""
              return ""
            })(),
          }
        : {
            action: "",
            method: "GET",
            enctype: "application/x-www-form-urlencoded",
            fields: [],
            submit_label: "",
          })
      .filter((item) => item.action)
      .slice(0, 100)
    const actions = Array.from(document.querySelectorAll("button, input[type='submit'], input[type='button'], a[href], [role='button'], [data-endpoint], [data-url], [data-href]"))
      .map((item) => {
        if (disabled(item)) return
        const form =
          item instanceof HTMLButtonElement || item instanceof HTMLInputElement
            ? item.form
            : item.closest("form")
        const itemLabel = label(item)
        const url =
          item instanceof HTMLButtonElement || item instanceof HTMLInputElement
            ? item.formAction || data(item, "endpoint") || data(item, "url") || data(item, "href")
            : item instanceof HTMLAnchorElement
              ? item.href || data(item, "endpoint") || data(item, "url")
              : data(item, "endpoint") || data(item, "url") || data(item, "href")
        const method =
          item instanceof HTMLButtonElement || item instanceof HTMLInputElement
            ? item.formMethod || data(item, "method") || (form instanceof HTMLFormElement ? form.method : "")
            : data(item, "method") || "GET"
        const source =
          data(item, "endpoint") || data(item, "url") || data(item, "href")
            ? "browser_dataset_action"
            : item instanceof HTMLAnchorElement
              ? "browser_link_action"
              : "browser_button"
        const fields = readFields(form instanceof HTMLFormElement ? form : null)
        const content =
          data(item, "content-type") ||
          data(item, "enctype") ||
          (item instanceof HTMLButtonElement || item instanceof HTMLInputElement ? item.getAttribute("formenctype") ?? "" : "") ||
          (form instanceof HTMLFormElement ? form.enctype : "")
        const payloadJson = data(item, "payload-json")
        const payload = data(item, "payload")
        const body =
          payloadJson ||
          payload ||
          (content.toLowerCase().includes("json") ? jsonBody(fields) : "")
        const kind = data(item, "action") || actionKind(url, itemLabel)
        const explicit =
          !!payloadJson ||
          !!payload ||
          !!data(item, "endpoint") ||
          !!data(item, "url") ||
          !!data(item, "href") ||
          !!data(item, "method") ||
          !!(item instanceof HTMLButtonElement || item instanceof HTMLInputElement ? item.formAction : "")
        if (!url) return
        if (!explicit && !kind) return
        return {
          url,
          method: method || "GET",
          source_kind: source,
          action_kind: kind,
          target_state: data(item, "target-state") || actionTarget(kind),
          resource_url: data(item, "resource-url"),
          content_type: content,
          body,
          label: itemLabel,
          fields: body ? [] : fields,
        }
      })
      .filter((item): item is {
        url: string
        method: string
        source_kind: string
        action_kind: string
        target_state: string
        resource_url: string
        content_type: string
        body: string
        label: string
        fields: BrowserFormFieldInput[]
      } => !!item)
      .slice(0, 150)
    const resources = performance.getEntriesByType("resource")
      .map((item) => "name" in item ? String(item.name ?? "") : "")
      .filter(Boolean)
      .slice(0, 200)
    return {
      links,
      forms,
      actions,
      resources,
      local_storage: local,
      session_storage: session,
    }
  })
  const cookies = (await context.cookies()).map((item: any) => ({
    name: String(item.name ?? ""),
    value: String(item.value ?? ""),
    domain: String(item.domain ?? ""),
    path: String(item.path ?? "/"),
    secure: item.secure === true,
    httpOnly: item.httpOnly === true,
    sameSite: String(item.sameSite ?? ""),
  }))
  const snapshot = {
    page_url: page.url(),
    page_title: title,
    actor_session_id: runtime?.actorSessionID,
    browser_session_id: runtime?.browserSessionID,
    page_id: runtime?.pageID,
    navigation_index: runtime?.navigationIndex,
    actor_label: runtime?.actorLabel,
    headers: params.headers,
    cookies,
    local_storage: values.local_storage,
    session_storage: values.session_storage,
    links: values.links,
    forms: values.forms,
    actions: values.actions,
    network: (network ?? []).map((item) => {
      const kind = inferActionKind(item.url, "")
      return {
        url: item.url,
        method: item.method,
        status: item.status,
        initiator_url: item.initiatorURL,
        resource_type: item.resourceType,
        content_type: item.contentType,
        body: item.requestBody,
        failure: item.failure,
        action_kind: kind,
        target_state: actionTarget(kind),
        resource_url: inferActionResourceUrl(item.url, kind),
      } satisfies BrowserNetworkInput
    }),
    resources: values.resources,
  } satisfies BrowserInventorySnapshot
  return snapshot
}

function annotateEnvelope(envelope: ReturnType<typeof buildBrowserInventoryEnvelope>, recovery?: RecoveryTelemetry) {
  if (!recovery) return envelope
  return makeToolResultEnvelope({
    ...envelope,
    observations: [...envelope.observations, recoveryObservation(recovery)],
    metrics: {
      ...envelope.metrics,
      recovery_attempts: recovery.attempts,
    },
  })
}

async function hydrateActorSession(
  context: any,
  page: any,
  params: BrowserParams,
  stored: Awaited<ReturnType<typeof mergeActorSession>>,
  strictCookies: boolean,
) {
  const auth = actorSessionRequest(stored, params.headers, params.cookies)
  await context.setExtraHTTPHeaders(auth.headers)
  const seeded = {
    ...params,
    headers: auth.headers,
    local_storage: auth.localStorage,
    session_storage: auth.sessionStorage,
  } satisfies BrowserParams
  await seedStorage(page, seeded)
  if (!auth.cookies) {
    return {
      auth,
      seeded,
    }
  }
  const url = cookieURL(params, page) || stored.lastURL
  if (!url) {
    if (strictCookies) {
      throw new Error("A concrete http(s) url is required before seeding cookies into a browser actor session.")
    }
    return {
      auth,
      seeded,
    }
  }
  const seed = cookieSeed(url, auth.cookies)
  if (seed.length > 0) {
    await context.addCookies(seed)
  }
  return {
    auth,
    seeded,
  }
}

async function navigateWithRecovery(page: any, url: string, timeout: number) {
  try {
    const response = await page.goto(url, { timeout, waitUntil: "networkidle" })
    return { response }
  } catch (error) {
    const failure = classifyBrowserFailure(error)
    if (failure.code !== "navigation_timeout") throw error
    const response = await page.goto(url, { timeout, waitUntil: "domcontentloaded" })
    return {
      response,
      recovery: {
        initial_code: failure.code,
        attempts: 2,
        strategy: "reload_requested_url",
        recovered: true,
      } satisfies RecoveryTelemetry,
    }
  }
}

function cookieURL(params: BrowserParams, page: any) {
  if (params.url) return params.url
  const current = String(page.url?.() ?? "")
  if (current.startsWith("http://") || current.startsWith("https://")) return current
  return ""
}

function errorResult(error: unknown, recovery?: RecoveryTelemetry) {
  const info = classifyBrowserFailure(error)
  return {
    title: "Browser action failed",
    metadata: {} as any,
    envelope: makeToolResultEnvelope({
      status: info.retryable ? "retryable_error" : "fatal_error",
      observations: [
        failureObservation(info),
        ...(recovery ? [recoveryObservation(recovery)] : []),
      ],
      metrics: {
        recovery_attempts: recovery?.attempts ?? 0,
      },
      error: {
        code: info.code,
        message: info.message,
      },
    }),
    output: [info.message, recovery ? `Recovery attempted: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
  }
}

export function shouldResetBrowserSessionAfterFailure(input: Pick<ExecutionFailure, "code" | "retryable">) {
  if (input.retryable) return true
  return input.code === "page_crashed"
}

async function requireOrigin(
  params: BrowserParams,
  page: any,
  context: any,
  stored: Awaited<ReturnType<typeof mergeActorSession>>,
  timeout: number,
) {
  if (params.action === "navigate") return
  if (params.action === "get_cookies") return
  if (params.url) return
  const current = String(page.url?.() ?? "")
  if (current && !current.startsWith("about:blank")) return
  if (!stored.lastURL) {
    throw new Error("This browser actor session has no initialized origin yet. Use url=... once or run navigate first with the same actor_label or actor_session_id.")
  }
  await hydrateActorSession(context, page, params, stored, false)
  await page.goto(stored.lastURL, { timeout, waitUntil: "domcontentloaded" })
  return {
    initial_code: "origin_uninitialized",
    attempts: 2,
    strategy: "reload_last_origin",
    recovered: true,
  } satisfies RecoveryTelemetry
}

export const BrowserTool = Tool.define("browser", {
  description: DESCRIPTION,
  parameters: BrowserParameters,
  async execute(params, ctx) {
    await ctx.ask({
      permission: "browser",
      patterns: [params.url ?? params.selector ?? params.action],
      always: [] as string[],
      metadata: { action: params.action, url: params.url } as Record<string, any>,
    })

    const timeout = params.timeout ?? 30_000
    let session: Awaited<ReturnType<typeof prepareBrowserSession>>
    try {
      if (params.url) {
        Scope.ensure(ctx.sessionID, params.url)
        persistEngagementTarget({
          sessionID: ctx.sessionID,
          url: params.url,
          source: "browser",
        })
      }
      session = await prepareBrowserSession({
        sessionID: ctx.sessionID,
        actorSessionID: params.actor_session_id,
        actorLabel: params.actor_label,
        reset: params.reset_session === true,
      })
    } catch (error) {
      return errorResult(error)
    }

    const writeAttempt = async (status: string, errorCode: string, notes?: Record<string, unknown>) =>
      recordBrowserExecutionAttempt({
        sessionID: ctx.sessionID,
        actorSessionID: session.actorSessionID,
        browserSessionID: session.browserSessionID,
        pageID: session.pageID,
        action: params.action,
        status,
        errorCode,
        notes: {
          ...(notes ?? {}),
          recovery_strategy: recovery?.strategy ?? "",
          recovery_attempts: recovery?.attempts ?? 0,
        },
      }).catch(() => undefined)

    let stored: Awaited<ReturnType<typeof mergeActorSession>> | undefined
    let recovery: RecoveryTelemetry | undefined
    try {
      const context = session.context
      const page = session.page
      stored = await mergeActorSession({
        sessionID: ctx.sessionID,
        actorSessionID: session.actorSessionID,
        actorLabel: params.actor_label,
        material: {
          ...httpAuthMaterial({
            actorLabel: params.actor_label,
            url: cookieURL(params, page) || "https://actor.invalid/",
            requestHeaders: params.headers,
            requestCookies: params.cookies,
          }),
          localStorage: params.local_storage,
          sessionStorage: params.session_storage,
        },
      })
      const hydrated = await hydrateActorSession(context, page, params, stored, true)
      const auth = hydrated.auth
      const seeded = hydrated.seeded
      const profileURL = params.url || stored.lastURL || cookieURL(params, page)
      const profile = profileURL ? await applyTargetProfile(ctx.sessionID, profileURL) : undefined
      const markSuccess = async (url: string) =>
        noteTargetSignal(ctx.sessionID, url, "success", true).catch(() => undefined)

      let response: any = null
      let navigated = false
      if (params.url) {
        const value = await navigateWithRecovery(page, params.url, timeout)
        response = value.response
        if (value.recovery) recovery = value.recovery
        navigated = true
      }

      const originRecovery = await requireOrigin(params, page, context, stored, timeout)
      if (originRecovery) recovery = originRecovery
      const snapshotFor = async (info: BrowserSessionInfo) =>
        collectSnapshot(
          page,
          context,
          seeded,
          info,
          await recentBrowserNetwork({
            sessionID: ctx.sessionID,
            actorSessionID: session.actorSessionID,
          }).catch(() => []),
        )

      if (params.action === "navigate") {
        if (!params.url) throw new Error("url is required for navigate action")
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        const content = await page.content()
        await writeAttempt("ok", "", {
          response_status: response ? response.status() : undefined,
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: `Navigate → ${params.url}`,
          metadata: {
            status: response ? response.status() : undefined,
            pageTitle: title,
            cookieCount: snapshot.cookies.length,
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            inventoryCandidates: (snapshot.links ?? []).length + (snapshot.forms ?? []).length + (snapshot.resources ?? []).length + 1,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: [
            `Status: ${response ? response.status() : "unknown"}`,
            `Title: ${title}`,
            `URL: ${page.url()}`,
            `Actor session: ${info.actorSessionID}`,
            `Browser session: ${info.browserSessionID}`,
            `Navigation index: ${info.navigationIndex}`,
            recovery ? `Recovery: ${recovery.strategy} after ${recovery.attempts} attempt(s)` : "",
            `Cookies: ${snapshot.cookies.length}`,
            `Links: ${(snapshot.links ?? []).length}`,
            `Forms: ${(snapshot.forms ?? []).length}`,
            `Resources: ${(snapshot.resources ?? []).length}`,
            "",
            "── Page HTML (first 8000 chars) ──",
            content.slice(0, 8000),
          ].join("\n"),
        }
      }

      if (params.action === "click") {
        if (!params.selector) throw new Error("selector is required for click action")
        const before = page.url()
        await page.click(params.selector, { timeout })
        await page.waitForLoadState("networkidle").catch(() => {})
        if (page.url() !== before) navigated = true
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        await writeAttempt("ok", "", {
          selector: params.selector,
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: `Click ${params.selector}`,
          metadata: {
            url: page.url(),
            cookieCount: snapshot.cookies.length,
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: [`Clicked "${params.selector}". Current URL: ${page.url()}`, recovery ? `Recovery: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
        }
      }

      if (params.action === "fill") {
        if (!params.selector) throw new Error("selector is required for fill action")
        if (!params.value) throw new Error("value is required for fill action")
        await page.fill(params.selector, params.value, { timeout })
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        await writeAttempt("ok", "", {
          selector: params.selector,
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: `Fill ${params.selector}`,
          metadata: {
            url: page.url(),
            cookieCount: snapshot.cookies.length,
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: [`Filled "${params.selector}" with value.`, recovery ? `Recovery: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
        }
      }

      if (params.action === "screenshot") {
        const buf = await page.screenshot({ fullPage: true, type: "png" })
        const base64 = buf.toString("base64")
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        await writeAttempt("ok", "", {
          size: buf.length,
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: "Screenshot captured",
          metadata: {
            size: buf.length,
            url: page.url(),
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: ["Screenshot captured successfully.", recovery ? `Recovery: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
          attachments: [{ type: "file" as const, mime: "image/png", url: `data:image/png;base64,${base64}` }],
        }
      }

      if (params.action === "evaluate") {
        if (!params.value) throw new Error("value (JS code) is required for evaluate action")
        const result = await page.evaluate(params.value)
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        await writeAttempt("ok", "", {
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: "JS Evaluate",
          metadata: {
            url: page.url(),
            cookieCount: snapshot.cookies.length,
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: [typeof result === "string" ? result : JSON.stringify(result, null, 2), recovery ? `Recovery: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
        }
      }

      if (params.action === "get_cookies") {
        const title = await page.title().catch(() => "")
        const info = await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          title,
          navigated,
          materialSummary: actorSessionSummary(stored),
        })
        const snapshot = await snapshotFor(info)
        const merged = await mergeActorSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          actorLabel: info.actorLabel,
          material: browserAuthMaterial({
            actorLabel: info.actorLabel,
            pageURL: snapshot.page_url,
            headers: auth.headers,
            cookies: snapshot.cookies,
            localStorage: snapshot.local_storage,
            sessionStorage: snapshot.session_storage,
          }),
        })
        stored = merged
        await syncBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          materialSummary: actorSessionSummary(merged),
        })
        const lines = snapshot.cookies.map(
          (c: BrowserCookieInput) =>
            `${c.name}=${c.value} (domain=${c.domain}, path=${c.path}, secure=${c.secure}, httpOnly=${c.httpOnly}, sameSite=${c.sameSite})`,
        )
        await writeAttempt("ok", "", {
          count: snapshot.cookies.length,
          url: page.url(),
        })
        await markSuccess(page.url())
        return {
          title: `${snapshot.cookies.length} cookies`,
          metadata: {
            count: snapshot.cookies.length,
            actorSessionID: info.actorSessionID,
            browserSessionID: info.browserSessionID,
            pageID: info.pageID,
            navigationIndex: info.navigationIndex,
            recoveryAttempts: recovery?.attempts ?? 0,
            recoveryStrategy: recovery?.strategy,
            targetProfileStatus: profile?.status,
          } as any,
          envelope: annotateEnvelope(buildBrowserInventoryEnvelope(snapshot), recovery),
          output: [lines.join("\n") || "No cookies.", recovery ? `Recovery: ${recovery.strategy}` : ""].filter(Boolean).join("\n"),
        }
      }

      return {
        title: "Unknown action",
        metadata: {} as any,
        envelope: makeToolResultEnvelope({
          status: "fatal_error",
          error: {
            code: "unknown_action",
            message: `Unknown action: ${params.action}`,
          },
        }),
        output: `Unknown action: ${params.action}`,
      }
    } catch (error) {
      const info = classifyBrowserFailure(error)
      const failureURL = params.url || stored?.lastURL || session.page.url()
      if (failureURL) {
        await noteTargetSignal(ctx.sessionID, failureURL, info.code, true).catch(() => undefined)
      }
      await writeAttempt("error", info.code, {
        message: info.message,
        recovery_strategy: recovery?.strategy,
        recovery_attempts: recovery?.attempts ?? 0,
      })
      if (shouldResetBrowserSessionAfterFailure(info)) {
        await resetBrowserSession({
          sessionID: ctx.sessionID,
          actorSessionID: session.actorSessionID,
          status: "reset",
          errorCode: info.code,
        }).catch(() => undefined)
        return errorResult(error, recovery)
      }
      await syncBrowserSession({
        sessionID: ctx.sessionID,
        actorSessionID: session.actorSessionID,
        materialSummary: stored ? actorSessionSummary(stored) : undefined,
        status: "error",
        errorCode: info.code,
      }).catch(() => undefined)
      return errorResult(error, recovery)
    }
  },
})
