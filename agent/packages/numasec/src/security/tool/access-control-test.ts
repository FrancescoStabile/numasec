/**
 * Tool: access_control_test
 *
 * Tests for IDOR, CSRF, CORS misconfigurations, and mass assignment.
 */

import z from "zod"
import { Database, eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { actionTarget, inferActionKind, inferActionResourceUrl } from "../action-inference"
import type { HttpRequestOptions } from "../http-client"
import { inferActorIdentity, type ActorIdentity } from "../actor-inference"
import { EvidenceNodeTable } from "../evidence.sql"
import { detectCollectionExposure, detectResourceExposure } from "../resource-inference"
import { canonicalSecuritySessionID } from "../security-session"
import {
  actorIdentityFromMaterial,
  actorSessionRequest,
  httpAuthMaterial,
  mergeActorSession,
} from "../runtime/actor-session-store"
import { executeHttpWithRecovery } from "../runtime/http-execution"
import { makeToolResultEnvelope } from "./result-envelope"

function slug(value: string) {
  return value.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase()
}

function target(url: string, parameter: string, value: string) {
  const token = `{${parameter}}`
  if (url.includes(token)) return url.replaceAll(token, encodeURIComponent(value))
  const colon = `:${parameter}`
  if (url.includes(colon)) return url.replaceAll(colon, encodeURIComponent(value))
  const next = new URL(url)
  next.searchParams.set(parameter, value)
  return next.toString()
}

function success(status: number) {
  return status >= 200 && status < 300
}

function bodyObject(input: string) {
  try {
    const value = JSON.parse(input)
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      return value as Record<string, unknown>
    }
  } catch {}
  return
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function payload(input: unknown) {
  if (input && typeof input === "object" && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
}

const RESTRICTED_TRANSITIONS = new Set(["approved", "claimed", "published", "verified", "completed", "closed", "deleted", "active", "archived"])

function workflowTransition(body?: string) {
  if (!body) return
  const value = bodyObject(body)
  if (!value) return
  const state = typeof value.state === "string" ? value.state : typeof value.status === "string" ? value.status : ""
  if (state && RESTRICTED_TRANSITIONS.has(state.toLowerCase())) {
    return {
      field: typeof value.state === "string" ? "state" : "status",
      target: state.toLowerCase(),
    }
  }
  const flags: Array<[string, string]> = [
    ["approved", "approved"],
    ["claimed", "claimed"],
    ["published", "published"],
    ["verified", "verified"],
    ["completed", "completed"],
    ["closed", "closed"],
    ["deleted", "deleted"],
    ["active", "active"],
    ["archived", "archived"],
  ]
  for (const [field, target] of flags) {
    if (value[field] !== true) continue
    return {
      field,
      target,
    }
  }
}

function actorLabel(input: "primary" | "secondary") {
  if (input === "secondary") return "secondary"
  return "primary"
}

function authContext(input?: Actor) {
  if (!input) return false
  if (input.cookies) return true
  if (!input.headers) return false
  return Object.keys(input.headers).some((item) => /(authorization|auth|token|session|jwt|api[-_]?key)/i.test(item))
}

type Actor = {
  name: "primary" | "secondary"
  actor_label?: string
  actor_session_id?: string
  headers?: Record<string, string>
  cookies?: string
  actor_id?: string
  actor_email?: string
  actor_role?: string
  identity?: ActorIdentity
}

type IdorResult = {
  actor: "primary" | "secondary"
  id: string
  status: number
  length: number
  url: string
  self: boolean
  foreign: boolean
  principal: boolean
  response_id: string
  response_owner: string
  response_state: string
}

type WorkflowResult = {
  actor: "primary" | "secondary"
  url: string
  method: string
  action_status: number
  before_status: number
  before_state: string
  before_self: boolean
  before_foreign: boolean
  after_status: number
  after_state: string
  after_self: boolean
  after_foreign: boolean
  after_missing: boolean
  response_deleted: boolean
}

const DESCRIPTION = `Test for access control vulnerabilities:
- IDOR: change resource IDs to access other users' data
- CSRF: check for missing anti-CSRF protections
- CORS: test for permissive cross-origin policies
- Mass Assignment: send extra fields to modify protected attributes
- Workflow actions: replay browser-mined approve/claim/publish endpoints and confirm restricted state transitions

Requires: target URL. For IDOR, also provide the parameter with the resource ID. For workflow replay, provide an action endpoint URL or rely on browser-mined resource inventory metadata for the resource URL and form replay details.

CHAIN POTENTIAL:
- IDOR → data leak of all users' data
- CORS misconfiguration → cross-site data theft via victim's browser
- CSRF + IDOR → modify other users' data from attacker's site
- Mass assignment → privilege escalation (role: "admin")`

const AccessControlParameters = z.object({
  url: z.string().describe("Target URL"),
  test_type: z
    .enum(["idor", "csrf", "cors", "mass_assignment", "workflow", "all"])
    .default("all")
    .describe("Specific test type or all"),
  parameter: z.string().optional().describe("Parameter with resource ID (for IDOR)"),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).optional().describe("HTTP method"),
  headers: z.record(z.string(), z.string()).optional().describe("Headers including auth"),
  actor_session_id: z.string().optional().describe("Optional shared actor session ID for the primary actor"),
  actor_label: z.string().optional().describe("Optional shared actor label used to derive the primary actor session"),
  secondary_headers: z.record(z.string(), z.string()).optional().describe("Optional secondary actor headers for differential authz testing"),
  secondary_actor_session_id: z.string().optional().describe("Optional shared actor session ID for the secondary actor"),
  secondary_actor_label: z.string().optional().describe("Optional shared actor label used to derive the secondary actor session"),
  cookies: z.string().optional().describe("Cookies"),
  secondary_cookies: z.string().optional().describe("Optional secondary actor cookies for differential authz testing"),
  actor_id: z.string().optional().describe("Optional known identifier for the primary actor"),
  actor_email: z.string().optional().describe("Optional known email/username for the primary actor"),
  actor_role: z.string().optional().describe("Optional known role for the primary actor"),
  secondary_actor_id: z.string().optional().describe("Optional known identifier for the secondary actor"),
  secondary_actor_email: z.string().optional().describe("Optional known email/username for the secondary actor"),
  secondary_actor_role: z.string().optional().describe("Optional known role for the secondary actor"),
  body: z.string().optional().describe("Request body"),
  id_values: z.array(z.string()).optional().describe("Optional custom identifier values for IDOR testing"),
  own_value: z.string().optional().describe("Known resource identifier owned by the primary actor"),
  foreign_value: z.string().optional().describe("Known resource identifier owned by another actor"),
  resource_url: z.string().optional().describe("Optional baseline/readback resource URL for workflow action probes"),
  action_kind: z.string().optional().describe("Optional workflow action hint such as approve, claim, publish, or verify"),
  target_state: z.string().optional().describe("Optional expected post-action state for workflow probes"),
})

type AccessControlParams = z.infer<typeof AccessControlParameters>

async function buildActors(params: AccessControlParams, observations: Record<string, any>[], sessionID: Tool.Context["sessionID"]) {
  const actors: Actor[] = [
    {
      name: "primary" as const,
      actor_label: params.actor_label,
      actor_session_id: params.actor_session_id,
      headers: params.headers,
      cookies: params.cookies,
      actor_id: params.actor_id,
      actor_email: params.actor_email,
      actor_role: params.actor_role,
    },
  ]
  if (
    params.secondary_headers ||
    params.secondary_cookies ||
    params.secondary_actor_id ||
    params.secondary_actor_email ||
    params.secondary_actor_role ||
    params.secondary_actor_session_id ||
    params.secondary_actor_label
  ) {
    actors.push({
      name: "secondary" as const,
      actor_label: params.secondary_actor_label,
      actor_session_id: params.secondary_actor_session_id,
      headers: params.secondary_headers,
      cookies: params.secondary_cookies,
      actor_id: params.secondary_actor_id,
      actor_email: params.secondary_actor_email,
      actor_role: params.secondary_actor_role,
    })
  }
  const actorKeys: string[] = []
  for (const actor of actors) {
    const merged = await mergeActorSession({
      sessionID,
      actorSessionID: actor.actor_session_id,
      actorLabel: actor.actor_label || actor.name,
      material: {
        ...httpAuthMaterial({
          actorLabel: actor.actor_label || actor.name,
          url: params.url,
          requestHeaders: actor.headers,
          requestCookies: actor.cookies,
        }),
        actorID: actor.actor_id,
        actorEmail: actor.actor_email,
        actorRole: actor.actor_role,
      },
    })
    const auth = actorSessionRequest(merged, actor.headers, actor.cookies)
    actor.actor_session_id = merged.actorSessionID
    actor.actor_label = merged.actorLabel
    actor.headers = Object.keys(auth.headers).length > 0 ? auth.headers : undefined
    actor.cookies = auth.cookies || undefined
    actor.identity = actorIdentityFromMaterial(merged)
    const item = `actor-${actor.name}`
    actorKeys.push(item)
    observations.push({
      key: item,
      family: "actor_identity",
      kind: "request_actor",
      actor_label: actor.identity.label,
      actor_id: actor.identity.id,
      actor_email: actor.identity.email,
      actor_role: actor.identity.role,
      privileged: actor.identity.privileged,
      source: actor.identity.source,
      actor_session_id: actor.actor_session_id,
    })
  }
  return {
    actors,
    actorKeys,
  }
}

async function send(ctx: Tool.Context, actor: Actor | undefined, url: string, action: string, request: HttpRequestOptions) {
  const result = await executeHttpWithRecovery({
    sessionID: ctx.sessionID,
    toolName: "access_control_test",
    action,
    actorSessionID: actor?.actor_session_id,
    url,
    request,
  })
  return result.response
}

function workflowCandidate(sessionID: Tool.Context["sessionID"], url: string, actor?: ActorIdentity) {
  const currentSessionID = canonicalSecuritySessionID(sessionID)
  const rows = Database.use((db) =>
    db
      .select()
      .from(EvidenceNodeTable)
      .where(eq(EvidenceNodeTable.session_id, currentSessionID))
      .all(),
  )
  let fallback: Record<string, unknown> | undefined
  let index = rows.length - 1
  while (index >= 0) {
    const row = rows[index]
    index -= 1
    if (row.type !== "observation") continue
    const value = payload(row.payload)
    if (text(value.family) !== "resource_inventory") continue
    if (text(value.url) !== url) continue
    if (!text(value.action_kind) && !text(value.resource_url) && !text(value.form_body)) continue
    if (!actor) return value
    const id = text(value.actor_id)
    if (actor.id && id && actor.id === id) return value
    const email = text(value.actor_email)
    if (actor.email && email && actor.email.toLowerCase() === email.toLowerCase()) return value
    if (!fallback) fallback = value
  }
  return fallback
}

function requestHeaders(input?: Record<string, string>, body?: string, enctype?: string) {
  const out = {
    ...(input ?? {}),
  }
  if (!body || !enctype) return out
  const keys = Object.keys(out)
  for (const item of keys) {
    if (item.toLowerCase() !== "content-type") continue
    return out
  }
  out["Content-Type"] = enctype
  return out
}

function missing(status: number) {
  return status === 404 || status === 410
}

function deletedFlag(input: unknown): boolean {
  if (input === true) return true
  if (typeof input === "string") return input.toLowerCase() === "true"
  if (typeof input === "number") return input === 1
  if (!input || typeof input !== "object") return false
  if (Array.isArray(input)) {
    for (const item of input) {
      if (deletedFlag(item)) return true
    }
    return false
  }
  const value = payload(input)
  if (deletedFlag(value.deleted)) return true
  if (deletedFlag(value.destroyed)) return true
  if (deletedFlag(value.removed)) return true
  for (const item of Object.keys(value)) {
    if (deletedFlag(value[item])) return true
  }
  return false
}

function bodyDeleted(input: string) {
  const value = bodyObject(input)
  if (!value) return false
  return deletedFlag(value)
}

function destructiveAction(action: string, target: string) {
  if (action.toLowerCase() === "delete") return true
  return target.toLowerCase() === "deleted"
}

async function runWorkflowActionProbe(
  params: AccessControlParams,
  ctx: Tool.Context,
  actors: Actor[],
  actorKeys: string[],
) {
  const parts: string[] = []
  const artifacts: Record<string, any>[] = []
  const verifications: Record<string, any>[] = []
  let findings = 0
  ctx.metadata({ title: "Testing workflow action authorization..." })
  const primary = actors.find((item) => item.name === "primary")
  const candidate = workflowCandidate(ctx.sessionID, params.url, primary?.identity)
  const label = text(candidate?.action_label) || text(candidate?.submit_label)
  const action = params.action_kind || text(candidate?.action_kind) || inferActionKind(params.url, label)
  const target = params.target_state || text(candidate?.action_target_state) || actionTarget(action)
  const resource = params.resource_url || text(candidate?.resource_url) || inferActionResourceUrl(params.url, action)
  const method = params.method || text(candidate?.method) || "POST"
  const body = params.body || text(candidate?.request_body) || text(candidate?.form_body)
  const enctype = text(candidate?.request_content_type) || text(candidate?.form_enctype)
  const destructive = destructiveAction(action, target)
  if (!resource) {
    parts.push("\n── Workflow action probe skipped: resource URL unavailable ──")
    return {
      parts,
      artifacts,
      verifications,
      findings,
    }
  }

  const rows: WorkflowResult[] = []
  for (const actor of actors) {
    const identity = actor.identity ?? inferActorIdentity({ label: actor.name })
    const before = await send(ctx, actor, resource, "workflow_before", {
      method: "GET",
      headers: actor.headers,
      cookies: actor.cookies,
    })
    const beforeMatch = detectResourceExposure(before.body, identity)
    const actionResp = await send(ctx, actor, params.url, "workflow_action", {
      method,
      headers: requestHeaders(actor.headers, body, enctype),
      body,
      cookies: actor.cookies,
    })
    const after = await send(ctx, actor, resource, "workflow_after", {
      method: "GET",
      headers: actor.headers,
      cookies: actor.cookies,
    })
    const afterMatch = detectResourceExposure(after.body, identity)
    const replyMatch = detectResourceExposure(actionResp.body, identity)
    rows.push({
      actor: actor.name,
      url: params.url,
      method,
      action_status: actionResp.status,
      before_status: before.status,
      before_state: beforeMatch?.summary.state ?? "",
      before_self: beforeMatch?.self ?? false,
      before_foreign: beforeMatch?.foreign ?? false,
      after_status: after.status,
      after_state: afterMatch?.summary.state || replyMatch?.summary.state || "",
      after_self: afterMatch?.self ?? replyMatch?.self ?? false,
      after_foreign: afterMatch?.foreign ?? replyMatch?.foreign ?? false,
      after_missing: missing(after.status),
      response_deleted: bodyDeleted(actionResp.body),
    })
  }

  const hits = rows.filter((item) => {
    const actor = actors.find((row) => row.name === item.actor)
    if (actor?.identity?.privileged) return false
    if (!success(item.action_status)) return false
    if (destructive) {
      if (!success(item.before_status)) return false
      if (!(item.before_self || item.before_foreign)) return false
      if (item.after_missing) return true
      if (item.response_deleted) return true
      if (!target) return false
      return item.after_state.toLowerCase() === target.toLowerCase()
    }
    if (!target) return false
    if (!item.after_state) return false
    if (item.after_state.toLowerCase() !== target.toLowerCase()) return false
    if (!item.before_state) return false
    if (item.before_state.toLowerCase() === target.toLowerCase()) return false
    return item.before_self || item.before_foreign || item.after_self || item.after_foreign
  })
  if (hits.length === 0) {
    parts.push(`\n── Workflow action: no restricted transition confirmed on ${params.url} ──`)
    return {
      parts,
      artifacts,
      verifications,
      findings,
    }
  }

  const item = `workflow-action-${slug(new URL(params.url).pathname || "root")}-${slug(action || target || method)}`
  parts.push(`\n── ⚠ Workflow abuse: restricted action endpoint confirmed ──`)
  for (const hit of hits) {
    const relation = hit.before_foreign ? "foreign" : "owned"
    const outcome = destructive
      ? hit.after_missing || hit.response_deleted
        ? `${hit.before_state || "present"} -> deleted`
        : `${hit.before_state} -> ${hit.after_state}`
      : `${hit.before_state} -> ${hit.after_state}`
    parts.push(`  ${actorLabel(hit.actor)} actor used ${action || method} on ${relation} resource via ${params.url} (${outcome})`)
  }
  findings += 1
  artifacts.push({
    key: item,
    subtype: "workflow_action_scan",
    url: params.url,
    resource_url: resource,
    method,
    action_kind: action,
    target_state: target,
    destructive,
    payload: body,
    enctype,
    actors: actors.map((actor) => ({
      actor: actor.name,
      identity: actor.identity,
    })),
    results: rows,
  })
  verifications.push({
    key: `${item}-verified`,
    family: "workflow",
    kind: destructive ? "destructive_action_transition" : "restricted_action_transition",
    title: destructive
      ? `Low-privilege actor deleted resource via restricted workflow action ${action || method}`
      : `Low-privilege actor reached restricted workflow action ${action || method}`,
    technical_severity: "high",
    passed: true,
    control: "positive",
    url: params.url,
    method,
    action_kind: action,
    target_state: target,
    resource_url: resource,
    destructive,
    payload: body,
    evidence_keys: [item, ...actorKeys],
  })
  return {
    parts,
    artifacts,
    verifications,
    findings,
  }
}

export const AccessControlTestTool = Tool.define("access_control_test", {
  description: DESCRIPTION,
  parameters: AccessControlParameters,
  async execute(params, ctx) {
    await ctx.ask({
      permission: "access_control_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, test_type: params.test_type } as Record<string, any>,
    })

    const tests = params.test_type === "all" ? ["idor", "csrf", "cors", "mass_assignment"] : [params.test_type]
    const parts: string[] = []
    let totalFindings = 0
    const artifacts: Record<string, any>[] = []
    const observations: Record<string, any>[] = []
    const verifications: Record<string, any>[] = []
    const value = await buildActors(params, observations, ctx.sessionID)
    const actors = value.actors
    const actorKeys = value.actorKeys
    const primary = actors.find((item) => item.name === "primary")

    // CORS test
    if (tests.includes("cors")) {
      ctx.metadata({ title: "Testing CORS..." })
      const origins = ["https://evil.com", "null", "https://evil." + new URL(params.url).hostname]
      const details: string[] = []
      let critical = false
      let reflected = false
      let wildcard = false

      for (const origin of origins) {
        const resp = await send(ctx, primary, params.url, "cors_probe", {
          method: "GET",
          headers: { ...(primary?.headers ?? {}), Origin: origin },
          cookies: primary?.cookies,
        })

        const acao = resp.headers["access-control-allow-origin"]
        const acac = resp.headers["access-control-allow-credentials"]
        if (!acao) continue
        const allowCredentials = acac === "true"
        const reflectOrigin = acao === origin
        if (reflectOrigin && allowCredentials) {
          critical = true
          details.push(`  Origin ${origin} reflected with credentials enabled`)
          continue
        }
        if (reflectOrigin) {
          reflected = true
          details.push(`  Origin ${origin} reflected without credentials`)
          continue
        }
        if (acao === "*" && allowCredentials) {
          critical = true
          details.push(`  Wildcard origin with credentials enabled`)
          continue
        }
        if (acao === "*") {
          wildcard = true
          details.push(`  Wildcard origin without credentials`)
        }
      }

      if (critical) {
        parts.push(`\n── ⚠ CORS Misconfiguration (high risk) ──`)
        for (const detail of details) parts.push(detail)
        totalFindings++
        const item = `cors-${slug(new URL(params.url).pathname || "root")}`
        artifacts.push({
          key: item,
          subtype: "cors_scan",
          url: params.url,
          details,
          tested_origins: origins,
        })
        verifications.push({
          key: `${item}-verified`,
          family: "cors",
          kind: "dangerous_policy",
          title: "Dangerous CORS policy on sensitive endpoint",
          technical_severity: "high",
          passed: true,
          control: "positive",
          url: params.url,
          method: "GET",
          evidence_keys: [item],
        })
      } else if (reflected) {
        parts.push(`\n── ⚠ CORS Misconfiguration (review required) ──`)
        for (const detail of details) parts.push(detail)
        totalFindings++
        observations.push({
          key: `cors-review-${slug(new URL(params.url).pathname || "root")}`,
          family: "cors",
          kind: "origin_reflection_without_credentials",
          url: params.url,
          details,
        })
      } else if (wildcard) {
        parts.push(`\n── CORS wildcard observed (informational) ──`)
        for (const detail of details) parts.push(detail)
        observations.push({
          key: `cors-info-${slug(new URL(params.url).pathname || "root")}`,
          family: "cors",
          kind: "wildcard_without_credentials",
          url: params.url,
          details,
        })
      } else {
        parts.push("\n── CORS: properly configured ──")
      }
    }

    // CSRF test
    if (tests.includes("csrf")) {
      ctx.metadata({ title: "Testing CSRF..." })
      const method = params.method ?? "POST"

      if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
        // Send request without CSRF token
        const resp = await send(ctx, primary, params.url, "csrf_probe", {
          method,
          headers: {
            ...(primary?.headers ?? {}),
            "Content-Type": "application/x-www-form-urlencoded",
            Referer: "https://evil.com",
            Origin: "https://evil.com",
          },
          body: params.body ?? "test=1",
          cookies: primary?.cookies,
        })

        if (resp.status >= 200 && resp.status < 400) {
          const item = `csrf-${method.toLowerCase()}-${slug(new URL(params.url).pathname || "root")}`
          artifacts.push({
            key: item,
            subtype: "csrf_check",
            url: params.url,
            method,
            status: resp.status,
            response_preview: resp.body.slice(0, 300),
          })
          if (authContext(primary)) {
            parts.push(`\n── ⚠ Potential CSRF ──`)
            parts.push(`  ${method} ${params.url} accepted cross-origin request`)
            parts.push(`  Status: ${resp.status}`)
            parts.push(`  No CSRF token validation detected`)
            totalFindings++
            verifications.push({
              key: `${item}-verified`,
              family: "csrf",
              kind: "cross_origin_state_change",
              title: "Potential CSRF on authenticated state-changing endpoint",
              technical_severity: "medium",
              passed: true,
              control: "positive",
              url: params.url,
              method,
              evidence_keys: [item],
            })
          } else {
            parts.push(`\n── Cross-origin unauthenticated state change accepted ──`)
            parts.push(`  ${method} ${params.url} accepted cross-origin request without victim auth context`)
            parts.push(`  Status: ${resp.status}`)
            parts.push(`  This is weaker than classic CSRF because no authenticated session or token was exercised`)
            observations.push({
              key: `${item}-observation`,
              family: "csrf",
              kind: "cross_origin_unauthenticated_state_change",
              url: params.url,
              method,
              status: resp.status,
            })
          }
        } else {
          parts.push(`\n── CSRF: ${method} request rejected (status ${resp.status}) ──`)
        }
      } else {
        parts.push("\n── CSRF: GET requests not vulnerable by design ──")
      }
    }

    // IDOR test
    if (tests.includes("idor")) {
      const baseUrl = new URL(params.url)
      if (!params.parameter) {
        ctx.metadata({ title: "Testing collection authz exposure..." })
        const scans: Array<Record<string, unknown>> = []
        for (const actor of actors) {
          const resp = await send(ctx, actor, params.url, "idor_collection", {
            method: params.method ?? "GET",
            headers: actor.headers,
            cookies: actor.cookies,
          })
          const summary = detectCollectionExposure(resp.body, actor.identity ?? inferActorIdentity({ label: actor.name }))
          scans.push({
            actor: actor.name,
            status: resp.status,
            url: params.url,
            identity: actor.identity ?? inferActorIdentity({ label: actor.name }),
            total: summary?.total ?? 0,
            foreign_count: summary?.foreign_count ?? 0,
            foreign_ids: summary?.foreign_ids ?? [],
            foreign_emails: summary?.foreign_emails ?? [],
            principal: summary?.principal ?? false,
            sample: summary?.sample ?? [],
          })
        }

        const leaks = scans.filter((item) => {
          const status = Number(item.status ?? 0)
          const count = Number(item.foreign_count ?? 0)
          const principal = item.principal === true
          const identity = item.identity as ActorIdentity | undefined
          if (!success(status) || count <= 0 || !principal) return false
          if (identity?.privileged) return false
          if (identity?.role) return true
          return actors.length > 1
        })

        if (leaks.length > 0) {
          parts.push(`\n── ⚠ IDOR: collection exposure confirmed ──`)
          for (const item of leaks) {
            const actor = String(item.actor ?? "primary")
            const sample = Array.isArray(item.sample) ? item.sample.join(", ") : ""
            parts.push(`  ${actorLabel(actor as "primary" | "secondary")} actor saw foreign records: ${sample}`)
          }
          totalFindings++
          const item = `idor-collection-${slug(baseUrl.pathname || "root")}`
          artifacts.push({
            key: item,
            subtype: "idor_collection_scan",
            url: params.url,
            actors: scans,
          })
          verifications.push({
            key: `${item}-verified`,
            family: "idor",
            kind: leaks.length > 1 ? "collection_cross_actor_exposure" : "collection_foreign_records",
            title: "Low-privilege collection returned foreign actor records",
            technical_severity: "high",
            passed: true,
            control: "positive",
            url: params.url,
            method: params.method ?? "GET",
            evidence_keys: [item, ...actorKeys],
          })
        }

        if (leaks.length === 0) {
          const reviews = scans.filter((item) => Number(item.foreign_count ?? 0) > 0)
          if (reviews.length > 0) {
            parts.push(`\n── IDOR collection exposure requires review ──`)
            observations.push({
              key: `idor-collection-review-${slug(baseUrl.pathname || "root")}`,
              family: "idor",
              kind: "collection_review",
              url: params.url,
              actors: scans,
            })
          }
          if (reviews.length === 0) {
            parts.push(`\n── IDOR: no collection exposure detected ──`)
          }
        }
      }

      if (params.parameter) {
        ctx.metadata({ title: `Testing IDOR on ${params.parameter}...` })

        const testIds = params.id_values ?? ["1", "2", "0", "999999", "-1", "admin", "test"]
        const values = Array.from(new Set([params.own_value, params.foreign_value, ...testIds].filter((item): item is string => typeof item === "string" && item.length > 0)))
        const method = params.method ?? "GET"
        const mutation = method !== "GET"
        const workflow = mutation ? workflowTransition(params.body) : undefined
        const baseline = new Map<string, {
          status: number
          state: string
          self: boolean
          foreign: boolean
        }>()
        if (workflow) {
          for (const actor of actors) {
            for (const id of values) {
              const testUrl = target(params.url, params.parameter, id)
              const resp = await send(ctx, actor, testUrl, "workflow_baseline", {
                method: "GET",
                headers: actor.headers,
                cookies: actor.cookies,
              })
              const match = detectResourceExposure(resp.body, actor.identity ?? inferActorIdentity({ label: actor.name }))
              baseline.set(`${actor.name}:${id}`, {
                status: resp.status,
                state: match?.summary.state ?? "",
                self: match?.self ?? false,
                foreign: match?.foreign ?? false,
              })
            }
          }
        }
        const ids: IdorResult[] = []
        for (const actor of actors) {
          for (const id of values) {
            const testUrl = target(params.url, params.parameter, id)
            const resp = await send(ctx, actor, testUrl, "idor_probe", {
              method,
              headers: actor.headers,
              body: params.body,
              cookies: actor.cookies,
            })
            const match = detectResourceExposure(resp.body, actor.identity ?? inferActorIdentity({ label: actor.name }))
            ids.push({
              actor: actor.name,
              id,
              status: resp.status,
              length: resp.body.length,
              url: testUrl,
              self: match?.self ?? false,
              foreign: match?.foreign ?? false,
              principal: match?.principal ?? false,
              response_id: match?.summary.id ?? "",
              response_owner: match?.summary.owner ?? "",
              response_state: match?.summary.state ?? "",
            })
          }
        }

        const primaryRows = ids.filter((item) => item.actor === "primary")
        const secondaryRows = ids.filter((item) => item.actor === "secondary")
        const primarySelf = primaryRows.find((item) => success(item.status) && item.self)
        const secondarySelf = secondaryRows.find((item) => success(item.status) && item.self)
        const primaryForeigns = primaryRows.filter((item) => success(item.status) && item.foreign)
        const secondaryForeigns = secondaryRows.filter((item) => success(item.status) && item.foreign)
        const ownPrimary = primaryRows.find((item) => item.id === params.own_value && success(item.status))
        const foreignPrimary = primaryRows.find((item) => item.id === params.foreign_value && success(item.status))
        const ownSecondary = secondaryRows.find((item) => item.id === params.foreign_value && success(item.status))
        const foreignSecondary = secondaryRows.find((item) => item.id === params.own_value && success(item.status))
        const primaryActor = actors.find((item) => item.name === "primary")
        const secondaryActor = actors.find((item) => item.name === "secondary")
        const primaryKnownSelf = params.own_value ? ownPrimary : primarySelf
        const primaryKnownForeign = params.foreign_value ? foreignPrimary : primaryForeigns[0]
        const secondaryKnownSelf = params.foreign_value ? ownSecondary : secondarySelf
        const secondaryKnownForeign = params.own_value ? foreignSecondary : secondaryForeigns[0]
        const primaryVerified = !!primaryKnownSelf && !!primaryKnownForeign && !primaryActor?.identity?.privileged
        const secondaryVerified = !!secondaryKnownSelf && !!secondaryKnownForeign && !secondaryActor?.identity?.privileged
        const primaryCrossTarget = secondarySelf?.id || params.foreign_value || ""
        const secondaryCrossTarget = primarySelf?.id || params.own_value || ""
        const primaryCross = primaryForeigns.some((item) => item.id === primaryCrossTarget)
        const secondaryCross = secondaryForeigns.some((item) => item.id === secondaryCrossTarget)

        if (primaryVerified || secondaryVerified) {
          const item = `idor-diff-${slug(params.parameter)}-${slug(baseUrl.pathname || "root")}`
          parts.push(
            mutation
              ? primaryCross && secondaryCross
                ? `\n── ⚠ IDOR: cross-actor mutation confirmed on ${params.parameter} ──`
                : `\n── ⚠ IDOR: foreign resource mutation confirmed on ${params.parameter} ──`
              : primaryCross && secondaryCross
                ? `\n── ⚠ IDOR: cross-actor access confirmed on ${params.parameter} ──`
                : `\n── ⚠ IDOR: known foreign resource access confirmed on ${params.parameter} ──`,
          )
          if (primaryVerified) parts.push(`  Primary actor reached foreign resource ${primaryKnownForeign?.id ?? params.foreign_value ?? ""}`)
          if (secondaryVerified) parts.push(`  Secondary actor reached foreign resource ${secondaryKnownForeign?.id ?? params.own_value ?? ""}`)
          totalFindings++
          artifacts.push({
            key: item,
            subtype: "idor_differential_scan",
            url: params.url,
            parameter: params.parameter,
            own_value: params.own_value ?? primaryKnownSelf?.id ?? "",
            foreign_value: params.foreign_value ?? primaryKnownForeign?.id ?? "",
            method,
            body: params.body ?? "",
            actors: actors.map((actor) => ({
              actor: actor.name,
              identity: actor.identity,
            })),
            results: ids,
          })
          verifications.push({
            key: `${item}-verified`,
            family: "idor",
            kind: mutation
              ? primaryCross && secondaryCross
                ? "cross_actor_mutation"
                : "foreign_resource_mutation"
              : primaryCross && secondaryCross
                ? "cross_actor_access"
                : "foreign_resource_access",
            title: mutation
              ? primaryCross && secondaryCross
                ? `Cross-actor mutation confirmed on ${params.parameter}`
                : `Known foreign resource mutation confirmed on ${params.parameter}`
              : primaryCross && secondaryCross
                ? `Cross-actor access confirmed on ${params.parameter}`
                : `Known foreign resource access confirmed on ${params.parameter}`,
            technical_severity: "high",
            passed: true,
            control: "positive",
            url: params.url,
            method,
            parameter: params.parameter,
            evidence_keys: [item, ...actorKeys],
          })
        }

        if (workflow) {
          const transitions = ids.filter((item) => {
            const actor = actors.find((row) => row.name === item.actor)
            if (actor?.identity?.privileged) return false
            if (!success(item.status) || !item.self) return false
            if (item.response_state.toLowerCase() !== workflow.target) return false
            const before = baseline.get(`${item.actor}:${item.id}`)
            if (!before || !success(before.status) || !before.self) return false
            if (!before.state) return false
            return before.state.toLowerCase() !== workflow.target
          })
          if (transitions.length > 0) {
            const item = `workflow-${slug(params.parameter)}-${slug(baseUrl.pathname || "root")}-${workflow.target}`
            parts.push(`\n── ⚠ Workflow abuse: restricted state transition confirmed on ${params.parameter} ──`)
            for (const hit of transitions) {
              const before = baseline.get(`${hit.actor}:${hit.id}`)
              parts.push(`  ${actorLabel(hit.actor)} actor moved resource ${hit.id} from ${before?.state || "unknown"} to ${workflow.target}`)
            }
            totalFindings++
            artifacts.push({
              key: item,
              subtype: "workflow_transition_scan",
              url: params.url,
              parameter: params.parameter,
              method,
              workflow_field: workflow.field,
              target_state: workflow.target,
              actors: actors.map((actor) => ({
                actor: actor.name,
                identity: actor.identity,
              })),
              baseline: Object.fromEntries(baseline),
              results: ids,
            })
            verifications.push({
              key: `${item}-verified`,
              family: "workflow",
              kind: "restricted_state_transition",
              title: `Low-privilege actor advanced resource state to ${workflow.target}`,
              technical_severity: "high",
              passed: true,
              control: "positive",
              url: params.url,
              method,
              parameter: params.parameter,
              workflow_field: workflow.field,
              target_state: workflow.target,
              payload: params.body ?? "",
              evidence_keys: [item, ...actorKeys],
            })
          }
        }

        if (!primaryVerified && !secondaryVerified) {
          let idorFindings = 0
          for (const item of ids.filter((row) => row.actor === "primary")) {
            if (item.status === 200 && item.length > 100) {
              idorFindings++
              parts.push(`  ${actorLabel("primary")} ID ${item.id}: ${item.status} (${item.length} bytes)`)
            }
          }

          if (idorFindings > 1) {
            parts.push(`\n── ⚠ IDOR: ${idorFindings} different IDs returned data ──`)
            parts.push(`  Parameter: ${params.parameter}`)
            totalFindings++
            const item = `idor-${slug(params.parameter)}-${slug(baseUrl.pathname || "root")}`
            artifacts.push({
              key: item,
              subtype: "idor_scan",
              url: params.url,
              parameter: params.parameter,
              actors: actors.map((actor) => ({
                actor: actor.name,
                identity: actor.identity,
              })),
              results: ids,
            })
            verifications.push({
              key: `${item}-verified`,
              family: "idor",
              kind: "resource_enumeration",
              title: `IDOR indicated on ${params.parameter}`,
              technical_severity: "high",
              passed: true,
              control: "positive",
              url: params.url,
              method,
              parameter: params.parameter,
              evidence_keys: [item, ...actorKeys],
            })
          }

          if (idorFindings <= 1) {
            parts.push(`\n── IDOR: no enumeration detected on ${params.parameter} ──`)
          }
        }
      }
    }

    if (tests.includes("workflow")) {
      const workflow = await runWorkflowActionProbe(params, ctx, actors, actorKeys)
      totalFindings += workflow.findings
      parts.push(...workflow.parts)
      artifacts.push(...workflow.artifacts)
      verifications.push(...workflow.verifications)
    }

    // Mass assignment test
    if (tests.includes("mass_assignment")) {
      ctx.metadata({ title: "Testing mass assignment..." })
      const extraFields = ["role", "admin", "is_admin", "isAdmin", "privilege", "status", "verified", "active"]

      const baseBody = params.body ? JSON.parse(params.body) : {}
      for (const field of extraFields) {
        const testBody = { ...baseBody, [field]: field === "role" ? "admin" : true }
        const resp = await send(ctx, primary, params.url, "mass_assignment", {
          method: params.method ?? "POST",
          headers: { ...(primary?.headers ?? {}), "Content-Type": "application/json" },
          body: JSON.stringify(testBody),
          cookies: primary?.cookies,
        })

        if (resp.status >= 200 && resp.status < 300) {
          const respLower = resp.body.toLowerCase()
          if (respLower.includes(`"${field}"`) || respLower.includes(`"${field}":true`) || respLower.includes(`"${field}":"admin"`)) {
            parts.push(`\n── ⚠ Mass Assignment: "${field}" accepted ──`)
            parts.push(`  Response includes the injected field`)
            parts.push(`  Response: ${resp.body.slice(0, 300)}`)
            totalFindings++
            const item = `mass-${slug(field)}-${slug(new URL(params.url).pathname || "root")}`
            artifacts.push({
              key: item,
              subtype: "mass_assignment_scan",
              url: params.url,
              field,
              status: resp.status,
              payload: testBody,
              response_preview: resp.body.slice(0, 300),
            })
            verifications.push({
              key: `${item}-verified`,
              family: "mass_assignment",
              kind: "protected_field_accepted",
              title: `Mass assignment accepted protected field ${field}`,
              technical_severity: field === "role" || field === "admin" || field === "is_admin" || field === "isAdmin" ? "high" : "medium",
              passed: true,
              control: "positive",
              url: params.url,
              method: params.method ?? "POST",
              parameter: field,
              evidence_keys: [item],
            })
          }
        }
      }
      if (!parts.some((l) => l.includes("Mass Assignment"))) {
        parts.push("\n── Mass Assignment: extra fields not reflected ──")
      }
    }

    return {
      title: totalFindings > 0
        ? `⚠ ${totalFindings} access control issue(s)`
        : "Access control: no issues",
      metadata: { findings: totalFindings, tests: tests.length } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts,
        observations,
        verifications,
        metrics: {
          findings: totalFindings,
          tests: tests.length,
        },
      }),
      output: parts.join("\n"),
    }
  },
})
