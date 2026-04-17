import { Cause, Duration, Effect, Layer, Schedule, Schema, ServiceMap } from "effect"
import { eq, inArray } from "../../storage/db"
import { makeRuntime } from "../../effect/run-service"
import type { SessionID } from "../../session/schema"
import { SessionTable } from "../../session/session.sql"
import { Database } from "../../storage/db"
import { inferActorIdentity, type ActorIdentity } from "../actor-inference"
import { decodeJwt } from "../scanner/jwt-analyzer"
import { canonicalSecuritySessionID } from "../security-session"
import { browserActorSessionID } from "./browser-runtime"
import { Log } from "../../util/log"
import {
  SecurityActorSessionTable,
  type SecurityActorSessionID,
  type SecurityBrowserSessionID,
} from "./runtime.sql"

export interface SessionCookie {
  name: string
  value: string
  domain?: string
  path?: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: string
}

export interface ActorSessionMaterial {
  actorSessionID: SecurityActorSessionID
  actorLabel: string
  actorID: string
  actorEmail: string
  actorRole: string
  privileged: boolean
  source: string
  headers: Record<string, string>
  cookies: SessionCookie[]
  localStorage: Record<string, string>
  sessionStorage: Record<string, string>
  csrf: Record<string, string>
  lastOrigin: string
  lastURL: string
  timeUpdated: number
}

export interface ActorSessionUpdate {
  actorLabel?: string
  actorID?: string
  actorEmail?: string
  actorRole?: string
  source?: string
  headers?: Record<string, string>
  cookies?: SessionCookie[]
  localStorage?: Record<string, string>
  sessionStorage?: Record<string, string>
  csrf?: Record<string, string>
  lastOrigin?: string
  lastURL?: string
}

export interface ResolveActorSessionInput {
  sessionID: SessionID
  actorSessionID?: string
  actorLabel?: string
}

export interface MergeActorSessionInput extends ResolveActorSessionInput {
  material: ActorSessionUpdate
}

type State = {
  sessions: Map<string, SessionEntry>
}

type SessionEntry = {
  sessionID: SessionID
  material: ActorSessionMaterial
}

const log = Log.create({ service: "security.actor-session-store" })

export const ACTOR_SESSION_TTL_MS = 15 * 60 * 1000

const AUTH = [
  "authorization",
  "proxy-authorization",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "x-csrf-token",
  "x-xsrf-token",
  "csrf-token",
  "xsrf-token",
  "x-api-key",
]

const TOKEN = new Set([
  "token",
  "authtoken",
  "accesstoken",
  "accesstokenjwt",
  "idtoken",
  "id_token",
  "access_token",
  "jwt",
  "bearer",
])

const ID = new Set(["sub", "id", "userid", "user_id"])
const MAIL = new Set(["email", "mail", "username"])
const ROLE = new Set(["role", "roles"])

function row(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return
  return input as Record<string, unknown>
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function key(input: string) {
  return input.replace(/[^a-z0-9]+/gi, "").toLowerCase()
}

function origin(input: string) {
  try {
    const url = new URL(input)
    if (url.protocol !== "http:" && url.protocol !== "https:") return ""
    return url.origin
  } catch {
    return ""
  }
}

function pair(sessionID: SessionID, actorSessionID: string) {
  return `${canonicalSecuritySessionID(sessionID)}:${actorSessionID}`
}

function stale(input: ActorSessionMaterial, now = Date.now()) {
  return now - input.timeUpdated > ACTOR_SESSION_TTL_MS
}

function cleanupState(state: State, now = Date.now()) {
  if (state.sessions.size === 0) return
  const seen = new Set<string>()
  const ids: SessionID[] = []
  for (const item of state.sessions.values()) {
    if (seen.has(item.sessionID)) continue
    seen.add(item.sessionID)
    ids.push(item.sessionID)
  }
  const live = new Set(
    Database.use((db) => {
      if (ids.length === 0) return [] as SessionID[]
      return db
        .select({ id: SessionTable.id })
        .from(SessionTable)
        .where(inArray(SessionTable.id, ids))
        .all()
        .map((item) => item.id)
    }),
  )
  for (const [item, value] of state.sessions) {
    if (live.has(value.sessionID) && !stale(value.material, now)) continue
    state.sessions.delete(item)
  }
}

function same(left: SessionCookie, right: SessionCookie) {
  return `${left.name}|${left.domain || ""}|${left.path || "/"}`
    === `${right.name}|${right.domain || ""}|${right.path || "/"}`
}

function parse(input: string) {
  const value = input.trim()
  if (!value) return
  if (!value.startsWith("{") && !value.startsWith("[")) return
  try {
    return JSON.parse(value)
  } catch {
    return
  }
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
  const value = input as Record<string, unknown>
  for (const item of Object.keys(value)) {
    if (!names.has(key(item))) continue
    const next = text(value[item])
    if (next) return next
  }
  for (const item of Object.keys(value)) {
    const next = scan(value[item], names)
    if (next) return next
  }
  return ""
}

function objects(input: Record<string, string>) {
  const out: Record<string, unknown>[] = []
  for (const item of Object.keys(input)) {
    const value = row(input[item])
    if (value) out.push(value)
    const nested = row(parse(input[item]))
    if (nested) out.push(nested)
  }
  return out
}

function storageActor(local: Record<string, string>, session: Record<string, string>) {
  const values = [...objects(local), ...objects(session)]
  return {
    id: scan(values, ID),
    email: scan(values, MAIL),
    role: scan(values, ROLE),
  }
}

function jwt(input: string) {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(input)
}

function authHeaders(input?: Record<string, string>) {
  const out: Record<string, string> = {}
  if (!input) return out
  for (const item of Object.keys(input)) {
    const name = item.toLowerCase()
    if (name === "cookie") continue
    if (AUTH.includes(name) || /auth|token|session|csrf|xsrf|api[-_]?key/.test(name)) {
      out[name] = input[item] ?? ""
    }
  }
  return out
}

function bearerHeader(input?: Record<string, string>) {
  if (!input) return ""
  for (const item of Object.keys(input)) {
    if (item.toLowerCase() !== "authorization") continue
    const value = input[item] ?? ""
    if (!value.toLowerCase().startsWith("bearer ")) return ""
    return value.slice(7).trim()
  }
  return ""
}

function mergeHeaders(left: Record<string, string>, right?: Record<string, string>) {
  return {
    ...left,
    ...authHeaders(right),
  }
}

function requestHeaders(left: Record<string, string>, right?: Record<string, string>) {
  const out = {
    ...left,
  }
  if (!right) return out
  for (const item of Object.keys(right)) {
    if (item.toLowerCase() === "cookie") continue
    out[item] = right[item] ?? ""
  }
  return out
}

function mergeCookies(left: SessionCookie[], right?: SessionCookie[]) {
  const out = left.map((item) => ({ ...item }))
  if (!right || right.length === 0) return out
  for (const item of right) {
    const index = out.findIndex((entry) => same(entry, item))
    if (index >= 0) {
      out[index] = {
        ...out[index],
        ...item,
      }
      continue
    }
    out.push({ ...item })
  }
  return out
}

function cookieHeader(cookies: SessionCookie[]) {
  return cookies.map((item) => `${item.name}=${item.value}`).join("; ")
}

function parseCookieHeader(input?: string, url?: string) {
  if (!input) return []
  const out: SessionCookie[] = []
  const host = url ? new URL(url).hostname : ""
  for (const item of input.split(";")) {
    const value = item.trim()
    const index = value.indexOf("=")
    if (index <= 0) continue
    out.push({
      name: value.slice(0, index).trim(),
      value: value.slice(index + 1).trim(),
      domain: host || undefined,
      path: "/",
    })
  }
  return out
}

function parseSetCookie(input: string) {
  const parts = input.split(";")
  const head = parts.shift()?.trim() ?? ""
  const index = head.indexOf("=")
  if (index <= 0) return
  const out: SessionCookie = {
    name: head.slice(0, index).trim(),
    value: head.slice(index + 1).trim(),
    path: "/",
  }
  for (const item of parts) {
    const value = item.trim()
    const lower = value.toLowerCase()
    if (lower === "secure") {
      out.secure = true
      continue
    }
    if (lower === "httponly") {
      out.httpOnly = true
      continue
    }
    const split = value.indexOf("=")
    if (split <= 0) continue
    const name = value.slice(0, split).trim().toLowerCase()
    const next = value.slice(split + 1).trim()
    if (name === "domain") out.domain = next
    if (name === "path") out.path = next || "/"
    if (name === "samesite") out.sameSite = next
  }
  return out
}

function bodyToken(input: string) {
  const value = parse(input)
  if (!value) {
    const match = input.match(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/)
    if (!match?.[0]) return ""
    return match[0]
  }
  if (Array.isArray(value)) return ""
  const auth = row((value as Record<string, unknown>).authentication)
  const direct = text(auth?.token)
  if (direct && jwt(direct)) return direct
  const stack: Array<{ path: string; value: unknown }> = [{ path: "", value }]
  while (stack.length > 0) {
    const item = stack.pop()
    if (!item) continue
    if (Array.isArray(item.value)) {
      for (const next of item.value) {
        stack.push({ path: item.path, value: next })
      }
      continue
    }
    const next = row(item.value)
    if (!next) continue
    for (const name of Object.keys(next)) {
      const path = item.path ? `${item.path}.${name}` : name
      const value = next[name]
      if (typeof value === "string") {
        const want = TOKEN.has(key(name)) || (path.toLowerCase().includes("authentication") && name.toLowerCase() === "token")
        if (want && (jwt(value) || name.toLowerCase() !== "token")) return value
      }
      stack.push({ path, value })
    }
  }
  return ""
}

function bodyActor(input: string) {
  const value = parse(input)
  if (!value || typeof value !== "object" || Array.isArray(value)) return {
    id: "",
    email: "",
    role: "",
  }
  return {
    id: scan(value, ID),
    email: scan(value, MAIL),
    role: scan(value, ROLE),
  }
}

function csrfBody(input: string) {
  const value = parse(input)
  const out: Record<string, string> = {}
  if (!value || typeof value !== "object") return out
  const stack: Array<{ path: string; value: unknown }> = [{ path: "", value }]
  while (stack.length > 0) {
    const item = stack.pop()
    if (!item) continue
    if (Array.isArray(item.value)) {
      for (const next of item.value) {
        stack.push({ path: item.path, value: next })
      }
      continue
    }
    const next = row(item.value)
    if (!next) continue
    for (const name of Object.keys(next)) {
      const path = item.path ? `${item.path}.${name}` : name
      const value = next[name]
      if (typeof value === "string" && /csrf|xsrf/i.test(name)) {
        out[path] = value
      }
      stack.push({ path, value })
    }
  }
  return out
}

function csrfHeaders(input?: Record<string, string>) {
  const out: Record<string, string> = {}
  if (!input) return out
  for (const item of Object.keys(input)) {
    if (!/csrf|xsrf/i.test(item)) continue
    out[item.toLowerCase()] = input[item] ?? ""
  }
  return out
}

function actor(input: {
  actorLabel: string
  actorID?: string
  actorEmail?: string
  actorRole?: string
  headers: Record<string, string>
  cookies: SessionCookie[]
  localStorage: Record<string, string>
  sessionStorage: Record<string, string>
  source?: string
}) {
  const storage = storageActor(input.localStorage, input.sessionStorage)
  const actorID = input.actorID || storage.id
  const actorEmail = input.actorEmail || storage.email
  const actorRole = input.actorRole || storage.role
  const inferred = inferActorIdentity({
    label: input.actorLabel,
    headers: input.headers,
    cookies: cookieHeader(input.cookies),
    actor_id: actorID || undefined,
    actor_email: actorEmail || undefined,
    actor_role: actorRole || undefined,
  })
  return {
    actorID: actorID || inferred.id,
    actorEmail: actorEmail || inferred.email,
    actorRole: actorRole || inferred.role,
    privileged: inferred.privileged || /(admin|root|super|staff|support|manager|operator|internal)/i.test(actorRole),
    source: input.source || inferred.source,
  }
}

function blank(input: ResolveActorSessionInput) {
  return {
    actorSessionID: browserActorSessionID(input.sessionID, input.actorLabel, input.actorSessionID),
    actorLabel: input.actorLabel || "primary",
    actorID: "",
    actorEmail: "",
    actorRole: "",
    privileged: false,
    source: "unknown",
    headers: {},
    cookies: [],
    localStorage: {},
    sessionStorage: {},
    csrf: {},
    lastOrigin: "",
    lastURL: "",
    timeUpdated: Date.now(),
  } satisfies ActorSessionMaterial
}

function merge(base: ActorSessionMaterial, input: ActorSessionUpdate) {
  const headers = mergeHeaders(base.headers, input.headers)
  const cookies = mergeCookies(base.cookies, input.cookies)
  const localStorage = {
    ...base.localStorage,
    ...(input.localStorage ?? {}),
  }
  const sessionStorage = {
    ...base.sessionStorage,
    ...(input.sessionStorage ?? {}),
  }
  const csrf = {
    ...base.csrf,
    ...(input.csrf ?? {}),
  }
  const next = actor({
    actorLabel: input.actorLabel || base.actorLabel,
    actorID: input.actorID || base.actorID,
    actorEmail: input.actorEmail || base.actorEmail,
    actorRole: input.actorRole || base.actorRole,
    headers,
    cookies,
    localStorage,
    sessionStorage,
    source: input.source || base.source,
  })
  return {
    actorSessionID: base.actorSessionID,
    actorLabel: input.actorLabel || base.actorLabel,
    actorID: next.actorID,
    actorEmail: next.actorEmail,
    actorRole: next.actorRole,
    privileged: next.privileged,
    source: next.source,
    headers,
    cookies,
    localStorage,
    sessionStorage,
    csrf,
    lastOrigin: input.lastOrigin || base.lastOrigin,
    lastURL: input.lastURL || base.lastURL,
    timeUpdated: Date.now(),
  } satisfies ActorSessionMaterial
}

export function actorSessionSummary(input: ActorSessionMaterial) {
  return {
    actor_id: input.actorID,
    actor_email: input.actorEmail,
    actor_role: input.actorRole,
    privileged: input.privileged,
    source: input.source,
    header_keys: Object.keys(input.headers),
    cookie_names: input.cookies.map((item) => item.name),
    local_storage_keys: Object.keys(input.localStorage),
    session_storage_keys: Object.keys(input.sessionStorage),
    csrf_keys: Object.keys(input.csrf),
    last_origin: input.lastOrigin,
    last_url: input.lastURL,
  } satisfies Record<string, unknown>
}

export function actorIdentityFromMaterial(input: ActorSessionMaterial): ActorIdentity {
  return {
    label: input.actorLabel,
    id: input.actorID,
    email: input.actorEmail,
    role: input.actorRole,
    privileged: input.privileged,
    source: input.source,
  }
}

export function actorSessionRequest(input: ActorSessionMaterial, headers?: Record<string, string>, cookies?: string) {
  return {
    actorSessionID: input.actorSessionID,
    actorLabel: input.actorLabel,
    headers: requestHeaders(input.headers, headers),
    cookies: cookieHeader(mergeCookies(input.cookies, parseCookieHeader(cookies, input.lastURL))),
    localStorage: {
      ...input.localStorage,
    },
    sessionStorage: {
      ...input.sessionStorage,
    },
  }
}

export function httpAuthMaterial(input: {
  actorLabel?: string
  actorID?: string
  actorEmail?: string
  actorRole?: string
  url: string
  requestHeaders?: Record<string, string>
  requestCookies?: string
  responseHeaders?: Record<string, string>
  responseBody?: string
  setCookies?: string[]
}) {
  const headers = mergeHeaders(authHeaders(input.requestHeaders), input.responseHeaders)
  const requestToken = bearerHeader(input.requestHeaders)
  const responseToken = bodyToken(input.responseBody ?? "")
  if (responseToken && !headers.authorization) {
    headers.authorization = `Bearer ${responseToken}`
  }
  const cookies = mergeCookies(
    parseCookieHeader(input.requestCookies, input.url),
    (input.setCookies ?? [])
      .map((item) => parseSetCookie(item))
      .filter((item): item is SessionCookie => !!item),
  )
  const decoded = responseToken || requestToken ? decodeJwt(responseToken || requestToken) : null
  const body = bodyActor(input.responseBody ?? "")
  return {
    actorLabel: input.actorLabel,
    actorID: input.actorID || scan(decoded?.payload ?? {}, ID) || body.id,
    actorEmail: input.actorEmail || scan(decoded?.payload ?? {}, MAIL) || body.email,
    actorRole: input.actorRole || scan(decoded?.payload ?? {}, ROLE) || body.role,
    source: responseToken ? "http_response" : requestToken ? "http_request" : "http_request",
    headers,
    cookies,
    csrf: {
      ...csrfHeaders(input.responseHeaders),
      ...csrfBody(input.responseBody ?? ""),
    },
    lastOrigin: origin(input.url),
    lastURL: input.url,
  } satisfies ActorSessionUpdate
}

export function browserAuthMaterial(input: {
  actorLabel?: string
  pageURL: string
  headers?: Record<string, string>
  cookies: SessionCookie[]
  localStorage?: Record<string, string>
  sessionStorage?: Record<string, string>
}) {
  const headers = authHeaders(input.headers)
  const localStorage = {
    ...(input.localStorage ?? {}),
  }
  const sessionStorage = {
    ...(input.sessionStorage ?? {}),
  }
  const token = bodyToken(Object.values(localStorage).join("\n")) || bodyToken(Object.values(sessionStorage).join("\n"))
  if (token && !headers.authorization) {
    headers.authorization = `Bearer ${token}`
  }
  return {
    actorLabel: input.actorLabel,
    source: "browser",
    headers,
    cookies: input.cookies,
    localStorage,
    sessionStorage,
    csrf: {
      ...csrfBody(JSON.stringify(localStorage)),
      ...csrfBody(JSON.stringify(sessionStorage)),
    },
    lastOrigin: origin(input.pageURL),
    lastURL: input.pageURL,
  } satisfies ActorSessionUpdate
}

export class ActorSessionStoreError extends Schema.TaggedErrorClass<ActorSessionStoreError>()(
  "ActorSessionStoreError",
  {
    code: Schema.String,
    message: Schema.String,
    cause: Schema.Unknown,
  },
) {}

namespace ActorSessionStoreApi {
  export interface Service {
    readonly read: (input: ResolveActorSessionInput) => Effect.Effect<ActorSessionMaterial | undefined, ActorSessionStoreError>
    readonly merge: (input: MergeActorSessionInput) => Effect.Effect<ActorSessionMaterial, ActorSessionStoreError>
  }
}

class ActorSessionStoreApi extends ServiceMap.Service<ActorSessionStoreApi, ActorSessionStoreApi.Service>()(
  "@numasec/ActorSessionStore",
) {}

const layer = Layer.effect(
  ActorSessionStoreApi,
  Effect.gen(function* () {
    const state = {
      sessions: new Map<string, SessionEntry>(),
    } satisfies State

    const cleanup = Effect.fn("ActorSessionStore.cleanup")(function* () {
      cleanupState(state)
    })

    yield* cleanup().pipe(
      Effect.catchCause((cause) => {
        log.error("cleanup loop failed", { cause: Cause.pretty(cause) })
        return Effect.void
      }),
      Effect.repeat(Schedule.spaced(Duration.minutes(1))),
      Effect.delay(Duration.minutes(1)),
      Effect.forkScoped,
    )

    const read = Effect.fn("ActorSessionStore.read")(function* (input: ResolveActorSessionInput) {
      yield* cleanup()
      const sessionID = canonicalSecuritySessionID(input.sessionID)
      const actorSessionID = browserActorSessionID(sessionID, input.actorLabel, input.actorSessionID)
      return state.sessions.get(pair(sessionID, actorSessionID))?.material
    })

    const mergeOne = Effect.fn("ActorSessionStore.merge")(function* (input: MergeActorSessionInput) {
      yield* cleanup()
      const sessionID = canonicalSecuritySessionID(input.sessionID)
      const actorSessionID = browserActorSessionID(sessionID, input.actorLabel, input.actorSessionID)
      const current = state.sessions.get(pair(sessionID, actorSessionID))?.material || blank({
        sessionID,
        actorSessionID,
        actorLabel: input.actorLabel,
      })
      const next = merge(current, input.material)
      const session = Database.use((db) =>
        db
          .select({
            id: SessionTable.id,
          })
          .from(SessionTable)
          .where(eq(SessionTable.id, sessionID))
          .get(),
      )
      if (!session) return next
      state.sessions.set(pair(sessionID, actorSessionID), {
        sessionID,
        material: next,
      })
      yield* Effect.try({
        try: () =>
          Database.use((db) => {
            const current = db
              .select()
              .from(SecurityActorSessionTable)
              .where(eq(SecurityActorSessionTable.id, actorSessionID))
              .get()
            db
                .insert(SecurityActorSessionTable)
                .values({
                  id: actorSessionID,
                  session_id: sessionID,
                  actor_label: next.actorLabel,
                  browser_session_id: current?.browser_session_id || ("" as SecurityBrowserSessionID),
                  status: "active",
                last_origin: next.lastOrigin,
                last_url: next.lastURL,
                material_summary: actorSessionSummary(next),
              })
              .onConflictDoUpdate({
                target: SecurityActorSessionTable.id,
                set: {
                  actor_label: next.actorLabel,
                  status: "active",
                  last_origin: next.lastOrigin,
                  last_url: next.lastURL,
                  material_summary: actorSessionSummary(next),
                  time_updated: Date.now(),
                },
              })
              .run()
          }),
        catch: (cause) =>
          new ActorSessionStoreError({
            code: "actor_session_persist_failed",
            message: "Failed to persist actor session summary",
            cause,
          }),
      })
      return next
    })

    return ActorSessionStoreApi.of({
      read,
      merge: mergeOne,
    })
  }),
)

const { runPromise } = makeRuntime(ActorSessionStoreApi, layer)

export function readActorSession(input: ResolveActorSessionInput) {
  return runPromise((svc) => svc.read(input))
}

export function mergeActorSession(input: MergeActorSessionInput) {
  return runPromise((svc) => svc.merge(input))
}
