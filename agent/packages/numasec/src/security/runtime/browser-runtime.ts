import { createHash } from "crypto"
import { Cause, Duration, Effect, Layer, Schedule, Schema, ServiceMap } from "effect"
import type { Browser, BrowserContext, Page, Request as PlaywrightRequest } from "playwright"
import { ulid } from "ulid"
import { InstanceState } from "../../effect/instance-state"
import { makeRuntime } from "../../effect/run-service"
import { Flag } from "../../flag/flag"
import type { SessionID } from "../../session/schema"
import { SessionTable } from "../../session/session.sql"
import { Database, inArray } from "../../storage/db"
import { Log } from "../../util/log"
import { Scope } from "../scope"
import { canonicalSecuritySessionID } from "../security-session"
import {
  SecurityActorSessionTable,
  SecurityBrowserPageTable,
  SecurityBrowserSessionTable,
  SecurityExecutionAttemptTable,
  type SecurityActorSessionID,
  type SecurityBrowserPageID,
  type SecurityBrowserSessionID,
  type SecurityExecutionAttemptID,
} from "./runtime.sql"

const log = Log.create({ service: "security.browser.runtime" })
export const ACTIVE_TTL_MS = 15 * 60 * 1000
const NETWORK_LIMIT = 64
const PAGE_ROLE = "primary"
const USER_AGENT = "Mozilla/5.0 (compatible; numasec/4.2)"

type PlaywrightModule = typeof import("playwright")

export interface BrowserNetworkEvent {
  url: string
  method: string
  status: number
  resourceType: string
  contentType: string
  requestBody: string
  initiatorURL: string
  failure: string
  timeCaptured: number
}

type Active = {
  sessionID: SessionID
  actorSessionID: SecurityActorSessionID
  browserSessionID: SecurityBrowserSessionID
  pageID: SecurityBrowserPageID
  actorLabel: string
  context: BrowserContext
  page: Page
  navigationIndex: number
  title: string
  materialSummary: Record<string, unknown>
  network: BrowserNetworkEvent[]
  pending: Map<PlaywrightRequest, BrowserNetworkEvent>
  timeUpdated: number
}

type State = {
  sessions: Map<string, Active>
  playwright?: PlaywrightModule
  browser?: Browser
}

function hash(input: string) {
  return createHash("sha256").update(input).digest("hex").slice(0, 16).toUpperCase()
}

function key(sessionID: SessionID, actorSessionID: string) {
  return `${canonicalSecuritySessionID(sessionID)}:${actorSessionID}`
}

function value(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {}
  return input as Record<string, unknown>
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

export function browserLaunchArgs() {
  const args: string[] = []
  if (Flag.NUMASEC_SECURITY_BROWSER_NO_SANDBOX) {
    args.push("--no-sandbox", "--disable-setuid-sandbox")
  }
  if (Flag.NUMASEC_SECURITY_INSECURE_TLS) {
    args.push("--ignore-certificate-errors")
  }
  return args
}

export function browserContextConfig() {
  return {
    ignoreHTTPSErrors: Flag.NUMASEC_SECURITY_INSECURE_TLS,
    userAgent: USER_AGENT,
  }
}

function redactText(input: string) {
  const next = input
    .replace(/bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [redacted]")
    .replace(/(\"?(?:password|token|authorization|cookie|set-cookie)\"?\s*[:=]\s*)\"[^\"]*\"/gi, '$1"[redacted]"')
    .replace(/((?:password|token|authorization|cookie|set-cookie)=)[^&\\s]+/gi, "$1[redacted]")
  if (next.length <= 2000) return next
  return next.slice(0, 2000)
}

function redactURL(input: string) {
  try {
    const url = new URL(input)
    for (const item of Array.from(url.searchParams.keys())) {
      if (!/token|auth|key|session|cookie|password/i.test(item)) continue
      url.searchParams.set(item, "[redacted]")
    }
    return url.toString()
  } catch {
    return input
  }
}

function pushNetwork(active: Active, event: BrowserNetworkEvent) {
  active.network.push(event)
  if (active.network.length <= NETWORK_LIMIT) return
  active.network.splice(0, active.network.length - NETWORK_LIMIT)
}

function requestEvent(request: PlaywrightRequest): BrowserNetworkEvent {
  return {
    url: redactURL(request.url()),
    method: request.method(),
    status: 0,
    resourceType: request.resourceType(),
    contentType: "",
    requestBody: redactText(request.postData() ?? ""),
    initiatorURL: redactURL(request.frame()?.url() ?? ""),
    failure: "",
    timeCaptured: Date.now(),
  }
}

function bindNetwork(active: Active) {
  active.page.on("request", (request) => {
    active.pending.set(request, requestEvent(request))
  })
  active.page.on("response", async (response) => {
    const request = response.request()
    const current = active.pending.get(request) ?? requestEvent(request)
    current.status = response.status()
    current.contentType = response.headers()["content-type"] ?? ""
    current.timeCaptured = Date.now()
    active.pending.delete(request)
    pushNetwork(active, current)
  })
  active.page.on("requestfailed", (request) => {
    const current = active.pending.get(request) ?? requestEvent(request)
    current.failure = request.failure()?.errorText ?? "request_failed"
    current.timeCaptured = Date.now()
    active.pending.delete(request)
    pushNetwork(active, current)
  })
}

async function bindScope(context: BrowserContext, sessionID: SessionID) {
  await context.route("**/*", async (route) => {
    const current = Scope.get(sessionID)
    if (!current) {
      await route.continue()
      return
    }
    const result = Scope.check(sessionID, route.request().url())
    if (result.allowed) {
      await route.continue()
      return
    }
    await route.abort("blockedbyclient")
  })
}

function message(cause: unknown) {
  if (cause instanceof Error && cause.message) return cause.message
  return String(cause ?? "")
}

function launchCode(cause: unknown) {
  const text = message(cause)
  if (text.includes("Executable doesn't exist")) return "playwright_browser_missing"
  if (text.includes("Please run the following command")) return "playwright_browser_missing"
  return "browser_launch_failed"
}

function launchMessage(cause: unknown) {
  const code = launchCode(cause)
  if (code === "playwright_browser_missing") {
    return "Playwright browser binaries are not installed. Install with: npx playwright install chromium"
  }
  return `Failed to launch Playwright Chromium: ${message(cause)}`
}

function actorRow(active: Active, status: string) {
  const url = active.page.url()
  return {
    id: active.actorSessionID,
    session_id: active.sessionID,
    actor_label: active.actorLabel,
    browser_session_id: active.browserSessionID,
    status,
    last_origin: origin(url),
    last_url: url,
    material_summary: active.materialSummary,
  }
}

function browserRow(active: Active, status: string, errorCode: string) {
  const url = active.page.url()
  return {
    id: active.browserSessionID,
    session_id: active.sessionID,
    actor_session_id: active.actorSessionID,
    status,
    headless: true,
    user_agent: USER_AGENT,
    navigation_index: active.navigationIndex,
    last_origin: origin(url),
    last_url: url,
    last_error_code: errorCode,
  }
}

function pageRow(active: Active, status: string) {
  return {
    id: active.pageID,
    session_id: active.sessionID,
    browser_session_id: active.browserSessionID,
    page_role: PAGE_ROLE,
    status,
    last_url: active.page.url(),
    title: active.title,
  }
}

function syncRows(active: Active, status: string, errorCode = "") {
  Database.use((db) => {
    db
      .insert(SecurityActorSessionTable)
      .values(actorRow(active, status))
      .onConflictDoUpdate({
        target: SecurityActorSessionTable.id,
        set: {
          actor_label: active.actorLabel,
          browser_session_id: active.browserSessionID,
          status,
          last_origin: origin(active.page.url()),
          last_url: active.page.url(),
          material_summary: active.materialSummary,
          time_updated: Date.now(),
        },
      })
      .run()

    db
      .insert(SecurityBrowserSessionTable)
      .values(browserRow(active, status, errorCode))
      .onConflictDoUpdate({
        target: SecurityBrowserSessionTable.id,
        set: {
          status,
          navigation_index: active.navigationIndex,
          last_origin: origin(active.page.url()),
          last_url: active.page.url(),
          last_error_code: errorCode,
          time_updated: Date.now(),
        },
      })
      .run()

    db
      .insert(SecurityBrowserPageTable)
      .values(pageRow(active, status))
      .onConflictDoUpdate({
        target: SecurityBrowserPageTable.id,
        set: {
          status,
          last_url: active.page.url(),
          title: active.title,
          time_updated: Date.now(),
        },
      })
      .run()
  })
}

function attemptID() {
  return `EATT-${ulid()}` as SecurityExecutionAttemptID
}

function liveSessions(input: Active[]) {
  const ids: SessionID[] = []
  const seen = new Set<string>()
  for (const item of input) {
    if (seen.has(item.sessionID)) continue
    seen.add(item.sessionID)
    ids.push(item.sessionID)
  }
  if (ids.length === 0) return new Set<string>()
  return new Set(
    Database.use((db) =>
      db
        .select({ id: SessionTable.id })
        .from(SessionTable)
        .where(inArray(SessionTable.id, ids))
        .all()
        .map((item) => item.id),
    ),
  )
}

async function closeActive(state: Pick<State, "sessions">, active: Active, status: string, errorCode = "", persist = true) {
  state.sessions.delete(key(active.sessionID, active.actorSessionID))
  try {
    if (persist) syncRows(active, status, errorCode)
  } finally {
    await active.context.close().catch(() => undefined)
  }
}

export async function cleanupBrowserSessions(state: Pick<State, "sessions">, now = Date.now()) {
  const sessions = Array.from(state.sessions.values())
  const live = liveSessions(sessions)
  for (const active of sessions) {
    const missing = !live.has(active.sessionID)
    if (!missing && !stale(active, now) && !active.page.isClosed() && !broken(active)) continue
    const status = stale(active, now) ? "expired" : "closed"
    await closeActive(state, active, status, "", !missing)
  }
}

async function closeBrowser(state: State) {
  const sessions = Array.from(state.sessions.values())
  for (const active of sessions) {
    await closeActive(state, active, "closed")
  }
  if (!state.browser) return
  await state.browser.close().catch(() => undefined)
  state.browser = undefined
}

function stale(active: Active, now = Date.now()) {
  return now - active.timeUpdated > ACTIVE_TTL_MS
}

function broken(active: Active) {
  const url = active.page.url()
  return url.startsWith("chrome-error://") || url.startsWith("edge-error://") || url.startsWith("about:neterror")
}

export class BrowserRuntimeError extends Schema.TaggedErrorClass<BrowserRuntimeError>()(
  "BrowserRuntimeError",
  {
    code: Schema.String,
    message: Schema.String,
    cause: Schema.Unknown,
  },
) {}

export interface BrowserSessionInfo {
  actorSessionID: SecurityActorSessionID
  browserSessionID: SecurityBrowserSessionID
  pageID: SecurityBrowserPageID
  actorLabel: string
  navigationIndex: number
  currentURL: string
}

export interface PreparedBrowserSession extends BrowserSessionInfo {
  context: BrowserContext
  page: Page
}

export interface PrepareBrowserSessionInput {
  sessionID: SessionID
  actorSessionID?: string
  actorLabel?: string
  reset?: boolean
}

export interface ResetBrowserSessionInput {
  sessionID: SessionID
  actorSessionID: string
  status?: string
  errorCode?: string
}

export interface SyncBrowserSessionInput {
  sessionID: SessionID
  actorSessionID: string
  title?: string
  navigated?: boolean
  materialSummary?: Record<string, unknown>
  status?: string
  errorCode?: string
}

export interface BrowserExecutionAttemptInput {
  sessionID: SessionID
  actorSessionID?: string
  browserSessionID?: string
  pageID?: string
  action: string
  status: string
  errorCode?: string
  notes?: Record<string, unknown>
}

export interface BrowserNetworkSnapshotInput {
  sessionID: SessionID
  actorSessionID: string
}

export function browserActorSessionID(sessionID: SessionID, actorLabel?: string, explicit?: string) {
  if (explicit) return explicit as SecurityActorSessionID
  return `ASES-${hash(`${canonicalSecuritySessionID(sessionID)}:${actorLabel || "default"}`)}` as SecurityActorSessionID
}

export function browserSessionID(sessionID: SessionID, actorSessionID: string) {
  return `BSES-${hash(`${canonicalSecuritySessionID(sessionID)}:${actorSessionID}`)}` as SecurityBrowserSessionID
}

export function browserPageID(sessionID: SessionID, actorSessionID: string) {
  return `BPAG-${hash(`${canonicalSecuritySessionID(sessionID)}:${actorSessionID}:${PAGE_ROLE}`)}` as SecurityBrowserPageID
}

namespace BrowserRuntimeStore {
  export interface Service {
    readonly prepare: (input: PrepareBrowserSessionInput) => Effect.Effect<PreparedBrowserSession, BrowserRuntimeError>
    readonly sync: (input: SyncBrowserSessionInput) => Effect.Effect<BrowserSessionInfo, BrowserRuntimeError>
    readonly recordAttempt: (input: BrowserExecutionAttemptInput) => Effect.Effect<void, BrowserRuntimeError>
    readonly network: (input: BrowserNetworkSnapshotInput) => Effect.Effect<BrowserNetworkEvent[], BrowserRuntimeError>
    readonly reset: (input: ResetBrowserSessionInput) => Effect.Effect<void, BrowserRuntimeError>
  }
}

class BrowserRuntimeStore extends ServiceMap.Service<BrowserRuntimeStore, BrowserRuntimeStore.Service>()(
  "@numasec/BrowserRuntimeStore",
) {}

const layer = Layer.effect(
  BrowserRuntimeStore,
  Effect.gen(function* () {
    const state = yield* InstanceState.make<State>(
      Effect.fn("BrowserRuntime.state")(function* () {
        const next = {
          sessions: new Map<string, Active>(),
        } satisfies State

        yield* Effect.addFinalizer(() => Effect.promise(() => closeBrowser(next)))
        yield* Effect.promise(() => cleanupBrowserSessions(next)).pipe(
          Effect.catchCause((cause) => {
            log.error("cleanup loop failed", { cause: Cause.pretty(cause) })
            return Effect.void
          }),
          Effect.repeat(Schedule.spaced(Duration.minutes(1))),
          Effect.delay(Duration.minutes(1)),
          Effect.forkScoped,
        )
        return next
      }),
    )

    const cleanup = Effect.fn("BrowserRuntime.cleanup")(function* (cache: State) {
      yield* Effect.promise(() => cleanupBrowserSessions(cache))
    })

    const playwright = Effect.fn("BrowserRuntime.playwright")(function* (cache: State) {
      if (cache.playwright) return cache.playwright
      const mod = yield* Effect.tryPromise({
        try: async () => await import("playwright"),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: "playwright_missing",
            message: "Playwright JS package is not available in this numasec install. Reinstall numasec or run bun install in the repo, then install Chromium with: npx playwright install chromium",
            cause,
          }),
      })
      cache.playwright = mod
      return mod
    })

    const browser = Effect.fn("BrowserRuntime.browser")(function* (cache: State) {
      if (cache.browser) return cache.browser
      const mod = yield* playwright(cache)
      const next = yield* Effect.tryPromise({
        try: async () =>
          await mod.chromium.launch({
            headless: true,
            args: browserLaunchArgs(),
          }),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: launchCode(cause),
            message: launchMessage(cause),
            cause,
          }),
      })
      cache.browser = next
      return next
    })

    const prepare = Effect.fn("BrowserRuntime.prepare")(function* (input: PrepareBrowserSessionInput) {
      const cache = yield* InstanceState.get(state)
      yield* cleanup(cache)

      const sessionID = canonicalSecuritySessionID(input.sessionID)
      const actorLabel = input.actorLabel || "browser"
      const actorSessionID = browserActorSessionID(sessionID, actorLabel, input.actorSessionID)
      const current = cache.sessions.get(key(sessionID, actorSessionID))
      if (current && input.reset) {
        yield* Effect.promise(() => closeActive(cache, current, "reset"))
      }

      const existing = cache.sessions.get(key(sessionID, actorSessionID))
      if (existing) {
        existing.timeUpdated = Date.now()
        syncRows(existing, "active")
        return {
          actorSessionID: existing.actorSessionID,
          browserSessionID: existing.browserSessionID,
          pageID: existing.pageID,
          actorLabel: existing.actorLabel,
          navigationIndex: existing.navigationIndex,
          currentURL: existing.page.url(),
          context: existing.context,
          page: existing.page,
        } satisfies PreparedBrowserSession
      }

      const activeBrowser = yield* browser(cache)
      const context = yield* Effect.tryPromise({
        try: async () => await activeBrowser.newContext(browserContextConfig()),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: "browser_context_failed",
            message: `Failed to create browser context: ${message(cause)}`,
            cause,
          }),
      })
      yield* Effect.tryPromise({
        try: async () => await bindScope(context, sessionID),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: "browser_context_failed",
            message: `Failed to bind browser scope enforcement: ${message(cause)}`,
            cause,
          }),
      })
      const page = yield* Effect.tryPromise({
        try: async () => await context.newPage(),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: "browser_page_failed",
            message: `Failed to create browser page: ${message(cause)}`,
            cause,
          }),
      })

      const active = {
        sessionID,
        actorSessionID,
        browserSessionID: browserSessionID(sessionID, actorSessionID),
        pageID: browserPageID(sessionID, actorSessionID),
        actorLabel,
        context,
        page,
        navigationIndex: 0,
        title: "",
        materialSummary: {},
        network: [],
        pending: new Map<PlaywrightRequest, BrowserNetworkEvent>(),
        timeUpdated: Date.now(),
      } satisfies Active

      bindNetwork(active)
      cache.sessions.set(key(sessionID, actorSessionID), active)
      syncRows(active, "active")
      log.info("prepared browser actor session", {
        actorSessionID: active.actorSessionID,
        browserSessionID: active.browserSessionID,
        sessionID: active.sessionID,
      })

      return {
        actorSessionID: active.actorSessionID,
        browserSessionID: active.browserSessionID,
        pageID: active.pageID,
        actorLabel: active.actorLabel,
        navigationIndex: active.navigationIndex,
        currentURL: active.page.url(),
        context: active.context,
        page: active.page,
      } satisfies PreparedBrowserSession
    })

    const sync = Effect.fn("BrowserRuntime.sync")(function* (input: SyncBrowserSessionInput) {
      const cache = yield* InstanceState.get(state)
      const sessionID = canonicalSecuritySessionID(input.sessionID)
      const actorSessionID = browserActorSessionID(sessionID, undefined, input.actorSessionID)
      const active = cache.sessions.get(key(sessionID, actorSessionID))
      if (!active) {
        return yield* Effect.fail(
          new BrowserRuntimeError({
            code: "browser_session_missing",
            message: `Browser actor session not found: ${actorSessionID}`,
            cause: actorSessionID,
          }),
        )
      }

      active.title = input.title ?? active.title
      active.timeUpdated = Date.now()
      if (input.navigated) active.navigationIndex += 1
      if (input.materialSummary) active.materialSummary = value(input.materialSummary)

      const status = input.status ?? "active"
      syncRows(active, status, input.errorCode ?? "")

      return {
        actorSessionID: active.actorSessionID,
        browserSessionID: active.browserSessionID,
        pageID: active.pageID,
        actorLabel: active.actorLabel,
        navigationIndex: active.navigationIndex,
        currentURL: active.page.url(),
      } satisfies BrowserSessionInfo
    })

    const recordAttempt = Effect.fn("BrowserRuntime.recordAttempt")(function* (input: BrowserExecutionAttemptInput) {
      const sessionID = canonicalSecuritySessionID(input.sessionID)
      yield* Effect.try({
        try: () =>
          Database.use((db) =>
            db
              .insert(SecurityExecutionAttemptTable)
              .values({
                id: attemptID(),
                session_id: sessionID,
                actor_session_id: input.actorSessionID as SecurityActorSessionID | undefined,
                browser_session_id: input.browserSessionID as SecurityBrowserSessionID | undefined,
                page_id: input.pageID as SecurityBrowserPageID | undefined,
                tool_name: "browser",
                action: input.action,
                status: input.status,
                error_code: input.errorCode ?? "",
                notes: input.notes ?? {},
              })
              .run(),
          ),
        catch: (cause) =>
          new BrowserRuntimeError({
            code: "browser_attempt_persist_failed",
            message: "Failed to persist browser execution attempt",
            cause,
          }),
      })
    })

    const network = Effect.fn("BrowserRuntime.network")(function* (input: BrowserNetworkSnapshotInput) {
      const cache = yield* InstanceState.get(state)
      const sessionID = canonicalSecuritySessionID(input.sessionID)
      const actorSessionID = browserActorSessionID(sessionID, undefined, input.actorSessionID)
      const active = cache.sessions.get(key(sessionID, actorSessionID))
      if (!active) {
        return yield* Effect.fail(
          new BrowserRuntimeError({
            code: "browser_session_missing",
            message: `Browser actor session not found: ${actorSessionID}`,
            cause: actorSessionID,
          }),
        )
      }
      active.timeUpdated = Date.now()
      return active.network.map((item) => ({ ...item }))
    })

    const reset = Effect.fn("BrowserRuntime.reset")(function* (input: ResetBrowserSessionInput) {
      const cache = yield* InstanceState.get(state)
      const active = cache.sessions.get(key(canonicalSecuritySessionID(input.sessionID), input.actorSessionID))
      if (!active) return
      yield* Effect.promise(() => closeActive(cache, active, input.status ?? "reset", input.errorCode ?? ""))
    })

    return BrowserRuntimeStore.of({
      prepare,
      sync,
      recordAttempt,
      network,
      reset,
    })
  }),
)

const { runPromise } = makeRuntime(BrowserRuntimeStore, layer)

export function prepareBrowserSession(input: PrepareBrowserSessionInput) {
  return runPromise((svc) => svc.prepare(input))
}

export function syncBrowserSession(input: SyncBrowserSessionInput) {
  return runPromise((svc) => svc.sync(input))
}

export function recordBrowserExecutionAttempt(input: BrowserExecutionAttemptInput) {
  return runPromise((svc) => svc.recordAttempt(input))
}

export function recentBrowserNetwork(input: BrowserNetworkSnapshotInput) {
  return runPromise((svc) => svc.network(input))
}

export function resetBrowserSession(input: ResetBrowserSessionInput) {
  return runPromise((svc) => svc.reset(input))
}
