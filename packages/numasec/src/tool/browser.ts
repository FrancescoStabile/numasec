import z from "zod"
import { Effect } from "effect"
import path from "path"
import * as Tool from "./tool"
import DESCRIPTION from "./browser.txt"
import { buildPassiveAppSecResult } from "../browser/passive-run"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Operation } from "@/core/operation"
import { activeIdentity } from "@/core/vault"
import { Instance } from "@/project/instance"

const parameters = z.object({
  action: z
    .enum([
      "navigate",
      "click",
      "fill",
      "screenshot",
      "evaluate",
      "get_cookies",
      "dom_snapshot",
      "storage_snapshot",
      "console_log",
      "network_tab",
      "dom_diff",
      "passive_appsec",
    ])
    .describe("Browser action to perform"),
  url: z
    .string()
    .optional()
    .describe("URL to navigate to. When provided for non-navigate actions, the page is loaded first."),
  selector: z.string().optional().describe("CSS selector for click/fill actions"),
  value: z.string().optional().describe("Value for fill action or JS code for evaluate"),
  timeout: z.number().optional().describe("Action timeout in ms (default 30000)"),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Headers to inject into browser requests"),
  cookies: z.string().optional().describe("Raw Cookie header to seed the browser session"),
  local_storage: z.record(z.string(), z.string()).optional().describe("localStorage seed"),
  session_storage: z.record(z.string(), z.string()).optional().describe("sessionStorage seed"),
  max_bytes: z
    .number()
    .int()
    .min(1024)
    .max(1048576)
    .optional()
    .describe("Max output bytes for dom_snapshot / console_log / network_tab / passive_appsec"),
  clear: z.boolean().optional().describe("Drain console/network buffer after read"),
})

type Params = z.infer<typeof parameters>

interface ConsoleEntry {
  level: string
  text: string
  ts: number
}
interface NetworkEntry {
  ts: number
  method: string
  url: string
  status?: number
  content_type?: string
  duration_ms?: number
  req_id: string
}

interface Session {
  browser: any
  context: any
  page: any
  console: ConsoleEntry[]
  network: NetworkEntry[]
  lastDom?: string
}

const sessions = new Map<string, Session>()
let counter = 0

const EVIDENCE_MAX_OUTPUT = 128_000

function cookieSeed(url: string, raw: string) {
  const base = new URL(url)
  const out: Array<{
    name: string
    value: string
    domain: string
    path: string
    secure: boolean
    httpOnly: boolean
  }> = []
  for (const item of raw.split(";")) {
    const trimmed = item.trim()
    const idx = trimmed.indexOf("=")
    if (idx <= 0) continue
    out.push({
      name: trimmed.slice(0, idx).trim(),
      value: trimmed.slice(idx + 1).trim(),
      domain: base.hostname,
      path: "/",
      secure: base.protocol === "https:",
      httpOnly: false,
    })
  }
  return out
}

async function seedStorage(page: any, params: Params) {
  const local = params.local_storage ?? {}
  const session = params.session_storage ?? {}
  if (Object.keys(local).length === 0 && Object.keys(session).length === 0) return
  await page
    .addInitScript(
      (value: { local: Record<string, string>; session: Record<string, string> }) => {
        for (const k of Object.keys(value.local)) window.localStorage.setItem(k, value.local[k]!)
        for (const k of Object.keys(value.session)) window.sessionStorage.setItem(k, value.session[k]!)
      },
      { local, session },
    )
    .catch(() => undefined)
  const current = page.url()
  if (!current || current.startsWith("about:")) return
  await page
    .evaluate(
      (value: { local: Record<string, string>; session: Record<string, string> }) => {
        for (const k of Object.keys(value.local)) window.localStorage.setItem(k, value.local[k]!)
        for (const k of Object.keys(value.session)) window.sessionStorage.setItem(k, value.session[k]!)
      },
      { local, session },
    )
    .catch(() => undefined)
}

async function ensure(abort: AbortSignal): Promise<Session> {
  const id = `s${counter}`
  const existing = sessions.get(id)
  if (existing) return existing

  let pw: typeof import("playwright") | undefined
  try {
    pw = await import("playwright")
  } catch {
    // import entirely failed — not installed
  }

  // In compiled binaries, import("playwright") may succeed but return a
  // broken module (chromium undefined) due to Bun embedding CI paths into
  // playwright-core's require.resolve calls. Try local filesystem fallback.
  if (!pw?.chromium?.launch) {
    try {
      const { createRequire } = await import("module")
      const require = createRequire(path.join(Instance.directory, "package.json"))
      pw = require("playwright") as typeof import("playwright")
    } catch {
      // local filesystem fallback also failed
    }
  }

  if (!pw?.chromium?.launch) {
    throw new Error(
      "Playwright is not installed. Run: bun add playwright && npx playwright install chromium",
    )
  }

  const launchOptions = (executablePath?: string) => {
    const base = executablePath ? { executablePath } : {}
    if (process.platform === "win32" && typeof globalThis.Bun !== "undefined") {
      return {
        ...base,
        headless: false,
        args: ["--headless=new"],
      } as Parameters<typeof pw.chromium.launch>[0]
    }
    return { ...base, headless: true } as Parameters<typeof pw.chromium.launch>[0]
  }

  let firstError: string | undefined
  let browser: Awaited<ReturnType<typeof pw.chromium.launch>>
  try {
    browser = await pw.chromium.launch(launchOptions())
  } catch (err) {
    firstError = err instanceof Error ? err.message : String(err)

    // Fallback: NUMASEC_CHROMIUM_PATH env var
    const envPath = process.env.NUMASEC_CHROMIUM_PATH
    if (envPath) {
      try {
        browser = await pw.chromium.launch(launchOptions(envPath))
      } catch {
        // Fallback to system PATH below
      }
    }

    // Fallback: search system PATH for chromium / chrome
    if (!browser!) {
      const systemNames = ["chromium", "chromium-browser", "google-chrome", "chrome"]
      for (const name of systemNames) {
        const found = Bun.which(name)
        if (!found) continue
        try {
          browser = await pw.chromium.launch(launchOptions(found))
          break
        } catch {
          // try next
        }
      }
    }

    if (!browser!) {
      const pathNote = envPath ? ` | tried NUMASEC_CHROMIUM_PATH=${envPath}` : ""
      throw new Error(
        `Chromium browser not found. Run: npx playwright install chromium — ${firstError}${pathNote}`,
      )
    }
  }
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
  })
  const page = await context.newPage()
  const entry: Session = { browser, context, page, console: [], network: [] }

  const MAX_BUFFER = 500
  page.on("console", (msg: any) => {
    entry.console.push({
      level: msg.type?.() ?? "log",
      text: msg.text?.() ?? String(msg),
      ts: Date.now(),
    })
    if (entry.console.length > MAX_BUFFER) entry.console.shift()
  })
  page.on("pageerror", (err: any) => {
    entry.console.push({ level: "pageerror", text: String(err?.message ?? err), ts: Date.now() })
    if (entry.console.length > MAX_BUFFER) entry.console.shift()
  })
  const pending = new Map<string, { ts: number; method: string; url: string }>()
  context.on("request", (req: any) => {
    const id = `${Date.now()}-${req.url()}`
    pending.set(req, { ts: Date.now(), method: req.method(), url: req.url() })
    ;(req as any).__id = id
  })
  context.on("response", async (resp: any) => {
    const req = resp.request()
    const start = pending.get(req)
    pending.delete(req)
    const ts = start?.ts ?? Date.now()
    const headers = resp.headers?.() ?? {}
    entry.network.push({
      ts,
      method: req.method(),
      url: req.url(),
      status: resp.status(),
      content_type: headers["content-type"],
      duration_ms: Date.now() - ts,
      req_id: (req as any).__id ?? "",
    })
    if (entry.network.length > MAX_BUFFER) entry.network.shift()
  })

  sessions.set(id, entry)

  abort.addEventListener(
    "abort",
    () => {
      sessions.delete(id)
      browser.close().catch(() => undefined)
      counter += 1
    },
    { once: true },
  )

  return entry
}

async function hydrate(context: any, page: any, params: Params) {
  const identity = await activeIdentity().catch(() => undefined)
  const headers = { ...(identity?.headers ?? {}), ...(params.headers ?? {}) }
  if (Object.keys(headers).length > 0) {
    await context.setExtraHTTPHeaders(headers)
  }
  await seedStorage(page, params)
  const url = params.url || page.url()
  const cookieHeader = params.cookies ?? identity?.cookies
  if (cookieHeader && url && url.startsWith("http")) {
    const seed = cookieSeed(url, cookieHeader)
    if (seed.length > 0) await context.addCookies(seed)
  }
  return identity
}

function browserEvidenceMime(action: Params["action"]) {
  if (action === "screenshot") return "image/png"
  if (action === "dom_snapshot") return "text/html"
  return "application/json"
}

function browserEvidenceExt(action: Params["action"]) {
  if (action === "screenshot") return "png"
  if (action === "dom_snapshot") return "html"
  return "json"
}

function summarizePassiveFindings(output: string) {
  try {
    const parsed = JSON.parse(output) as {
      findings?: Array<{ id: string; severity: string; title: string; evidence?: string[] }>
      summary?: { total_findings?: number; request_count?: number }
    }
    return parsed
  } catch {
    return undefined
  }
}

function routeOf(url: string) {
  const target = new URL(url)
  return {
    host: target.hostname,
    origin: target.origin,
    service: `${target.hostname}:${target.port || (target.protocol === "https:" ? "443" : "80")}`,
    route: `${target.origin}${target.pathname || "/"}`,
    scheme: target.protocol.replace(":", ""),
  }
}

function browserEvidencePayload(params: Params, result: Tool.ExecuteResult) {
  return JSON.stringify(
    {
      action: params.action,
      input: {
        url: params.url,
        selector: params.selector,
        timeout: params.timeout,
        headers: params.headers,
        cookies: params.cookies,
      },
      result: {
        title: result.title,
        metadata: result.metadata,
        output: result.output.slice(0, EVIDENCE_MAX_OUTPUT),
        output_truncated: result.output.length > EVIDENCE_MAX_OUTPUT,
      },
    },
    null,
    2,
  )
}

function persistBrowserObservation(params: Params, result: Tool.ExecuteResult, ctx: Tool.Context) {
  return Effect.gen(function* () {
    const currentUrl =
      typeof result.metadata?.url === "string"
        ? result.metadata.url
        : typeof result.metadata?.currentUrl === "string"
          ? result.metadata.currentUrl
          : params.url
    const workspace = Instance.directory
    const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
    const evidence =
      !slug
        ? undefined
        : yield* Effect.promise(() =>
            Evidence.put(workspace, slug, browserEvidencePayload(params, result), {
              mime: browserEvidenceMime(params.action),
              ext: browserEvidenceExt(params.action),
              label: `browser ${params.action}${currentUrl ? ` ${currentUrl}` : ""}`,
              source: "browser",
            }),
          )
    const evidenceRefs = evidence ? [evidence.sha256] : undefined
    const eventID = yield* Cyber.appendLedger({
      kind: "fact.observed",
      source: "browser",
      summary: result.title,
      session_id: ctx.sessionID,
      message_id: ctx.messageID,
      evidence_refs: evidenceRefs,
      data: {
        action: params.action,
        url: currentUrl,
        metadata: result.metadata,
      },
    }).pipe(Effect.catch(() => Effect.succeed("")))

    if (!currentUrl || (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://"))) return

    const route = routeOf(currentUrl)
    yield* Cyber.upsertFact({
      entity_kind: "host",
      entity_key: route.host,
      fact_name: "browser_seen_url",
      value_json: currentUrl,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertFact({
      entity_kind: "service",
      entity_key: route.service,
      fact_name: "transport",
      value_json: route.scheme,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertFact({
      entity_kind: "http_route",
      entity_key: route.route,
      fact_name: `browser_action:${params.action}`,
      value_json: {
        title: result.title,
        metadata: result.metadata,
      },
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      src_kind: "host",
      src_key: route.host,
      relation: "exposes",
      dst_kind: "service",
      dst_key: route.service,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    yield* Cyber.upsertRelation({
      src_kind: "service",
      src_key: route.service,
      relation: "serves",
      dst_kind: "http_route",
      dst_key: route.route,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: eventID || undefined,
      evidence_refs: evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed("")))
    if (typeof result.metadata?.activeIdentity === "string") {
      yield* Cyber.upsertRelation({
        src_kind: "identity",
        src_key: result.metadata.activeIdentity,
        relation: "used_on",
        dst_kind: "http_route",
        dst_key: route.route,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: eventID || undefined,
        evidence_refs: evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed("")))
    }

    if (params.action === "dom_snapshot") {
      const summary = result.metadata?.summary as
        | { forms?: unknown[]; links?: string[]; scripts?: string[] }
        | undefined
      for (const link of summary?.links ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: link,
          fact_name: "dom_link",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const script of summary?.scripts ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "artifact",
          entity_key: script,
          fact_name: "javascript_resource",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const form of summary?.forms ?? []) {
        const item = form as { action?: string; method?: string; inputs?: unknown[] }
        if (!item.action || !item.method) continue
        yield* Cyber.upsertFact({
          entity_kind: "http_form",
          entity_key: `${item.method}:${item.action}`,
          fact_name: "shape",
          value_json: item,
          writer_kind: "parser",
          status: "observed",
          confidence: 850,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
    }

    if (params.action === "passive_appsec") {
      const parsed = summarizePassiveFindings(result.output)
      for (const item of (result.metadata?.request_urls as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: item,
          fact_name: "browser_request",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 850,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const item of (result.metadata?.form_actions as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "http_form",
          entity_key: item,
          fact_name: "passive_form_action",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const item of (result.metadata?.script_urls as string[] | undefined) ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "artifact",
          entity_key: item,
          fact_name: "javascript_resource",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
      for (const finding of parsed?.findings ?? []) {
        yield* Cyber.upsertFact({
          entity_kind: "finding_candidate",
          entity_key: `${route.host}:${finding.id}`,
          fact_name: "passive_appsec",
          value_json: finding,
          writer_kind: "parser",
          status: "candidate",
          confidence: finding.severity === "high" ? 800 : finding.severity === "medium" ? 700 : 600,
          source_event_id: eventID || undefined,
          evidence_refs: evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed("")))
      }
    }
  })
}

async function run(params: Params, abort: AbortSignal): Promise<Tool.ExecuteResult> {
  const timeout = params.timeout ?? 30_000
  const session = await ensure(abort)
  const identity = await hydrate(session.context, session.page, params)
  const page = session.page
  const context = session.context

  if (params.url && params.action !== "navigate" && params.action !== "passive_appsec") {
    await page.goto(params.url, { timeout, waitUntil: "domcontentloaded" })
  }

  if (params.action === "navigate") {
    if (!params.url) throw new Error("url is required for navigate action")
    const response = await page
      .goto(params.url, { timeout, waitUntil: "networkidle" })
      .catch(() => page.goto(params.url!, { timeout, waitUntil: "domcontentloaded" }))
    const title = await page.title().catch(() => "")
    const content = await page.content()
    const cookies = await context.cookies()
    const preview =
      content.length > 8000
        ? content.slice(0, 8000) + `\n... (truncated, ${content.length} chars total)`
        : content
    return {
      title: `Navigate → ${params.url}`,
      metadata: {
        status: response ? response.status() : undefined,
        pageTitle: title,
        cookieCount: cookies.length,
        url: page.url(),
        activeIdentity: identity?.key,
      },
      output: [
        `Status: ${response ? response.status() : "unknown"}`,
        `Title: ${title}`,
        `URL: ${page.url()}`,
        `Cookies: ${cookies.length}`,
        "",
        "── Page HTML ──",
        preview,
      ].join("\n"),
    }
  }

  if (params.action === "passive_appsec") {
    if (!params.url) throw new Error("url is required for passive_appsec action")
    const networkStart = session.network.length
    const consoleStart = session.console.length
    const response = await page
      .goto(params.url, { timeout, waitUntil: "networkidle" })
      .catch(() => page.goto(params.url!, { timeout, waitUntil: "domcontentloaded" }))
    const title = (await page.title().catch(() => "")) || page.url() || params.url
    const headers = response ? await response.headers() : undefined
    return buildPassiveAppSecResult({
      title,
      headers,
      page,
      context,
      session,
      startIndexes: {
        network: networkStart,
        console: consoleStart,
      },
      max_bytes: params.max_bytes,
      clear: params.clear,
    })
  }

  if (params.action === "click") {
    if (!params.selector) throw new Error("selector is required for click action")
    await page.click(params.selector, { timeout })
    await page.waitForLoadState("networkidle").catch(() => undefined)
    return {
      title: `Click ${params.selector}`,
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: `Clicked "${params.selector}". Current URL: ${page.url()}`,
    }
  }

  if (params.action === "fill") {
    if (!params.selector) throw new Error("selector is required for fill action")
    if (!params.value) throw new Error("value is required for fill action")
    await page.fill(params.selector, params.value, { timeout })
    return {
      title: `Fill ${params.selector}`,
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: `Filled "${params.selector}" with value.`,
    }
  }

  if (params.action === "screenshot") {
    const buf = await page.screenshot({ fullPage: true, type: "png" })
    const base64 = buf.toString("base64")
    return {
      title: "Screenshot captured",
      metadata: { size: buf.length, url: page.url(), activeIdentity: identity?.key },
      output: "Screenshot captured successfully.",
      attachments: [
        { type: "file" as const, mime: "image/png", url: `data:image/png;base64,${base64}` },
      ],
    }
  }

  if (params.action === "evaluate") {
    if (!params.value) throw new Error("value (JS code) is required for evaluate action")
    const result = await page.evaluate(params.value)
    const formatted = typeof result === "string" ? result : JSON.stringify(result, null, 2)
    return {
      title: "JS Evaluate",
      metadata: { currentUrl: page.url(), activeIdentity: identity?.key },
      output: formatted,
    }
  }

  if (params.action === "get_cookies") {
    const cookies = await context.cookies()
    const lines = cookies.map(
      (c: any) =>
        `${c.name}=${c.value} (domain=${c.domain}, path=${c.path}, secure=${c.secure}, httpOnly=${c.httpOnly}, sameSite=${c.sameSite})`,
    )
    return {
      title: `${cookies.length} cookies`,
      metadata: { count: cookies.length, url: page.url(), activeIdentity: identity?.key },
      output: lines.join("\n") || "No cookies.",
    }
  }

  if (params.action === "dom_snapshot") {
    const max = params.max_bytes ?? 65536
    const html = await page.content()
    session.lastDom = html
    const title = await page.title().catch(() => "")
    const summary = await page
      .evaluate(() => {
        const forms = Array.from(document.querySelectorAll("form")).map((f) => ({
          action: (f as HTMLFormElement).action,
          method: (f as HTMLFormElement).method,
          inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i) => ({
            name: (i as HTMLInputElement).name,
            type: (i as HTMLInputElement).type,
          })),
        }))
        const links = Array.from(document.querySelectorAll("a[href]"))
          .slice(0, 200)
          .map((a) => (a as HTMLAnchorElement).href)
        const scripts = Array.from(document.querySelectorAll("script[src]"))
          .map((s) => (s as HTMLScriptElement).src)
          .slice(0, 100)
        return { forms, links, scripts }
      })
      .catch(() => ({ forms: [], links: [], scripts: [] }))
    const body = html.length > max ? html.slice(0, max) + `\n... (truncated, ${html.length} chars)` : html
    return {
      title: `DOM snapshot ${page.url()}`,
      metadata: { url: page.url(), size: html.length, title, summary, activeIdentity: identity?.key } as any,
      output: [
        `URL: ${page.url()}`,
        `Title: ${title}`,
        `Forms: ${summary.forms.length}  Links: ${summary.links.length}  Scripts: ${summary.scripts.length}`,
        "",
        "── Summary ──",
        JSON.stringify(summary, null, 2),
        "",
        "── HTML ──",
        body,
      ].join("\n"),
    }
  }

  if (params.action === "storage_snapshot") {
    const storage = await page
      .evaluate(() => {
        const local: Record<string, string> = {}
        const session: Record<string, string> = {}
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i)
          if (k) local[k] = localStorage.getItem(k) ?? ""
        }
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i)
          if (k) session[k] = sessionStorage.getItem(k) ?? ""
        }
        return { local, session }
      })
      .catch(() => ({ local: {}, session: {} }))
    const cookies = await context.cookies()
    return {
      title: `Storage ${page.url()}`,
      metadata: {
        localKeys: Object.keys(storage.local).length,
        sessionKeys: Object.keys(storage.session).length,
        cookieCount: cookies.length,
        url: page.url(),
        activeIdentity: identity?.key,
      },
      output: JSON.stringify({ ...storage, cookies }, null, 2),
    }
  }

  if (params.action === "console_log") {
    const max = params.max_bytes ?? 65536
    const entries = [...session.console]
    if (params.clear) session.console.length = 0
    const lines = entries.map((e) => `[${new Date(e.ts).toISOString()}] ${e.level}: ${e.text}`).join("\n")
    const body = lines.length > max ? lines.slice(0, max) + `\n... (truncated, ${lines.length} chars)` : lines
    return {
      title: `Console log (${entries.length})`,
      metadata: { count: entries.length, url: page.url(), activeIdentity: identity?.key },
      output: body || "(no console entries)",
    }
  }

  if (params.action === "network_tab") {
    const max = params.max_bytes ?? 65536
    const entries = [...session.network]
    if (params.clear) session.network.length = 0
    const lines = entries
      .map(
        (e) =>
          `[${new Date(e.ts).toISOString()}] ${e.method} ${e.status ?? "---"} ${e.url}  (${e.duration_ms ?? "?"}ms, ${e.content_type ?? "?"})`,
      )
      .join("\n")
    const body = lines.length > max ? lines.slice(0, max) + `\n... (truncated, ${lines.length} chars)` : lines
    return {
      title: `Network (${entries.length} requests)`,
      metadata: { count: entries.length, url: page.url(), activeIdentity: identity?.key },
      output: body || "(no requests)",
    }
  }

  if (params.action === "dom_diff") {
    const prev = session.lastDom
    if (!prev) throw new Error("dom_diff requires a prior dom_snapshot in this session")
    const current = await page.content()
    session.lastDom = current
    const prevLines = prev.split("\n")
    const curLines = current.split("\n")
    const added: string[] = []
    const removed: string[] = []
    const prevSet = new Set(prevLines)
    const curSet = new Set(curLines)
    for (const l of curLines) if (!prevSet.has(l)) added.push(l)
    for (const l of prevLines) if (!curSet.has(l)) removed.push(l)
    const max = params.max_bytes ?? 65536
    const out = [
      `+ ${added.length} added lines`,
      `- ${removed.length} removed lines`,
      "",
      ...added.slice(0, 200).map((l) => `+ ${l}`),
      ...removed.slice(0, 200).map((l) => `- ${l}`),
    ].join("\n")
    return {
      title: `DOM diff (+${added.length}/-${removed.length})`,
      metadata: { added: added.length, removed: removed.length, url: page.url(), activeIdentity: identity?.key } as any,
      output: out.length > max ? out.slice(0, max) + "\n... (truncated)" : out,
    }
  }

  throw new Error(`Unknown action: ${params.action}`)
}

export const BrowserTool = Tool.define(
  "browser",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "browser",
            patterns: [params.url ?? params.selector ?? params.action],
            always: [],
            metadata: { action: params.action, url: params.url },
          })
          const result = yield* Effect.promise(() => run(params, ctx.abort))
          yield* persistBrowserObservation(params, result, ctx).pipe(Effect.catch(() => Effect.void))
          return result
        }).pipe(Effect.orDie),
    }
  }),
)
