import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./browser.txt"

const parameters = z.object({
  action: z
    .enum(["navigate", "click", "fill", "screenshot", "evaluate", "get_cookies"])
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
})

type Params = z.infer<typeof parameters>

interface Session {
  browser: any
  context: any
  page: any
}

const sessions = new Map<string, Session>()
let counter = 0

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

  let pw: typeof import("playwright")
  try {
    pw = await import("playwright")
  } catch {
    throw new Error(
      "Playwright is not installed. Run: npx playwright install chromium",
    )
  }
  let browser: Awaited<ReturnType<typeof pw.chromium.launch>>
  try {
    browser = await pw.chromium.launch({ headless: true })
  } catch {
    throw new Error(
      "Chromium browser not found. Run: npx playwright install chromium",
    )
  }
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
  })
  const page = await context.newPage()
  const entry: Session = { browser, context, page }
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
  if (params.headers) {
    await context.setExtraHTTPHeaders(params.headers)
  }
  await seedStorage(page, params)
  const url = params.url || page.url()
  if (params.cookies && url && url.startsWith("http")) {
    const seed = cookieSeed(url, params.cookies)
    if (seed.length > 0) await context.addCookies(seed)
  }
}

async function run(params: Params, abort: AbortSignal): Promise<Tool.ExecuteResult> {
  const timeout = params.timeout ?? 30_000
  const session = await ensure(abort)
  await hydrate(session.context, session.page, params)
  const page = session.page
  const context = session.context

  if (params.url && params.action !== "navigate") {
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

  if (params.action === "click") {
    if (!params.selector) throw new Error("selector is required for click action")
    await page.click(params.selector, { timeout })
    await page.waitForLoadState("networkidle").catch(() => undefined)
    return {
      title: `Click ${params.selector}`,
      metadata: {},
      output: `Clicked "${params.selector}". Current URL: ${page.url()}`,
    }
  }

  if (params.action === "fill") {
    if (!params.selector) throw new Error("selector is required for fill action")
    if (!params.value) throw new Error("value is required for fill action")
    await page.fill(params.selector, params.value, { timeout })
    return {
      title: `Fill ${params.selector}`,
      metadata: {},
      output: `Filled "${params.selector}" with value.`,
    }
  }

  if (params.action === "screenshot") {
    const buf = await page.screenshot({ fullPage: true, type: "png" })
    const base64 = buf.toString("base64")
    return {
      title: "Screenshot captured",
      metadata: { size: buf.length, url: page.url() },
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
      metadata: {},
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
      metadata: { count: cookies.length },
      output: lines.join("\n") || "No cookies.",
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
          return yield* Effect.promise(() => run(params, ctx.abort))
        }).pipe(Effect.orDie),
    }
  }),
)
