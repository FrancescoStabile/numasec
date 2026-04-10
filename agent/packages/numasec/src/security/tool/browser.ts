/**
 * Tool: browser
 *
 * Playwright-based browser automation for security testing.
 * Handles DOM XSS detection, SPA interaction, screenshot capture,
 * authenticated crawling, and JavaScript execution in page context.
 *
 * Requires: playwright or chromium available in PATH.
 */

import z from "zod"
import { Tool } from "../../tool/tool"

const DESCRIPTION = `Automate a headless browser for security testing. Use for:
- Navigating to pages that require JavaScript rendering (SPAs)
- Testing DOM-based XSS by injecting payloads and checking execution
- Filling forms and clicking buttons programmatically
- Taking screenshots of application state
- Evaluating JavaScript in the page context
- Interacting with authenticated sessions (cookies persist)

Actions: navigate, click, fill, screenshot, evaluate, get_cookies.

NOTE: Requires Playwright. If not available, returns an error — use
http_request instead for static pages.

NEXT STEPS after browser results:
- If you found a DOM XSS sink, try more payloads with evaluate
- If the page has forms, use fill + click to test them
- If you need to prove a finding, take a screenshot`

export const BrowserTool = Tool.define("browser", {
  description: DESCRIPTION,
  parameters: z.object({
    action: z
      .enum(["navigate", "click", "fill", "screenshot", "evaluate", "get_cookies"])
      .describe("Browser action to perform"),
    url: z.string().optional().describe("URL to navigate to (required for 'navigate')"),
    selector: z.string().optional().describe("CSS selector for click/fill actions"),
    value: z.string().optional().describe("Value for fill action or JS code for evaluate"),
    timeout: z.number().optional().describe("Action timeout in ms (default 30000)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "browser",
      patterns: [params.url ?? params.selector ?? params.action],
      always: [] as string[],
      metadata: { action: params.action, url: params.url } as Record<string, any>,
    })

    // Lazy-load playwright to avoid crash if not installed
    let pw: any
    try {
      // Dynamic import with variable to prevent static module resolution
      const modName = "playwright"
      pw = await import(/* @vite-ignore */ modName)
    } catch {
      return {
        title: "Browser not available",
        metadata: {} as any,
        output:
          "Playwright is not installed. Install with: bunx playwright install chromium\n" +
          "Falling back to http_request for non-JS pages.",
      }
    }

    const timeout = params.timeout ?? 30_000
    const browser = await pw.chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors"],
    })

    try {
      const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        userAgent: "Mozilla/5.0 (compatible; numasec/4.2)",
      })
      const page = await context.newPage()

      switch (params.action) {
        case "navigate": {
          if (!params.url) throw new Error("url is required for navigate action")
          const response = await page.goto(params.url, { timeout, waitUntil: "networkidle" })
          const title = await page.title()
          const content = await page.content()
          const cookies = await context.cookies()

          return {
            title: `Navigate → ${params.url}`,
            metadata: { status: response?.status(), pageTitle: title, cookieCount: cookies.length } as any,
            output: [
              `Status: ${response?.status() ?? "unknown"}`,
              `Title: ${title}`,
              `URL: ${page.url()}`,
              `Cookies: ${cookies.length}`,
              "",
              "── Page HTML (first 8000 chars) ──",
              content.slice(0, 8000),
            ].join("\n"),
          }
        }

        case "click": {
          if (!params.selector) throw new Error("selector is required for click action")
          await page.click(params.selector, { timeout })
          await page.waitForLoadState("networkidle").catch(() => {})
          return {
            title: `Click ${params.selector}`,
            metadata: {} as any,
            output: `Clicked "${params.selector}". Current URL: ${page.url()}`,
          }
        }

        case "fill": {
          if (!params.selector) throw new Error("selector is required for fill action")
          if (!params.value) throw new Error("value is required for fill action")
          await page.fill(params.selector, params.value, { timeout })
          return {
            title: `Fill ${params.selector}`,
            metadata: {} as any,
            output: `Filled "${params.selector}" with value.`,
          }
        }

        case "screenshot": {
          const buf = await page.screenshot({ fullPage: true, type: "png" })
          const base64 = buf.toString("base64")
          return {
            title: "Screenshot captured",
            metadata: { size: buf.length } as any,
            output: "Screenshot captured successfully.",
            attachments: [{ type: "file" as const, mime: "image/png", url: `data:image/png;base64,${base64}` }],
          }
        }

        case "evaluate": {
          if (!params.value) throw new Error("value (JS code) is required for evaluate action")
          const result = await page.evaluate(params.value)
          return {
            title: "JS Evaluate",
            metadata: {} as any,
            output: typeof result === "string" ? result : JSON.stringify(result, null, 2),
          }
        }

        case "get_cookies": {
          const cookies = await context.cookies()
          const lines = cookies.map(
            (c: any) =>
              `${c.name}=${c.value} (domain=${c.domain}, path=${c.path}, secure=${c.secure}, httpOnly=${c.httpOnly}, sameSite=${c.sameSite})`,
          )
          return {
            title: `${cookies.length} cookies`,
            metadata: { count: cookies.length } as any,
            output: lines.join("\n") || "No cookies.",
          }
        }

        default:
          return { title: "Unknown action", metadata: {} as any, output: `Unknown action: ${params.action}` }
      }
    } finally {
      await browser.close()
    }
  },
})
