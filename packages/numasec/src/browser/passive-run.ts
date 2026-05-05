import type * as Tool from "../tool/tool"
import { analyzePassiveAppSec, type PassiveInput } from "./passive"

type BrowserPage = {
  url(): string
  evaluate(fn: () => PassiveSnapshot | Promise<PassiveSnapshot>): Promise<PassiveSnapshot>
}

type BrowserContext = {
  cookies(): Promise<PassiveInput["cookies"]>
}

type BrowserSession = {
  network: Array<{
    method: string
    url: string
    status?: number
    content_type?: string
  }>
  console: Array<{
    level: string
    text: string
  }>
}

type PassiveSnapshot = {
  storage: NonNullable<PassiveInput["storage"]>
  forms: NonNullable<PassiveInput["forms"]>
  scripts: NonNullable<PassiveInput["scripts"]>
}

type FormControlElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement

function truncateOutput(output: string, max_bytes?: number) {
  const bytes = Buffer.byteLength(output)
  if (!max_bytes || bytes <= max_bytes) return output
  return `${Buffer.from(output).subarray(0, max_bytes).toString()}\n... (truncated, ${bytes} bytes total)`
}

export async function collectPassiveInput(
  page: BrowserPage,
  context: BrowserContext,
  session: BrowserSession,
  headers?: Record<string, string>,
  startIndexes?: {
    network: number
    console: number
  },
  clear?: boolean,
): Promise<PassiveInput> {
  const [cookies, snapshot] = await Promise.all([
    context.cookies().catch(() => []),
    page
      .evaluate(() => {
        const local: Record<string, string> = {}
        const sessionData: Record<string, string> = {}

        for (let index = 0; index < localStorage.length; index++) {
          const key = localStorage.key(index)
          if (key) local[key] = localStorage.getItem(key) ?? ""
        }

        for (let index = 0; index < window.sessionStorage.length; index++) {
          const key = window.sessionStorage.key(index)
          if (key) sessionData[key] = window.sessionStorage.getItem(key) ?? ""
        }

        const isFormControl = (input: Element): input is FormControlElement =>
          input instanceof HTMLInputElement ||
          input instanceof HTMLTextAreaElement ||
          input instanceof HTMLSelectElement

        // Keep form control collection local to the browser context so it serializes safely.
        const forms = Array.from(document.querySelectorAll("form")).map((form) => ({
          name: form.getAttribute("name") || undefined,
          action: (form as HTMLFormElement).action,
          method: (form as HTMLFormElement).method,
          inputs: Array.from(form.querySelectorAll("input,textarea,select"))
            .filter(isFormControl)
            .map((input) => {
              if (input instanceof HTMLTextAreaElement) {
                return {
                  name: input.name || undefined,
                  value: input.value || undefined,
                }
              }

              return {
                name: input.name || undefined,
                type: input.type || undefined,
                value: input.value || undefined,
              }
            }),
        }))

        const scripts = Array.from(document.querySelectorAll("script"))

        return {
          storage: { local, session: sessionData },
          forms,
          scripts: {
            inline_count: scripts.filter((script) => !script.getAttribute("src")).length,
            external: scripts.flatMap((script) => {
              const src = script.getAttribute("src")
              return src ? [(script as HTMLScriptElement).src] : []
            }),
          },
        }
      })
      .catch(() => ({
        storage: { local: {}, session: {} },
        forms: [],
        scripts: { inline_count: 0, external: [] },
      })),
  ])
  const requests = session.network.slice(startIndexes?.network ?? 0)
  const consoleEntries = session.console.slice(startIndexes?.console ?? 0)

  if (clear) {
    session.network.length = 0
    session.console.length = 0
  }

  return {
    url: page.url(),
    headers,
    cookies,
    storage: snapshot.storage,
    forms: snapshot.forms,
    requests: requests.map((entry) => ({
      method: entry.method,
      url: entry.url,
      status: entry.status,
      content_type: entry.content_type,
    })),
    console: consoleEntries.map((entry) => ({
      level: entry.level,
      text: entry.text,
    })),
    scripts: snapshot.scripts,
  }
}

export function formatPassiveAppSecResult(input: {
  title: string
  report: ReturnType<typeof analyzePassiveAppSec>
  passive?: PassiveInput
  max_bytes?: number
}): Tool.ExecuteResult {
  const passive = input.passive ?? { url: "" }
  return {
    title: `Passive AppSec → ${input.title}`,
    metadata: {
      findings: input.report.summary.total_findings,
      high: input.report.summary.high,
      medium: input.report.summary.medium,
      low: input.report.summary.low,
      console_errors: input.report.summary.console_errors,
      request_count: input.report.summary.request_count,
      request_urls: (passive.requests ?? []).map((item) => item.url).slice(0, 100),
      form_actions: (passive.forms ?? []).map((item) => item.action).slice(0, 50),
      script_urls: (passive.scripts?.external ?? []).slice(0, 100),
      cookie_names: (passive.cookies ?? []).map((item) => item.name).slice(0, 50),
      finding_ids: input.report.findings.map((item) => item.id),
    },
    output: truncateOutput(
      JSON.stringify(
        {
          title: input.title,
          summary: input.report.summary,
          findings: input.report.findings,
        },
        null,
        2,
      ),
      input.max_bytes ?? 65536,
    ),
  }
}

export async function buildPassiveAppSecResult(input: {
  title: string
  headers?: Record<string, string>
  page: BrowserPage
  context: BrowserContext
  session: BrowserSession
  startIndexes?: {
    network: number
    console: number
  }
  max_bytes?: number
  clear?: boolean
}) {
  const passive = await collectPassiveInput(
    input.page,
    input.context,
    input.session,
    input.headers,
    input.startIndexes,
    input.clear,
  )
  const report = analyzePassiveAppSec(passive)

  return formatPassiveAppSecResult({
    title: input.title,
    report,
    passive,
    max_bytes: input.max_bytes,
  })
}
