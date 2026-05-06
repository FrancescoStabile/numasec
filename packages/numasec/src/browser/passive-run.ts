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

const MAX_PASSIVE_FORM_ENTRIES = 25
const MAX_PASSIVE_FORM_INPUTS = 10
const MAX_PASSIVE_STRING = 120

type FormControlElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | HTMLButtonElement

function truncateOutput(output: string, max_bytes?: number) {
  const bytes = Buffer.byteLength(output)
  if (!max_bytes || bytes <= max_bytes) return output
  return `${Buffer.from(output).subarray(0, max_bytes).toString()}\n... (truncated, ${bytes} bytes total)`
}

function truncateField(value?: string) {
  if (!value) return undefined
  const normalized = value.trim()
  if (!normalized) return undefined
  return normalized.length > MAX_PASSIVE_STRING ? normalized.slice(0, MAX_PASSIVE_STRING) : normalized
}

function sanitizePassiveForms(forms: NonNullable<PassiveInput["forms"]>) {
  return forms.map((form) => ({
    name: form.name,
    action: form.action,
    method: form.method,
    source: form.source,
    inputs: form.inputs.map((input) => ({
      name: input.name,
      type: input.type,
      id: input.id,
      placeholder: input.placeholder,
      aria_label: input.aria_label,
      autocomplete: input.autocomplete,
      required: input.required,
    })),
  }))
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
        const MAX_FORM_ENTRIES = 25
        const MAX_FORM_INPUTS = 10
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
          input instanceof HTMLSelectElement ||
          input instanceof HTMLButtonElement

        const normalizeMethod = (value?: string | null) => {
          const normalized = value?.trim().toLowerCase()
          return normalized ? normalized : "get"
        }

        const truncateField = (value?: string | null) => {
          if (!value) return undefined
          const normalized = value.trim()
          if (!normalized) return undefined
          return normalized.length > 120 ? normalized.slice(0, 120) : normalized
        }

        const controlShape = (input: FormControlElement) => {
          const base = {
            name: truncateField("name" in input ? input.name : undefined),
            type: truncateField("type" in input ? input.type : undefined),
            id: truncateField(input.id),
            placeholder:
              "placeholder" in input ? truncateField((input as HTMLInputElement | HTMLTextAreaElement).placeholder) : undefined,
            aria_label: truncateField(input.getAttribute("aria-label")),
            autocomplete: "autocomplete" in input ? truncateField((input as HTMLInputElement).autocomplete) : undefined,
            required: "required" in input ? Boolean(input.required) : undefined,
          }
          if (input instanceof HTMLButtonElement) {
            return {
              ...base,
              type: truncateField(input.type || "button"),
              name: base.name ?? truncateField(input.textContent ?? undefined),
            }
          }
          return base
        }

        const belongsToForm = (input: Element) => {
          if (typeof (input as Element & { closest?: unknown }).closest === "function") {
            return Boolean((input as Element & { closest(selector: string): Element | null }).closest("form"))
          }
          return false
        }

        // Keep form control collection local to the browser context so it serializes safely.
        const forms = Array.from(document.querySelectorAll("form"))
          .slice(0, MAX_FORM_ENTRIES)
          .map((form) => ({
            name: truncateField(form.getAttribute("name")),
            action: truncateField((form as HTMLFormElement).action) ?? document.location?.href ?? "",
            method: normalizeMethod((form as HTMLFormElement).method),
            source: "form" as const,
            inputs: Array.from(form.querySelectorAll("input,textarea,select,button"))
              .slice(0, MAX_FORM_INPUTS)
              .filter(isFormControl)
              .filter((input) => !(input instanceof HTMLInputElement && input.type?.toLowerCase() === "hidden"))
              .map(controlShape),
          }))
        const standaloneControls = Array.from(document.querySelectorAll("input,textarea,select,button"))
          .filter(isFormControl)
          .filter((input) => !belongsToForm(input))
          .filter((input) => !(input instanceof HTMLInputElement && input.type?.toLowerCase() === "hidden"))
          .slice(0, Math.max(0, MAX_FORM_ENTRIES - forms.length))
          .map((input) => {
            const shape = controlShape(input)
            return {
              name: shape.name,
              action: document.location?.href ?? "",
              method: "get",
              source: "standalone_control" as const,
              inputs: [shape],
            }
          })

        const scripts = Array.from(document.querySelectorAll("script"))

        return {
          storage: { local, session: sessionData },
          forms: [...forms, ...standaloneControls].slice(0, MAX_FORM_ENTRIES),
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
  const sanitizedForms = sanitizePassiveForms(passive.forms ?? [])
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
      forms: sanitizedForms.slice(0, MAX_PASSIVE_FORM_ENTRIES).map((form) => ({
        name: truncateField(form.name),
        action: truncateField(form.action),
        method: truncateField(form.method),
        source: form.source,
        inputs: form.inputs.slice(0, MAX_PASSIVE_FORM_INPUTS).map((input) => ({
          name: truncateField(input.name),
          type: truncateField(input.type),
          id: truncateField(input.id),
          placeholder: truncateField(input.placeholder),
          aria_label: truncateField(input.aria_label),
          autocomplete: truncateField(input.autocomplete),
          required: input.required,
        })),
      })),
      script_urls: (passive.scripts?.external ?? []).slice(0, 100),
      cookie_names: (passive.cookies ?? []).map((item) => item.name).slice(0, 50),
      finding_ids: input.report.findings.map((item) => item.id),
    },
    output: truncateOutput(
      JSON.stringify(
        {
          title: input.title,
          summary: input.report.summary,
          forms: sanitizedForms,
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
