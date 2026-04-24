export type PassiveCookie = {
  name: string
  value: string
  domain: string
  path: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: string
}

export type PassiveInput = {
  url: string
  headers?: Record<string, string>
  cookies?: PassiveCookie[]
  storage?: {
    local?: Record<string, string>
    session?: Record<string, string>
  }
  forms?: PassiveForm[]
  requests?: PassiveRequest[]
  console?: Array<{ level: string; text: string }>
  scripts?: {
    inline_count?: number
    external?: string[]
  }
}

export type PassiveInputStorage = NonNullable<PassiveInput["storage"]>

export type PassiveInputConsole = NonNullable<PassiveInput["console"]>[number]

export type PassiveInputScripts = NonNullable<PassiveInput["scripts"]>

export type PassiveInputHeaders = NonNullable<PassiveInput["headers"]>
export type PassiveFormInput = {
  name?: string
  type?: string
  value?: string
}

export type PassiveForm = {
  name?: string
  action: string
  method: string
  inputs: PassiveFormInput[]
}

export type PassiveRequest = {
  method: string
  url: string
  status?: number
  content_type?: string
}

export type PassiveFindingId =
  | "storage-secret"
  | "weak-cookie"
  | "missing-security-header"
  | "csrf-form"
  | "mixed-content"

export type PassiveFindingSeverity = "high" | "medium" | "low"

export type PassiveFinding = {
  id: PassiveFindingId
  severity: PassiveFindingSeverity
  title: string
  evidence: string[]
}

export type PassiveReport = {
  findings: PassiveFinding[]
  summary: {
    high: number
    medium: number
    low: number
    total_findings: number
    console_errors: number
    request_count: number
  }
}

const SECURITY_HEADERS = ["content-security-policy", "x-content-type-options", "referrer-policy"]
const SECRET_STORAGE_KEYS = new Set([
  "token",
  "secret",
  "password",
  "passwd",
  "jwt",
  "apikey",
  "api_key",
  "api_secret",
  "api_token",
  "authtoken",
  "auth_token",
  "authkey",
  "auth_key",
  "authsecret",
  "auth_secret",
  "sessionid",
  "session_id",
  "sessiontoken",
  "session_token",
  "csrftoken",
  "csrf_token",
  "bearertoken",
  "bearer_token",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "clientsecret",
  "client_secret",
])
const SECRET_VALUE = /(sk_(live|test)_[a-z0-9]{16,}|gh[pousr]_[a-z0-9]{20,}|xox[baprs]-[a-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,})/i
const CSRF_FIELD = /^(?:_?csrf(?:[-_]?token|middlewaretoken)?|x[-_]?srf(?:[-_]?token)?|authenticity[-_]?token|anti[-_]?forgery[-_]?token|__requestverificationtoken)$/i

function isSecret(value: string) {
  return SECRET_VALUE.test(value)
}

function normalizeStorageKey(key: string) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
}

function isSecretStorageKey(key: string) {
  return SECRET_STORAGE_KEYS.has(normalizeStorageKey(key))
}

function secretStorageEvidence(storage?: PassiveInput["storage"]) {
  const evidence: string[] = []

  for (const [scope, entries] of Object.entries(storage ?? {})) {
    if (!entries) continue
    for (const [key, value] of Object.entries(entries)) {
      const path = `${scope}.${key}`
      if (isSecretStorageKey(key)) evidence.push(path)
      if (isSecret(value)) evidence.push(`${path} value matches token pattern`)
    }
  }

  return evidence
}

function weakCookieEvidence(cookie: PassiveCookie) {
  const evidence: string[] = []

  if (!cookie.secure) evidence.push(`${cookie.name}: missing Secure`)
  if (!cookie.httpOnly) evidence.push(`${cookie.name}: missing HttpOnly`)
  if (!cookie.sameSite) evidence.push(`${cookie.name}: missing SameSite`)
  if (cookie.sameSite?.toLowerCase() === "none" && !cookie.secure)
    evidence.push(`${cookie.name}: SameSite=None without Secure`)

  return evidence
}

function missingSecurityHeaderEvidence(headers?: Record<string, string>) {
  const normalized = new Set(Object.keys(headers ?? {}).map((header) => header.toLowerCase()))
  return SECURITY_HEADERS.filter((header) => !normalized.has(header))
}

function methodIsPost(method: string) {
  return method.toLowerCase() === "post"
}

function hasCsrfField(inputs: PassiveFormInput[]) {
  return inputs.some((input) => CSRF_FIELD.test(input.name ?? ""))
}

function csrfFormEvidence(form: PassiveForm) {
  if (!methodIsPost(form.method)) return []
  if (hasCsrfField(form.inputs)) return []
  return [`${form.name ?? form.action}: POST form missing CSRF token`]
}

function isMixedContentUrl(pageUrl: string, targetUrl: string) {
  return pageUrl.startsWith("https://") && targetUrl.startsWith("http://")
}

function mixedContentEvidence(input: PassiveInput) {
  const evidence = new Map<string, string>()

  for (const request of input.requests ?? []) {
    if (!isMixedContentUrl(input.url, request.url)) continue
    if (!evidence.has(request.url)) evidence.set(request.url, `request: ${request.url}`)
  }

  for (const script of input.scripts?.external ?? []) {
    if (!isMixedContentUrl(input.url, script)) continue
    if (!evidence.has(script)) evidence.set(script, `script: ${script}`)
  }

  for (const form of input.forms ?? []) {
    if (!isMixedContentUrl(input.url, form.action)) continue
    if (!evidence.has(form.action)) evidence.set(form.action, `form: ${form.action}`)
  }

  return [...evidence.values()]
}

function makeFinding(id: PassiveFindingId, severity: PassiveFindingSeverity, title: string, evidence: string[]): PassiveFinding {
  return { id, severity, title, evidence }
}

function summarize(findings: PassiveFinding[], consoleErrors: number, requestCount: number) {
  return {
    high: findings.filter((item) => item.severity === "high").length,
    medium: findings.filter((item) => item.severity === "medium").length,
    low: findings.filter((item) => item.severity === "low").length,
    total_findings: findings.length,
    console_errors: consoleErrors,
    request_count: requestCount,
  }
}

export function analyzePassiveAppSec(input: PassiveInput): PassiveReport {
  const findings: PassiveFinding[] = []

  const secretStorage = secretStorageEvidence(input.storage)
  if (secretStorage.length) {
    findings.push(
      makeFinding(
        "storage-secret",
        "high",
        "Secret-like value in storage",
        secretStorage,
      ),
    )
  }

  const weakCookies = (input.cookies ?? []).flatMap(weakCookieEvidence)
  if (weakCookies.length) {
    findings.push(
      makeFinding(
        "weak-cookie",
        "medium",
        "Weak cookie attributes",
        weakCookies,
      ),
    )
  }

  const missingHeaders = missingSecurityHeaderEvidence(input.headers)
  if (missingHeaders.length) {
    findings.push(
      makeFinding(
        "missing-security-header",
        "low",
        "Missing security headers",
        missingHeaders,
      ),
    )
  }

  const csrfEvidence = (input.forms ?? []).flatMap(csrfFormEvidence)
  if (csrfEvidence.length) {
    findings.push(
      makeFinding(
        "csrf-form",
        "medium",
        "POST form without CSRF token",
        csrfEvidence,
      ),
    )
  }

  const mixedContent = mixedContentEvidence(input)
  if (mixedContent.length) {
    findings.push(
      makeFinding(
        "mixed-content",
        "high",
        "Mixed content loaded over HTTP",
        mixedContent,
      ),
    )
  }

  const consoleErrors = (input.console ?? []).filter((entry) => {
    const level = entry.level.toLowerCase()
    return level === "error" || level === "pageerror"
  }).length

  return {
    findings,
    summary: summarize(findings, consoleErrors, (input.requests ?? []).length),
  }
}
