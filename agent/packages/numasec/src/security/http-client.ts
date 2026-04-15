/**
 * Shared HTTP client for all security scanners.
 *
 * Wraps fetch() with:
 * - Follow redirects (configurable depth)
 * - Respect TLS verification by default with opt-in insecure override
 * - Configurable timeout
 */

import { Flag } from "../flag/flag"
import type { SessionID } from "../session/schema"
import { Scope } from "./scope"

const DEFAULT_TIMEOUT = 15_000
const MAX_REDIRECTS = 10
type HttpFetchOptions = RequestInit & { tls?: { rejectUnauthorized: boolean } }

export interface HttpRequestOptions {
  method?: string
  headers?: Record<string, string>
  body?: string
  timeout?: number
  followRedirects?: boolean
  maxRedirects?: number
  cookies?: string
  insecureTls?: boolean
  sessionID?: SessionID | string
}

export interface HttpResponse {
  status: number
  statusText: string
  headers: Record<string, string>
  setCookies: string[]
  body: string
  url: string
  redirectChain: string[]
  elapsed: number
}

export function insecureTlsEnabled(options: HttpRequestOptions = {}) {
  if (typeof options.insecureTls === "boolean") return options.insecureTls
  return Flag.NUMASEC_SECURITY_INSECURE_TLS
}

export function httpRequestTls(options: HttpRequestOptions = {}) {
  if (!insecureTlsEnabled(options)) return
  return { rejectUnauthorized: false }
}

// ── Core fetch wrapper ─────────────────────────────────────────

/**
 * Make an HTTP request with scanner-appropriate defaults.
 *
 * Unlike raw fetch(), this:
 * - Returns the full body as a string
 * - Tracks redirect chains
 * - Measures elapsed time
 */
export async function httpRequest(
  url: string,
  options: HttpRequestOptions = {},
): Promise<HttpResponse> {
  const {
    method = "GET",
    headers = {},
    body,
    timeout = DEFAULT_TIMEOUT,
    followRedirects = true,
    maxRedirects = MAX_REDIRECTS,
    cookies,
  } = options

  const reqHeaders: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (compatible; numasec/5.0)",
    ...headers,
  }
  if (cookies) reqHeaders["Cookie"] = cookies

  const redirectChain: string[] = []
  let currentUrl = url
  const start = Date.now()

  for (let i = 0; i <= maxRedirects; i++) {
    if (options.sessionID) {
      Scope.ensure(options.sessionID, currentUrl)
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)

    try {
      const request: HttpFetchOptions = {
        method: i === 0 ? method : "GET",
        headers: reqHeaders,
        body: i === 0 ? body : undefined,
        signal: controller.signal,
        redirect: "manual",
      }
      const tls = httpRequestTls(options)
      if (tls) request.tls = tls
      const response = await fetch(currentUrl, request)
      clearTimeout(timer)

      // Handle redirects manually to track chain
      if (followRedirects && response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location")
        if (location) {
          redirectChain.push(currentUrl)
          currentUrl = new URL(location, currentUrl).href
          continue
        }
      }

      const responseBody = await response.text()
      const elapsed = Date.now() - start

      const responseHeaders: Record<string, string> = {}
      response.headers.forEach((v, k) => { responseHeaders[k] = v })
      const setCookies =
        typeof (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === "function"
          ? (response.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
          : response.headers.get("set-cookie")
            ? [response.headers.get("set-cookie") ?? ""]
            : []

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        setCookies,
        body: responseBody,
        url: currentUrl,
        redirectChain,
        elapsed,
      }
    } catch (error) {
      clearTimeout(timer)
      if (error instanceof DOMException && error.name === "AbortError") {
        return {
          status: 0,
          statusText: "Timeout",
          headers: {},
          setCookies: [],
          body: "",
          url: currentUrl,
          redirectChain,
          elapsed: Date.now() - start,
        }
      }
      return {
        status: 0,
        statusText: String(error),
        headers: {},
        setCookies: [],
        body: "",
        url: currentUrl,
        redirectChain,
        elapsed: Date.now() - start,
      }
    }
  }

  return {
    status: 0,
    statusText: "Too many redirects",
    headers: {},
    setCookies: [],
    body: "",
    url: currentUrl,
    redirectChain,
    elapsed: Date.now() - start,
  }
}
