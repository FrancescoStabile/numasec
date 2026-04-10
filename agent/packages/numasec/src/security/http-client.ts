/**
 * Shared HTTP client for all security scanners.
 *
 * Wraps fetch() with:
 * - Follow redirects (configurable depth)
 * - Skip TLS verification (NODE_TLS_REJECT_UNAUTHORIZED=0)
 * - Configurable timeout
 * - SSRF protection: blocks private IPs unless NUMASEC_ALLOW_INTERNAL=1
 */

const DEFAULT_TIMEOUT = 15_000
const MAX_REDIRECTS = 10

export interface HttpRequestOptions {
  method?: string
  headers?: Record<string, string>
  body?: string
  timeout?: number
  followRedirects?: boolean
  maxRedirects?: number
  cookies?: string
  skipSsrfCheck?: boolean
}

export interface HttpResponse {
  status: number
  statusText: string
  headers: Record<string, string>
  body: string
  url: string
  redirectChain: string[]
  elapsed: number
}

// ── SSRF Protection ────────────────────────────────────────────

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc/i,
  /^fd/i,
  /^fe80:/i,
]

const PRIVATE_HOSTS = new Set(["localhost", "0.0.0.0", "[::1]"])

function isPrivateHost(hostname: string): boolean {
  if (PRIVATE_HOSTS.has(hostname.toLowerCase())) return true
  return PRIVATE_RANGES.some((re) => re.test(hostname))
}

function assertNotSsrf(url: string): void {
  if (process.env.NUMASEC_ALLOW_INTERNAL === "1") return
  try {
    const parsed = new URL(url)
    if (isPrivateHost(parsed.hostname)) {
      throw new Error(`SSRF blocked: ${parsed.hostname} is a private address. Set NUMASEC_ALLOW_INTERNAL=1 to override.`)
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("SSRF")) throw e
    // Invalid URL — let fetch() handle it
  }
}

// ── Core fetch wrapper ─────────────────────────────────────────

/**
 * Make an HTTP request with scanner-appropriate defaults.
 *
 * Unlike raw fetch(), this:
 * - Returns the full body as a string
 * - Tracks redirect chains
 * - Measures elapsed time
 * - Applies SSRF protection
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
    skipSsrfCheck = false,
  } = options

  if (!skipSsrfCheck) assertNotSsrf(url)

  // Disable TLS verification for scanners (targets often use self-signed certs)
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

  const reqHeaders: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (compatible; numasec/4.2)",
    ...headers,
  }
  if (cookies) reqHeaders["Cookie"] = cookies

  const redirectChain: string[] = []
  let currentUrl = url
  const start = Date.now()

  for (let i = 0; i <= maxRedirects; i++) {
    if (!skipSsrfCheck && i > 0) assertNotSsrf(currentUrl)

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)

    try {
      const response = await fetch(currentUrl, {
        method: i === 0 ? method : "GET",
        headers: reqHeaders,
        body: i === 0 ? body : undefined,
        signal: controller.signal,
        redirect: "manual",
      })
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

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
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
    body: "",
    url: currentUrl,
    redirectChain,
    elapsed: Date.now() - start,
  }
}
