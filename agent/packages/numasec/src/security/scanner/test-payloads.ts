/**
 * Scanner: test_payloads
 *
 * Generic payload→response scanner that replaces ~10 individual Python
 * scanners. Takes a URL, parameter, list of payloads, and success/failure
 * indicators. Sends each payload and checks responses for matches.
 *
 * This is the core scanning primitive. Composite tools call this with
 * different payload sets (SQLi, XSS, SSTI, CmdI, CRLF, LFI, etc.)
 */

import { httpRequest, type HttpResponse, type HttpRequestOptions } from "../http-client"

export type PayloadPosition = "query" | "body" | "header" | "path" | "cookie" | "json"

export interface PayloadConfig {
  url: string
  method?: string
  parameter: string
  position: PayloadPosition
  payloads: string[]
  successIndicators: string[]
  failureIndicators?: string[]
  headers?: Record<string, string>
  cookies?: string
  baseBody?: string
  timeout?: number
  concurrency?: number
  timingThresholdMs?: number
}

export interface PayloadResult {
  vulnerable: boolean
  payload: string
  evidence: string
  status: number
  elapsed: number
  matchType: "content" | "timing" | "status" | "error" | "none"
}

export interface ScanResult {
  vulnerable: boolean
  results: PayloadResult[]
  testedCount: number
  baselineStatus: number
  baselineLength: number
}

/**
 * Build a request with the payload injected at the specified position.
 */
function buildRequest(
  config: PayloadConfig,
  payload: string,
): { url: string; options: HttpRequestOptions } {
  const { url, method = "GET", parameter, position, headers = {}, cookies, baseBody, timeout } = config

  const options: HttpRequestOptions = {
    method,
    headers: { ...headers },
    cookies,
    timeout: timeout ?? 15_000,
    followRedirects: true,
  }

  switch (position) {
    case "query": {
      const u = new URL(url)
      u.searchParams.set(parameter, payload)
      return { url: u.href, options }
    }

    case "body": {
      const params = new URLSearchParams(baseBody ?? "")
      params.set(parameter, payload)
      options.body = params.toString()
      options.method = method === "GET" ? "POST" : method
      options.headers = { ...options.headers, "Content-Type": "application/x-www-form-urlencoded" }
      return { url, options }
    }

    case "json": {
      const json = baseBody ? JSON.parse(baseBody) : {}
      json[parameter] = payload
      options.body = JSON.stringify(json)
      options.method = method === "GET" ? "POST" : method
      options.headers = { ...options.headers, "Content-Type": "application/json" }
      return { url, options }
    }

    case "header": {
      options.headers = { ...options.headers, [parameter]: payload }
      return { url, options }
    }

    case "path": {
      const replaced = url.replace(`{${parameter}}`, encodeURIComponent(payload))
      return { url: replaced, options }
    }

    case "cookie": {
      const existing = cookies ? `${cookies}; ` : ""
      options.cookies = `${existing}${parameter}=${payload}`
      return { url, options }
    }

    default:
      return { url, options }
  }
}

/**
 * Check if a response matches success indicators.
 */
function checkIndicators(
  response: HttpResponse,
  config: PayloadConfig,
  baselineElapsed: number,
): { matched: boolean; matchType: PayloadResult["matchType"]; evidence: string } {
  const body = response.body.toLowerCase()

  // Check failure indicators first — if any match, this is NOT a hit
  if (config.failureIndicators) {
    for (const indicator of config.failureIndicators) {
      if (body.includes(indicator.toLowerCase())) {
        return { matched: false, matchType: "none", evidence: "" }
      }
    }
  }

  // Content-based matching
  for (const indicator of config.successIndicators) {
    const lower = indicator.toLowerCase()
    if (body.includes(lower)) {
      const idx = body.indexOf(lower)
      const start = Math.max(0, idx - 50)
      const end = Math.min(body.length, idx + indicator.length + 50)
      const snippet = response.body.slice(start, end)
      return {
        matched: true,
        matchType: "content",
        evidence: `Indicator "${indicator}" found in response: ...${snippet}...`,
      }
    }
  }

  // Timing-based detection (e.g., SQL SLEEP)
  if (config.timingThresholdMs && response.elapsed > config.timingThresholdMs) {
    const diff = response.elapsed - baselineElapsed
    if (diff > config.timingThresholdMs * 0.8) {
      return {
        matched: true,
        matchType: "timing",
        evidence: `Response took ${response.elapsed}ms (baseline: ${baselineElapsed}ms, threshold: ${config.timingThresholdMs}ms)`,
      }
    }
  }

  // Status-based detection (5xx suggests error injection worked)
  if (response.status >= 500) {
    return {
      matched: true,
      matchType: "status",
      evidence: `Server error ${response.status} after payload injection`,
    }
  }

  return { matched: false, matchType: "none", evidence: "" }
}

/**
 * Run the payload scan. Sends a baseline request first, then tests each payload.
 */
export async function testPayloads(config: PayloadConfig): Promise<ScanResult> {
  const concurrency = config.concurrency ?? 5

  // Baseline request with benign value
  const baseline = buildRequest({ ...config, payloads: [] }, "test123")
  const baselineResponse = await httpRequest(baseline.url, baseline.options)
  const baselineElapsed = baselineResponse.elapsed

  const results: PayloadResult[] = []
  let vulnerable = false

  // Process payloads in batches
  for (let i = 0; i < config.payloads.length; i += concurrency) {
    const batch = config.payloads.slice(i, i + concurrency)

    const batchResults = await Promise.all(
      batch.map(async (payload) => {
        const req = buildRequest(config, payload)
        const response = await httpRequest(req.url, req.options)
        const check = checkIndicators(response, config, baselineElapsed)

        const result: PayloadResult = {
          vulnerable: check.matched,
          payload,
          evidence: check.evidence,
          status: response.status,
          elapsed: response.elapsed,
          matchType: check.matchType,
        }

        if (check.matched) vulnerable = true
        return result
      }),
    )

    results.push(...batchResults)
  }

  return {
    vulnerable,
    results,
    testedCount: config.payloads.length,
    baselineStatus: baselineResponse.status,
    baselineLength: baselineResponse.body.length,
  }
}
